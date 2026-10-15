# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""``agent-shield serve``: WebSocket and ACP Streamable HTTP, one harness per connection (SHIELD SH-52, SH-56)."""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from acp import text_block
from acp.schema import AllowedOutcome, RequestPermissionResponse

from agent_shield.acp import StdioACPChannel, WebSocketACPChannel
from agent_shield.acp.proxy import ShieldProxy
from agent_shield.acp.remote import RemoteRefused, remote_url
from agent_shield.acp.server import (
    ACP_PATH,
    HEADER_CONNECTION,
    HEADER_SESSION,
    UNAUTHENTICATED,
    ServeRefused,
    ShieldBackend,
    ShieldServer,
)
from agent_shield.audit import AuditLog
from agent_shield.policy import LoadedPolicy, default_policy

aiohttp = pytest.importorskip("aiohttp", reason="`serve` needs the serve extra")
websockets = pytest.importorskip("websockets", reason="the WebSocket channel needs the websocket extra")

FAKE = str(Path(__file__).parent / "fixtures" / "fake_agent.py")
TOKEN = "s3cret-token-for-the-tests"  # noqa: S105 - a test's token


class Handler:
    """A client's side: allows every permission, keeps what it saw."""

    def __init__(self) -> None:
        self.updates: list[str] = []
        self.permissions: list[str] = []

    async def session_update(self, session_id, update, **kw):
        self.updates.append(update.session_update)

    async def request_permission(self, options, session_id, tool_call, **kw):
        self.permissions.append(tool_call.title)
        return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id=options[0].option_id))


def _factory(tmp_path: Path, audit: AuditLog):
    def make() -> ShieldProxy:
        return ShieldProxy(
            [sys.executable, FAKE],
            policies=[LoadedPolicy(policy=default_policy(), origin="the default")],
            audit=audit,
            workspace=tmp_path,
        )

    return make


@pytest.fixture
async def server(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.jsonl", environment={})
    served = ShieldServer({"": _factory(tmp_path, audit)}, audit=audit, idle_seconds=2.0)
    await served.start("127.0.0.1", 0)
    try:
        yield served
    finally:
        await served.stop()


@pytest.fixture
async def tokened(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.jsonl", environment={})
    served = ShieldServer({"": _factory(tmp_path, audit), "fake": _factory(tmp_path, audit)}, audit=audit, token=TOKEN)
    await served.start("127.0.0.1", 0)
    try:
        yield served
    finally:
        await served.stop()


def ws_url(server: ShieldServer, suffix: str = "") -> str:
    return f"ws://127.0.0.1:{server.port}{ACP_PATH}{suffix}"


# -- WebSocket -----------------------------------------------------------------------------------


async def test_the_websocket_channel_drives_a_shielded_harness_through_serve(server: ShieldServer, tmp_path: Path):
    handler = Handler()
    (tmp_path / "README.md").write_text("readme\n")
    async with WebSocketACPChannel.connect(handler, ws_url(server)) as channel:
        answer = await channel.initialize()
        assert answer.agent_info is not None and answer.agent_info.name == "agent-shield"
        session = await channel.new_session(tmp_path)
        turn = await channel.prompt(session.session_id, [text_block("please edit and read")])
        assert turn.stop_reason == "end_turn"
        assert "tool_call" in handler.updates and "agent_message_chunk" in handler.updates
        # The default policy allows an edit inside the workspace: the Shield answered it, the client was not asked.
        assert handler.permissions == []
        assert (tmp_path / "hello.txt").read_text() == "hello, shield\n"
        assert len(server.connections) == 1
    await asyncio.sleep(0.2)
    assert server.connections == {}
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(row["event"] == "session" and row.get("what") == "connection" for row in rows)
    assert any(row["event"] == "session" and row.get("what") == "connection_closed" for row in rows)
    assert any(row["event"] == "fs_write" for row in rows)


async def test_each_connection_gets_a_harness_of_its_own(server: ShieldServer, tmp_path: Path):
    async with (
        WebSocketACPChannel.connect(Handler(), ws_url(server)) as one,
        WebSocketACPChannel.connect(Handler(), ws_url(server, "/ws")) as two,
    ):
        await one.initialize()
        await two.initialize()
        backends = [served.backend for served in server.connections.values()]
        assert len(backends) == 2 and all(isinstance(backend, ShieldBackend) for backend in backends)
        processes = {backend.proxy.channel.process.pid for backend in backends}  # type: ignore[union-attr]
        assert len(processes) == 2


async def test_a_bearer_header_authenticates_the_websocket(tokened: ShieldServer, tmp_path: Path):
    async with WebSocketACPChannel.connect(
        Handler(), ws_url(tokened, "/fake"), headers={"Authorization": f"Bearer {TOKEN}"}
    ) as channel:
        answer = await channel.initialize()
        assert answer.protocol_version == 1


async def test_the_token_in_the_first_message_authenticates_the_websocket(tokened: ShieldServer):
    from websockets.asyncio.client import connect

    async with connect(ws_url(tokened)) as socket:
        await socket.send(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "authenticate",
                    "params": {"methodId": "bearer", "_meta": {"token": TOKEN}},
                }
            )
        )
        assert json.loads(await socket.recv()) == {"jsonrpc": "2.0", "id": 1, "result": {}}
        await socket.send(
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": 1}})
        )
        answer = json.loads(await socket.recv())
        assert answer["id"] == 2 and answer["result"]["protocolVersion"] == 1


async def test_a_websocket_that_does_not_authenticate_first_is_refused_and_closed(tokened: ShieldServer):
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed

    async with connect(ws_url(tokened)) as socket:
        await socket.send(
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        )
        answer = json.loads(await socket.recv())
        assert answer["error"]["code"] == UNAUTHENTICATED and "authenticate first" in answer["error"]["message"]
        with pytest.raises(ConnectionClosed):
            await socket.recv()
    async with connect(ws_url(tokened)) as socket:
        await socket.send(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "authenticate",
                    "params": {"methodId": "bearer", "_meta": {"token": "wrong"}},
                }
            )
        )
        answer = json.loads(await socket.recv())
        assert answer["error"]["code"] == UNAUTHENTICATED and "wrong" in answer["error"]["message"]
    assert tokened.connections == {}


async def test_a_wrong_header_and_a_token_in_the_address_are_refused(tokened: ShieldServer):
    from websockets.asyncio.client import connect
    from websockets.exceptions import InvalidStatus

    with pytest.raises(InvalidStatus) as refused:
        async with connect(ws_url(tokened), additional_headers={"Authorization": "Bearer nope"}):
            pass
    assert refused.value.response.status_code == 401
    assert refused.value.response.headers.get("WWW-Authenticate") == 'Bearer realm="agent-shield"'
    with pytest.raises(InvalidStatus) as address:
        async with connect(
            ws_url(tokened) + f"?token={TOKEN}", additional_headers={"Authorization": f"Bearer {TOKEN}"}
        ):
            pass
    assert address.value.response.status_code == 400


async def test_beyond_the_loopback_a_token_is_needed(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.jsonl", environment={})
    served = ShieldServer({"": _factory(tmp_path, audit)}, audit=audit)
    with pytest.raises(ServeRefused, match="needs a token"):
        await served.start("0.0.0.0", 0)  # noqa: S104 - the refusal is the point
    with pytest.raises(ServeRefused, match="nothing to serve"):
        ShieldServer({}, audit=audit)


# -- Streamable HTTP ----------------------------------------------------------------------------


async def _events(response, until, timeout: float = 10.0) -> list[dict]:
    """The SSE events of a stream until ``until(message)`` says so."""
    seen: list[dict] = []

    async def read() -> None:
        buffer = b""
        async for chunk in response.content.iter_any():
            buffer += chunk
            while b"\n\n" in buffer:
                event, buffer = buffer.split(b"\n\n", 1)
                for line in event.split(b"\n"):
                    if line.startswith(b"data: "):
                        message = json.loads(line[6:])
                        seen.append(message)
                        if until(message):
                            return

    await asyncio.wait_for(read(), timeout=timeout)
    return seen


async def test_streamable_http_carries_a_whole_turn_with_a_permission_answered_by_post(
    tokened: ShieldServer, tmp_path: Path
):
    base = f"http://127.0.0.1:{tokened.port}{ACP_PATH}"
    auth = {"Authorization": f"Bearer {TOKEN}"}
    async with aiohttp.ClientSession(headers=auth) as http:
        # 1. initialize makes the connection: 200, the result, the id in the header and the body.
        initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}}
        async with http.post(base, json=initialize) as answer:
            assert answer.status == 200
            connection = answer.headers[HEADER_CONNECTION]
            body = await answer.json()
            assert body["result"]["protocolVersion"] == 1 and body["result"]["connectionId"] == connection
        headers = {HEADER_CONNECTION: connection}
        # 2. session/new is 202; its response arrives on the connection-scoped stream.
        async with http.get(base, headers={**headers, "Accept": "text/event-stream"}) as stream:
            assert stream.status == 200
            new = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "session/new",
                "params": {"cwd": str(tmp_path), "mcpServers": []},
            }
            async with http.post(base, json=new, headers=headers) as accepted:
                assert accepted.status == 202
            seen = await _events(stream, lambda m: m.get("id") == 2)
            session = seen[-1]["result"]["sessionId"]
        # 3. a session-scoped POST without the session header is refused; with it, the turn's updates,
        #    the permission request and the prompt's response arrive on the session-scoped stream.
        prompt = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "session/prompt",
            "params": {"sessionId": session, "prompt": [{"type": "text", "text": "push"}]},
        }
        async with http.post(base, json=prompt, headers=headers) as refused:
            assert refused.status == 400 and HEADER_SESSION in await refused.text()
        scoped = {**headers, HEADER_SESSION: session}
        async with http.get(base, headers={**scoped, "Accept": "text/event-stream"}) as stream:
            async with http.post(base, json=prompt, headers=scoped) as accepted:
                assert accepted.status == 202
            seen = await _events(stream, lambda m: m.get("method") == "session/request_permission")
            asked = seen[-1]
            assert asked["params"]["toolCall"]["title"] == "git push origin main"
            option = asked["params"]["options"][0]["optionId"]
            reply = {
                "jsonrpc": "2.0",
                "id": asked["id"],
                "result": {"outcome": {"outcome": "selected", "optionId": option}},
            }
            async with http.post(base, json=reply, headers=scoped) as accepted:
                assert accepted.status == 202
            seen = await _events(stream, lambda m: m.get("id") == 3)
            assert seen[-1]["result"]["stopReason"] == "end_turn"
            assert any(m.get("method") == "session/update" for m in seen)
        # 4. DELETE ends the connection and the harness.
        pid = next(iter(tokened.connections.values())).backend.proxy.channel.process.pid  # type: ignore[union-attr]
        async with http.delete(base, headers=headers) as ended:
            assert ended.status == 202
        assert tokened.connections == {}
        await asyncio.sleep(0.3)
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        # 5. what the transport refuses, in its own words.
        async with http.post(base, json=new) as missing:
            assert missing.status == 400
        async with http.get(base, headers={HEADER_CONNECTION: "nope", "Accept": "text/event-stream"}) as unknown:
            assert unknown.status == 404
        async with http.post(base, json=[initialize]) as batch:
            assert batch.status == 501
        async with http.post(base, data="x", headers={"Content-Type": "text/plain"}) as plain:
            assert plain.status == 415
    async with aiohttp.ClientSession() as anonymous:
        async with anonymous.post(base, json=initialize) as refused:
            assert refused.status == 401 and refused.headers["WWW-Authenticate"] == 'Bearer realm="agent-shield"'
        async with anonymous.post(f"{base}?access_token={TOKEN}", json=initialize, headers=auth) as address:
            assert address.status == 400 and "never in the address" in await address.text()


async def test_an_idle_http_connection_is_ended(server: ShieldServer):
    base = f"http://127.0.0.1:{server.port}{ACP_PATH}"
    async with aiohttp.ClientSession() as http:
        initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}}
        async with http.post(base, json=initialize) as answer:
            assert answer.status == 200
    assert len(server.connections) == 1
    await asyncio.sleep(3.5)
    assert server.connections == {}


# -- the bridge and the mirror ------------------------------------------------------------------


async def test_the_bridge_relays_verbatim_to_a_harness_per_connection(tmp_path: Path):
    from websockets.asyncio.client import connect

    audit = AuditLog(tmp_path / "audit.jsonl", environment={})
    server = ShieldServer({"fake": [sys.executable, FAKE]}, audit=audit, bridge_cwd=str(tmp_path))
    await server.start("127.0.0.1", 0)
    try:
        assert server.bridge
        async with connect(ws_url(server, "/fake")) as socket:
            await socket.send(
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            )
            answer = json.loads(await socket.recv())
            # No Shield in between: the harness's own name comes back.
            assert answer["result"]["agentInfo"]["name"] == "fake-agent"
        await asyncio.sleep(0.2)
        assert server.connections == {}
    finally:
        await server.stop()


async def test_connect_mirrors_a_served_shield_on_stdio(tokened: ShieldServer, tmp_path: Path):
    handler = Handler()
    (tmp_path / "README.md").write_text("readme\n")
    env = {**os.environ, "SHIELD_TOKEN": TOKEN}
    async with StdioACPChannel.launch(
        handler,
        sys.executable,
        "-m",
        "agent_shield.cli",
        "connect",
        ws_url(tokened, "/fake"),
        "--token-env",
        "SHIELD_TOKEN",
        cwd=tmp_path,
        env=env,
    ) as channel:
        answer = await channel.initialize()
        assert answer.agent_info is not None and answer.agent_info.name == "agent-shield"
        session = await channel.new_session(tmp_path)
        turn = await channel.prompt(session.session_id, [text_block("please read")])
        assert turn.stop_reason == "end_turn"


def test_the_mirror_refuses_a_token_in_the_address():
    assert remote_url("ws://127.0.0.1:1/acp") == "ws://127.0.0.1:1/acp"
    with pytest.raises(RemoteRefused, match="never in the address"):
        remote_url("ws://127.0.0.1:1/acp?token=x")
    with pytest.raises(RemoteRefused, match="never in the address"):
        remote_url("ws://user:pw@127.0.0.1:1/acp")
    with pytest.raises(RemoteRefused, match="ws://"):
        remote_url("http://127.0.0.1:1/acp")


# -- the command ---------------------------------------------------------------------------------


async def test_the_serve_command_listens_and_says_where(tmp_path: Path):
    policy = tmp_path / "agent-shield.yaml"
    subprocess.run(
        [sys.executable, "-m", "agent_shield.cli", "policy", "init", str(policy)], check=True, capture_output=True
    )
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "agent_shield.cli",
        "serve",
        "--port",
        "0",
        "--policy",
        str(policy),
        "--workspace",
        str(tmp_path),
        "--audit",
        str(tmp_path / "audit.jsonl"),
        "--",
        sys.executable,
        FAKE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "AGENT_SHIELD_HOME": str(tmp_path / "home")},
    )
    assert process.stderr is not None
    port = None
    try:
        for _ in range(20):
            line = (await asyncio.wait_for(process.stderr.readline(), timeout=20)).decode()
            found = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
            if found:
                port = int(found.group(1))
                assert "no token: loopback only" in line
                break
        assert port, "serve did not say where it listens"
        async with WebSocketACPChannel.connect(Handler(), f"ws://127.0.0.1:{port}/acp") as channel:
            assert (await channel.initialize()).protocol_version == 1
    finally:
        process.terminate()
        await process.wait()


def test_serve_refuses_an_empty_token_and_a_missing_command(tmp_path: Path):
    env = {**os.environ, "AGENT_SHIELD_HOME": str(tmp_path), "EMPTY": ""}
    out = subprocess.run(
        [sys.executable, "-m", "agent_shield.cli", "serve", "--token-env", "EMPTY", "--", "x"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert out.returncode == 2 and "never from an argument or the address" in out.stderr
    out = subprocess.run([sys.executable, "-m", "agent_shield.cli", "serve"], capture_output=True, text=True, env=env)
    assert out.returncode == 2 and "one command after `--`" in out.stderr
