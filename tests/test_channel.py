# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The stdio and WebSocket ``ACPChannel`` (SHIELD SH-02)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from acp import text_block
from acp.exceptions import RequestError
from acp.schema import AllowedOutcome, ReadTextFileResponse, RequestPermissionResponse

from agent_shield.acp import ChannelRefused, StdioACPChannel, WebSocketACPChannel, build_handler
from agent_shield.acp.channel import ELICITATION_CREATE

FAKE = str(Path(__file__).parent / "fixtures" / "fake_agent.py")


class Handler:
    def __init__(self) -> None:
        self.updates: list[str] = []
        self.permissions: list[str] = []
        self.questions: list[dict] = []

    async def session_update(self, session_id, update, **kw):
        self.updates.append(update.session_update)

    async def request_permission(self, options, session_id, tool_call, **kw):
        self.permissions.append(tool_call.title)
        return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id="allow"))

    async def read_text_file(self, path, session_id, **kw):
        return ReadTextFileResponse(content="readme text")

    async def write_text_file(self, content, path, session_id, **kw):
        return None

    async def elicitation(self, session_id, params):
        self.questions.append(params)
        return {"action": "accept", "content": {"answer": "yes"}}


async def test_the_stdio_channel_launches_initializes_prompts_and_ends_the_process(tmp_path: Path):
    handler = Handler()
    stderr: list[str] = []
    async with StdioACPChannel.launch(handler, sys.executable, FAKE, cwd=tmp_path, stderr=stderr.append) as channel:
        answer = await channel.initialize()
        assert answer.protocol_version == 1 and channel.agent_info.name == "fake-agent"
        assert channel.agent_capabilities.load_session is True
        session = await channel.new_session(tmp_path)
        seen: list[dict] = []
        stop = channel.listen(seen.append)
        turn = await channel.prompt(session.session_id, [text_block("please edit and read")])
        stop()
        assert turn.stop_reason == "end_turn"
        assert handler.permissions == ["Edit hello.txt"]
        assert "tool_call" in handler.updates and "agent_message_chunk" in handler.updates
        assert any(m.get("method") == "session/prompt" and m["direction"] == "outgoing" for m in seen)
        assert any(m.get("method") == "session/update" and m["direction"] == "incoming" for m in seen)
        loaded = await channel.load_session(session.session_id, tmp_path)
        assert loaded is not None and "agent_message_chunk" in handler.updates
        await channel.set_mode(session.session_id, "plan")
        await channel.cancel(session.session_id)
        process = channel.process
    assert process.returncode is not None
    assert any("fake-agent: session" in line for line in stderr)


async def test_a_turn_can_be_cancelled(tmp_path: Path):
    async with StdioACPChannel.launch(Handler(), sys.executable, FAKE, cwd=tmp_path) as channel:
        await channel.initialize()
        session = await channel.new_session(tmp_path)
        turn = asyncio.create_task(channel.prompt(session.session_id, [text_block("slow")]))
        await asyncio.sleep(0.2)
        await channel.cancel(session.session_id)
        assert (await asyncio.wait_for(turn, 5)).stop_reason == "cancelled"


async def test_load_session_is_refused_when_the_agent_does_not_advertise_it(tmp_path: Path):
    async with StdioACPChannel.launch(Handler(), sys.executable, FAKE, cwd=tmp_path) as channel:
        with pytest.raises(ChannelRefused, match="did not advertise loadSession"):
            await channel.load_session("x", tmp_path)


async def test_the_agents_environment_is_trimmed_to_what_is_named(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LEAKY_SECRET_KEY", "nope")
    script = tmp_path / "env_agent.py"
    script.write_text(
        "import os, sys\n"
        "sys.stderr.write('leak=' + os.environ.get('LEAKY_SECRET_KEY', 'absent') + ' named=' + os.environ.get('NAMED', 'absent') + '\\n')\n"
    )
    stderr: list[str] = []
    async with StdioACPChannel.launch(
        Handler(), sys.executable, str(script), stderr=stderr.append, env={"NAMED": "yes"}
    ):
        await asyncio.sleep(0.3)
    assert stderr == ["leak=absent named=yes\n"]


async def test_the_handler_routes_elicitation_create_and_refuses_it_without_a_handler():
    handler = Handler()
    route = build_handler(handler)
    answer = await route(ELICITATION_CREATE, {"sessionId": "s", "message": "ok?"}, False)
    assert answer == {"action": "accept", "content": {"answer": "yes"}} and handler.questions
    with pytest.raises(RequestError, match="Invalid params"):
        await route(ELICITATION_CREATE, {"message": "no session"}, False)

    class NoElicitation:
        async def session_update(self, session_id, update, **kw): ...

    with pytest.raises(RequestError, match="Method not found"):
        await build_handler(NoElicitation())(ELICITATION_CREATE, {"sessionId": "s"}, False)


async def test_an_agent_answering_another_protocol_version_is_refused(tmp_path: Path):
    script = tmp_path / "v2.py"
    script.write_text(
        "import sys, json\n"
        "for line in sys.stdin:\n"
        "    m = json.loads(line)\n"
        "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': {'protocolVersion': 2}}) + '\\n'); sys.stdout.flush()\n"
    )
    async with StdioACPChannel.launch(Handler(), sys.executable, str(script)) as channel:
        with pytest.raises(ChannelRefused, match="answers protocol version 2; the Shield speaks 1"):
            await channel.initialize()


class _AgentSide:
    """What the fake agent needs of its client over a raw Connection: updates and permissions."""

    def __init__(self, connection) -> None:
        self._conn = connection

    async def session_update(self, session_id, update, **kw):
        from acp.schema import SessionNotification
        from acp.utils import notify_model

        await notify_model(self._conn, "session/update", SessionNotification(session_id=session_id, update=update))

    async def request_permission(self, options, session_id, tool_call, **kw):
        from acp.schema import RequestPermissionRequest
        from acp.utils import request_model

        return await request_model(
            self._conn,
            "session/request_permission",
            RequestPermissionRequest(options=options, session_id=session_id, tool_call=tool_call),
            RequestPermissionResponse,
        )

    async def write_text_file(self, session_id, path, content, **kw):
        from acp.schema import WriteTextFileRequest
        from acp.utils import serialize_params

        await self._conn.send_request(
            "fs/write_text_file",
            serialize_params(WriteTextFileRequest(session_id=session_id, path=path, content=content)),
        )


async def test_the_websocket_channel_speaks_the_same_interface(tmp_path: Path):
    pytest.importorskip("websockets")
    from acp.agent.router import build_agent_router
    from acp.connection import Connection
    from websockets.asyncio.server import serve

    from agent_shield.acp.channel import _WebSocketWriter

    sys.path.insert(0, str(Path(FAKE).parent))
    from fake_agent import FakeAgent  # type: ignore[import-not-found]

    async def serve_agent(socket):
        # The SDK's agent-side wrapper wants real asyncio streams; its Connection takes any writer
        # with write and drain, so the server side is wired the way the channel's WebSocket is.
        reader = asyncio.StreamReader()
        agent = FakeAgent()
        connection = Connection(build_agent_router(agent), _WebSocketWriter(socket), reader, listening=False)  # type: ignore[arg-type]
        agent.on_connect(_AgentSide(connection))

        async def feed():
            async for message in socket:
                reader.feed_data((message if isinstance(message, bytes) else message.encode()) + b"\n")
            reader.feed_eof()

        feeder = asyncio.create_task(feed())
        try:
            await connection.main_loop()
        finally:
            feeder.cancel()
            await connection.close()

    async with serve(serve_agent, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        handler = Handler()
        async with WebSocketACPChannel.connect(handler, f"ws://127.0.0.1:{port}/acp") as channel:
            answer = await channel.initialize()
            assert answer.agent_info.name == "fake-agent"
            session = await channel.new_session(tmp_path)
            turn = await channel.prompt(session.session_id, [text_block("please edit")])
            assert turn.stop_reason == "end_turn" and handler.permissions == ["Edit hello.txt"]


async def test_an_agent_that_exits_fails_the_request_at_once_not_at_a_timeout(tmp_path: Path):
    """SH-45's finding: `agent-shield run` with no policy exits, and the caller waited its
    request timeout. A dead agent is a refusal naming its exit code, at once."""
    dead = tmp_path / "dead.py"
    dead.write_text("import sys\nsys.stderr.write('no policy\\n')\nsys.exit(3)\n")
    loop = asyncio.get_running_loop()
    started = loop.time()
    async with StdioACPChannel.launch(
        Handler(), sys.executable, str(dead), cwd=tmp_path, stderr=lambda line: None
    ) as channel:
        with pytest.raises(ChannelRefused, match=r"the agent exited \(code 3\) before answering initialize"):
            await asyncio.wait_for(channel.initialize(), timeout=20)
    assert loop.time() - started < 10


async def test_the_agent_is_handed_a_shell_the_trimmed_environment_drops(tmp_path: Path, monkeypatch):
    """Claude Code's Bash refuses to run without ``SHELL`` (seen live, 20 October 2026)."""
    from agent_shield.acp.channel import with_shell

    monkeypatch.delenv("SHELL", raising=False)
    assert with_shell(None)["SHELL"] == "/bin/sh"
    assert with_shell({"SHELL": "/bin/bash"})["SHELL"] == "/bin/bash"
    monkeypatch.setenv("SHELL", "/bin/zsh")
    assert with_shell({"A": "b"}) == {"A": "b", "SHELL": "/bin/zsh"}
