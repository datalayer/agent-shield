# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Authority across the chain (SHIELD §2.4, SH-33): the execution credential a caller hands the Shield.

Handed in ``_meta.datalayer.credential``, it never reaches the agent (``withheld``
in the ``_meta`` it is handed), it is the authority of every HTTP MCP server the
session is lent — so whatever the agent or a sub-agent it spawns calls through
them is decided by that credential's manifest at the gateway — and a turn
carrying another is refused in a sentence. A stdio server cannot carry it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from acp import RequestError, text_block
from acp.schema import AllowedOutcome, HttpHeader, HttpMcpServer, RequestPermissionResponse, StdioMcpServer

from agent_shield.acp import WebSocketACPChannel
from agent_shield.acp.credential import WITHHELD, take_credential
from agent_shield.acp.proxy import ShieldProxy
from agent_shield.acp.server import ACP_PATH, ShieldServer
from agent_shield.audit import AuditLog
from agent_shield.policy import LoadedPolicy, Mcp, default_policy

pytest.importorskip("aiohttp", reason="`serve` needs the serve extra")
pytest.importorskip("websockets", reason="the WebSocket channel needs the websocket extra")

FAKE = str(Path(__file__).parent / "fixtures" / "fake_agent.py")
GATEWAY = "https://mcp.example/mcp?only=notebooks"


class Client:
    """A client that keeps what the agent said, and allows what it is asked."""

    def __init__(self) -> None:
        self.said: list[str] = []

    async def session_update(self, session_id, update, **kw):
        if update.session_update == "agent_message_chunk":
            self.said.append(update.content.text)

    async def request_permission(self, options, session_id, tool_call, **kw):
        return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id=options[0].option_id))

    def line(self, prefix: str) -> str:
        return next(text for text in self.said if text.startswith(prefix))[len(prefix) :]


def gateway(authorization: str = "Bearer the-clients-own") -> HttpMcpServer:
    return HttpMcpServer(
        type="http",
        name="notebooks",
        url=GATEWAY,
        headers=[HttpHeader(name="Authorization", value=authorization), HttpHeader(name="X-Kept", value="1")],
    )


def handed(credential: str) -> dict:
    return {"datalayer": {"credential": credential, "execution": {"executionId": "ex-1"}}}


@pytest.fixture
async def served(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.jsonl", environment={})
    policy = default_policy().model_copy(update={"mcp": Mcp(allow=["notebooks", "local"])})

    def make() -> ShieldProxy:
        return ShieldProxy(
            [sys.executable, FAKE],
            policies=[LoadedPolicy(policy=policy, origin="the test")],
            audit=audit,
            workspace=tmp_path,
        )

    server = ShieldServer({"": make}, audit=audit, idle_seconds=5.0)
    await server.start("127.0.0.1", 0)
    try:
        yield server, tmp_path / "audit.jsonl"
    finally:
        await server.stop()


def test_the_credential_is_taken_out_and_withheld_in_a_copy():
    meta = handed("tok-exec")
    kept, credential = take_credential(meta)
    assert credential == "tok-exec"
    assert kept["datalayer"]["credential"] == WITHHELD and kept["datalayer"]["execution"] == {"executionId": "ex-1"}
    assert meta["datalayer"]["credential"] == "tok-exec", "the caller's mapping is not changed"
    assert take_credential(kept) == (kept, None), "withheld is not a credential"
    assert take_credential(None) == (None, None)
    assert take_credential({"traceparent": "00-x"}) == ({"traceparent": "00-x"}, None)


async def test_the_lent_servers_carry_the_execution_credential_and_the_agent_never_sees_it(served, tmp_path: Path):
    server, audit = served
    client = Client()
    async with WebSocketACPChannel.connect(client, f"ws://127.0.0.1:{server.port}{ACP_PATH}") as channel:
        await channel.initialize()
        session = await channel.new_session(tmp_path, [gateway()], meta=handed("tok-exec"))
        turn = await channel.prompt(session.session_id, [text_block("lent meta")], meta=handed("tok-exec"))
    assert turn.stop_reason == "end_turn"
    # The lent server's authority is the execution's, whatever the client wrote there.
    assert json.loads(client.line("lent: ")) == [["notebooks", "Bearer tok-exec"]]
    # The agent was handed `_meta` with the credential withheld, at session/new and at the prompt.
    said = json.loads(client.line("meta: "))
    assert said["new"]["datalayer"] == {"credential": WITHHELD, "execution": {"executionId": "ex-1"}}
    assert said["prompt"]["datalayer"]["credential"] == WITHHELD
    text = audit.read_text()
    assert "tok-exec" not in text, "the credential is written nowhere"
    rows = [json.loads(line) for line in text.splitlines()]
    assert any(row["event"] == "mcp" and row.get("credential") == "lent" for row in rows)


async def test_a_turn_with_another_credential_is_refused_in_a_sentence(served, tmp_path: Path):
    server, audit = served
    client = Client()
    async with WebSocketACPChannel.connect(client, f"ws://127.0.0.1:{server.port}{ACP_PATH}") as channel:
        await channel.initialize()
        session = await channel.new_session(tmp_path, [gateway()], meta=handed("tok-read-only"))
        with pytest.raises(RequestError, match="another authority"):
            await channel.prompt(session.session_id, [text_block("lent")], meta=handed("tok-wider"))
        # Without one, the turn runs on what the session was lent.
        turn = await channel.prompt(session.session_id, [text_block("lent")])
    assert turn.stop_reason == "end_turn"
    assert json.loads(client.line("lent: ")) == [["notebooks", "Bearer tok-read-only"]]
    text = audit.read_text()
    assert "tok-wider" not in text and "tok-read-only" not in text
    assert any(json.loads(line)["event"] == "refusal" for line in text.splitlines())


async def test_a_session_without_a_credential_keeps_what_the_client_lent(served, tmp_path: Path):
    server, _ = served
    client = Client()
    async with WebSocketACPChannel.connect(client, f"ws://127.0.0.1:{server.port}{ACP_PATH}") as channel:
        await channel.initialize()
        session = await channel.new_session(tmp_path, [gateway()])
        await channel.prompt(session.session_id, [text_block("lent")])
        # A credential first handed with a turn is not the session's: refused.
        with pytest.raises(RequestError, match="another authority"):
            await channel.prompt(session.session_id, [text_block("lent")], meta=handed("tok-exec"))
    assert json.loads(client.line("lent: ")) == [["notebooks", "Bearer the-clients-own"]]


async def test_a_stdio_server_cannot_carry_the_credential(served, tmp_path: Path):
    server, audit = served
    client = Client()
    local = StdioMcpServer(name="local", command="mcp-local", args=[], env=[])
    async with WebSocketACPChannel.connect(client, f"ws://127.0.0.1:{server.port}{ACP_PATH}") as channel:
        await channel.initialize()
        with pytest.raises(RequestError, match="stdio server"):
            await channel.new_session(tmp_path, [gateway(), local], meta=handed("tok-exec"))
    assert "tok-exec" not in audit.read_text()
