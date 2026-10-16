# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The standalone proxy and PAP (SH-73): a registered Shield lends the gateway's
``pap`` toolset at a company with its own token; local-only, PAP is refused in a sentence."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from acp import text_block
from acp.schema import AllowedOutcome, RequestPermissionResponse
from typer.testing import CliRunner

from agent_shield.acp import WebSocketACPChannel
from agent_shield.acp.proxy import ShieldProxy
from agent_shield.acp.server import ACP_PATH, ShieldServer
from agent_shield.audit import AuditLog
from agent_shield.cli import app
from agent_shield.policy import LoadedPolicy, Mcp, default_policy
from agent_shield.registration import (
    CREDENTIALS_FILE,
    Registration,
    RegistrationRefused,
    pap_server_name,
    pap_servers,
)

pytest.importorskip("aiohttp", reason="`serve` needs the serve extra")
pytest.importorskip("websockets", reason="the WebSocket channel needs the websocket extra")

FAKE = str(Path(__file__).parent / "fixtures" / "fake_agent.py")
COMPANY = "manzanita.examples.datalayer.run"
SERVER = "pap_manzanita_examples_datalayer_run"
TOKEN = "eyJregistered.shield.token"  # noqa: S105
runner = CliRunner()


def registered(base: Path) -> Registration:
    registration = Registration(
        path=base / CREDENTIALS_FILE,
        iam_url="https://iam.example",
        org_uid="org-1",
        agent_uid="agent-1",
        key="svc-key-never-printed",
        token=TOKEN,
        token_expires=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    registration.save()
    return registration


class Client:
    def __init__(self) -> None:
        self.said: list[str] = []

    async def session_update(self, session_id, update, **kw):
        if update.session_update == "agent_message_chunk":
            self.said.append(update.content.text)

    async def request_permission(self, options, session_id, tool_call, **kw):
        return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id=options[0].option_id))

    def line(self, prefix: str) -> str:
        return next(text for text in self.said if text.startswith(prefix))[len(prefix) :]


def test_a_companys_server_is_named_as_the_runtime_names_it_and_reaches_the_gateways_pap_toolset(tmp_path: Path):
    assert pap_server_name(COMPANY) == SERVER
    assert pap_server_name("Northwind.Example") == "pap_northwind_example"
    with pytest.raises(RegistrationRefused, match="named by its domain"):
        pap_server_name("  ")
    [server] = pap_servers(registered(tmp_path), [COMPANY], gateway_url="https://mcp.example/mcp")
    assert server.name == SERVER
    assert server.url == f"https://mcp.example/mcp?only=pap&pap-company={COMPANY}"
    assert [(h.name, h.value) for h in server.headers] == [("Authorization", f"Bearer {TOKEN}")]
    assert pap_servers(None, []) == [], "no company, nothing lent and nothing asked"


def test_local_only_pap_is_refused_in_a_sentence():
    with pytest.raises(RegistrationRefused, match="unavailable while local-only"):
        pap_servers(None, [COMPANY])


@pytest.fixture
async def served(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.jsonl", environment={})
    policy = default_policy().model_copy(update={"mcp": Mcp(allow=[SERVER, "notebooks"])})
    registration = registered(tmp_path / "home")

    def make() -> ShieldProxy:
        return ShieldProxy(
            [sys.executable, FAKE],
            policies=[LoadedPolicy(policy=policy, origin="the test")],
            audit=audit,
            workspace=tmp_path,
            companies=[COMPANY],
            own_servers=lambda: pap_servers(registration, [COMPANY], gateway_url="https://mcp.example/mcp"),
        )

    server = ShieldServer({"": make}, audit=audit, idle_seconds=5.0)
    await server.start("127.0.0.1", 0)
    try:
        yield server, tmp_path / "audit.jsonl"
    finally:
        await server.stop()


async def test_the_registered_proxy_lends_the_pap_toolset_with_its_own_token(served, tmp_path: Path):
    server, audit = served
    client = Client()
    async with WebSocketACPChannel.connect(client, f"ws://127.0.0.1:{server.port}{ACP_PATH}") as channel:
        await channel.initialize()
        session = await channel.new_session(tmp_path, [])
        turn = await channel.prompt(session.session_id, [text_block("lent")])
    assert turn.stop_reason == "end_turn"
    assert json.loads(client.line("lent: ")) == [[SERVER, f"Bearer {TOKEN}"]]
    text = audit.read_text()
    assert TOKEN not in text, "the token is written nowhere"
    rows = [json.loads(line) for line in text.splitlines()]
    assert any(row["event"] == "mcp" and row.get("name") == SERVER and row["decision"] == "allow" for row in rows)


@pytest.fixture
def shield_home(tmp_path: Path, monkeypatch) -> Path:
    base = tmp_path / "home"
    monkeypatch.setenv("AGENT_SHIELD_HOME", str(base))
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["policy", "init"]).exit_code == 0
    return base


def test_run_refuses_pap_while_local_only_before_the_agent_starts(shield_home: Path):
    result = runner.invoke(app, ["run", "--pap", COMPANY, "--", sys.executable, FAKE])
    assert result.exit_code == 2
    assert "unavailable while local-only" in result.output and "setup --register" in result.output


def test_run_refuses_pap_the_policy_does_not_allow(shield_home: Path):
    registered(shield_home)
    result = runner.invoke(app, ["run", "--pap", COMPANY, "--", sys.executable, FAKE])
    assert result.exit_code == 2
    assert f"PAP at {SERVER} is not on the policy's mcp.allow list" in result.output
    assert TOKEN not in result.output and "svc-key-never-printed" not in result.output
