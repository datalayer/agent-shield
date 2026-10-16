# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A terminal's output pushed while its command runs (SHIELD SH-13, SH-16).

The terminal is the Shield's, so the client cannot ask it for its output: the
proxy pushes it on its own row as it arrives — each `tool_call_update` carrying
it whole with the terminal's reference — and once more when the command ended.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from acp import text_block
from acp.schema import AllowedOutcome, RequestPermissionResponse

from agent_shield.acp import WebSocketACPChannel
from agent_shield.acp.proxy import ShieldProxy
from agent_shield.acp.server import ACP_PATH, ShieldServer
from agent_shield.audit import AuditLog
from agent_shield.policy import LoadedPolicy, default_policy

pytest.importorskip("aiohttp", reason="`serve` needs the serve extra")
pytest.importorskip("websockets", reason="the WebSocket channel needs the websocket extra")

FAKE = str(Path(__file__).parent / "fixtures" / "fake_agent.py")


class Watcher:
    """A client that allows what it is asked and keeps every pushed output, with when it came."""

    def __init__(self) -> None:
        self.pushes: list[tuple[float, str, str]] = []

    async def session_update(self, session_id, update, **kw):
        if update.session_update != "tool_call_update":
            return
        texts = [
            item.content.text
            for item in update.content or []
            if getattr(item, "type", None) == "content" and getattr(item.content, "type", None) == "text"
        ]
        refs = [item for item in update.content or [] if getattr(item, "type", None) == "terminal"]
        if texts and refs:
            self.pushes.append((time.monotonic(), update.status, texts[0]))

    async def request_permission(self, options, session_id, tool_call, **kw):
        return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id=options[0].option_id))


@pytest.fixture
async def server(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.jsonl", environment={})

    def make() -> ShieldProxy:
        return ShieldProxy(
            [sys.executable, FAKE],
            policies=[LoadedPolicy(policy=default_policy(), origin="the default")],
            audit=audit,
            workspace=tmp_path,
        )

    served = ShieldServer({"": make}, audit=audit, idle_seconds=5.0)
    await served.start("127.0.0.1", 0)
    try:
        yield served
    finally:
        await served.stop()


async def test_a_running_terminal_s_output_is_pushed_as_it_arrives(server: ShieldServer, tmp_path: Path):
    watcher = Watcher()
    command = "echo one; sleep 0.8; echo two; sleep 0.8; echo three"
    async with WebSocketACPChannel.connect(watcher, f"ws://127.0.0.1:{server.port}{ACP_PATH}") as channel:
        await channel.initialize()
        session = await channel.new_session(tmp_path)
        started = time.monotonic()
        turn = await channel.prompt(session.session_id, [text_block(f"run {command}")])
        ended = time.monotonic()
    assert turn.stop_reason == "end_turn"
    outputs = [text for _, _, text in watcher.pushes]
    # Pushed while it ran: the first line alone, then the first two, before the third existed.
    assert "one\n" in outputs, outputs
    assert "one\ntwo\n" in outputs, outputs
    first = next(at for at, status, text in watcher.pushes if text == "one\n")
    assert first - started < (ended - started) - 1.0, "the first line came long before the command ended"
    assert all(status == "in_progress" for _, status, text in watcher.pushes if "three" not in text)
    # And whole at the end, the row completed.
    _, status, text = watcher.pushes[-1]
    assert (status, text) == ("completed", "one\ntwo\nthree\n")


async def test_a_quiet_command_is_pushed_once_when_it_ends(server: ShieldServer, tmp_path: Path):
    watcher = Watcher()
    async with WebSocketACPChannel.connect(watcher, f"ws://127.0.0.1:{server.port}{ACP_PATH}") as channel:
        await channel.initialize()
        session = await channel.new_session(tmp_path)
        await channel.prompt(session.session_id, [text_block("run true")])
    assert [(status, text) for _, status, text in watcher.pushes] == [("completed", "")]
