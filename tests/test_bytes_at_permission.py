# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A harness writing with its own tool is held to ``bytes_written`` at its permission.

Claude Code writes files with its own Write and Edit tools: it shows the diff,
then asks permission, and never calls ``fs/write_text_file``. The permission is
decided with the diff's size, so a hard ``bytes_written`` refuses the write in a
sentence and ends the turn, and an allowed write counts toward the limit.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from acp import text_block
from acp.schema import AllowedOutcome, RequestPermissionResponse

from agent_shield.acp import StdioACPChannel
from agent_shield.policy import default_policy
from agent_shield.policy.model import Threshold

FAKE = str(Path(__file__).parent / "fixtures" / "fake_agent.py")


class Client:
    def __init__(self) -> None:
        self.said: list[str] = []
        self.asked: list[str] = []

    async def session_update(self, session_id, update, **kw):
        if update.session_update == "agent_message_chunk":
            self.said.append(update.content.text)

    async def request_permission(self, options, session_id, tool_call, **kw):
        self.asked.append(tool_call.title)
        return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id=options[0].option_id))


def _policy_file(tmp_path: Path) -> Path:
    policy = default_policy()
    policy.limits.bytes_written = Threshold(soft=40, hard=60)
    path = tmp_path / "agent-shield.yaml"
    path.write_text(policy.model_dump_json(by_alias=True, exclude_none=True))
    return path


async def _turns(tmp_path: Path, *prompts: str) -> tuple[Client, list[str], list[str]]:
    client = Client()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    audit = tmp_path / "audit.jsonl"
    args = ["-m", "agent_shield.cli", "run", "--workspace", str(workspace), "--policy", str(_policy_file(tmp_path))]
    args += ["--audit", str(audit), "--", sys.executable, FAKE]
    stops: list[str] = []
    async with StdioACPChannel.launch(client, sys.executable, *args, cwd=workspace) as channel:
        await channel.initialize()
        session = await channel.new_session(workspace)
        for text in prompts:
            stops.append((await channel.prompt(session.session_id, [text_block(text)])).stop_reason)
    return client, stops, audit.read_text().splitlines()


async def test_a_write_over_the_hard_bytes_limit_is_refused_at_its_permission_and_ends_the_turn(tmp_path: Path):
    client, stops, rows = await _turns(tmp_path, "selfwrite 200")
    assert stops == ["refusal"]
    sentence = "".join(client.said)
    assert "[Shield]" in sentence and "bytes written" in sentence and "hard limit of 60" in sentence, sentence
    assert "wrote 200 bytes" not in sentence
    refused = [json.loads(row) for row in rows if json.loads(row).get("event") == "permission"]
    assert [row["decision"] for row in refused] == ["deny"] and "bytes written" in refused[0]["sentence"], refused


async def test_allowed_writes_count_toward_the_limit(tmp_path: Path):
    client, stops, _ = await _turns(tmp_path, "selfwrite 30", "selfwrite 30")
    # 30 bytes is allowed; the next 30 would reach 60: past the soft limit of 40, so the person is asked.
    assert stops == ["end_turn", "end_turn"]
    assert "wrote 30 bytes" in "".join(client.said)
    assert client.asked == ["Write big.txt"], client.asked
