# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A tool call streamed before its input is whole is decided again once it is.

Claude Code's adapter says a Bash call as *Terminal* with no command while
the model still streams its input, then refines it with a ``tool_call_update``
carrying the command. The first notification was decided on nothing; the
refinement is decided again with the command — the rule on commands, the
deleting families classed delete — a row written for it, and the completion
row carries the command, so a reader of the record knows what ran.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from acp import text_block
from acp.schema import AllowedOutcome, RequestPermissionResponse

from agent_shield.acp import StdioACPChannel
from agent_shield.policy import Rule, default_policy

FAKE = str(Path(__file__).parent / "fixtures" / "fake_agent.py")


class Client:
    def __init__(self) -> None:
        self.said: list[str] = []

    async def session_update(self, session_id, update, **kw):
        if update.session_update == "agent_message_chunk":
            self.said.append(update.content.text)

    async def request_permission(self, options, session_id, tool_call, **kw):
        return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id=options[0].option_id))


def _policy_file(tmp_path: Path, *, delete: str = "ask") -> Path:
    policy = default_policy()
    policy.rules.insert(0, Rule(name="Delete files", decision=delete, classes=["delete"]))
    path = tmp_path / "agent-shield.yaml"
    path.write_text(policy.model_dump_json(by_alias=True, exclude_none=True))
    return path


async def _turns(tmp_path: Path, *prompts: str, delete: str = "ask") -> tuple[Client, list[str], list[dict]]:
    client = Client()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    audit = tmp_path / "audit.jsonl"
    args = [
        "-m",
        "agent_shield.cli",
        "run",
        "--workspace",
        str(workspace),
        "--policy",
        str(_policy_file(tmp_path, delete=delete)),
    ]
    args += ["--audit", str(audit), "--", sys.executable, FAKE]
    stops: list[str] = []
    async with StdioACPChannel.launch(client, sys.executable, *args, cwd=workspace) as channel:
        await channel.initialize()
        session = await channel.new_session(workspace)
        for text in prompts:
            stops.append((await channel.prompt(session.session_id, [text_block(text)])).stop_reason)
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    return client, stops, [row for row in rows if row.get("tool_call_id") == "c7"]


async def test_the_refinement_is_decided_again_with_the_command_and_the_completion_names_it(tmp_path: Path):
    _, stops, rows = await _turns(tmp_path, "stream wc -c hello.txt")
    assert stops == ["end_turn"]
    said = [(r["event"], r.get("title"), r.get("command"), r.get("decision"), r.get("rule"), r.get("by")) for r in rows]
    assert said == [
        ("tool_call", "Terminal", None, "ask", "run a command", "policy"),
        ("tool_call", "wc -c hello.txt", "wc -c hello.txt", "ask", "run a command", "policy"),
        ("tool_call", "wc -c hello.txt", "wc -c hello.txt", "ask", None, "agent"),
    ]
    assert rows[1]["class"] == "execute" and rows[2]["status"] == "completed"


async def test_a_deleting_command_is_a_delete_when_its_command_arrives(tmp_path: Path):
    _, stops, rows = await _turns(tmp_path, "stream rm hello.txt")
    assert stops == ["end_turn"]
    refined = rows[1]
    assert (refined["class"], refined["decision"], refined["rule"]) == ("delete", "ask", "Delete files")
    assert rows[2]["command"] == "rm hello.txt"


async def test_a_delete_the_rules_leave_to_the_person_ends_the_turn_once_the_command_is_known(tmp_path: Path):
    client, stops, rows = await _turns(tmp_path, "stream rm -rf build", delete="deny")
    assert stops == ["refusal"]
    assert rows[1]["class"] == "delete" and rows[1]["decision"] == "deny"
    assert any("leave it to me" in text and "Delete files" in text for text in client.said)
