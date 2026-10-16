# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The workspace (SHIELD §4.6) and the audit (§6.4)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent_shield.acp.workspace import OutsideWorkspace, Terminals, Workspace
from agent_shield.audit import DECIDERS, EVENTS, REDACTED, AuditLog, diff_summary, redact


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("one\ntwo\nthree\n")
    return Workspace(tmp_path)


def test_a_path_is_placed_inside_or_outside_symlinks_followed(ws: Workspace, tmp_path: Path):
    assert ws.place("src/a.py").inside and ws.place("src/a.py").shown == "src/a.py"
    assert ws.place(str(tmp_path / "src" / "a.py")).inside
    assert not ws.place("/etc/hostname").inside and ws.place("/etc/hostname").shown == "/etc/hostname"
    assert not ws.place("../outside").inside
    assert ws.place(".").inside and ws.place(".").shown == "."
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "secret").write_text("x")
    os.symlink(outside / "secret", tmp_path / "link")
    assert not ws.place("link").inside


def test_reads_are_whole_or_by_line_and_limit(ws: Workspace):
    assert ws.read_text("src/a.py") == "one\ntwo\nthree\n"
    assert ws.read_text("src/a.py", line=2) == "two\nthree\n"
    assert ws.read_text("src/a.py", line=2, limit=1) == "two\n"
    assert ws.read_text("src/a.py", limit=1) == "one\n"


def test_reads_and_writes_outside_are_refused_in_a_sentence(ws: Workspace):
    with pytest.raises(OutsideWorkspace, match="/etc/hostname is outside the workspace"):
        ws.read_text("/etc/hostname")
    with pytest.raises(OutsideWorkspace, match="outside the workspace"):
        ws.write_text("../x", "no")


def test_a_write_creates_parents_and_returns_its_bytes(ws: Workspace):
    assert ws.write_text("new/dir/b.txt", "héllo") == 6
    assert (ws.root / "new" / "dir" / "b.txt").read_text() == "héllo"


def test_a_missing_directory_cannot_be_the_workspace(tmp_path: Path):
    with pytest.raises(OutsideWorkspace, match="is not a directory"):
        Workspace(tmp_path / "nope")


async def test_a_terminal_runs_in_the_workspace_with_a_trimmed_environment(ws: Workspace, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-leak-1234567890")
    terminals = Terminals(ws)
    run = await terminals.create(
        "/bin/sh", ["-c", "pwd; echo key=${ANTHROPIC_API_KEY:-unset}; echo extra=$EXTRA"], env={"EXTRA": "yes"}
    )
    assert terminals.open == 1
    done = await terminals.wait(run.terminal_id)
    output = done.output.decode()
    assert str(ws.root) in output
    assert "key=unset" in output
    assert "extra=yes" in output
    assert done.exit_code == 0 and done.signal is None
    await terminals.release(run.terminal_id)
    assert terminals.open == 0


async def test_a_command_line_with_no_args_runs_through_the_shell(ws: Workspace):
    terminals = Terminals(ws)
    run = await terminals.wait((await terminals.create("echo a b | tr a-z A-Z")).terminal_id)
    assert run.output.decode().strip() == "A B"
    await terminals.release_all()


async def test_output_is_truncated_from_the_start_to_the_limit(ws: Workspace):
    terminals = Terminals(ws)
    run = await terminals.create("/bin/sh", ["-c", "printf 'abcdefghij'"], output_byte_limit=4)
    run = await terminals.wait(run.terminal_id)
    assert run.output.decode() == "ghij" and run.truncated
    await terminals.release_all()


async def test_a_terminal_can_be_killed_and_a_cwd_outside_is_refused(ws: Workspace):
    terminals = Terminals(ws)
    run = await terminals.create("/bin/sh", ["-c", "sleep 30"])
    killed = await terminals.kill(run.terminal_id)
    assert killed.signal == "SIGKILL"
    with pytest.raises(OutsideWorkspace, match="cwd /etc is outside the workspace"):
        await terminals.create("ls", cwd="/etc")
    with pytest.raises(KeyError, match="no terminal 'nope' is open"):
        terminals.get("nope")
    await terminals.release_all()


# --- the audit ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnop", "ANTHROPIC_API_KEY=[redacted]"),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "Authorization: Bearer [redacted]"),
        ("aws AKIAIOSFODNN7EXAMPLE here", "aws [redacted] here"),
        ("token: ghp_abcdefghijklmnopqrstuvwxyz0123456789", "token: [redacted]"),
        ("password=hunter22 ok", "password=[redacted] ok"),
        ("plain words stay", "plain words stay"),
        ("key sk-0123456789abcdefghij in a command", "key [redacted] in a command"),
        ('"sk-ant-api03-abcdefghijk"', '"[redacted]"'),
        # A credential's prefix inside an identifier is not a credential: a PAP
        # operation's random id kept whole (SHIELD SH-71, a release run lost it).
        ("op_Q1-sk-0123456789abcdefXYZ", "op_Q1-sk-0123456789abcdefXYZ"),
        ("run_xAKIAIOSFODNN7EXAMPLE", "run_xAKIAIOSFODNN7EXAMPLE"),
    ],
)
def test_credentials_are_redacted_by_shape(text, expected):
    assert redact(text, environment={}) == expected


def test_the_shields_own_secret_values_are_redacted_by_value():
    env = {"MY_SERVICE_TOKEN": "zqx-plain-looking-value", "PATH": "/usr/bin", "SHORT_KEY": "abc"}
    assert redact("echo zqx-plain-looking-value abc", environment=env) == f"echo {REDACTED} abc"


def test_rows_are_json_lines_redacted_with_the_vocabulary(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl", environment={"X_SECRET": "deadbeefcafe"})
    row = log.write(
        "tool_call",
        session="s",
        title="Run",
        command="curl -H 'Bearer deadbeefcafe'",
        decision="ask",
        by="policy",
        nothing=None,
    )
    assert row["command"] == "curl -H 'Bearer [redacted]'"
    assert "nothing" not in row and row["event"] == "tool_call" and row["ts"].endswith("+00:00")
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert json.loads(lines[0]) == row
    assert log.rows(last=1) == [row]
    assert AuditLog(tmp_path / "missing.jsonl").rows() == []


def test_an_unknown_event_or_decider_is_refused(tmp_path: Path):
    log = AuditLog(tmp_path / "a.jsonl")
    with pytest.raises(ValueError, match="'party' is not an audit event"):
        log.write("party")
    with pytest.raises(ValueError, match="'nobody' is not a decider"):
        log.write("turn", by="nobody")
    assert "fs_write" in EVENTS and "person" in DECIDERS


def test_a_diff_is_kept_as_hash_and_size_never_text():
    summary = diff_summary("a.py", "new text", "old")
    assert summary == {"path": "a.py", "sha256": summary["sha256"], "bytes": 8, "old_bytes": 3}
    assert "new text" not in json.dumps(summary)
