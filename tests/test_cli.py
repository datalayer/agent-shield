# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The command (SH-09) and the entry points."""

from __future__ import annotations

import json
from importlib import import_module
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: tomllib arrived in 3.11
    import tomli as tomllib
from typer.testing import CliRunner

from agent_shield import __version__
from agent_shield.audit import AuditLog
from agent_shield.cli import app
from agent_shield.config import Config, find_policy_file, harness_prefix
from agent_shield.policy import default_policy, dump_policy, policy_json_schema

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def shield_home(tmp_path: Path, monkeypatch) -> Path:
    base = tmp_path / "home"
    monkeypatch.setenv("AGENT_SHIELD_HOME", str(base))
    monkeypatch.chdir(tmp_path)
    return base


def test_every_entry_point_of_pyproject_resolves():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    targets = list(data["project"]["scripts"].values())
    for group in data["project"].get("entry-points", {}).values():
        targets.extend(group.values())
    assert targets, "no entry points"
    for target in targets:
        module, _, attr = target.partition(":")
        assert callable(getattr(import_module(module), attr)), target


def test_the_reactor_extension_imports_without_the_reactor(monkeypatch):
    import builtins
    import importlib
    import sys

    real_import = builtins.__import__

    def no_reactor(name, *args, **kwargs):
        if name == "reactor":
            raise ImportError("no reactor here")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_reactor)
    sys.modules.pop("agent_shield.reactor_extension", None)
    module = importlib.import_module("agent_shield.reactor_extension")
    with pytest.raises(ImportError, match="needs the reactor"):
        module.plugin()


def test_the_reactor_extension_registers_the_group_when_the_reactor_is_there():
    pytest.importorskip("reactor")
    import typer

    from agent_shield.reactor_extension import plugin

    manifest, extension = plugin()
    assert manifest.name == "agent-shield" and manifest.version == __version__
    host = typer.Typer()
    extension.provide_cli(host)
    assert any(group.typer_instance.info.name == "agent-shield" for group in host.registered_groups)


def test_version_and_schema_and_harnesses():
    assert runner.invoke(app, ["version"]).stdout.strip() == __version__
    assert json.loads(runner.invoke(app, ["policy", "schema"]).stdout) == policy_json_schema()
    out = runner.invoke(app, ["harnesses"]).stdout
    assert "claude-code" in out and "served to third parties: api_key_only" in out and "18 June 2026" in out
    assert "register checked on 2026-10-15" in out and "from agentspecs" in out


def test_run_without_a_policy_or_a_command_refuses(shield_home: Path):
    result = runner.invoke(app, ["run", "--", "true"])
    assert result.exit_code == 2 and "agent-shield setup" in result.output
    result = runner.invoke(app, ["run"])
    assert result.exit_code == 2 and "no agent command" in result.output


def test_policy_init_and_show_say_every_line_and_where_it_came_from(shield_home: Path, tmp_path: Path):
    assert runner.invoke(app, ["policy", "init"]).exit_code == 0
    assert (tmp_path / "agent-shield.yaml").is_file()
    assert runner.invoke(app, ["policy", "init"]).exit_code == 2
    out = runner.invoke(app, ["policy", "show"]).stdout
    assert f"session policy (version 1) — from {tmp_path / 'agent-shield.yaml'}" in out
    assert "1. read inside the workspace: read inside the workspace → allow" in out
    assert "git push: execute → ask" in out
    assert "limit tool_calls: soft 100, hard 200" in out
    assert "fetch allow-list: none (every fetch refused)" in out
    assert "nothing a rule names falls to: ask me first" in out


def test_the_home_policy_is_the_fallback(shield_home: Path, tmp_path: Path):
    shield_home.mkdir(parents=True)
    (shield_home / "agent-shield.yaml").write_text(dump_policy(default_policy()))
    assert find_policy_file(tmp_path) == shield_home / "agent-shield.yaml"
    (tmp_path / "agent-shield.yaml").write_text(dump_policy(default_policy()))
    assert find_policy_file(tmp_path) == tmp_path / "agent-shield.yaml"


def test_log_prints_the_rows_or_says_there_are_none(shield_home: Path):
    assert "no audit rows yet" in runner.invoke(app, ["log"]).output
    AuditLog().write(
        "tool_call",
        title="Run",
        decision="ask",
        sentence="Run: ask me first — session rule 'run a command'",
        by="policy",
    )
    out = runner.invoke(app, ["log"]).stdout
    assert "tool_call" in out and "ask me first" in out and "[policy]" in out
    assert json.loads(runner.invoke(app, ["log", "--json"]).stdout.splitlines()[0])["event"] == "tool_call"


def test_serve_wants_one_command_or_a_harness(shield_home: Path):
    result = runner.invoke(app, ["serve"])
    assert result.exit_code == 2 and "one command after `--`" in result.output
    result = runner.invoke(app, ["serve", "--harness", "claude-code", "--", "x"])
    assert result.exit_code == 2 and "not both" in result.output


def test_uninstall_previews_by_default_and_keeps_the_audit(shield_home: Path):
    assert "nothing of the Shield's is installed" in runner.invoke(app, ["uninstall"]).output
    prefix = harness_prefix("claude-code", "0.91.0", shield_home)
    prefix.mkdir(parents=True)
    config = Config.load(shield_home)
    config.harnesses["claude-code"] = {"version": "0.91.0", "bin": str(prefix / "node_modules/.bin/claude-agent-acp")}
    config.save()
    AuditLog().write("session", what="x", by="shield")
    out = runner.invoke(app, ["uninstall"]).output
    assert "would remove:" in out and str(shield_home / "harnesses") in out and "kept: " in out
    assert (shield_home / "harnesses").exists()
    out = runner.invoke(app, ["uninstall", "--yes"]).output
    assert "removing:" in out and not (shield_home / "harnesses").exists() and (shield_home / "audit.jsonl").exists()


def test_setup_refuses_an_unknown_harness_and_stops_without_node(shield_home: Path, monkeypatch):
    result = runner.invoke(app, ["setup", "--harness", "nope", "--yes"])
    assert result.exit_code == 2 and "'nope' is not in the register" in result.output
    # The long tail is registered, and not offered until drilled (SH-57).
    result = runner.invoke(app, ["setup", "--harness", "cursor", "--yes"])
    assert result.exit_code == 2 and "listed, not drilled yet" in result.output
    monkeypatch.setattr("agent_shield.cli._node_version", lambda: (18, 0, 0))
    result = runner.invoke(app, ["setup", "--yes"])
    assert result.exit_code == 2 and "needs Node >=22" in result.output


def test_setup_and_run_refuse_a_subscription_login_where_only_a_key_serves(
    shield_home: Path, tmp_path: Path, monkeypatch
):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / ".credentials.json").write_text("{}")
    monkeypatch.setattr("agent_shield.cli._node_version", lambda: (22, 23, 2))
    result = runner.invoke(app, ["setup", "--yes"])
    assert (
        result.exit_code == 2
        and "a Claude Code login (Pro or Max)" in result.output
        and "API key only" in result.output
    )
    (tmp_path / "agent-shield.yaml").write_text(dump_policy(default_policy()))
    result = runner.invoke(app, ["run", "--", "claude-agent-acp"])
    assert result.exit_code == 2 and "API key only" in result.output


def test_setup_installs_through_npm_prefix_writes_config_and_policy_and_never_shows_a_secret(
    shield_home: Path, tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-value-never-shown-12345")
    calls: list[list[str]] = []

    def fake_install(entry, base=None):
        prefix = harness_prefix(entry.id, entry.version, base)
        executable = prefix / "node_modules" / ".bin" / entry.command
        executable.parent.mkdir(parents=True)
        executable.write_text("#!/bin/sh\n")
        calls.append([entry.npm_package, entry.version, str(prefix)])
        return executable

    monkeypatch.setattr("agent_shield.cli.install_adapter", fake_install)
    monkeypatch.setattr("agent_shield.cli._node_version", lambda: (22, 23, 2))
    refused = runner.invoke(app, ["setup", "--yes", "--register"])
    assert refused.exit_code == 2 and "the organization's uid is needed (`--org`)" in refused.output
    result = runner.invoke(app, ["setup", "--yes", "--local"])
    assert result.exit_code == 0, result.output
    assert calls == [
        ["@agentclientprotocol/claude-agent-acp", "0.91.0", str(harness_prefix("claude-code", "0.91.0", shield_home))]
    ]
    assert "credentials present: ANTHROPIC_API_KEY" in result.output
    assert "sk-ant-value" not in result.output
    assert "PAP: unavailable while local-only" in result.output and "setup --register" in result.output
    assert "run: agent-shield run -- claude-agent-acp" in result.output and "Zed:" in result.output
    config = Config.load(shield_home)
    assert config.installed("claude-code")["version"] == "0.91.0" and config.data["registered"] is False
    assert (tmp_path / "agent-shield.yaml").is_file()
    again = runner.invoke(app, ["setup", "--yes"])
    assert "adapter already installed" in again.output and "policy kept" in again.output and len(calls) == 1


def test_upgrade_check_compares_with_the_register(shield_home: Path, monkeypatch):
    monkeypatch.setattr("agent_shield.cli._latest_on_pypi", lambda: __version__)
    config = Config.load(shield_home)
    config.harnesses["claude-code"] = {"version": "0.90.0", "bin": "/nowhere"}
    config.save()
    out = runner.invoke(app, ["upgrade", "--check"]).output
    assert f"Shield {__version__} is the latest on PyPI" in out
    assert "claude-code: installed 0.90.0, pinned 0.91.0" in out
    assert Config.load(shield_home).installed("claude-code")["version"] == "0.90.0"
