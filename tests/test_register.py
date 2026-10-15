# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The harness register, read from agentspecs, and the Shield's credential refusals (SH-04)."""

from __future__ import annotations

from pathlib import Path

import pytest
from agentspecs.harnesses import load_harnesses, load_register

from agent_shield.register import RegisterRefused, catalogue, credential_refusal, harness, harness_of_command

CATALOGUE = {"claude-code", "codex", "gemini-cli", "goose", "opencode", "openhands", "fast-agent"}


def test_the_catalogue_is_agentspecs_without_custom():
    found = catalogue()
    assert set(found) == CATALOGUE
    assert set(load_harnesses()) == CATALOGUE | {"custom"}
    assert set(load_register()) >= CATALOGUE


def test_custom_is_not_set_up_from_the_catalogue():
    with pytest.raises(RegisterRefused, match="'custom' is an organization's own spec"):
        harness("custom")


def test_an_unknown_harness_is_refused_naming_the_register():
    with pytest.raises(RegisterRefused, match="'nope' is not in the register; the harnesses are claude-code"):
        harness("nope")


def test_claude_code_is_installed_from_the_prefix_never_npx():
    entry = harness("claude-code")
    assert entry.npm_package == "@agentclientprotocol/claude-agent-acp"
    assert entry.version == "0.91.0" and entry.adapter == entry.npm_package
    assert entry.command == "claude-agent-acp" and entry.launch_args == []
    assert entry.secrets == ["ANTHROPIC_API_KEY"]
    assert entry.node_requirement == ">=22"
    assert entry.entry.served_to_third_parties.value == "api_key_only"
    assert entry.install_dir_name == "claude-code@0.91.0"


def test_gemini_keeps_its_flag_and_its_tier_restriction():
    entry = harness("gemini-cli")
    assert entry.npm_package == "@google/gemini-cli" and entry.command == "gemini"
    assert entry.launch_args == ["--experimental-acp"]
    assert "18 June 2026" in (entry.entry.tier_restrictions or "")
    assert entry.node_requirement == ">=20"


def test_a_harness_that_is_its_own_program_keeps_its_command():
    entry = harness("goose")
    assert entry.npm_package is None
    assert entry.command == "goose" and entry.launch_args == entry.spec.acp.args


def test_the_command_names_the_harness():
    assert harness_of_command("/x/node_modules/.bin/claude-agent-acp").id == "claude-code"
    assert harness_of_command("gemini").id == "gemini-cli"
    assert harness_of_command("python") is None


def test_a_subscription_login_without_a_key_is_refused_where_only_a_key_serves(tmp_path: Path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / ".credentials.json").write_text("{}")
    entry = harness("claude-code")
    sentence = credential_refusal(entry, environment={}, home=tmp_path)
    assert sentence is not None
    assert "a Claude Code login (Pro or Max)" in sentence and "an API key only" in sentence
    assert "export ANTHROPIC_API_KEY" in sentence
    assert credential_refusal(entry, environment={"ANTHROPIC_API_KEY": "k"}, home=tmp_path) is None
    assert credential_refusal(entry, environment={}, home=tmp_path / "nowhere") is None


def test_a_google_login_on_the_consumer_tier_is_refused_and_the_tier_named(tmp_path: Path):
    (tmp_path / ".gemini").mkdir()
    (tmp_path / ".gemini" / "oauth_creds.json").write_text("{}")
    sentence = credential_refusal(harness("gemini-cli"), environment={}, home=tmp_path)
    assert sentence is not None and "a Google login" in sentence and "Standard or Enterprise" in sentence


def test_harnesses_without_a_login_file_are_not_refused(tmp_path: Path):
    for harness_id in ("goose", "opencode", "openhands", "fast-agent"):
        assert credential_refusal(harness(harness_id), environment={}, home=tmp_path) is None


def test_a_listed_or_an_organizations_own_harness_is_refused_by_the_standalone_shield():
    """SH-57: the long tail is listed, not drilled yet; SH-46: an organization's own
    harness is served on Datalayer, where its organization admits the reviewed command."""
    from agent_shield.register import RegisterRefused, harness

    with pytest.raises(RegisterRefused, match="listed, not drilled yet"):
        harness("qwen-code")
    with pytest.raises(RegisterRefused, match="served on Datalayer"):
        harness("org-acme-coder")
