# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The policy document and ``decide`` (SHIELD SH-07): classes, scopes, first decision wins, limits."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_shield.policy import (
    ACTION_CLASSES,
    FLAGGED_COMMANDS,
    KIND_CLASS,
    SCHEMA_PATH,
    VERDICT_WORDS,
    Action,
    Context,
    Decision,
    Limits,
    LimitState,
    Network,
    Policy,
    PolicyRefused,
    Rule,
    Threshold,
    UnknownKind,
    class_of,
    decide,
    default_policy,
    dump_policy,
    flagged,
    load_policies,
    parse_policies,
    policy_json_schema,
)


def action(kind: str, title: str = "t", **fields) -> Action:
    cls = class_of(kind)
    return Action(kind=kind, title=title, **{"class": cls}, **fields)


def one(verdict: str, name: str = "r", **fields) -> Policy:
    return Policy(scope="session", rules=[Rule(name=name, decision=verdict, **fields)])


# --- classes (§4.5) ---------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "cls"),
    [
        ("read", "read"),
        ("search", "read"),
        ("fetch", "read"),
        ("edit", "write"),
        ("move", "write"),
        ("delete", "delete"),
        ("execute", "execute"),
        ("think", None),
        ("switch_mode", None),
        ("other", "write"),
        ("fs_read", "read"),
        ("fs_write", "write"),
        ("terminal", "execute"),
    ],
)
def test_every_acp_kind_has_its_class(kind, cls):
    assert class_of(kind) == cls


def test_the_kind_table_covers_acp_and_only_acp():
    assert set(KIND_CLASS) == {
        "read", "edit", "delete", "move", "search", "execute", "think", "fetch", "switch_mode", "other"
    }


def test_an_unknown_kind_is_refused_in_a_sentence():
    with pytest.raises(UnknownKind, match="'teleport' is not a tool kind ACP names"):
        class_of("teleport")


def test_an_action_without_a_class_has_nothing_to_decide():
    with pytest.raises(ValueError, match="no class"):
        decide(Action(kind="think", title="Thinking"), Context(workspace="/w"), [default_policy()])


# --- the flagged commands (decision 5) ---------------------------------------


@pytest.mark.parametrize(
    ("command", "flag"),
    [
        ("git push origin main", "git push"),
        ("git -C /w push --force", "git push"),
        ("git status && git push", "git push"),
        ("sudo rm -rf /", "sudo"),
        ("ls; sudo apt update", "sudo"),
        ("pip install requests", "a package install from the network"),
        ("uv pip install -e .", "a package install from the network"),
        ("npm i left-pad", "a package install from the network"),
        ("yarn add react", "a package install from the network"),
        ("apt-get install curl", "a package install from the network"),
        ("cat ~/.aws/credentials", "a command naming a credential"),
        ("export ANTHROPIC_API_KEY=x", "a command naming a credential"),
        ("cat .env", "a command naming a credential"),
        ("source ~/.datalayer/datalayerrc-prod1", "a command naming a credential"),
    ],
)
def test_flagged_commands(command, flag):
    assert flagged(command) == flag


@pytest.mark.parametrize("command", ["ls -la", "git status", "git pull", "pytest -q", "echo pushover", "sudoku"])
def test_plain_commands_raise_no_flag(command):
    assert flagged(command) is None


def test_the_default_policy_carries_every_flag_as_a_rule():
    names = {rule.name for rule in default_policy().rules}
    assert set(FLAGGED_COMMANDS) <= names


# --- the default policy of decision 5 --------------------------------------------


@pytest.fixture
def ctx() -> Context:
    return Context(workspace="/w", session_id="s")


@pytest.fixture
def default() -> list[Policy]:
    return [default_policy()]


@pytest.mark.parametrize(
    ("act", "verdict", "rule"),
    [
        (dict(kind="read", path="a.py", inside=True), "allow", "read inside the workspace"),
        (dict(kind="search", path=".", inside=True), "allow", "read inside the workspace"),
        (dict(kind="edit", path="a.py", inside=True, bytes=5), "allow", "edit and move inside the workspace"),
        (dict(kind="move", path="a.py", inside=True), "allow", "edit and move inside the workspace"),
        (dict(kind="other", path="a.py", inside=True), "allow", "edit and move inside the workspace"),
        (dict(kind="delete", path="a.py", inside=True), "ask", "delete"),
        (dict(kind="execute", command="pytest"), "ask", "run a command"),
        (dict(kind="terminal", command="pytest"), "ask", "run a command"),
        (dict(kind="execute", command="git push"), "ask", "git push"),
        (dict(kind="execute", command="sudo ls"), "ask", "sudo"),
        (dict(kind="execute", command="pip install x"), "ask", "a package install from the network"),
        (dict(kind="execute", command="cat .env"), "ask", "a command naming a credential"),
        (dict(kind="read", path="/etc/passwd", inside=False), "ask", "outside the workspace"),
        (dict(kind="edit", path="/etc/hosts", inside=False), "ask", "outside the workspace"),
        (dict(kind="fs_read", path="a.py", inside=True), "allow", "read inside the workspace"),
        (dict(kind="fs_write", path="a.py", inside=True, bytes=3), "allow", "edit and move inside the workspace"),
    ],
)
def test_the_default_policy_decides_as_decision_5_says(ctx, default, act, verdict, rule):
    decision = decide(action(**act), ctx, default)
    assert (decision.verdict, decision.rule, decision.decided_by) == (verdict, rule, "rule")
    assert decision.scope == "session"
    assert VERDICT_WORDS[verdict] in decision.sentence
    assert f"'{rule}'" in decision.sentence


def test_a_fetch_is_refused_without_an_allow_list_and_the_sentence_says_how(ctx, default):
    decision = decide(action("fetch", url="https://pypi.org/simple"), ctx, default)
    assert decision.verdict == "deny"
    assert decision.decided_by == "network"
    assert "add pypi.org to network.fetch" in decision.sentence


def test_a_fetch_on_the_allow_list_is_done(ctx):
    policy = Policy(scope="session", network=Network(fetch=["pypi.org", "*.github.com"]))
    assert decide(action("fetch", url="https://pypi.org/x"), ctx, [policy]).verdict == "allow"
    assert decide(action("fetch", url="https://api.github.com/x"), ctx, [policy]).verdict == "allow"
    assert decide(action("fetch", url="https://github.com/x"), ctx, [policy]).verdict == "allow"
    refused = decide(action("fetch", url="https://evil.example/x"), ctx, [policy])
    assert refused.verdict == "deny"
    assert "evil.example is not on the session policy's fetch allow-list" in refused.sentence


def test_a_fetch_with_no_host_is_refused(ctx):
    decision = decide(action("fetch", url="not a url"), ctx, [Policy(scope="session", network=Network(fetch=["a.b"]))])
    assert decision.verdict == "deny"
    assert "names no host" in decision.sentence


def test_send_and_buy_ask(ctx, default):
    for cls in ("send", "buy"):
        decision = decide(Action(kind="other", title="t", **{"class": cls}), ctx, default)
        assert (decision.verdict, decision.rule) == ("ask", "send or buy")


def test_the_command_is_shown_in_the_sentence_and_a_long_one_is_cut(ctx, default):
    short = decide(action("execute", command="git push origin main"), ctx, default)
    assert "`git push origin main`" in short.sentence
    long = decide(action("execute", command="x" * 300), ctx, default)
    assert "…" in long.sentence and len(long.sentence) < 300


# --- nothing said: ask, never do it (R-05) ----------------------------------------


def test_an_action_no_rule_names_is_asked_about(ctx):
    decision = decide(action("delete", path="a", inside=True), ctx, [Policy(scope="session")])
    assert (decision.verdict, decision.decided_by, decision.rule) == ("ask", "default", None)
    assert "no rule names it" in decision.sentence


def test_no_policies_at_all_still_ask(ctx):
    assert decide(action("read", path="a", inside=True), ctx, []).verdict == "ask"


# --- first decision wins, strictest scope first (§6.3) ------------------------------


def test_the_first_matching_rule_of_a_policy_wins(ctx):
    policy = Policy(
        scope="session",
        rules=[Rule(name="first", decision="deny", classes=["read"]), Rule(name="second", decision="allow")],
    )
    assert decide(action("read", path="a", inside=True), ctx, [policy]).rule == "first"
    assert decide(action("edit", path="a", inside=True), ctx, [policy]).rule == "second"


def test_the_organization_decides_before_the_team_and_the_session_whatever_the_order_given(ctx):
    org = Policy(scope="organization", rules=[Rule(name="org says no", decision="deny", classes=["execute"])])
    team = Policy(scope="team", rules=[Rule(name="team asks", decision="ask", classes=["execute"])])
    session = Policy(scope="session", rules=[Rule(name="session allows", decision="allow")])
    for order in ([org, team, session], [session, team, org], [team, session, org]):
        decision = decide(action("execute", command="ls"), ctx, order)
        assert (decision.scope, decision.rule, decision.verdict) == ("organization", "org says no", "deny")
    assert decide(action("read", path="a", inside=True), ctx, [session, org, team]).scope == "session"


def test_a_scope_that_says_nothing_passes_the_action_down(ctx):
    org = Policy(scope="organization", rules=[Rule(name="only execute", decision="deny", classes=["execute"])])
    session = Policy(scope="session", rules=[Rule(name="reads", decision="allow", classes=["read"])])
    decision = decide(action("read", path="a", inside=True), ctx, [org, session])
    assert (decision.scope, decision.rule) == ("session", "reads")


# --- the matchers -------------------------------------------------------------------


def test_where_inside_needs_a_path_inside_and_outside_one_outside(ctx):
    inside = one("allow", where="inside")
    outside = one("allow", where="outside")
    assert decide(action("read", path="a", inside=True), ctx, [inside]).verdict == "allow"
    assert decide(action("read", path="a", inside=False), ctx, [inside]).verdict == "ask"
    assert decide(action("read"), ctx, [inside]).verdict == "ask"
    assert decide(action("read", path="/x", inside=False), ctx, [outside]).verdict == "allow"
    assert decide(action("read", path="a", inside=True), ctx, [outside]).verdict == "ask"
    assert decide(action("read"), ctx, [outside]).verdict == "ask"


def test_paths_are_globs_on_the_workspace_relative_path(ctx):
    policy = one("deny", paths=["secrets/*", "*.pem"])
    assert decide(action("read", path="secrets/a", inside=True), ctx, [policy]).verdict == "deny"
    assert decide(action("read", path="k.pem", inside=True), ctx, [policy]).verdict == "deny"
    assert decide(action("read", path="src/a.py", inside=True), ctx, [policy]).verdict == "ask"
    assert decide(action("read"), ctx, [policy]).verdict == "ask"


def test_kinds_narrow_a_rule(ctx):
    policy = one("deny", kinds=["delete"])
    assert decide(action("delete", path="a", inside=True), ctx, [policy]).verdict == "deny"
    assert decide(action("edit", path="a", inside=True), ctx, [policy]).verdict == "ask"


def test_commands_are_regular_expressions_on_the_whole_line(ctx):
    policy = one("deny", commands=[r"\brm\b.*-rf"])
    assert decide(action("execute", command="rm -rf build"), ctx, [policy]).verdict == "deny"
    assert decide(action("execute", command="rm build.txt"), ctx, [policy]).verdict == "ask"
    assert decide(action("execute"), ctx, [policy]).verdict == "ask"


# --- the stateful limits (§6.3) -----------------------------------------------------


def test_a_soft_limit_asks_once_then_lets_the_session_run_to_the_hard_one(ctx):
    policy = Policy(scope="team", limits=Limits(tool_calls=Threshold(soft=2, hard=4)),
                    rules=[Rule(name="all", decision="allow")])
    act = action("read", path="a", inside=True)
    verdicts = []
    for _ in range(6):
        decision = decide(act, ctx, [policy])
        verdicts.append(decision.verdict)
        if decision.decided_by == "limit" and decision.verdict == "ask":
            ctx.state.soft_asked.add((decision.scope, decision.rule))
        ctx.state.count(act, decision)
    assert verdicts == ["allow", "allow", "ask", "allow", "deny", "deny"]
    third = decide(act, Context(workspace="/w", state=LimitState(tool_calls=2)), [policy])
    assert third.decided_by == "limit" and third.rule == "tool_calls" and "soft limit of 2" in third.sentence
    assert "the hard limit is 4" in third.sentence


def test_a_hard_limit_refuses_and_says_what_would_let_it_go_on(ctx):
    policy = Policy(scope="organization", limits=Limits(tool_calls=Threshold(soft=0, hard=0)))
    decision = decide(action("read", path="a", inside=True), ctx, [policy])
    assert decision.verdict == "deny"
    assert "over the hard limit of 0 in the organization policy" in decision.sentence
    assert "widen the limit or start a new session" in decision.sentence
    assert not decision.counted


def test_terminals_open_and_bytes_written_count_only_what_they_name(ctx):
    policy = Policy(
        scope="session",
        limits=Limits(terminals_open=Threshold(soft=1, hard=1), bytes_written=Threshold(soft=10, hard=10)),
        rules=[Rule(name="all", decision="allow")],
    )
    ctx.state.terminals_open = 1
    assert decide(action("read", path="a", inside=True), ctx, [policy]).verdict == "allow"
    assert decide(action("terminal", command="ls"), ctx, [policy]).verdict == "deny"
    ctx.state.terminal_released()
    assert decide(action("terminal", command="ls"), ctx, [policy]).verdict == "allow"
    ctx.state.bytes_written = 8
    assert decide(action("fs_write", path="a", inside=True, bytes=2), ctx, [policy]).verdict == "allow"
    assert decide(action("fs_write", path="a", inside=True, bytes=3), ctx, [policy]).verdict == "deny"
    assert decide(action("fs_read", path="a", inside=True, bytes=300), ctx, [policy]).verdict == "allow"


def test_the_strictest_scopes_limit_is_checked_first(ctx):
    org = Policy(scope="organization", limits=Limits(tool_calls=Threshold(soft=0, hard=0)))
    session = Policy(scope="session", rules=[Rule(name="all", decision="allow")])
    decision = decide(action("read", path="a", inside=True), ctx, [session, org])
    assert (decision.verdict, decision.scope) == ("deny", "organization")


def test_counting_follows_the_decision(ctx):
    allowed = Decision(verdict="allow", sentence="", decided_by="rule", counted=True)
    denied = Decision(verdict="deny", sentence="", decided_by="rule")
    ctx.state.count(action("terminal", command="ls"), allowed)
    ctx.state.count(action("fs_write", path="a", inside=True, bytes=7), allowed)
    ctx.state.count(action("read", path="a", inside=True), denied)
    assert (ctx.state.tool_calls, ctx.state.terminals_open, ctx.state.bytes_written) == (2, 1, 7)


# --- the document, its schema and its files -----------------------------------------


def test_the_schema_file_is_the_models_schema():
    assert json.loads(SCHEMA_PATH.read_text()) == policy_json_schema()


def test_the_schema_names_the_classes_scopes_and_verdicts():
    schema = policy_json_schema()
    defs = schema["$defs"]
    assert defs["Rule"]["properties"]["classes"]["items"]["enum"] == list(ACTION_CLASSES)
    assert defs["Rule"]["properties"]["decision"]["enum"] == ["allow", "ask", "deny"]
    assert schema["properties"]["scope"]["enum"] == ["organization", "team", "session"]
    assert schema["additionalProperties"] is False


def test_an_unknown_key_is_refused_in_a_sentence():
    with pytest.raises(PolicyRefused, match="f.yaml: rules.0.colour: Extra inputs are not permitted"):
        parse_policies({"scope": "session", "rules": [{"name": "x", "decision": "allow", "colour": "red"}]}, "f.yaml")
    with pytest.raises(PolicyRefused, match="rules.0.decision: Field required"):
        parse_policies({"scope": "session", "rules": [{"name": "x"}]}, "f.yaml")


def test_a_soft_threshold_above_the_hard_one_is_refused():
    with pytest.raises(PolicyRefused, match="soft threshold"):
        parse_policies({"scope": "session", "limits": {"tool_calls": {"soft": 5, "hard": 1}}}, "f.yaml")


def test_two_rules_of_one_name_are_refused():
    with pytest.raises(PolicyRefused, match="names the rule 'a' twice"):
        parse_policies({"scope": "session", "rules": [{"name": "a", "decision": "ask"}, {"name": "a", "decision": "ask"}]}, "f")


def test_two_documents_of_one_scope_are_refused():
    with pytest.raises(PolicyRefused, match="two documents of the session scope"):
        parse_policies({"policies": [{"scope": "session"}, {"scope": "session"}]}, "f")


def test_a_file_with_policies_holds_nothing_else():
    with pytest.raises(PolicyRefused, match="holds nothing else"):
        parse_policies({"policies": [{"scope": "session"}], "scope": "team"}, "f")


def test_several_documents_come_back_strictest_first():
    loaded = parse_policies({"policies": [{"scope": "session"}, {"scope": "organization"}, {"scope": "team"}]}, "f")
    assert [item.policy.scope for item in loaded] == ["organization", "team", "session"]
    assert {item.origin for item in loaded} == {"f"}


def test_a_missing_file_names_setup(tmp_path: Path):
    with pytest.raises(PolicyRefused, match="no policy file; `agent-shield setup` writes the default one"):
        load_policies(tmp_path / "agent-shield.yaml")


def test_an_empty_or_broken_file_is_refused(tmp_path: Path):
    (tmp_path / "a.yaml").write_text("")
    with pytest.raises(PolicyRefused, match="the file is empty"):
        load_policies(tmp_path / "a.yaml")
    (tmp_path / "b.yaml").write_text("scope: [")
    with pytest.raises(PolicyRefused, match="not YAML"):
        load_policies(tmp_path / "b.yaml")
    (tmp_path / "c.yaml").write_text("- just\n- a list\n")
    with pytest.raises(PolicyRefused, match="a policy is a mapping with a scope, not list"):
        load_policies(tmp_path / "c.yaml")


def test_the_default_policy_round_trips_through_yaml(tmp_path: Path):
    path = tmp_path / "agent-shield.yaml"
    path.write_text(dump_policy(default_policy()))
    loaded = load_policies(path)
    assert loaded[0].policy == default_policy()
    assert "kinds: []" not in path.read_text()


def test_expires_is_a_datetime():
    policy = parse_policies({"scope": "team", "expires": "2026-10-16T00:00:00Z"}, "f")[0].policy
    assert policy.expires == datetime(2026, 10, 16, tzinfo=timezone.utc)
