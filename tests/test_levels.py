# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Three levels, the strictest answer in every order, nothing loosening below the organization's (SHIELD §6.3, SH-31)."""

from __future__ import annotations

from itertools import permutations

import pytest

from agent_shield.policy import (
    Action,
    Context,
    Harnesses,
    Limits,
    Mcp,
    Network,
    Policy,
    PolicyWidens,
    Rule,
    Threshold,
    admits,
    check_tightens,
    class_of,
    credentials_rule,
    decide,
    default_policy,
    overlaps,
    widening,
)


def act(kind: str, **fields) -> Action:
    return Action(kind=kind, title=kind, **{"class": class_of(kind)}, **fields)


CTX = Context(workspace="/w")


def level(scope: str, verdict: str, classes: list[str] | None = None, **fields) -> Policy:
    return Policy(
        scope=scope, rules=[Rule(name=f"{scope} on {verdict}", decision=verdict, classes=classes or [], **fields)]
    )


# --- SH-31: the three levels in every order ---------------------------------------------


@pytest.mark.parametrize(
    ("organization", "appspec", "session", "expected"),
    [
        ("ask", "allow", "allow", "ask"),  # the organization tightens what the Maker and the session allow
        ("deny", "ask", "allow", "deny"),
        ("allow", "ask", "allow", "allow"),  # the organization's say is first, whatever is below it
        ("allow", "allow", "deny", "allow"),
        ("ask", "deny", "allow", "ask"),
    ],
)
def test_the_organization_decides_first_in_every_order_the_policies_are_given(organization, appspec, session, expected):
    policies = [
        level("organization", organization, ["execute"]),
        level("team", appspec, ["execute"]),
        level("session", session, ["execute"]),
    ]
    for order in permutations(policies):
        decision = decide(act("execute", command="pytest"), CTX, list(order))
        assert decision.verdict == expected, order
        assert decision.scope == "organization"


@pytest.mark.parametrize(
    "appspec,session,expected", [("ask", "allow", "ask"), ("deny", "allow", "deny"), ("allow", "deny", "allow")]
)
def test_with_no_organization_rule_the_appspec_decides_before_the_session(appspec, session, expected):
    policies = [Policy(scope="organization"), level("team", appspec, ["write"]), level("session", session, ["write"])]
    for order in permutations(policies):
        decision = decide(act("edit", path="a.py", inside=True), CTX, list(order))
        assert decision.verdict == expected
        assert decision.scope == "team"


def test_an_organization_tightening_execute_to_ask_is_honoured_over_decision_5s_default_and_a_session_rule():
    # The r1 drill of SH-50 in a test: the organization says execute asks; a session rule the person added
    # allowing `pytest` and the default's rule are both below it.
    organization = Policy(scope="organization", rules=[Rule(name="execute asks", decision="ask", classes=["execute"])])
    session = default_policy().model_copy(
        update={"rules": [Rule(name="always: pytest", decision="allow", commands=["^pytest"]), *default_policy().rules]}
    )
    decision = decide(act("execute", command="pytest -q"), CTX, [session, organization])
    assert decision.verdict == "ask" and decision.rule == "execute asks" and decision.scope == "organization"


# --- widening: what a lower document may not say ----------------------------------------


def test_a_team_rule_that_permits_more_than_an_overlapping_organization_rule_is_widening():
    above = level("organization", "ask", ["execute"])
    assert widening(level("team", "allow", ["execute"], commands=["^pytest"]), above) == [
        "the team rule 'team on allow' says do it where the organization rule 'organization on ask' says ask me first; "
        "a team policy tightens the organization's and cannot loosen it"
    ]
    assert widening(level("team", "deny", ["execute"]), above) == []
    assert widening(level("team", "ask", ["execute"]), above) == []


def test_rules_on_different_classes_kinds_or_sides_of_the_workspace_do_not_overlap():
    assert not overlaps(
        Rule(name="a", decision="allow", classes=["read"]), Rule(name="b", decision="deny", classes=["delete"])
    )
    assert not overlaps(
        Rule(name="a", decision="allow", kinds=["read"]), Rule(name="b", decision="deny", classes=["execute"])
    )
    assert not overlaps(
        Rule(name="a", decision="allow", where="inside"), Rule(name="b", decision="deny", where="outside")
    )
    assert not overlaps(
        Rule(name="a", decision="allow", paths=["a.py"]), Rule(name="b", decision="deny", paths=["b.py"])
    )
    assert overlaps(
        Rule(name="a", decision="allow", paths=["src/*"]), Rule(name="b", decision="deny", paths=["src/x.py"])
    )
    assert overlaps(Rule(name="a", decision="allow"), Rule(name="b", decision="deny", classes=["execute"]))


def test_a_limit_above_the_organizations_is_widening_and_one_below_is_not():
    above = Policy(scope="organization", limits=Limits(tool_calls=Threshold(soft=10, hard=20)))
    assert widening(Policy(scope="team", limits=Limits(tool_calls=Threshold(soft=10, hard=30))), above) == [
        "the team limit on tool calls (10 then 30) is above the organization's (10 then 20); a limit below may only be lower"
    ]
    assert widening(Policy(scope="team", limits=Limits(tool_calls=Threshold(soft=5, hard=20))), above) == []
    assert widening(Policy(scope="team", limits=Limits(spend=Threshold(soft=5, hard=20))), above) == []


def test_a_fetch_host_an_mcp_server_or_a_harness_the_organization_does_not_list_is_widening():
    above = Policy(
        scope="organization",
        network=Network(fetch=["*.example.com"]),
        mcp=Mcp(allow=["earthdata"]),
        harnesses=Harnesses(admit=["claude-code"]),
    )
    lower = Policy(
        scope="team",
        network=Network(fetch=["api.example.com", "other.org"]),
        mcp=Mcp(allow=["earthdata", "github"]),
        harnesses=Harnesses(admit=["claude-code", "codex"]),
    )
    found = widening(lower, above)
    assert [sentence.split(";")[0] for sentence in found] == [
        "the team fetch allow-list names other.org, which the organization's does not",
        "the team policy lends the MCP server github, which the organization's does not",
        "the team policy admits the harness codex, which the organization's does not",
    ]


def test_the_credentials_rule_is_kept_below_unless_the_organization_says_either():
    assert widening(
        Policy(scope="team", harnesses=Harnesses(credentials="either")),
        Policy(scope="organization", harnesses=Harnesses(credentials="account")),
    ) == [
        "the team policy runs harnesses on either credentials where the organization's says account; "
        "a scope below keeps the credentials rule of the one above"
    ]
    assert (
        widening(
            Policy(scope="team", harnesses=Harnesses(credentials="platform")),
            Policy(scope="organization", harnesses=Harnesses(credentials="either")),
        )
        == []
    )


def test_a_document_that_says_nothing_widens_nothing():
    assert widening(Policy(scope="session"), default_policy().model_copy(update={"scope": "organization"})) == []


def test_check_tightens_refuses_in_sentences_and_only_against_the_scopes_above():
    organization = level("organization", "ask", ["execute"])
    with pytest.raises(PolicyWidens) as refused:
        check_tightens(level("session", "allow", ["execute"]), [organization, level("team", "allow", ["execute"])])
    assert refused.value.sentences == widening(level("session", "allow", ["execute"]), organization)
    check_tightens(level("session", "deny", ["execute"]), [organization])
    with pytest.raises(ValueError, match="is not below"):
        widening(organization, level("team", "ask"))


# --- the harnesses an organization admits ------------------------------------------------


def test_the_strictest_scope_that_lists_harnesses_admits_and_credentials_follow_the_strictest_scope():
    organization = Policy(scope="organization", harnesses=Harnesses(admit=["claude-code"], credentials="account"))
    team = Policy(scope="team", harnesses=Harnesses(admit=["codex"], credentials="either"))
    assert admits([team, organization], "claude-code") is None
    assert admits([team, organization], "codex") == (
        "the harness 'codex' is not one the organization policy admits (claude-code)"
    )
    assert admits([team], "codex") is None
    assert admits([Policy(scope="session")], "anything") is None
    assert credentials_rule([team, organization]) == "account"
    assert credentials_rule([team]) == "either"
    assert credentials_rule([]) == "account"
