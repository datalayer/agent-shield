# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The cedar authorizer (AC-41): Cedar behind the AuthZen port, entities from the call, deny by
default, forbid over permit, fail closed without cedarpy."""

from __future__ import annotations

import builtins
from pathlib import Path

import pytest

pytest.importorskip("cedarpy")

from agent_shield.policy import (
    Action,
    AuthorizerConfig,
    CedarAuthorizer,
    Context,
    Policy,
    PolicyRefused,
    Rule,
    Subject,
    call_from_request,
    decide,
    hook_for,
    parse_policies,
    request_for,
)

POLICIES = """permit (principal, action, resource)
when { principal has org_uid && principal.org_uid == "acme" };

@id("no big payments")
forbid (principal, action == Datalayer::Action::"bank___pay", resource)
when { context.input has amount && context.input.amount > 1000 };

forbid (principal, action == Datalayer::Action::"shield___terminal", resource == Datalayer::Runtime::"r-prod");
"""

ALICE = Subject(type="account", id="alice", properties={"org_uid": "acme", "app_uid": "app1", "agent_uid": "ag1"})
MALLORY = Subject(type="account", id="mallory", properties={"org_uid": "evil"})


def _context(subject: Subject, runtime: str | None = "r1", authorizer: CedarAuthorizer | None = None) -> Context:
    return Context(
        workspace="/w",
        session_id="s1",
        subject=subject,
        runtime=runtime,
        authorize=hook_for(authorizer) if authorizer else None,
    )


def _pay(amount: int) -> Action:
    return Action(
        kind="other", title="pay", tool="bank___pay", input={"amount": amount, "to": "bob"}, **{"class": "buy"}
    )


def test_the_call_as_cedar_sees_it() -> None:
    action = _pay(10)
    call = call_from_request(request_for(action, _context(ALICE)))
    assert call.principal == 'Datalayer::User::"alice"'
    assert call.action == 'Datalayer::Action::"bank___pay"'
    assert call.resource == 'Datalayer::Runtime::"r1"'
    assert call.principal_attrs == {"org_uid": "acme", "app_uid": "app1", "agent_uid": "ag1"}
    assert call.context["input"] == {"amount": 10, "to": "bob"}
    assert call.context["class"] == "buy" and call.context["kind"] == "other"
    own = call_from_request(
        request_for(Action(kind="terminal", title="ls", command="ls", **{"class": "execute"}), _context(ALICE, None))
    )
    assert own.action == 'Datalayer::Action::"shield___terminal"'
    assert own.resource == 'Datalayer::Runtime::"local"'
    agent = call_from_request(request_for(_pay(1), _context(Subject(type="agent", id="a1"))))
    assert agent.principal == 'Datalayer::Agent::"a1"'


def test_permit_forbid_and_deny_by_default() -> None:
    cedar = CedarAuthorizer(POLICIES)
    policy = Policy(scope="organization", authorize=["buy", "execute"], rules=[Rule(name="go", decision="allow")])
    allowed = decide(_pay(10), _context(ALICE, authorizer=cedar), [policy])
    assert allowed.verdict == "allow" and allowed.authorizer == "cedar" and allowed.authorization == "allow"
    big = decide(_pay(5000), _context(ALICE, authorizer=cedar), [policy])
    assert big.verdict == "deny" and big.decided_by == "authorizer"
    assert "a forbid" in big.sentence and "no big payments" in big.sentence
    stranger = decide(_pay(10), _context(MALLORY, authorizer=cedar), [policy])
    assert stranger.verdict == "deny"
    assert "Cedar denies by default" in stranger.sentence
    terminal = Action(kind="terminal", title="Run ls", command="ls", **{"class": "execute"})
    assert decide(terminal, _context(ALICE, "r-dev", cedar), [policy]).verdict == "allow"
    assert decide(terminal, _context(ALICE, "r-prod", cedar), [policy]).verdict == "deny"


def test_an_allow_never_loosens_a_rule() -> None:
    cedar = CedarAuthorizer(POLICIES)
    policy = Policy(
        scope="organization", authorize=["buy"], rules=[Rule(name="no buying", decision="deny", classes=["buy"])]
    )
    decision = decide(_pay(10), _context(ALICE, authorizer=cedar), [policy])
    assert decision.verdict == "deny" and decision.rule == "no buying"


def test_the_config_reads_inline_text_and_a_file(tmp_path: Path) -> None:
    loaded = parse_policies({"scope": "organization", "authorizer": {"cedar": {"policies": POLICIES}}}, "f")
    assert loaded[0].policy.authorizer is not None
    assert loaded[0].policy.authorizer.kind == "cedar"
    assert isinstance(loaded[0].policy.authorizer.build(), CedarAuthorizer)
    path = tmp_path / "org.cedar"
    path.write_text(POLICIES, encoding="utf-8")
    built = AuthorizerConfig.model_validate({"cedar": {"policies": str(path)}}).build()
    assert isinstance(built, CedarAuthorizer) and built.origin == str(path)
    with pytest.raises(PolicyRefused, match="does not exist"):
        parse_policies({"scope": "team", "authorizer": {"cedar": {"policies": str(tmp_path / "missing.cedar")}}}, "f")
    with pytest.raises(PolicyRefused, match="Cedar refuses them"):
        parse_policies({"scope": "team", "authorizer": {"cedar": {"policies": "permit (principal, action"}}}, "f")


def test_without_cedarpy_every_request_is_a_deny_that_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    cedar = CedarAuthorizer(POLICIES)
    real = builtins.__import__

    def without_cedarpy(name, *args, **kwargs):
        if name == "cedarpy":
            raise ImportError("no cedarpy")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_cedarpy)
    policy = Policy(scope="organization", authorize=["buy"], rules=[Rule(name="go", decision="allow")])
    decision = decide(_pay(10), _context(ALICE, authorizer=cedar), [policy])
    assert decision.verdict == "deny"
    assert "cedarpy is not installed" in decision.sentence
