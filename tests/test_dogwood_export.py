# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""``agent-shield policy export --dogwood`` (AC-43): a document's rules and limits as Dogwood,
round-trip tested — the exported set decides as the document does on the same events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

pytest.importorskip("cedarpy")

from agent_shield.cli import app
from agent_shield.policy import (
    Action,
    CedarCall,
    Context,
    EventLog,
    LimitState,
    Policy,
    Rule,
    Subject,
    call_from_request,
    decide,
    decide_budget,
    evaluate,
    parse_set,
    request_for,
)
from agent_shield.policy.export_dogwood import MODEL_TOOL, ExportRefused, export_dogwood

T0 = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)
TOOL = "files___op"

DOCUMENT = {
    "scope": "session",
    "rules": [
        {"name": "nothing is deleted", "decision": "deny", "classes": ["delete"]},
        {"name": "commands ask", "decision": "ask", "classes": ["execute"]},
        {"name": "writes under src", "decision": "allow", "classes": ["write"], "paths": ["src/*"]},
        {"name": "edits outside refused", "decision": "deny", "kinds": ["edit"], "where": "outside"},
        {"name": "reads inside", "decision": "allow", "classes": ["read"], "where": "inside"},
        {"name": "edits", "decision": "allow", "kinds": ["edit"]},
    ],
    # A soft threshold asks before the rules are read (and Dogwood has no ask): the round trip holds the
    # tool calls at soft == hard, the spend with a soft one the person grants.
    "limits": {"tool_calls": {"soft": 5, "hard": 5}, "spend": {"soft": 40, "hard": 100}},
}

STEPS = [
    ("read", "read", "src/a.py", True),
    ("edit", "write", "src/a.py", True),
    ("delete", "delete", "src/a.py", True),
    ("execute", "execute", None, None),
    ("edit", "write", "docs/x.md", True),  # 'edits' allows it: the write rule does not match docs/
    ("edit", "write", "/etc/passwd", False),  # outside: refused before 'edits'
    ("read", "read", "/etc/hosts", False),  # outside: no rule, the default asks
    ("read", "read", "README.md", True),
    ("read", "read", "src/b.py", True),
    ("read", "read", "src/c.py", True),  # the sixth call that goes on: over the hard limit of 5
    ("read", "read", "src/d.py", True),
]


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def _goes_on(verdict: str, decided_by: str) -> bool:
    """A decision the agent goes on with: an allow, or a soft limit's ask (the person grants it once)."""
    return verdict == "allow" or (verdict == "ask" and decided_by == "limit")


def test_the_exported_set_decides_as_the_document_does() -> None:
    policy = Policy.model_validate(DOCUMENT)
    exported = parse_set(export_dogwood(policy, tools=[TOOL]))
    state = LimitState()
    log = EventLog()
    shield, dogwood = [], []
    for n, (kind, cls, path, inside) in enumerate(STEPS):
        action = Action(kind=kind, title=f"{kind} {path}", path=path, inside=inside, tool=TOOL, **{"class": cls})
        context = Context(
            workspace="/w",
            session_id="s",
            state=state,
            history=log,
            now=at(n * 10),
            subject=Subject(type="account", id="a"),
        )
        decision = decide(action, context, [policy])
        call = call_from_request(request_for(action, context))
        answer = evaluate(exported, call, log.events, at(n * 10))
        goes_on = _goes_on(decision.verdict, decision.decided_by)
        shield.append(goes_on)
        dogwood.append(answer.allowed)
        if decision.decided_by == "limit" and decision.verdict == "ask":
            state.soft_asked.add((decision.scope, decision.rule))
        if goes_on:
            state.count(action, decision)
        log.decided(f"k{n}", call, allowed=goes_on, at=at(n * 10))
        if goes_on:
            log.ended(f"k{n}", at(n * 10 + 1), ok=True)
    assert shield == dogwood
    assert shield == [True, True, False, False, True, False, False, True, True, False, False]


def test_the_spend_limit_round_trips_on_the_model_requests() -> None:
    policy = Policy.model_validate(DOCUMENT)
    exported = parse_set(export_dogwood(policy, tools=[TOOL]))
    state = LimitState()
    log = EventLog()
    shield, dogwood = [], []
    for n, cost in enumerate([30, 30, 30, 20, 5]):
        context = Context(workspace="/w", session_id="s", state=state)
        decision = decide_budget(context, [policy], cost=cost)
        call = CedarCall(
            principal='Datalayer::User::"a"',
            action=f'Datalayer::Action::"{MODEL_TOOL}"',
            resource='Datalayer::Runtime::"local"',
            context={"input": {"credits": cost}},
        )
        answer = evaluate(exported, call, log.events, at(n))
        goes_on = _goes_on(decision.verdict, decision.decided_by)
        shield.append(goes_on)
        dogwood.append(answer.allowed)
        if decision.decided_by == "limit" and decision.verdict == "ask":
            state.soft_asked.add((decision.scope, decision.rule))
        if goes_on:
            state.spent(cost=cost)
        log.decided(f"m{n}", call, allowed=goes_on, at=at(n))
    assert shield == dogwood == [True, True, True, False, True]


def test_what_dogwood_cannot_say_is_refused() -> None:
    with pytest.raises(ExportRefused, match="regular expression"):
        export_dogwood(Policy(scope="session", rules=[Rule(name="rm", decision="deny", commands=["^rm "])]))
    with pytest.raises(ExportRefused, match="like knows"):
        export_dogwood(Policy(scope="session", rules=[Rule(name="p", decision="allow", paths=["src/?.py"])]))
    with pytest.raises(ExportRefused, match="name the tools"):
        export_dogwood(Policy(scope="session", limits={"tool_calls": {"soft": 1, "hard": 2}}))
    with pytest.raises(ExportRefused, match="already carries a dogwood set"):
        export_dogwood(Policy(scope="session", dogwood={"policies": "permit (principal, action, resource);"}))


def test_the_command_writes_the_set(tmp_path: Path) -> None:
    path = tmp_path / "agent-shield.yaml"
    path.write_text(yaml.safe_dump(DOCUMENT), encoding="utf-8")
    result = CliRunner().invoke(app, ["policy", "export", "--dogwood", str(path), "--tool", TOOL])
    assert result.exit_code == 0, result.output
    assert '@id("tool_calls: files___op")' in result.output
    assert "formerly within 24h" in result.output
    parse_set(result.output)
    refused = CliRunner().invoke(app, ["policy", "export", "--dogwood", str(path)])
    assert refused.exit_code == 2
    assert "--tool" in refused.output
    unsaid = CliRunner().invoke(app, ["policy", "export", str(path)])
    assert unsaid.exit_code == 2 and "--dogwood" in unsaid.output
