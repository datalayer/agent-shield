# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The conformance table (SH-35): the same action, the same answer whichever way it came.

An action reaches the Shield over one of five faces — MCP through the gateway,
A2A, ACP, AG-UI, the embed — and each face builds the same :class:`Action` for
it. The engine knows no face: this table holds the three levels to one answer
per action across every face, and the host's test in agent-runtimes drives the
same table through its adapter's faces.
"""

from __future__ import annotations

import pytest

from agent_shield.policy import (
    Action,
    Context,
    Limits,
    LimitState,
    Policy,
    Rule,
    Threshold,
    class_of,
    decide,
    default_policy,
)

FACES = ("mcp", "a2a", "acp", "ag-ui", "embed")

ORGANIZATION = Policy(
    scope="organization",
    rules=[
        Rule(name="execute asks", decision="ask", classes=["execute"]),
        Rule(name="no delete", decision="deny", classes=["delete"]),
    ],
    limits=Limits(tool_calls=Threshold(soft=3, hard=4)),
)
APPSPEC = Policy(scope="team", rules=[Rule(name="send: leave it to me", decision="deny", classes=["send"])])
SESSION = default_policy()
LEVELS = [SESSION, APPSPEC, ORGANIZATION]


def arriving(face: str, kind: str, **fields) -> Action:
    """What each face hands the engine: the same action, titled by the face it came over."""
    return Action(kind=kind, title=f"{kind} over {face}", **{"class": class_of(kind)}, **fields)


TABLE = [
    # (kind, fields, the verdict, the scope that decided, the rule)
    ("read", {"path": "src/a.py", "inside": True}, "allow", "session", "read inside the workspace"),
    ("edit", {"path": "src/a.py", "inside": True}, "allow", "session", "edit and move inside the workspace"),
    ("execute", {"command": "pytest -q"}, "ask", "organization", "execute asks"),
    ("execute", {"command": "git push origin main"}, "ask", "organization", "execute asks"),
    ("delete", {"path": "src/a.py", "inside": True}, "deny", "organization", "no delete"),
    ("read", {"path": "/etc/hostname", "inside": False}, "ask", "session", "outside the workspace"),
    ("fetch", {"url": "https://example.com/x"}, "deny", None, None),
    ("other", {"path": "src/b.py", "inside": True}, "allow", "session", "edit and move inside the workspace"),
]


@pytest.mark.parametrize(("kind", "fields", "verdict", "scope", "rule"), TABLE)
def test_every_face_gets_the_same_answer(kind, fields, verdict, scope, rule):
    answers = {face: decide(arriving(face, kind, **fields), Context(workspace="/w"), LEVELS) for face in FACES}
    for face, decision in answers.items():
        assert (decision.verdict, decision.scope, decision.rule) == (verdict, scope, rule), face
    assert len({d.decided_by for d in answers.values()}) == 1


def test_the_limits_count_the_same_across_faces():
    state = LimitState()
    ctx = Context(workspace="/w", state=state)
    verdicts = []
    for n, face in enumerate(FACES):
        action = arriving(face, "read", path=f"{n}.py", inside=True)
        decision = decide(action, ctx, LEVELS)
        state.count(action, decision)
        if decision.verdict == "ask" and decision.decided_by == "limit":
            state.soft_asked.add((decision.scope, decision.rule))
        verdicts.append((decision.verdict, decision.decided_by))
    assert verdicts == [("allow", "rule"), ("allow", "rule"), ("allow", "rule"), ("ask", "limit"), ("deny", "limit")]
