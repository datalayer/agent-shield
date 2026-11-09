# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The temporal evaluator (AC-42): a Dogwood policy set decided over the session's history.

A policy document's ``dogwood`` section holds a policy set — Cedar, with
``when temporal { … }`` conditions over the session's earlier events, as
AgentCore Policy takes them. Every classed action the Shield decides is put
to it, AgentCore's way:

- **deny by default**: an action no ``permit`` applies to is refused, and a
  ``forbid`` overrides any ``permit``;
- the **history** is the session's :class:`EventLog`: each decided call is a
  ``request`` (an ``error`` when it was refused, by the policy or by the
  person), each permitted call that completed a ``response`` carrying its
  output, each that failed an ``error``;
- the **current request counts** in a self-referential condition: it is
  observed as a ``request`` at the decision timepoint before the conditions
  are read;
- **windows** are closed (a witness exactly ``W`` back is in) and bounded at
  24 hours, held when the set is read (``dogwood.py``).

The Cedar is never interpreted here: each temporal clause is computed from
the history into a boolean slot, and the lowered set is decided by
``cedarpy`` with the slots under ``context.dogwood``. Without ``cedarpy`` the
set cannot decide, and every action is refused in a sentence (fail closed).

In ``log_only`` mode the set decides and its answer is recorded, but the
action is let through to the rules — AgentCore's ``LOG_ONLY``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from .cedar import CedarCall, cedar_decide
from .dogwood import (
    MAX_WINDOW_SECONDS,
    SLOT_RECORD,
    Agg,
    And,
    Arith,
    Arr,
    Compare,
    CtxRef,
    DogwoodSet,
    Entity,
    Exists,
    Formerly,
    Lit,
    Not,
    Pred,
    Previous,
    ScopeRef,
    Since,
    Tp,
    Var,
    Wild,
)

EventKind = Literal["request", "response", "error"]
#: How long the log keeps an event: no window looks further back.
HORIZON = timedelta(seconds=MAX_WINDOW_SECONDS)
_I64 = (-(2**63), 2**63 - 1)


class _Missing:
    def __repr__(self) -> str:
        return "MISSING"


MISSING: Any = _Missing()


@dataclass(frozen=True)
class Event:
    """One event of a session: a request, a response or an error, on one call."""

    kind: EventKind
    action: str
    principal: str
    resource: str
    at: datetime
    key: str
    input: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)

    def get(self, path: str) -> Any:
        """A field of the event as a predicate names it; ``MISSING`` when it carries none."""
        if path in ("eventPrincipal", "callerPrincipal"):
            return self.principal
        if path in ("eventResource", "callerResource"):
            return self.resource
        if path == "requestId":
            return self.key
        head, _, rest = path.partition(".")
        if head not in ("input", "output") or not rest:
            return MISSING
        return _walk(self.input if head == "input" else self.output, rest.split("."))

    def row(self) -> dict[str, Any]:
        """The event as the audit and the tests read it."""
        return {
            "kind": self.kind,
            "action": self.action,
            "principal": self.principal,
            "resource": self.resource,
            "input": self.input,
            "output": self.output,
            "at": self.at.isoformat(),
            "key": self.key,
        }


def _walk(value: Any, path: Sequence[str]) -> Any:
    for part in path:
        if not isinstance(value, Mapping) or part not in value:
            return MISSING
        value = value[part]
    return value


class EventLog:
    """A session's history: what the Shield decided and what completed, oldest first.

    Timestamps are kept strictly increasing (a clock that steps back is
    read as the last moment plus a microsecond), and events older than the
    24-hour horizon are dropped as new ones arrive.
    """

    def __init__(self, horizon: timedelta = HORIZON) -> None:
        self.horizon = horizon
        self.events: list[Event] = []

    def __len__(self) -> int:
        return len(self.events)

    def _moment(self, at: datetime) -> datetime:
        if self.events and at <= self.events[-1].at:
            return self.events[-1].at + timedelta(microseconds=1)
        return at

    def _append(self, event: Event) -> Event:
        event = Event(**{**event.__dict__, "at": self._moment(event.at)})
        self.events.append(event)
        cut = event.at - self.horizon
        while self.events and self.events[0].at < cut:
            self.events.pop(0)
        return event

    def _decision(self, key: str) -> Event | None:
        return next((e for e in reversed(self.events) if e.key == key and e.kind in ("request", "error")), None)

    def decided(self, key: str, call: CedarCall, *, allowed: bool, at: datetime) -> Event:
        """A call decided: a ``request`` when it may go on, an ``error`` when it was refused.

        A call decided again (its input completed by a later update) replaces
        its earlier decision.
        """
        self.events = [e for e in self.events if not (e.key == key and e.kind in ("request", "error"))]
        return self._append(
            Event(
                kind="request" if allowed else "error",
                action=call.action,
                principal=call.principal,
                resource=call.resource,
                at=at,
                key=key,
                input=call.input,
            )
        )

    def refused(self, key: str, at: datetime) -> Event | None:
        """The person refused a call that was asked: its ``request`` becomes an ``error``."""
        kept = self._decision(key)
        if kept is None or kept.kind == "error":
            return kept
        self.events.remove(kept)
        return self._append(Event(**{**kept.__dict__, "kind": "error", "at": at}))

    def ended(self, key: str, at: datetime, *, ok: bool, output: Any = None) -> Event | None:
        """A call that ran ended: a ``response`` with its output, or an ``error`` when it failed."""
        kept = self._decision(key)
        if kept is None or kept.kind == "error":
            return None
        if any(e.key == key and e.kind == "response" for e in self.events):
            return None
        return self._append(
            Event(
                kind="response" if ok else "error",
                action=kept.action,
                principal=kept.principal,
                resource=kept.resource,
                at=at,
                key=key,
                input=kept.input,
                output=dict(output) if ok and isinstance(output, Mapping) else {},
            )
        )

    def rows(self) -> list[dict[str, Any]]:
        return [event.row() for event in self.events]


# -- evaluating one temporal condition -------------------------------------------------------


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    return left == right


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _clamp(value: int) -> int:
    return max(_I64[0], min(_I64[1], value))


def _key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


class Evaluator:
    """One condition at one decision: the events up to and including the current request."""

    def __init__(self, events: Sequence[Event], call: CedarCall) -> None:
        self.events = list(events)
        self.call = call

    def holds(self, cond: Any) -> bool:
        """Whether the condition holds at the last event (the current request)."""
        return bool(self.rows(cond, len(self.events) - 1, {}))

    def _within(self, i: int, window_seconds: int) -> range:
        j = i
        while j - 1 >= 0 and (self.events[i].at - self.events[j - 1].at).total_seconds() <= window_seconds:
            j -= 1
        return range(i, j - 1, -1)

    def rows(self, cond: Any, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        """The assignments under which ``cond`` holds at timepoint ``i``, extending ``env``."""
        handler = getattr(self, f"_{type(cond).__name__.lower()}", None)
        if handler is None:
            raise TypeError(f"{type(cond).__name__} is not a temporal condition")
        return handler(cond, i, env)

    def _pred(self, cond: Pred, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        event = self.events[i]
        if event.action != cond.action or event.kind != cond.kind:
            return []
        bound = dict(env)
        for path, term in cond.fields:
            if isinstance(term, Wild):
                continue
            value = event.get(path)
            if value is MISSING:
                return []
            if isinstance(term, Var) and term.name not in bound:
                bound[term.name] = value
                continue
            wanted = self.value(term, i, bound)
            if wanted is MISSING or not _same(value, wanted):
                return []
        return [bound]

    def _tp(self, cond: Tp, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        if cond.var in env:
            return [env] if env[cond.var] == i else []
        return [{**env, cond.var: i}]

    def _formerly(self, cond: Formerly, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        return [row for j in self._within(i, cond.window.seconds) for row in self.rows(cond.body, j, env)]

    def _previous(self, cond: Previous, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        if i == 0 or (self.events[i].at - self.events[i - 1].at).total_seconds() > cond.window.seconds:
            return []
        return self.rows(cond.body, i - 1, env)

    def _since(self, cond: Since, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for j in self._within(i, cond.window.seconds):
            for anchor in self.rows(cond.right, j, env):
                if all(self.rows(cond.left, k, anchor) for k in range(j + 1, i + 1)):
                    found.append(anchor)
        return found

    def _not(self, cond: Not, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        return [] if self.rows(cond.body, i, env) else [env]

    def _and(self, cond: And, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        return [right for left in self.rows(cond.left, i, env) for right in self.rows(cond.right, i, left)]

    def _exists(self, cond: Exists, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        inner = {k: v for k, v in env.items() if k != cond.var}
        seen: dict[str, dict[str, Any]] = {}
        for row in self.rows(cond.body, i, inner):
            kept = {k: v for k, v in row.items() if k != cond.var}
            if cond.var in env:
                kept[cond.var] = env[cond.var]
            seen.setdefault(_key(kept), kept)
        return list(seen.values())

    def _compare(self, cond: Compare, i: int, env: dict[str, Any]) -> list[dict[str, Any]]:
        if cond.op == "==":
            for var, other in ((cond.left, cond.right), (cond.right, cond.left)):
                if isinstance(var, Var) and var.name not in env:
                    value = self.value(other, i, env)
                    return [] if value is MISSING else [{**env, var.name: value}]
        left, right = self.value(cond.left, i, env), self.value(cond.right, i, env)
        if left is MISSING or right is MISSING:
            return []
        if cond.op in ("==", "!="):
            return [env] if _same(left, right) == (cond.op == "==") else []
        a, b = _int(left), _int(right)
        if a is None or b is None:
            return []
        holds = {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[cond.op]
        return [env] if holds else []

    def value(self, term: Any, i: int, env: dict[str, Any]) -> Any:
        """A term's value at timepoint ``i``; ``MISSING`` when it does not resolve."""
        if isinstance(term, Lit):
            return term.value
        if isinstance(term, Var):
            return env.get(term.name, MISSING)
        if isinstance(term, Wild):
            return MISSING
        if isinstance(term, Entity):
            return term.uid
        if isinstance(term, (CtxRef, ScopeRef)):
            return self._reference(term)
        if isinstance(term, Arr):
            items = [self.value(item, i, env) for item in term.items]
            return MISSING if any(item is MISSING for item in items) else items
        if isinstance(term, Agg):
            return self._aggregate(term, i, env)
        if isinstance(term, Arith):
            a, b = _int(self.value(term.left, i, env)), _int(self.value(term.right, i, env))
            if a is None or b is None:
                return MISSING
            return _clamp({"+": a + b, "-": a - b, "*": a * b}[term.op])
        raise TypeError(f"{type(term).__name__} is not a term")

    def _reference(self, term: CtxRef | ScopeRef) -> Any:
        if isinstance(term, CtxRef):
            return _walk(self.call.context, term.path)
        if term.name == "principal":
            return _walk(self.call.principal_attrs, term.attrs) if term.attrs else self.call.principal
        return MISSING if term.attrs else self.call.resource

    def _aggregate(self, agg: Agg, i: int, env: dict[str, Any]) -> int:
        names = [name for name, _ in agg.domain]
        inner = {k: v for k, v in env.items() if k not in names}
        tuples: dict[str, tuple[Any, ...]] = {}
        for row in self.rows(agg.where, i, inner):
            if all(name in row for name in names):
                values = tuple(row[name] for name in names)
                tuples.setdefault(_key(values), values)
        if agg.kind == "count":
            return len(tuples)
        column = names.index(agg.value or "")
        return _clamp(sum(_int(values[column]) or 0 for values in tuples.values()))


# -- deciding a call against a set -----------------------------------------------------------


@dataclass(frozen=True)
class TemporalAnswer:
    """What a set decided for one call, and why, in a sentence."""

    allowed: bool
    sentence: str
    decided_by: tuple[str, ...] = ()
    slots: dict[str, bool] = field(default_factory=dict)


def current_request(call: CedarCall, at: datetime, key: str = "current") -> Event:
    """The call being decided, observed as a ``request`` at the decision timepoint."""
    return Event(
        kind="request",
        action=call.action,
        principal=call.principal,
        resource=call.resource,
        at=at,
        key=key,
        input=call.input,
    )


def _names(parsed: DogwoodSet, reasons: Sequence[str]) -> tuple[str, ...]:
    names: list[str] = []
    for reason in reasons:
        digits = reason.removeprefix("policy")
        names.append(
            parsed.policies[int(digits)].name if digits.isdigit() and int(digits) < len(parsed.policies) else reason
        )
    return tuple(names)


def evaluate(parsed: DogwoodSet, call: CedarCall, history: Sequence[Event], at: datetime) -> TemporalAnswer:
    """Decide one call: the temporal slots from the history and the current request, then Cedar.

    Parameters
    ----------
    parsed : DogwoodSet
        The policy set, parsed and lowered.
    call : CedarCall
        The call being decided.
    history : sequence of Event
        The session's events before it, oldest first.
    at : datetime
        The decision's moment.

    Returns
    -------
    TemporalAnswer
        Allowed or not, with the policies that decided and the slots computed.
    """
    last = history[-1].at if history else None
    moment = at if last is None or at > last else last + timedelta(microseconds=1)
    events = [*history, current_request(call, moment)]
    evaluator = Evaluator(events, call)
    slots = {slot: evaluator.holds(cond) for slot, cond in parsed.slots()}
    answer = cedar_decide(parsed.lowered, call, {SLOT_RECORD: slots})
    who = f"{call.action} by {call.principal}"
    if answer.unavailable:
        return TemporalAnswer(
            allowed=False,
            slots=slots,
            sentence=(
                "the dogwood policies cannot decide: cedarpy is not installed (pip install "
                "'datalayer-agent-shield[cedar]'), and nothing is permitted unsaid"
            ),
        )
    if answer.errors:
        return TemporalAnswer(
            allowed=False,
            slots=slots,
            sentence=f"the dogwood policies could not decide {who} ({'; '.join(answer.errors)}), so it is denied",
        )
    names = _names(parsed, answer.reasons)
    if answer.allowed:
        return TemporalAnswer(
            allowed=True, slots=slots, decided_by=names, sentence=f"the dogwood policy {', '.join(names)} permits {who}"
        )
    if names:
        return TemporalAnswer(
            allowed=False,
            slots=slots,
            decided_by=names,
            sentence=f"the dogwood policy {', '.join(names)} forbids {who} (a forbid overrides any permit)",
        )
    return TemporalAnswer(
        allowed=False,
        slots=slots,
        sentence=f"no dogwood policy permits {who} as the session stands (deny by default)",
    )


__all__ = [
    "HORIZON",
    "MISSING",
    "Evaluator",
    "Event",
    "EventKind",
    "EventLog",
    "TemporalAnswer",
    "current_request",
    "evaluate",
]
