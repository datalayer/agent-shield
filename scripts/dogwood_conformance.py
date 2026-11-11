# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Dogwood conformance: the Shield's temporal evaluator against Dogwood's reference CLI.

Each case is a policy set, an event trace and the requests in it. The script
writes the case in the files the ``dogwood`` CLI reads (``policy.dw``, a Cedar
``schema.cedarschema``, an optional event schema, a ``trace.log``), runs::

    dogwood replay policy.dw --policy-schema schema.cedarschema --trace trace.log \\
        [--event-schema events.dwschema] --format json

and compares the verdict Dogwood gives each request with the one
``agent_shield.policy.temporal.evaluate`` gives over the same history. A
disagreement fails the run with a sentence naming the case and both answers.

The cases:

- **Dogwood's published examples** (``dogwood-docs/examples`` of a Dogwood
  checkout, ``--dogwood-src``) that a trace replays and the Shield reads:
  those with macros, information providers, experimental arithmetic or
  custom event kinds are skipped, as is a set the Shield refuses (each said).
  Under Dogwood's default event schema every temporal predicate is pinned to
  the requesting principal; the Shield keeps one history per session, whose
  principal is one, so it is handed the request's principal's events alone.
- **The agentspecs organization examples** (the six ``dogwood-*`` policies),
  each played as a session.
- **The sessions of the Shield's own tests** (``tests/test_temporal.py``), in
  AgentCore's names.

A session is played as the Shield keeps it: each request decided over the
history before it, a permitted one recorded as a ``request`` and completed a
second later as a ``response`` (with its output), a refused one recorded as an
``error``. Each decision is its own Dogwood trace: the history, then the
request; the trace's last verdict is Dogwood's answer. These cases name
``eventPrincipal``, ``eventResource`` and ``requestId`` as AgentCore does, so
they carry an event schema with those fields.

``--dry-run`` writes the inputs and runs the Shield's side alone (no Dogwood
binary needed); a published example is then compared with the ``expected.out``
Dogwood ships beside it, which its own documentation harness produces with the
same CLI.

Dogwood is a CI-only tool here: ``.github/workflows/dogwood-conformance.yaml``
builds it from a pinned tag. It is never a dependency of the package.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent_shield.policy import CedarCall, DogwoodRefused, Event, EventLog, evaluate, parse_set
from agent_shield.policy.dogwood import cedar_problem, normalize_uid

T0 = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)
KINDS = ("request", "response", "error")

#: The event schema of the Shield's own cases: Dogwood's default layout in AgentCore's field names.
AGENTCORE_EVENT_SCHEMA = """\
decision event <A>::request {
    ...inputs(A),
    pin eventPrincipal: principalType(A) = principal,
    eventResource: resourceType(A),
    requestId: String,
}

event <A>::response {
    ...inputs(A),
    ...outputs(A),
    pin eventPrincipal: principalType(A) = principal,
    eventResource: resourceType(A),
    requestId: String,
}

event <A>::error {
    ...inputs(A),
    pin eventPrincipal: principalType(A) = principal,
    eventResource: resourceType(A),
    requestId: String,
}
"""


class CaseError(ValueError):
    """A case that cannot be written or replayed, said in a sentence."""


# -- values in Dogwood's trace format --------------------------------------------------------


@dataclass(frozen=True)
class EntityRef:
    """An entity value, ``Ns::Type::"id"``, kept as its normalised uid."""

    uid: str


class Dec(str):
    """A decimal value, kept as its text (the Shield compares decimals as text)."""


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER = re.compile(r"-?\d+(\.\d+)?")


class _Reader:
    """A recursive-descent reader of one ``.log`` line (Dogwood's ``log_parse.rs``)."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.at = 0

    def fail(self, said: str) -> CaseError:
        return CaseError(f"{said} at column {self.at + 1} of {self.text[:80]!r}")

    def ws(self) -> None:
        while self.at < len(self.text) and self.text[self.at].isspace():
            self.at += 1

    def startswith(self, word: str) -> bool:
        self.ws()
        return self.text.startswith(word, self.at)

    def take(self, word: str) -> None:
        if not self.startswith(word):
            raise self.fail(f"expected {word!r}")
        self.at += len(word)

    def ident(self) -> str:
        self.ws()
        found = _IDENT.match(self.text, self.at)
        if not found:
            raise self.fail("expected a name")
        self.at = found.end()
        return found.group()

    def string(self) -> str:
        self.take('"')
        out: list[str] = []
        escapes = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", '"': '"', "\\": "\\", "'": "'"}
        while self.at < len(self.text):
            ch = self.text[self.at]
            self.at += 1
            if ch == '"':
                return "".join(out)
            if ch == "\\" and self.at < len(self.text):
                nxt = self.text[self.at]
                self.at += 1
                if nxt == "u" and self.text.startswith("{", self.at):
                    end = self.text.index("}", self.at)
                    out.append(chr(int(self.text[self.at + 1 : end].replace("_", ""), 16)))
                    self.at = end + 1
                else:
                    out.append(escapes.get(nxt, "\\" + nxt))
                continue
            out.append(ch)
        raise self.fail("an unclosed string")

    def key(self) -> str:
        return self.string() if self.startswith('"') else self.ident()

    def entity(self) -> EntityRef:
        parts = [self.ident()]
        while self.startswith("::"):
            self.take("::")
            if self.startswith('"'):
                return EntityRef(normalize_uid("::".join(parts) + "::" + json.dumps(self.string())))
            parts.append(self.ident())
        raise self.fail("expected an entity uid")

    def entity_head(self) -> tuple[str, str]:
        """``Ns::Action::"id"::kind``: the action's uid and the event kind."""
        parts = [self.ident()]
        while self.startswith("::"):
            self.take("::")
            if self.startswith('"'):
                uid = normalize_uid("::".join(parts) + "::" + json.dumps(self.string()))
                self.take("::")
                return uid, self.ident()
            parts.append(self.ident())
        raise self.fail('expected an event head (Ns::Action::"id"::kind)')

    def value(self) -> Any:
        self.ws()
        if self.startswith('"'):
            return self.string()
        if self.startswith("{"):
            self.take("{")
            record: dict[str, Any] = {}
            while not self.startswith("}"):
                name = self.key()
                self.take(":")
                if name in record:
                    raise self.fail(f"the field {name!r} twice")
                record[name] = self.value()
                if not self.startswith("}"):
                    self.take(",")
            self.take("}")
            return record
        if self.startswith("["):
            self.take("[")
            items: list[Any] = []
            while not self.startswith("]"):
                items.append(self.value())
                if not self.startswith("]"):
                    self.take(",")
            self.take("]")
            return items
        number = _NUMBER.match(self.text, self.at)
        if number:
            self.at = number.end()
            return Dec(number.group()) if number.group(1) else int(number.group())
        for word, meaning in (("true", True), ("false", False)):
            found = _IDENT.match(self.text, self.at)
            if found and found.group() == word:
                self.at = found.end()
                return meaning
        return self.entity()

    def args(self, closing: str = ")") -> dict[str, Any]:
        found: dict[str, Any] = {}
        while not self.startswith(closing):
            name = self.key()
            self.take(":")
            if name in found:
                raise self.fail(f"the field {name!r} twice")
            found[name] = self.value()
            if not self.startswith(closing):
                self.take(",")
        self.take(closing)
        return found

    def entities(self) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        while not self.startswith(")"):
            ref = self.entity()
            self.take(":")
            attrs = self.value()
            if not isinstance(attrs, dict):
                raise self.fail(f"the attributes of {ref.uid} are not a record")
            found[ref.uid] = attrs
            if self.startswith("in"):
                self.take("in")
                self.value()  # the parents: the Shield's principal has none
            if not self.startswith(")"):
                self.take(",")
        self.take(")")
        return found


@dataclass
class TraceEvent:
    """One timepoint of a ``.log`` trace."""

    ts: int
    action: str
    kind: str
    logged: dict[str, Any]
    scope: dict[str, Any] = field(default_factory=dict)
    request_context: dict[str, Any] = field(default_factory=dict)
    entities: dict[str, dict[str, Any]] = field(default_factory=dict)


def parse_trace(text: str) -> list[TraceEvent]:
    """A ``.log`` trace, one event per non-blank line."""
    events: list[TraceEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        reader = _Reader(line)
        reader.take("@")
        ts = int(reader.text[reader.at :].split(None, 1)[0])
        reader.at += len(str(ts))
        scope: dict[str, Any] = {}
        entities: dict[str, dict[str, Any]] = {}
        request_context: dict[str, Any] = {}
        if reader.startswith("scope("):
            reader.take("scope(")
            scope = reader.args()
        if reader.startswith("entities("):
            reader.take("entities(")
            entities = reader.entities()
        if reader.startswith("request_context("):
            reader.take("request_context(")
            request_context = reader.args()
        head = reader.entity_head()
        reader.take("(")
        logged = reader.args()
        events.append(TraceEvent(ts, head[0], head[1], logged, scope, request_context, entities))
    return events


def plain(value: Any) -> Any:
    """A trace value as the Shield reads it: an entity its uid, a decimal its text."""
    if isinstance(value, EntityRef):
        return value.uid
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    if isinstance(value, Dec):
        return str(value)
    return value


def literal(value: Any) -> str:
    """A value in Dogwood's trace format."""
    if isinstance(value, EntityRef):
        return value.uid
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Dec):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
        return f'"{escaped}"'
    if isinstance(value, dict):
        for key in value:
            if not _IDENT.fullmatch(key):
                raise CaseError(f"the field name {key!r} is not one a trace can carry")
        return "{ " + ", ".join(f"{k}: {literal(v)}" for k, v in value.items()) + " }"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(literal(v) for v in value) + "]"
    raise CaseError(f"{value!r} is not a value a trace can carry")


# -- a case and its two answers ---------------------------------------------------------------


@dataclass
class Case:
    """A policy set, its schemas, a trace, and what the Shield decided at its requests."""

    name: str
    policies: str
    schema: str
    trace: str
    event_schema: str | None = None
    #: The Shield's verdict at each request it was asked to compare, by timestamp.
    shield: dict[int, bool] = field(default_factory=dict)
    #: The verdicts Dogwood publishes beside an example (expected.out), by timestamp.
    published: dict[int, bool] | None = None

    def write(self, root: Path) -> Path:
        where = root / self.name
        where.mkdir(parents=True, exist_ok=True)
        (where / "policy.dw").write_text(self.policies)
        (where / "schema.cedarschema").write_text(self.schema)
        (where / "trace.log").write_text(self.trace)
        if self.event_schema is not None:
            (where / "events.dwschema").write_text(self.event_schema)
        (where / "shield.json").write_text(json.dumps({str(k): v for k, v in self.shield.items()}, indent=2) + "\n")
        return where


def say(allowed: bool) -> str:
    return "ALLOW" if allowed else "DENY"


def disagreements(case: Case, reference: dict[int, bool], whose: str) -> list[str]:
    """The sentences for each request where the reference and the Shield differ."""
    said: list[str] = []
    for ts, allowed in sorted(case.shield.items()):
        if ts not in reference:
            said.append(f"{case.name}: at @{ts} {whose} gives no verdict, the Shield says {say(allowed)}")
        elif reference[ts] != allowed:
            said.append(f"{case.name}: at @{ts} {whose} says {say(reference[ts])}, the Shield says {say(allowed)}")
    return said


def run_dogwood(binary: str, case: Case, where: Path) -> dict[int, bool]:
    """Dogwood's verdict at each request of the case's trace, by timestamp."""
    command = [
        binary,
        "replay",
        str(where / "policy.dw"),
        "--policy-schema",
        str(where / "schema.cedarschema"),
        "--trace",
        str(where / "trace.log"),
        "--format",
        "json",
    ]
    if case.event_schema is not None:
        command += ["--event-schema", str(where / "events.dwschema")]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        said = (done.stdout + done.stderr).strip().replace("\n", " ")
        raise CaseError(f"{case.name}: Dogwood refuses the case (exit {done.returncode}): {said[:600]}")
    report = json.loads(done.stdout)
    return {int(v["timestamp"]): v["verdict"] == "allow" for v in report["verdicts"]}


# -- Dogwood's published examples --------------------------------------------------------------

_SKIPPED_FILES = {
    "macros.dw": "macros, which the Shield does not read",
    "providers.json": "information providers, which the Shield has none of",
    "requires-experimental-arithmetic": "Dogwood's experimental arithmetic, off in the CLI built here",
}


def _expected(text: str) -> dict[int, bool]:
    found: dict[int, bool] = {}
    for line in text.splitlines():
        hit = re.match(r"@(-?\d+) \(time point \d+\): (ALLOW|DENY)", line.strip())
        if hit:
            found[int(hit.group(1))] = hit.group(2) == "ALLOW"
    return found


def example_case(where: Path) -> Case | str:
    """A published example as a case, or the sentence saying why it is skipped."""
    for name, why in _SKIPPED_FILES.items():
        if (where / name).exists():
            return f"it uses {why}"
    event_schema = None
    for name in ("events.dwschema", "event.dwschema"):
        if (where / name).exists():
            event_schema = (where / name).read_text()
    pinned = True
    if event_schema is not None:
        kinds = set(re.findall(r"event\s*<\w+>::(\w+)", event_schema))
        if not kinds <= set(KINDS):
            return f"its event schema declares the kinds {sorted(kinds - set(KINDS))}, which the Shield does not keep"
        pins = re.findall(r"\bpin\s+([\w.]+)\s*:", event_schema)
        if set(pins) - {"callerPrincipal"}:
            return f"its event schema pins {sorted(set(pins) - {'callerPrincipal'})}, which the Shield does not key on"
        pinned = bool(pins)
    policies = (where / "policy.dw").read_text()
    try:
        parsed = parse_set(policies)
    except DogwoodRefused as refused:
        return f"the Shield refuses it: {refused}"
    said = cedar_problem(parsed.lowered)
    if said is not None:
        return f"the Shield refuses it: Cedar refuses its lowering ({said.splitlines()[0]})"
    text = (where / "trace.log").read_text()
    events = parse_trace(text)
    shield: dict[int, bool] = {}
    history: list[Event] = []
    for n, event in enumerate(events):
        principal = plain(event.logged.get("callerPrincipal", event.scope.get("principal")))
        resource = plain(event.logged.get("callerResource", event.scope.get("resource")))
        at = T0 + timedelta(seconds=event.ts)
        if event.kind == "request":
            scope_principal = plain(event.scope.get("principal", principal))
            call = CedarCall(
                principal=scope_principal,
                action=event.action,
                resource=plain(event.scope.get("resource", resource)),
                context=plain(event.request_context),
                principal_attrs=plain(event.entities.get(scope_principal, {})),
            )
            seen = [e for e in history if e.principal == scope_principal] if pinned else history
            shield[event.ts] = evaluate(parsed, call, seen, at).allowed
        history.append(
            Event(
                kind=event.kind,  # type: ignore[arg-type]
                action=event.action,
                principal=str(principal),
                resource=str(resource),
                at=at,
                key=str(plain(event.logged.get("requestId", f"e{n}"))),
                input=plain(event.logged.get("input", {})),
                output=plain(event.logged.get("output", {})),
            )
        )
    published = _expected((where / "expected.out").read_text()) if (where / "expected.out").exists() else None
    return Case(
        name=f"dogwood/{where.name}",
        policies=policies,
        schema=(where / "schema.cedarschema").read_text(),
        trace=text,
        event_schema=event_schema,
        shield=shield,
        published=published,
    )


def example_cases(src: Path) -> tuple[list[Case], list[str]]:
    """The published examples a trace replays, and a sentence for each one skipped."""
    root = src / "dogwood-docs" / "examples"
    if not root.is_dir():
        raise CaseError(f"{src} is not a Dogwood checkout: it has no dogwood-docs/examples")
    cases: list[Case] = []
    skipped: list[str] = []
    for where in sorted(p for p in root.iterdir() if (p / "trace.log").exists()):
        found = example_case(where)
        if isinstance(found, str):
            skipped.append(f"dogwood/{where.name}: skipped, {found}")
        else:
            cases.append(found)
    return cases, skipped


# -- sessions played as the Shield keeps them --------------------------------------------------


@dataclass(frozen=True)
class Step:
    """One request of a session: when, which action, its input, and its output once it completes."""

    t: int
    action: str
    input: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)


def _cedar_type(value: Any, where: str) -> str:
    if isinstance(value, bool):
        return "Bool"
    if isinstance(value, int):
        return "Long"
    if isinstance(value, str):
        return "String"
    if isinstance(value, dict):
        return _record(value, where)
    raise CaseError(f"{where}: {value!r} has no Cedar type here")


def _record(fields: dict[str, Any], where: str) -> str:
    return "{ " + ", ".join(f"{k}: {_cedar_type(v, f'{where}.{k}')}" for k, v in fields.items()) + " }"


def _split(uid: str) -> tuple[str, str]:
    """``Ns::Type::"id"`` as its namespace and its type."""
    head = uid.partition('::"')[0]
    namespace, _, kind = head.rpartition("::")
    return namespace, kind


def session_schema(name: str, policies: str, steps: Sequence[Step], principal: str, resource: str) -> str:
    """A Cedar schema for a session: its entity types, and each action's input and output records."""
    actions: dict[str, dict[str, dict[str, Any]]] = {}
    for uid in re.findall(r'[A-Za-z_][\w:]*::Action::"[^"]*"', policies):
        actions.setdefault(normalize_uid(uid), {})
    for step in steps:
        shape = actions.setdefault(step.action, {})
        for part, given in (("input", step.input), ("output", step.output)):
            if not given:
                continue
            if part in shape and shape[part].keys() != given.keys():
                raise CaseError(f"{name}: {step.action} is called with different {part} fields")
            shape[part] = given
    entity_types = sorted({_split(principal), _split(resource)})
    namespaces = sorted({ns for ns, _ in entity_types} | {_split(a)[0] for a in actions})
    blocks: list[str] = []
    for ns in namespaces:
        lines = [f"  entity {kind};" for space, kind in entity_types if space == ns]
        for uid, shape in sorted(actions.items()):
            if _split(uid)[0] != ns:
                continue
            context = []
            if shape.get("input"):
                context.append(f"input: {_record(shape['input'], f'{name} {uid} input')}")
            context.append(f"output?: {_record(shape.get('output', {}), f'{name} {uid} output')}")
            ident = json.dumps(json.loads(uid.partition("::Action::")[2]))
            lines.append(
                f"  action {ident} appliesTo {{\n"
                f"    principal: [{'::'.join(_split(principal))}],\n"
                f"    resource: [{'::'.join(_split(resource))}],\n"
                f"    context: {{ {', '.join(context)} }}\n  }};"
            )
        blocks.append(f"namespace {ns} {{\n" + "\n".join(lines) + "\n}\n")
    return "\n".join(blocks)


def _seconds(at: datetime, name: str) -> int:
    seconds = (at - T0).total_seconds()
    if not seconds.is_integer():
        raise CaseError(f"{name}: two events share a second; give the steps distinct times")
    return int(seconds)


def _trace_line(
    ts: int, kind: str, action: str, principal: str, resource: str, key: str, inputs: dict, output: dict
) -> str:
    scope = f"scope(principal: {principal}, resource: {resource})"
    logged = []
    if inputs:
        logged.append(f"input: {literal(inputs)}")
    if output and kind == "response":
        logged.append(f"output: {literal(output)}")
    logged += [f"eventPrincipal: {principal}", f"eventResource: {resource}", f"requestId: {literal(key)}"]
    context = f" request_context(input: {literal(inputs)})" if inputs and kind == "request" else ""
    return f"@{ts} {scope}{context} {action}::{kind}({', '.join(logged)})"


def session_cases(
    name: str,
    policies: str,
    steps: Sequence[Step],
    principal: str = 'Datalayer::User::"alice"',
    resource: str = 'Datalayer::Runtime::"r1"',
) -> list[Case]:
    """One case per request of a session: the Shield's history before it, then the request."""
    parsed = parse_set(policies)
    schema = session_schema(name, policies, steps, principal, resource)
    log = EventLog()
    cases: list[Case] = []
    last = -1
    for n, step in enumerate(steps, start=1):
        if step.t <= last:
            raise CaseError(f"{name}: step {n} is not after the one before it (a response takes a second)")
        key = f"r{n}"
        call = CedarCall(
            principal=principal, action=step.action, resource=resource, context={"input": dict(step.input)}
        )
        at = T0 + timedelta(seconds=step.t)
        allowed = evaluate(parsed, call, log.events, at).allowed
        lines = [
            _trace_line(_seconds(e.at, name), e.kind, e.action, e.principal, e.resource, e.key, e.input, e.output)
            for e in log.events
        ]
        lines.append(_trace_line(step.t, "request", step.action, principal, resource, key, step.input, {}))
        cases.append(
            Case(
                name=f"{name}/{n:02d}",
                policies=policies,
                schema=schema,
                trace="\n".join(lines) + "\n",
                event_schema=AGENTCORE_EVENT_SCHEMA,
                shield={step.t: allowed},
            )
        )
        log.decided(key, call, allowed=allowed, at=at)
        last = step.t
        if allowed:
            log.ended(key, at + timedelta(seconds=1), ok=True, output=dict(step.output))
            last = step.t + 1
    return cases


# -- the agentspecs organization examples (the policies' dogwood-* specs) ----------------------

PAY = 'Datalayer::Action::"payments___pay"'
APPROVE_INVOICE = 'Datalayer::Action::"payments___approve"'
TRANSFER = 'Datalayer::Action::"bank___transfer"'
MODEL = 'Datalayer::Action::"shield___model"'
APPLY_FIX = 'Datalayer::Action::"aws_account___apply_fix"'
APPROVE_RECOMMENDATION = 'Datalayer::Action::"aws_account___approve_recommendation"'

APPROVAL_BEFORE_PAYMENT = """\
@id("everything but a payment")
permit (principal, action, resource)
unless { action == Datalayer::Action::"payments___pay" };

@id("a payment needs its invoice approved within the hour")
permit (principal, action == Datalayer::Action::"payments___pay", resource)
when temporal {
    formerly within 1h Datalayer::Action::"payments___approve"::response{
        eventResource: resource,
        input.invoice: context.input.invoice
    }
};
"""

APPROVAL_BEFORE_ACCOUNT_CHANGE = """\
@id("everything but an account change")
permit (principal, action, resource)
unless { action == Datalayer::Action::"aws_account___apply_fix" };

@id("an account change needs its recommendation approved within the hour")
permit (principal, action == Datalayer::Action::"aws_account___apply_fix", resource)
when temporal {
    formerly within 1h Datalayer::Action::"aws_account___approve_recommendation"::response{
        eventResource: resource,
        input.recommendation: context.input.recommendation
    }
};
"""

DISTINCT_PAYEES = """\
permit (principal, action, resource);

@id("at most three payees a day")
forbid (principal, action == Datalayer::Action::"bank___transfer", resource)
when temporal {
    exists (n: Long).
        (count for (p: String).
            where (formerly within 24h Datalayer::Action::"bank___transfer"::request{ eventResource: resource, input.payee: p })) == n
        && n > 3
};
"""

RUNNING_TOTAL = """\
permit (principal, action, resource);

@id("payments total at most 500000 cents a day")
forbid (principal, action == Datalayer::Action::"payments___pay", resource)
when temporal {
    exists (total: Long).
        (sum amount for (amount: Long), (t: Timepoint).
            where (formerly within 24h (Datalayer::Action::"payments___pay"::request{ eventResource: resource, input.amountCents: amount } && tp(t)))) == total
        && total > 500000
};
"""

SPEND_PER_SESSION = """\
permit (principal, action, resource);

@id("spend")
forbid (principal, action == Datalayer::Action::"shield___model", resource)
when temporal {
    exists (total: Long).
        (sum v for (v: Long), (t: Timepoint).
            where (formerly within 24h (Datalayer::Action::"shield___model"::request{ eventResource: resource, input.credits: v } && tp(t)))) == total
        && total > 1000
};
"""

TRANSFERS_PER_HOUR = """\
permit (principal, action, resource);

@id("at most five transfers an hour")
forbid (principal, action == Datalayer::Action::"bank___transfer", resource)
when temporal {
    exists (n: Long).
        (count for (t: Timepoint).
            where (formerly within 1h (Datalayer::Action::"bank___transfer"::request{ eventResource: resource } && tp(t)))) == n
        && n > 5
};
"""


def agentspecs_cases() -> list[Case]:
    """The six organization examples, each played as a session."""

    def pay(t: int, invoice: str) -> Step:
        return Step(t, PAY, {"invoice": invoice})

    def transfer(t: int, payee: str) -> Step:
        return Step(t, TRANSFER, {"payee": payee})

    cases = session_cases(
        "agentspecs/approval-before-payment",
        APPROVAL_BEFORE_PAYMENT,
        [
            pay(0, "inv-1"),
            Step(10, APPROVE_INVOICE, {"invoice": "inv-1"}),
            pay(20, "inv-1"),
            pay(30, "inv-2"),
            pay(11 + 3600, "inv-1"),  # the approval's response exactly an hour back: in
            pay(11 + 3602, "inv-1"),  # two seconds further: out
        ],
    )

    def apply_fix(t: int, recommendation: str) -> Step:
        return Step(t, APPLY_FIX, {"recommendation": recommendation})

    cases += session_cases(
        "agentspecs/approval-before-account-change",
        APPROVAL_BEFORE_ACCOUNT_CHANGE,
        [
            apply_fix(0, "rec-1"),  # not approved: refused
            Step(10, APPROVE_RECOMMENDATION, {"recommendation": "rec-1"}),
            apply_fix(20, "rec-1"),  # the same recommendation approved: permitted
            apply_fix(30, "rec-2"),  # another recommendation: refused
            apply_fix(11 + 3600, "rec-1"),  # the approval's response exactly an hour back: in
            apply_fix(11 + 7200, "rec-1"),  # two hours after it: refused
        ],
    )
    cases += session_cases(
        "agentspecs/distinct-payees",
        DISTINCT_PAYEES,
        [
            transfer(0, "ann"),
            transfer(10, "bob"),
            transfer(20, "ann"),
            transfer(30, "cy"),
            transfer(40, "dan"),
            transfer(50, "ann"),
            transfer(86421, "fay"),
        ],
    )
    cases += session_cases(
        "agentspecs/running-total",
        RUNNING_TOTAL,
        [
            Step(0, PAY, {"amountCents": 200000}),
            Step(10, PAY, {"amountCents": 200000}),
            Step(20, PAY, {"amountCents": 100000}),
            Step(30, PAY, {"amountCents": 1}),
            Step(86415, PAY, {"amountCents": 400000}),
        ],
    )
    cases += session_cases(
        "agentspecs/spend-per-session",
        SPEND_PER_SESSION,
        [Step(t, MODEL, {"credits": c}) for t, c in ((0, 400), (10, 400), (20, 200), (30, 1))],
    )
    cases += session_cases(
        "agentspecs/transfers-per-hour",
        TRANSFERS_PER_HOUR,
        [transfer(t, "ann") for t in (0, 10, 20, 30, 40, 50, 3605)],
    )
    return cases


# -- the sessions of the Shield's tests (tests/test_temporal.py), in AgentCore's names -------

GW = 'AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:111122223333:gateway/insurance-gw-a1b2c3d4e5"'
USER = 'AgentCore::OAuthUser::"alice"'
DISBURSE = 'AgentCore::Action::"InsuranceAPI___disburse_payment"'
APPROVE = 'AgentCore::Action::"InsuranceAPI___approve_claim"'
STATUS = 'AgentCore::Action::"InsuranceAPI___get_claim_status"'
PERMIT_APPROVE = f"permit (principal, action == {APPROVE}, resource == {GW});\n"
PERMIT_STATUS = f"permit (principal, action == {STATUS}, resource == {GW});\n"
PERMIT_DISBURSE = f"permit (principal, action == {DISBURSE}, resource == {GW});\n"


def test_cases() -> list[Case]:
    """The sessions ``tests/test_temporal.py`` decides, as Dogwood cases."""

    def agentcore(name: str, text: str, steps: Sequence[Step]) -> list[Case]:
        return session_cases(f"tests/{name}", text, steps, principal=USER, resource=GW)

    approval = (
        PERMIT_APPROVE
        + f"""permit (principal, action == {DISBURSE}, resource == {GW})
when temporal {{
    formerly within 1h {APPROVE}::response{{
        eventResource: resource,
        output.claimId: context.input.claimId
    }}
}};"""
    )
    approve_c1 = Step(0, APPROVE, {"claimId": "c1"}, {"claimId": "c1"})
    cases = agentcore("approval-before-disbursal-none", approval, [Step(0, DISBURSE, {"claimId": "c1"})])
    cases += agentcore("approval-before-disbursal-same", approval, [approve_c1, Step(10, DISBURSE, {"claimId": "c1"})])
    cases += agentcore("approval-before-disbursal-other", approval, [approve_c1, Step(10, DISBURSE, {"claimId": "c2"})])

    lapses = (
        PERMIT_STATUS
        + f"""permit (principal, action == {APPROVE}, resource == {GW})
when temporal {{ formerly within 5m {STATUS}::response{{ eventResource: resource }} }};"""
    )
    cases += agentcore(
        "prerequisite-lapses",
        lapses,
        [Step(0, APPROVE), Step(10, STATUS), Step(20, APPROVE), Step(11 + 300, APPROVE), Step(11 + 302, APPROVE)],
    )

    cap = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{
    exists (n: Long).
        (count for (t: Timepoint).
            where (formerly within 5m ({DISBURSE}::request{{ eventResource: resource }} && tp(t)))) == n
        && n > 3
}};"""
    )
    cases += agentcore("three-disbursements", cap, [Step(i * 10, DISBURSE) for i in range(5)] + [Step(321, DISBURSE)])

    total = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{
    exists (total: Long).
        (sum amt for (amt: Long), (t: Timepoint).
            where (formerly within 5m ({DISBURSE}::request{{ eventResource: resource, input.amountCents: amt }} && tp(t)))) == total
        && total >= 300000
}};"""
    )
    cases += agentcore("running-total", total, [Step(t, DISBURSE, {"amountCents": 100000}) for t in (0, 10, 20)])

    once = (
        PERMIT_APPROVE
        + f"""permit (principal, action == {DISBURSE}, resource == {GW})
when temporal {{
    !{DISBURSE}::response{{ eventResource: resource }}
    since within 1h {APPROVE}::response{{ eventResource: resource }}
}};"""
    )
    cases += agentcore(
        "one-disbursement-per-approval",
        once,
        [Step(0, APPROVE), Step(10, DISBURSE), Step(20, DISBURSE), Step(30, APPROVE), Step(40, DISBURSE)],
    )

    cool = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{ formerly within 1m {DISBURSE}::response{{ eventResource: resource }} }};"""
    )
    cases += agentcore("cool-down", cool, [Step(0, DISBURSE), Step(30, DISBURSE), Step(62, DISBURSE)])

    itself = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{ formerly within 1m {DISBURSE}::request{{ eventResource: resource }} }};"""
    )
    cases += agentcore("self-reference", itself, [Step(0, DISBURSE)])

    cut = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{ formerly within 3m {APPROVE}::error{{ eventResource: resource }} }};"""
    )
    cases += agentcore(
        "cut-off-after-a-denial",
        cut,
        [Step(0, DISBURSE), Step(10, APPROVE), Step(20, DISBURSE), Step(10 + 181, DISBURSE)],
    )

    overrides = f"""permit (principal, action, resource);
@id("never disburse")
forbid (principal, action == {DISBURSE}, resource);"""
    cases += agentcore("forbid-overrides", overrides, [Step(0, APPROVE), Step(5, DISBURSE)])

    previous = (
        PERMIT_STATUS
        + f"""permit (principal, action == {APPROVE}, resource == {GW})
when temporal {{ previous within 1m {STATUS}::response{{ eventResource: resource }} }};"""
    )
    cases += agentcore(
        "previous-status",
        previous,
        [
            Step(0, APPROVE),
            Step(10, STATUS),
            Step(20, APPROVE),
            Step(30, APPROVE),
            Step(40, STATUS),
            Step(200, APPROVE),
        ],
    )

    payees = f"""permit (principal, action, resource);
@id("at most two payees an hour")
forbid (principal, action == {TRANSFER}, resource)
when temporal {{
    exists (n: Long).
        (count for (p: String). where (formerly within 1h {TRANSFER}::request{{ eventResource: resource, input.payee: p }})) == n
        && n > 2
}};"""
    cases += session_cases(
        "tests/distinct-payees-an-hour",
        payees,
        [Step(t, TRANSFER, {"payee": p}) for t, p in ((0, "ann"), (10, "bob"), (20, "ann"), (30, "cy"), (3611, "cy"))],
    )
    return cases


# -- the run -----------------------------------------------------------------------------------


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dogwood", default="dogwood", help="the dogwood binary (default: dogwood on PATH)")
    parser.add_argument("--dogwood-src", type=Path, help="a Dogwood checkout, for its published examples")
    parser.add_argument("--out", type=Path, help="where the cases are written (default: a temporary directory)")
    parser.add_argument(
        "--dry-run", action="store_true", help="write the cases and run the Shield's side alone (no dogwood binary)"
    )
    parser.add_argument("--print-cases", action="store_true", help="list the cases and the Shield's verdicts")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if cedar_problem("permit (principal, action, resource);") == "unavailable":
        print("cedarpy is not installed: pip install '.[cedar]' (the Shield's side cannot decide)", file=sys.stderr)
        return 2
    if not args.dry_run and shutil.which(args.dogwood) is None:
        print(f"the dogwood binary {args.dogwood!r} is not found (build it, or pass --dry-run)", file=sys.stderr)
        return 2

    cases: list[Case] = []
    skipped: list[str] = []
    if args.dogwood_src is not None:
        cases, skipped = example_cases(args.dogwood_src)
    cases += agentspecs_cases() + test_cases()

    out = args.out or Path(tempfile.mkdtemp(prefix="dogwood-conformance-"))
    failures: list[str] = []
    compared = 0
    for case in cases:
        where = case.write(out)
        if args.print_cases:
            verdicts = ", ".join(f"@{ts} {say(a)}" for ts, a in sorted(case.shield.items()))
            print(f"{case.name}: {verdicts}")
        if args.dry_run:
            if case.published is not None:
                failures += disagreements(case, case.published, "Dogwood's expected.out")
            compared += len(case.shield)
            continue
        try:
            reference = run_dogwood(args.dogwood, case, where)
        except CaseError as error:
            failures.append(str(error))
            continue
        failures += disagreements(case, reference, "Dogwood")
        compared += len(case.shield)

    for line in skipped:
        print(line)
    side = "the Shield's side alone (dry run)" if args.dry_run else "the Shield against Dogwood"
    print(f"{len(cases)} cases, {compared} decisions, {side}; {len(skipped)} examples skipped; inputs in {out}")
    for line in failures:
        print(f"DISAGREE {line}", file=sys.stderr)
    if failures:
        print(f"{len(failures)} disagreements", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
