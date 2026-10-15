# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Conformance: a standard's controls answered from the Shield's evidence (SHIELD §6.9, SH-61).

A standard is a spec of agentspecs' ``standards/`` catalogue (``aiuc-1``
first, decision 15; ``iso-42001`` through its crosswalk, SH-66). For each
control the **evidence map** (:mod:`agent_shield.conformance.map`) says which
evidence kinds it takes, which **collectors** read that evidence
(:mod:`agent_shield.conformance.collect` — the policy document in force and
its version, the record's rows by class and decision, the OTEL counts, the
drills, the Validate gates and benchmarks, the screens and notices, the
organization's signed documents, a third party's recorded reports, and the
facts the host asserts of its platform) and the **status rule** that gives
the control one of five statuses, honest by construction:

- ``met`` — *met by evidence*: every piece the rule asks for was collected,
  and is attached;
- ``partly`` — *partly met*: what is there is attached and what is missing
  is named;
- ``organizations`` — *the organization's*: a document a person writes and
  signs; never auto-met, met only once a signed, in-date document exists;
- ``third_party`` — *a third party's*: the standard's quarterly testing; met
  only while a report recorded within its cadence says it passed;
- ``not_applicable`` — with why (a control retired in the version in force,
  a capability the agent lacks).

:func:`assess` runs the map over :class:`Inputs` and answers an
:class:`Assessment` — one :class:`ControlStatus` per control, each machine-
readable (:meth:`ControlStatus.to_json`: the control, its status, the
evidence with its links and when it was collected, what is missing, the
crosswalks, the cadence clock). The package never reads a network or a
store: the host collects the inputs (agent-runtimes, or ai-agents for a
deployment) and this module decides.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from agent_shield.policy import Policy

Status = Literal["met", "partly", "organizations", "third_party", "not_applicable"]

#: Each status in the words of §6.9.
STATUS_WORDS: dict[str, str] = {
    "met": "met by evidence",
    "partly": "partly met",
    "organizations": "the organization's",
    "third_party": "a third party's",
    "not_applicable": "not applicable",
}

#: The statuses in the order a report lists them: what needs attention first.
STATUS_ORDER: tuple[str, ...] = ("partly", "organizations", "third_party", "met", "not_applicable")

EvidenceKind = Literal["documentation", "config", "logs", "evals", "report", "demonstration"]


class ConformanceError(ValueError):
    """What cannot be assessed, said in a sentence."""


@dataclass(frozen=True)
class Evidence:
    """One piece of evidence a collector attached to a control."""

    kind: str
    what: str
    collected_at: str
    link: str | None = None
    #: The standard's evidence item it answers (``D003.1``), when it answers one.
    item: str | None = None
    detail: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "what": self.what,
            "collected_at": self.collected_at,
            "link": self.link,
            "item": self.item,
            "detail": dict(self.detail),
        }


@dataclass(frozen=True)
class Document:
    """A document of the Studio a person wrote for a control (SH-64)."""

    control: str
    title: str
    owner: str
    version: int
    review_on: str | None
    signed_by: str | None = None
    signed_on: str | None = None
    link: str | None = None
    #: The ``{{ field }}`` names still unfilled: a document with any is not signable.
    unfilled: Sequence[str] = ()

    @property
    def signed(self) -> bool:
        return bool(self.signed_by and self.signed_on) and not self.unfilled

    def in_date(self, now: datetime) -> bool:
        if not self.review_on:
            return False
        return _day(self.review_on) >= now.date()


@dataclass(frozen=True)
class ThirdPartyReport:
    """A third party's evaluation report, recorded with its date (the quarterly clock starts there)."""

    control: str
    by: str
    on: str
    outcome: Literal["passed", "failed", "partial"]
    link: str | None = None
    summary: str = ""


@dataclass(frozen=True)
class DrillResult:
    """One of SH-37's drills, as its report records it."""

    id: str
    title: str
    outcome: Literal["refused", "allowed", "failed", "not_run"]
    at: str
    where: str = ""
    says: str = ""
    link: str | None = None


@dataclass(frozen=True)
class Fact:
    """A fact the host asserts of its platform, with where it was proved.

    The map takes a fact as evidence only when ``holds`` is true; a host that
    cannot vouch for one leaves it out, and the control is partly met with
    the fact named as missing.
    """

    holds: bool
    says: str
    proved: str = ""
    link: str | None = None


@dataclass
class Inputs:
    """Everything the map reads, collected by the host."""

    #: The policies in force, as the Shield decides with them (every scope present).
    policies: Sequence[Policy] = ()
    #: The record's entries for the deployment: ``{"kind", "summary", "payload", "at", "session"}``.
    record: Sequence[Mapping[str, Any]] = ()
    #: The OTEL counts of the period, by instrument (``shield.decisions`` …).
    counts: Mapping[str, int] = field(default_factory=dict)
    drills: Sequence[DrillResult] = ()
    #: The Validate gate of the version: ``gate`` (passed, failed, stale, none), ``pass_rate``,
    #: ``min_pass_rate``, ``safety`` ({held, failed, total} or None), ``version``, ``at``.
    validation: Mapping[str, Any] | None = None
    #: Benchmarks run on the agent: ``{"name", "at", "score", "link"}``.
    benchmarks: Sequence[Mapping[str, Any]] = ()
    documents: Mapping[str, Document] = field(default_factory=dict)
    third_party: Mapping[str, ThirdPartyReport] = field(default_factory=dict)
    facts: Mapping[str, Fact] = field(default_factory=dict)
    #: Screens and notices, by name: a link to where each is seen.
    demonstrations: Mapping[str, str] = field(default_factory=dict)
    #: The harness's register entry, when the agent runs on one.
    harness: Mapping[str, Any] | None = None
    #: The period the logs cover.
    period_days: int = 90
    #: Where the evidence is read: links the report attaches.
    links: Mapping[str, str] = field(default_factory=dict)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Cadence:
    """A control's clock: how often, when last, when next, whether it has run out."""

    months: int | None
    last: str | None
    next_due: str | None
    overdue: bool

    def to_json(self) -> dict[str, Any]:
        return {"months": self.months, "last": self.last, "next_due": self.next_due, "overdue": self.overdue}


@dataclass
class ControlStatus:
    """One control's answer."""

    control: str
    title: str
    domain: str
    status: str
    reason: str
    evidence: list[Evidence]
    missing: list[str]
    crosswalks: Mapping[str, Sequence[str]]
    cadence: Cadence
    mandatory: bool
    retired: bool
    collected_at: str
    url: str = ""

    @property
    def words(self) -> str:
        return STATUS_WORDS[self.status]

    @property
    def gap(self) -> bool:
        """Whether a mandatory control is not met by evidence: the report's gap list."""
        return self.mandatory and self.status != "met"

    def to_json(self) -> dict[str, Any]:
        return {
            "control": self.control,
            "title": self.title,
            "domain": self.domain,
            "status": self.status,
            "status_words": self.words,
            "reason": self.reason,
            "mandatory": self.mandatory,
            "retired": self.retired,
            "gap": self.gap,
            "evidence": [e.to_json() for e in self.evidence],
            "missing": list(self.missing),
            "crosswalks": {k: list(v) for k, v in self.crosswalks.items()},
            "cadence": self.cadence.to_json(),
            "collected_at": self.collected_at,
            "url": self.url,
        }


@dataclass
class Assessment:
    """Every control of a standard, answered."""

    standard: str
    standard_name: str
    version: str
    controls: list[ControlStatus]
    assessed_at: str
    version_notice: str | None = None

    def by_status(self) -> dict[str, int]:
        found = dict.fromkeys(STATUS_ORDER, 0)
        for control in self.controls:
            found[control.status] += 1
        return found

    @property
    def gaps(self) -> list[ControlStatus]:
        return [c for c in self.controls if c.gap]

    def control(self, control_id: str) -> ControlStatus:
        for found in self.controls:
            if found.control == control_id:
                return found
        raise ConformanceError(f"{self.standard_name} has no control {control_id!r}")

    def to_json(self) -> dict[str, Any]:
        return {
            "standard": self.standard,
            "standard_name": self.standard_name,
            "version": self.version,
            "assessed_at": self.assessed_at,
            "version_notice": self.version_notice,
            "by_status": self.by_status(),
            "gaps": [c.control for c in self.gaps],
            "controls": [c.to_json() for c in self.controls],
            "disclaimer": DISCLAIMER,
        }


#: The sentence on every report's first page (§6.9): the Shield evidences, it never certifies.
DISCLAIMER = (
    "This report evidences: it collects, for each control of the standard, what Datalayer's Shield can "
    "show of this deployment, says what is met by evidence, what is partly met and what is missing, what "
    "only the organization can write, and what only a third party can test. It does not certify. A "
    "certification is an accredited auditor's, against a Statement of Applicability, and nothing here "
    "replaces it."
)


def _day(value: str):
    return (
        datetime.fromisoformat(value.replace("Z", "+00:00")).date()
        if "T" in value
        else datetime.fromisoformat(value).date()
    )


def _months_later(day: str, months: int) -> str:
    """The same day of the month, ``months`` later (30-day months, which is how the clocks read)."""
    return (_day(day) + timedelta(days=30 * months)).isoformat()


def cadence_of(months: int | None, last: str | None, now: datetime) -> Cadence:
    """A control's clock from its cadence and the last time it was demonstrated."""
    if months is None:
        return Cadence(months=None, last=last, next_due=None, overdue=False)
    if not last:
        return Cadence(months=months, last=None, next_due=None, overdue=False)
    next_due = _months_later(last, months)
    return Cadence(months=months, last=last, next_due=next_due, overdue=_day(next_due) < now.date())


def assess(standard: Any, inputs: Inputs) -> Assessment:
    """Every control of ``standard`` (an agentspecs ``StandardSpec``) answered from ``inputs``."""
    answered: list[ControlStatus] = []
    at = inputs.now.isoformat(timespec="seconds")
    mapped_to = getattr(standard, "maps_to", None)
    covering: Assessment | None = None
    if mapped_to:
        from agent_shield.conformance.map import covering_standard

        covering = assess(covering_standard(mapped_to), inputs)
    for control in standard.controls:
        answered.append(_answer(control, inputs, at, covering))
    notice = None
    try:
        from agentspecs.standards import version_notice

        notice = version_notice(standard, today=inputs.now.date())
    except ImportError:
        notice = None
    return Assessment(
        standard=standard.id,
        standard_name=standard.name,
        version=standard.version,
        controls=answered,
        assessed_at=at,
        version_notice=notice,
    )


def _answer(control: Any, inputs: Inputs, at: str, covering: Assessment | None) -> ControlStatus:
    from agent_shield.conformance.map import answer_covered, rule_for

    if control.retired:
        status, reason, evidence, missing, last = (
            "not_applicable",
            f"retired in {control.retired_in}: the standard folded it into another control",
            [],
            [],
            None,
        )
    elif control.covered_by is not None:
        status, reason, evidence, missing, last = answer_covered(control, covering, inputs)
    else:
        rule = rule_for(control.id)
        if rule is None:
            raise ConformanceError(
                f"the evidence map has no rule for {control.id}: every control is mapped before it is assessed"
            )
        status, reason, evidence, missing, last = rule(control, inputs)
    return ControlStatus(
        control=control.id,
        title=control.title,
        domain=control.domain,
        status=status,
        reason=reason,
        evidence=list(evidence),
        missing=list(missing),
        crosswalks=dict(control.crosswalks),
        cadence=cadence_of(control.cadence_months, last, inputs.now),
        mandatory=control.mandatory,
        retired=control.retired,
        collected_at=at,
        url=control.url,
    )


__all__ = [
    "DISCLAIMER",
    "STATUS_ORDER",
    "STATUS_WORDS",
    "Assessment",
    "Cadence",
    "ConformanceError",
    "ControlStatus",
    "Document",
    "DrillResult",
    "Evidence",
    "Fact",
    "Inputs",
    "Status",
    "ThirdPartyReport",
    "assess",
    "cadence_of",
]
