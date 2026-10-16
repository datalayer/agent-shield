# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Continuous conformance (SH-63): recomputed as the inputs change, a lapse raised as a notice.

The host recomputes an :class:`Assessment` on the events that already flow —
a policy replaced from IAM, a record row written, a drill report recorded, a
document signed or past its review — and keeps a :class:`Snapshot` of each
(one a day is enough for the line over time). :func:`lapses` compares the
new assessment with the previous one and says, control by control, what
lapsed: a cadence clock run out, a policy weakened below the organization's,
a drill that failed, a document past its review, a control that was met and
no longer is. Each lapse is a :class:`Notice` the host sends to the
organization's owners through the notifications it already sends.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_shield.conformance import Assessment, ControlStatus, Inputs
from agent_shield.conformance import collect as c
from agent_shield.policy import Policy, parse_policy

#: The kinds of lapse, each the ``kind`` of the notice it raises.
CLOCK_RUN_OUT = "conformance.clock_run_out"
POLICY_WEAKENED = "conformance.policy_weakened"
DRILL_FAILED = "conformance.drill_failed"
DOCUMENT_PAST_REVIEW = "conformance.document_past_review"
STATUS_DROPPED = "conformance.status_dropped"


@dataclass(frozen=True)
class Notice:
    """One lapse, for the organization's owners."""

    kind: str
    control: str | None
    title: str
    says: str

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "control": self.control, "title": self.title, "message": self.says}


@dataclass
class Snapshot:
    """What an assessment amounted to, kept for the line over time."""

    at: str
    standard: str
    version: str
    by_status: dict[str, int]
    gaps: list[str]
    mandatory: int
    met: int
    #: The policies the assessment decided with, by scope, as written: the next one reads whether they weakened.
    policies: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def of(cls, assessment: Assessment, inputs: Inputs | None = None) -> Snapshot:
        mandatory = [control for control in assessment.controls if control.mandatory]
        return cls(
            at=assessment.assessed_at,
            standard=assessment.standard,
            version=assessment.version,
            by_status=assessment.by_status(),
            gaps=[control.control for control in assessment.gaps],
            mandatory=len(mandatory),
            met=sum(1 for control in mandatory if control.status == "met"),
            policies={
                p.scope: p.model_dump(mode="json", exclude_none=True) for p in (inputs.policies if inputs else ())
            },
        )

    def policies_in_force(self) -> list[Policy]:
        return [parse_policy(document, f"snapshot {self.at}") for document in self.policies.values()]

    def to_json(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "standard": self.standard,
            "version": self.version,
            "by_status": dict(self.by_status),
            "gaps": list(self.gaps),
            "mandatory": self.mandatory,
            "met": self.met,
            "policies": {k: dict(v) for k, v in self.policies.items()},
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Snapshot:
        return cls(
            at=str(data["at"]),
            standard=str(data["standard"]),
            version=str(data["version"]),
            by_status=dict(data.get("by_status") or {}),
            gaps=list(data.get("gaps") or []),
            mandatory=int(data.get("mandatory") or 0),
            met=int(data.get("met") or 0),
            policies={str(k): dict(v) for k, v in (data.get("policies") or {}).items()},
        )


def lapses(
    previous: Assessment | None, current: Assessment, inputs: Inputs, previous_policies: Sequence[Policy] = ()
) -> list[Notice]:
    """What lapsed between two assessments, each a notice; empty when nothing did.

    ``previous_policies`` are the documents the previous assessment decided
    with (the snapshot keeps them): the organization's document permitting
    more than it did then is a lapse too.
    """
    notices: list[Notice] = []
    before: dict[str, ControlStatus] = {control.control: control for control in previous.controls} if previous else {}
    for control in current.controls:
        earlier = before.get(control.control)
        if control.cadence.overdue and not (earlier and earlier.cadence.overdue):
            notices.append(
                Notice(
                    CLOCK_RUN_OUT,
                    control.control,
                    f"{control.control}'s clock has run out",
                    f"{control.control} ({control.title}) was last demonstrated on {control.cadence.last}; its cadence of {control.cadence.months} months ran out on {control.cadence.next_due}.",
                )
            )
        if earlier and earlier.status == "met" and control.status != "met":
            notices.append(
                Notice(
                    STATUS_DROPPED,
                    control.control,
                    f"{control.control} is no longer met",
                    f"{control.control} ({control.title}) was met by evidence and is now {control.words}: "
                    + ("; ".join(control.missing) if control.missing else control.reason)
                    + ".",
                )
            )
    for sentence in c.policy_weakened(inputs):
        notices.append(
            Notice(POLICY_WEAKENED, None, "An application's rules permit more than the organization's", sentence + ".")
        )
    for sentence in c.organization_weakened(previous_policies, inputs):
        notices.append(
            Notice(POLICY_WEAKENED, None, "The organization's rules now permit more than before", sentence + ".")
        )
    for drill in c.failed_drills(inputs):
        notices.append(
            Notice(
                DRILL_FAILED,
                None,
                f"The drill {drill.title} did not hold",
                f"The drill {drill.title} ({drill.id}) {('allowed what it tried' if drill.outcome == 'allowed' else 'failed')} on {drill.at}{(': ' + drill.says) if drill.says else ''}.",
            )
        )
    for control_id, document in inputs.documents.items():
        if document.signed and not document.in_date(inputs.now):
            notices.append(
                Notice(
                    DOCUMENT_PAST_REVIEW,
                    control_id,
                    f"{document.title} is past its review",
                    f"{document.title} ({control_id}) was to be reviewed by {document.review_on}; until it is reviewed and signed again, {control_id} is the organization's.",
                )
            )
    return notices


def notice_keys(notices: Sequence[Notice], day: str) -> list[str]:
    """One key per notice and day, so an owner is told once of each lapse a day: a notice of a control
    by its control, one of a rule or a drill by a digest of its words."""
    import hashlib

    return [
        f"{notice.kind}:{notice.control or hashlib.sha256((notice.title + notice.says).encode('utf-8')).hexdigest()[:12]}:{day}"
        for notice in notices
    ]


@dataclass
class Trend:
    """The line over time: snapshots, one per day at most, oldest first."""

    snapshots: list[Snapshot] = field(default_factory=list)

    def add(self, snapshot: Snapshot) -> None:
        """Keep one snapshot a day: a later one of the same day replaces the earlier."""
        day = snapshot.at[:10]
        self.snapshots = [s for s in self.snapshots if s.at[:10] != day]
        self.snapshots.append(snapshot)
        self.snapshots.sort(key=lambda s: s.at)

    def weekly(self) -> list[Snapshot]:
        """The last snapshot of each ISO week: a point per week for the organization's page."""
        from datetime import date

        by_week: dict[tuple[int, int], Snapshot] = {}
        for snapshot in self.snapshots:
            year, week, _ = date.fromisoformat(snapshot.at[:10]).isocalendar()
            by_week[(year, week)] = snapshot
        return [by_week[key] for key in sorted(by_week)]


__all__ = [
    "CLOCK_RUN_OUT",
    "DOCUMENT_PAST_REVIEW",
    "DRILL_FAILED",
    "POLICY_WEAKENED",
    "STATUS_DROPPED",
    "Notice",
    "Snapshot",
    "Trend",
    "lapses",
    "notice_keys",
]
