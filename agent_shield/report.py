# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The conformance report, with the Shield report as its Shield section (SHIELD §6.5, §6.9, SH-36, SH-62, SH-65).

Per deployment or per organization: every control of the standard with its
status, its evidence linked, the cadence clocks, the gaps, and each
control's crosswalk (the EU AI Act article, the NIST AI RMF function, the
ISO/IEC 42001 clause, the OWASP Agentic threat, and the rest the standard
publishes). Its first page says the Shield evidences and never certifies.
The **Shield section** is §6.5's report: the policies in force at the three
levels, the tests the Rules passed (the Validate gate with SH-37's drills),
the approvals and denials of the period with who decided, the limits and what
they stopped, the harness's register entry.

Exported three ways: as **Markdown** and as a **Lexical document** (the
Studio's documents are Lexical; :func:`lexical_state` writes the editor state
the Studio opens and comments on), and as **JSON** per control. For an
assessor (SH-65): the **evidence list** in the shape of AIUC-1's own
spreadsheet (its columns *Requirement*, *Control activity*, *Evidence*,
*Tags*, with the status, the Datalayer evidence and its link beside them),
as rows and as CSV, and an **audit-hub** JSON an evidence platform ingests,
with the representative configurations attached.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_shield.conformance import DISCLAIMER, STATUS_ORDER, STATUS_WORDS, Assessment, ControlStatus, Inputs
from agent_shield.conformance import collect as c

#: The crosswalk frameworks the report answers by name, in this order (SH-62), then the rest.
NAMED_FRAMEWORKS = ("eu-ai-act", "nist-ai-rmf", "iso-42001", "owasp-agentic-top-10")


@dataclass
class ShieldSection:
    """§6.5: what the Shield decided with, and what it decided, over the period."""

    policies: Mapping[str, Mapping[str, Any]]
    period_days: int
    decisions: Mapping[str, int]
    decided_by: Mapping[str, int]
    approvals: Mapping[str, int]
    limits_reached: Mapping[str, int]
    drills: Sequence[Mapping[str, Any]]
    gate: Mapping[str, Any] | None
    harness: Mapping[str, Any] | None
    weakened: Sequence[str]

    @classmethod
    def of(cls, inputs: Inputs) -> ShieldSection:
        decisions: dict[str, int] = {}
        decided_by: dict[str, int] = {}
        limits: dict[str, int] = {}
        for row in c.record_rows(inputs, "decision"):
            payload = row.get("payload") or {}
            behaviour = str(payload.get("behaviour") or "")
            if behaviour:
                decisions[behaviour] = decisions.get(behaviour, 0) + 1
            because = str(payload.get("because") or "")
            if because:
                decided_by[because] = decided_by.get(because, 0) + 1
            if because == "limit" and payload.get("limit"):
                limits[str(payload["limit"])] = limits.get(str(payload["limit"]), 0) + 1
        approvals: dict[str, int] = {}
        for row in c.record_rows(inputs, "approval"):
            payload = row.get("payload") or {}
            state = str(payload.get("state") or payload.get("decision") or "answered")
            approvals[state] = approvals.get(state, 0) + 1
        return cls(
            policies={
                p.scope: {
                    "version": p.version,
                    "rules": len(p.rules),
                    "limits": {
                        name: {"soft": t.soft, "hard": t.hard}
                        for name, t in (
                            (n, getattr(p.limits, n))
                            for n in ("tool_calls", "terminals_open", "bytes_written", "model_tokens", "spend")
                        )
                        if t is not None
                    },
                }
                for p in inputs.policies
            },
            period_days=inputs.period_days,
            decisions=decisions,
            decided_by=decided_by,
            approvals=approvals,
            limits_reached=limits,
            drills=[
                {"id": d.id, "title": d.title, "outcome": d.outcome, "at": d.at, "where": d.where}
                for d in inputs.drills
            ],
            gate=dict(inputs.validation) if inputs.validation else None,
            harness=dict(inputs.harness) if inputs.harness else None,
            weakened=c.policy_weakened(inputs),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "policies": {k: dict(v) for k, v in self.policies.items()},
            "period_days": self.period_days,
            "decisions": dict(self.decisions),
            "decided_by": dict(self.decided_by),
            "approvals": dict(self.approvals),
            "limits_reached": dict(self.limits_reached),
            "drills": [dict(d) for d in self.drills],
            "gate": dict(self.gate) if self.gate else None,
            "harness": dict(self.harness) if self.harness else None,
            "weakened": list(self.weakened),
        }


@dataclass
class ConformanceReport:
    """One report: the scope it is of, the assessment, the Shield section."""

    #: ``deployment`` or ``organization``.
    scope: str
    name: str
    uid: str
    assessment: Assessment
    shield: ShieldSection
    #: The representative configurations (SH-65): the Appspec, the policies, the harness spec, as the host attaches them.
    configurations: Mapping[str, Any] = field(default_factory=dict)
    standard: Any = None

    # -- JSON --------------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "name": self.name,
            "uid": self.uid,
            "disclaimer": DISCLAIMER,
            "assessment": self.assessment.to_json(),
            "shield": self.shield.to_json(),
            "configurations": dict(self.configurations),
        }

    # -- Markdown ----------------------------------------------------------

    def title(self) -> str:
        return f"Conformance report: {self.name} against {self.assessment.standard_name} {self.assessment.version}"

    def markdown(self) -> str:
        a = self.assessment
        counts = a.by_status()
        lines = [
            f"# {self.title()}",
            "",
            f"*{self.scope.capitalize()} {self.name} · assessed {a.assessed_at}*",
            "",
            DISCLAIMER,
            "",
        ]
        if a.version_notice:
            lines += [f"> {a.version_notice}", ""]
        lines += ["## At a glance", ""]
        lines += [f"- {STATUS_WORDS[status]}: {counts[status]}" for status in STATUS_ORDER]
        lines += [f"- Mandatory controls not met by evidence (the gaps): {len(a.gaps)}", ""]
        if a.gaps:
            lines += ["## The gaps", ""]
            for control in a.gaps:
                lines.append(
                    f"- **{control.control}** {control.title} — {control.words}: "
                    + ("; ".join(control.missing) if control.missing else control.reason)
                )
            lines.append("")
        lines += [
            "## The cadence clocks",
            "",
            "| Control | Every | Last | Next due | |",
            "| --- | --- | --- | --- | --- |",
        ]
        for control in a.controls:
            if control.cadence.months and (control.cadence.last or control.status in ("third_party", "organizations")):
                lines.append(
                    f"| {control.control} | {control.cadence.months} months | {control.cadence.last or 'never'} | {control.cadence.next_due or '—'} | {'run out' if control.cadence.overdue else ''} |"
                )
        lines.append("")
        lines += self._shield_markdown()
        domains = self._domains()
        for domain_id, domain_name in domains:
            controls = [control for control in a.controls if control.domain == domain_id]
            if not controls:
                continue
            lines += [f"## {domain_id}. {domain_name}", ""]
            for control in controls:
                lines += [
                    f"### {control.control} {control.title}",
                    "",
                    f"**{control.words.capitalize()}** — {control.reason}",
                    "",
                ]
                if control.evidence:
                    lines += ["Evidence:", ""]
                    for evidence in control.evidence:
                        link = f" ([link]({evidence.link}))" if evidence.link else ""
                        item = f" `{evidence.item}`" if evidence.item else ""
                        lines.append(
                            f"- *{evidence.kind}*{item}: {evidence.what}{link} — collected {evidence.collected_at}"
                        )
                    lines.append("")
                if control.missing:
                    lines += ["Missing:", ""] + [f"- {m}" for m in control.missing] + [""]
                crosswalk = self._crosswalk_lines(control)
                if crosswalk:
                    lines += ["Crosswalk:", "", *crosswalk, ""]
        return "\n".join(lines)

    def _domains(self) -> list[tuple[str, str]]:
        if self.standard is not None and getattr(self.standard, "domains", None):
            return [(d.id, d.name) for d in self.standard.domains]
        seen: list[tuple[str, str]] = []
        for control in self.assessment.controls:
            if control.domain not in [d for d, _ in seen]:
                seen.append((control.domain, control.domain))
        return seen

    def _framework_name(self, framework: str) -> str:
        names = getattr(self.standard, "frameworks", None) or {}
        return names.get(framework, framework)

    def _crosswalk_lines(self, control: ControlStatus) -> list[str]:
        lines: list[str] = []
        ordered = [f for f in NAMED_FRAMEWORKS if f in control.crosswalks] + sorted(
            f for f in control.crosswalks if f not in NAMED_FRAMEWORKS
        )
        for framework in ordered:
            refs = control.crosswalks.get(framework) or []
            if refs:
                lines.append(f"- {self._framework_name(framework)}: {'; '.join(refs)}")
        return lines

    def _shield_markdown(self) -> list[str]:
        s = self.shield
        lines = [
            "## The Shield",
            "",
            f"What the Shield decided with and what it decided over the last {s.period_days} days.",
            "",
            "### The policies in force",
            "",
        ]
        if s.policies:
            for scope in ("organization", "team", "session"):
                found = s.policies.get(scope)
                if found:
                    limits = ", ".join(f"{n} {v['soft']}/{v['hard']}" for n, v in found["limits"].items()) or "none set"
                    lines.append(f"- **{scope}** v{found['version']}: {found['rules']} rules; limits {limits}")
        else:
            lines.append("- No policy could be read: nothing is decided without one.")
        if s.weakened:
            lines += ["", "A scope below the organization's permits more than it:", ""] + [f"- {w}" for w in s.weakened]
        lines += ["", "### The tests the Rules passed", ""]
        if s.gate:
            lines.append(
                f"- The Validate gate on version {s.gate.get('version')}: {s.gate.get('gate')} ({round(float(s.gate.get('pass_rate') or 0) * 100)}% of its tests; ships at {round(float(s.gate.get('min_pass_rate') or 0) * 100)}%)"
                + (
                    f"; safety {s.gate['safety'].get('held')}/{s.gate['safety'].get('total')} held"
                    if s.gate.get("safety")
                    else ""
                )
            )
        else:
            lines.append("- No run of this version yet.")
        for drill in s.drills:
            lines.append(
                f"- Drill {drill['title']}: {drill['outcome']} on {drill['at']}{(' (' + drill['where'] + ')') if drill.get('where') else ''}"
            )
        lines += ["", "### Approvals and denials", ""]
        if s.decisions:
            lines.append("- Decisions: " + ", ".join(f"{n} {b}" for b, n in sorted(s.decisions.items())))
            lines.append("- Decided by: " + ", ".join(f"{n} by {b}" for b, n in sorted(s.decided_by.items())))
        else:
            lines.append("- No decision in the record over the period.")
        lines.append(
            "- Answered by a person: "
            + (", ".join(f"{n} {state}" for state, n in sorted(s.approvals.items())) if s.approvals else "none")
        )
        lines += ["", "### The limits", ""]
        lines.append(
            "- Reached: "
            + (
                ", ".join(f"{name} {n} times" for name, n in sorted(s.limits_reached.items()))
                if s.limits_reached
                else "none reached over the period"
            )
        )
        if s.harness:
            lines += [
                "",
                "### The coding agent",
                "",
                f"- {s.harness.get('adapter')} {s.harness.get('version')}: licence {s.harness.get('licence')}, credential {s.harness.get('credential')}, third parties {s.harness.get('served_to_third_parties')}",
            ]
        lines.append("")
        return lines

    # -- Lexical -----------------------------------------------------------

    def lexical(self) -> dict[str, Any]:
        """The report as a Lexical editor state: the document the Studio opens."""
        return lexical_state(
            self.markdown(),
            provenance={
                "report": "conformance",
                "standard": self.assessment.standard,
                "scope": self.scope,
                "uid": self.uid,
                "at": self.assessment.assessed_at,
            },
        )

    # -- The assessor's export (SH-65) ---------------------------------------

    EVIDENCE_COLUMNS = (
        "Requirement",
        "Control activity",
        "Evidence",
        "Tags",
        "Status",
        "Datalayer evidence",
        "Link",
        "Collected at",
        "Missing",
    )

    def evidence_rows(self) -> list[dict[str, str]]:
        """AIUC-1's evidence list, one row per evidence item of the standard, with the Shield's answer beside it."""
        rows: list[dict[str, str]] = []
        for control in self.assessment.controls:
            spec = self.standard.control(control.control) if self.standard is not None else None
            requirement = f"{control.control}: {control.title} ({'retired' if control.retired else 'mandatory' if control.mandatory else 'optional'} requirement)"
            items = list(spec.evidence) if spec is not None else []
            if not items:
                rows.append(
                    {
                        "Requirement": requirement,
                        "Control activity": "",
                        "Evidence": "",
                        "Tags": "",
                        "Status": control.words,
                        "Datalayer evidence": control.reason,
                        "Link": "",
                        "Collected at": control.collected_at,
                        "Missing": "; ".join(control.missing),
                    }
                )
                continue
            activities = [a.activity for a in spec.activities] if spec is not None else []
            for index, item in enumerate(items):
                ours = [e for e in control.evidence if e.item == item.id]
                rows.append(
                    {
                        "Requirement": requirement,
                        "Control activity": activities[index] if index < len(activities) else "",
                        "Evidence": f"{item.id} {item.kind.capitalize()}: {item.title}."
                        + (f" {item.description}" if item.description else ""),
                        "Tags": ", ".join(
                            [
                                f"{item.required.capitalize()} control",
                                *([item.category] if item.category else []),
                                *item.locations,
                            ]
                        ),
                        "Status": control.words,
                        "Datalayer evidence": " | ".join(e.what for e in ours) if ours else "",
                        "Link": " | ".join(e.link for e in ours if e.link),
                        "Collected at": control.collected_at,
                        "Missing": "; ".join(control.missing) if not ours else "",
                    }
                )
        return rows

    def evidence_csv(self) -> str:
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=list(self.EVIDENCE_COLUMNS))
        writer.writeheader()
        for row in self.evidence_rows():
            writer.writerow(row)
        return out.getvalue()

    def audit_hub(self) -> dict[str, Any]:
        """What an evidence platform ingests: one record per control, its evidence typed, the configurations attached."""
        a = self.assessment
        return {
            "framework": {"id": a.standard, "name": a.standard_name, "version": a.version},
            "scope": {"kind": self.scope, "name": self.name, "id": self.uid},
            "generated_at": a.assessed_at,
            "disclaimer": DISCLAIMER,
            "controls": [
                {
                    "id": control.control,
                    "name": control.title,
                    "domain": control.domain,
                    "applicability": "not_applicable"
                    if control.status == "not_applicable"
                    else "mandatory"
                    if control.mandatory
                    else "optional",
                    "status": control.status,
                    "status_label": control.words,
                    "reason": control.reason,
                    "owner": "datalayer"
                    if control.status in ("met", "partly")
                    else "organization"
                    if control.status == "organizations"
                    else "third_party"
                    if control.status == "third_party"
                    else None,
                    "due": control.cadence.next_due,
                    "evidence": [
                        {
                            "type": e.kind,
                            "title": e.what,
                            "item": e.item,
                            "collected_at": e.collected_at,
                            "link": e.link,
                            "detail": dict(e.detail),
                        }
                        for e in control.evidence
                    ],
                    "gaps": list(control.missing),
                    "crosswalks": {k: list(v) for k, v in control.crosswalks.items()},
                }
                for control in a.controls
            ],
            "configurations": dict(self.configurations),
            "shield": self.shield.to_json(),
        }


def build_report(
    standard: Any, inputs: Inputs, *, scope: str, name: str, uid: str, configurations: Mapping[str, Any] | None = None
) -> ConformanceReport:
    """Assess ``standard`` on ``inputs`` and write the report of it."""
    from agent_shield.conformance import assess

    return ConformanceReport(
        scope=scope,
        name=name,
        uid=uid,
        assessment=assess(standard, inputs),
        shield=ShieldSection.of(inputs),
        configurations=dict(configurations or {}),
        standard=standard,
    )


def merge_assessments(assessments: Sequence[Assessment]) -> Assessment:
    """An organization's assessment from its deployments': each control at the weakest of them, the evidence of all."""
    if not assessments:
        raise ValueError("an organization's report needs at least one deployment's assessment")
    first = assessments[0]
    merged: list[ControlStatus] = []
    for control in first.controls:
        answers = [a.control(control.control) for a in assessments]
        weakest = min(answers, key=lambda x: STATUS_ORDER.index(x.status))
        evidence = [e for answer in answers for e in answer.evidence]
        missing: list[str] = []
        for answer in answers:
            for m in answer.missing:
                if m not in missing:
                    missing.append(m)
        merged.append(
            ControlStatus(
                control=control.control,
                title=control.title,
                domain=control.domain,
                status=weakest.status,
                reason=f"Across {len(assessments)} deployments, the weakest answer: {weakest.reason}",
                evidence=evidence,
                missing=missing,
                crosswalks=control.crosswalks,
                cadence=weakest.cadence,
                mandatory=control.mandatory,
                retired=control.retired,
                collected_at=first.assessed_at,
                url=control.url,
            )
        )
    return Assessment(
        standard=first.standard,
        standard_name=first.standard_name,
        version=first.version,
        controls=merged,
        assessed_at=first.assessed_at,
        version_notice=first.version_notice,
    )


# ---------------------------------------------------------------------------
# Markdown → Lexical, by hand: the same node shapes the editor writes
# ---------------------------------------------------------------------------


def _text(content: str, fmt: int = 0) -> dict[str, Any]:
    return {"detail": 0, "format": fmt, "mode": "normal", "style": "", "text": content, "type": "text", "version": 1}


def _block(kind: str, children: list[dict[str, Any]], provenance: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "children": children,
        "direction": "ltr",
        "format": "",
        "indent": 0,
        "type": kind,
        "version": 1,
        "$": {"evidence": dict(provenance)},
        **extra,
    }


def _inline(line: str) -> list[dict[str, Any]]:
    """Bold (`**`), italic (`*`) and code (backticks) as text runs; links as their words."""
    import re

    line = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", line)
    runs: list[dict[str, Any]] = []
    for match in re.finditer(r"\*\*(.+?)\*\*|\*(.+?)\*|`(.+?)`|([^*`]+|[*`])", line):
        bold, italic, code, plain = match.groups()
        if bold:
            runs.append(_text(bold, 1))
        elif italic:
            runs.append(_text(italic, 2))
        elif code:
            runs.append(_text(code, 16))
        elif plain:
            runs.append(_text(plain))
    return runs or [_text("")]


def _table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def lexical_state(markdown: str, provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """A Lexical editor state from the report's Markdown: headings, paragraphs, quotes, bullet lists and tables."""
    provenance = dict(provenance or {})
    children: list[dict[str, Any]] = []
    lines = markdown.splitlines()
    index = 0
    paragraph: list[str] = []

    def flush() -> None:
        if paragraph:
            children.append(_block("paragraph", _inline(" ".join(paragraph)), provenance, textFormat=0, textStyle=""))
            paragraph.clear()

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            flush()
            index += 1
            continue
        if stripped.startswith("#"):
            flush()
            level = len(stripped) - len(stripped.lstrip("#"))
            children.append(_block("heading", _inline(stripped[level:].strip()), provenance, tag=f"h{min(level, 6)}"))
            index += 1
            continue
        if stripped.startswith("> "):
            flush()
            children.append(_block("quote", _inline(stripped[2:]), provenance))
            index += 1
            continue
        if stripped.startswith("|"):
            flush()
            rows: list[list[str]] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                cells = _table_cells(lines[index])
                if not all(set(cell) <= set("-: ") for cell in cells):
                    rows.append(cells)
                index += 1
            body = []
            for row_index, row in enumerate(rows):
                body.append(
                    _block(
                        "tablerow",
                        [
                            _block(
                                "tablecell",
                                [_block("paragraph", _inline(cell), provenance, textFormat=0, textStyle="")],
                                provenance,
                                headerState=1 if row_index == 0 else 0,
                                colSpan=1,
                                rowSpan=1,
                                backgroundColor=None,
                            )
                            for cell in row
                        ],
                        provenance,
                    )
                )
            children.append(_block("table", body, provenance))
            continue
        if stripped.startswith("- "):
            flush()
            items: list[dict[str, Any]] = []
            while index < len(lines) and lines[index].strip().startswith("- "):
                items.append(_block("listitem", _inline(lines[index].strip()[2:]), provenance, value=len(items) + 1))
                index += 1
            children.append(_block("list", items, provenance, listType="bullet", start=1, tag="ul"))
            continue
        paragraph.append(stripped)
        index += 1
    flush()
    return {"root": {"children": children, "direction": "ltr", "format": "", "indent": 0, "type": "root", "version": 1}}


def report_json_text(report: ConformanceReport) -> str:
    return json.dumps(report.to_json(), indent=2, ensure_ascii=False, default=str) + "\n"


__all__ = [
    "NAMED_FRAMEWORKS",
    "ConformanceReport",
    "ShieldSection",
    "build_report",
    "lexical_state",
    "merge_assessments",
    "report_json_text",
]
