# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The evidence map (SHIELD §6.9, SH-61), the report (SH-62, SH-65), continuous conformance (SH-63),
and ISO/IEC 42001 through the crosswalk (SH-66): five statuses honest by construction."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("agentspecs.standards", reason="the standards catalogue needs agentspecs 0.0.104")

from agentspecs.standards import get_standard

from agent_shield.conformance import (
    DISCLAIMER,
    STATUS_WORDS,
    Document,
    DrillResult,
    Fact,
    Inputs,
    ThirdPartyReport,
    assess,
)
from agent_shield.conformance.continuous import (
    CLOCK_RUN_OUT,
    DOCUMENT_PAST_REVIEW,
    DRILL_FAILED,
    POLICY_WEAKENED,
    STATUS_DROPPED,
    Snapshot,
    Trend,
    lapses,
    notice_keys,
)
from agent_shield.conformance.map import FACTS, MAP
from agent_shield.policy import Limits, Mcp, Network, Policy, Rule, Threshold, default_policy
from agent_shield.report import ConformanceReport, build_report, lexical_state, merge_assessments

AIUC = get_standard("aiuc-1")
ISO = get_standard("iso-42001")
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)

ORGANIZATION = Policy(
    scope="organization",
    version=3,
    rules=[
        Rule(name="execute asks", decision="ask", classes=["execute"]),
        Rule(name="nothing deleted", decision="deny", classes=["delete"]),
        Rule(name="send and buy ask", decision="ask", classes=["send", "buy"]),
        Rule(name="outside the workspace", decision="ask", where="outside"),
    ],
    limits=Limits(
        tool_calls=Threshold(soft=100, hard=200),
        terminals_open=Threshold(soft=4, hard=8),
        spend=Threshold(soft=500, hard=1000),
    ),
    network=Network(fetch=["*.datalayer.io"]),
    mcp=Mcp(allow=["gmail"]),
)
SESSION = default_policy()


def row(entry: str, at: str = "2026-10-10T10:00:00+00:00", **payload):
    return {"kind": entry, "summary": entry, "payload": payload, "at": at, "session": "s1"}


def facts(holding: bool = True) -> dict[str, Fact]:
    return {
        name: Fact(holds=holding, says=f"{words[0].upper()}{words[1:]}.", proved="r1, 2026-10-15")
        for name, words in FACTS.items()
    }


def documents(signed: bool = True, review_on: str = "2027-10-01") -> dict[str, Document]:
    from agentspecs.standards import TEMPLATES

    return {
        control: Document(
            control=control,
            title=f"{control} document",
            owner="Ana",
            version=2,
            review_on=review_on,
            signed_by="Ana" if signed else None,
            signed_on="2026-10-01" if signed else None,
            link=f"/documents/{control}",
        )
        for control in TEMPLATES
    }


def reports(on: str = "2026-09-01", outcome: str = "passed") -> dict[str, ThirdPartyReport]:
    return {
        c: ThirdPartyReport(control=c, by="AIUC", on=on, outcome=outcome, link="/reports/1")
        for c in ("A009", "B001", "C010", "D004", "E018")
    }


def drills(outcome: str = "refused") -> list[DrillResult]:
    return [
        DrillResult(
            id=d, title=t, outcome=outcome, at="2026-10-15T09:00:00+00:00", where="r1", says="refused in a sentence"
        )
        for d, t in (
            ("outside-curl", "an outside curl"),
            ("write-outside-workspace", "a write outside the workspace"),
            ("secret-in-argument", "a secret in a tool argument"),
            ("own-port", "a runtime reached at its own port"),
        )
    ]


def full_inputs(**changes) -> Inputs:
    base = dict(
        policies=[ORGANIZATION, SESSION],
        record=[
            row(
                "decision",
                tool="rm -rf",
                behaviour="leave it to me",
                because="rule",
                classes=["delete"],
                rule="nothing deleted",
                scope="organization",
            ),
            row("decision", tool="git push", behaviour="ask me first", because="rule", classes=["execute"]),
            row("decision", tool="read", behaviour="do it", because="default", classes=["read"]),
            row("decision", tool="calls", behaviour="ask me first", because="limit", limit="tool_calls"),
            row("decision", tool="gmail.send", behaviour="ask me first", because="rule", kind="mcp", server="gmail"),
            row("tool_call", tool="read", kind="read", status="completed", path="a.py"),
            row("tool_call", tool="terminal", kind="execute", status="completed", command="pytest"),
            row("approval", tool="git push", state="approved", by="Ana"),
            row("feedback", liked=True),
            row("session", what="started"),
        ],
        counts={"shield.actions": 12, "shield.decisions": 5, "shield.refusals": 1, "shield.limits": 1},
        drills=drills(),
        validation={
            "gate": "passed",
            "pass_rate": 0.92,
            "min_pass_rate": 0.8,
            "safety": {"held": 4, "failed": 0, "total": 4},
            "version": 3,
            "at": "2026-10-14T10:00:00+00:00",
        },
        benchmarks=[
            {"name": "Secure code patterns", "at": "2026-10-01", "score": 0.9},
            {"name": "Hallucination set", "at": "2026-10-01", "score": 0.95},
            {"name": "Intellectual property outputs", "at": "2026-10-01", "score": 0.97},
        ],
        documents=documents(),
        third_party=reports(),
        facts=facts(),
        demonstrations={"presence_line": "/apps/desk"},
        harness={
            "adapter": "@agentclientprotocol/claude-agent-acp",
            "version": "0.91.0",
            "licence": "Apache-2.0",
            "credential": "ANTHROPIC_API_KEY",
            "served_to_third_parties": "api_key_only",
        },
        links={
            "policies": "/settings/organizations/acme/mcp",
            "activity": "/studio/apps/1/activity",
            "validate": "/studio/apps/1/validate",
            "dashboard": "/otel/shield",
            "documents": "/settings/organizations/acme/conformance",
        },
        now=NOW,
    )
    base.update(changes)
    return Inputs(**base)


# ---------------------------------------------------------------------------
# Every control reaches a status
# ---------------------------------------------------------------------------


def test_the_map_covers_every_control_of_aiuc_1_and_every_mandatory_control_reaches_a_status():
    ids = {c.id for c in AIUC.controls if not c.retired}
    assert set(MAP) == ids
    assessment = assess(AIUC, Inputs(now=NOW))
    assert len(assessment.controls) == 55
    for control in AIUC.mandatory_controls:
        found = assessment.control(control.id)
        assert found.status in STATUS_WORDS and found.reason.startswith(control.id)
    for retired in ("C011", "C012", "D002", "E007", "E014"):
        found = assessment.control(retired)
        assert found.status == "not_applicable" and "retired in 2026.4" in found.reason


def test_with_nothing_collected_every_status_is_honest():
    assessment = assess(AIUC, Inputs(now=NOW))
    for control_id in (
        "E001",
        "E002",
        "E003",
        "E010",
        "E011",
        "E012",
        "A001",
        "A002",
        "C001",
        "E006",
        "B003",
        "E005",
        "E008",
        "E017",
    ):
        found = assessment.control(control_id)
        assert found.status == "organizations", control_id
        assert "no document of the organization exists" in found.reason
    for control_id in ("A009", "B001", "C010", "D004", "E018"):
        found = assessment.control(control_id)
        assert found.status == "third_party" and "no third-party report has been recorded" in found.reason
    for control_id in ("D003", "B006", "A003", "A008", "B008", "C002", "E015", "E016"):
        found = assessment.control(control_id)
        assert found.status == "partly" and found.missing, control_id
    # Nothing is met by evidence out of nothing.
    assert assessment.by_status()["met"] == 0
    assert len(assessment.gaps) == 42


def test_with_everything_collected_the_technical_controls_are_met_and_the_rest_follow_their_evidence():
    assessment = assess(AIUC, full_inputs())
    met = {c.control for c in assessment.controls if c.status == "met"}
    for control_id in (
        "D003",
        "B006",
        "A003",
        "A005",
        "A008",
        "B004",
        "B008",
        "B009",
        "B010",
        "C002",
        "C003",
        "C006",
        "C007",
        "C008",
        "C009",
        "D001",
        "E009",
        "E015",
        "E016",
    ):
        assert control_id in met, (control_id, assessment.control(control_id).missing)
    # A signed, in-date document meets the organization's controls; a recorded report the third party's.
    for control_id in ("E001", "E010", "E011", "A001", "A002", "C001", "E006"):
        assert assessment.control(control_id).status == "met", control_id
        assert any(e.kind == "documentation" for e in assessment.control(control_id).evidence)
    for control_id in ("A009", "B001", "C010", "D004", "E018"):
        assert assessment.control(control_id).status == "met"
    # What needs the organization or a provider beyond the Shield stays partly met, with what is missing named.
    for control_id in ("A004", "A006", "A007", "B002", "B007", "E004", "F001", "F002"):
        found = assessment.control(control_id)
        assert found.status == "partly" and found.missing, control_id
    # And what nobody wrote stays the organization's.
    for control_id in ("B003", "E005", "E008", "E017"):
        assert assessment.control(control_id).status == "organizations"


def test_a_document_is_evidence_only_once_signed_in_date_and_filled():
    unsigned = assess(AIUC, full_inputs(documents=documents(signed=False)))
    assert unsigned.control("E010").status == "organizations"
    assert "nobody has signed it" in unsigned.control("E010").reason
    stale = assess(AIUC, full_inputs(documents=documents(review_on="2026-01-01")))
    assert stale.control("E010").status == "organizations" and "past its review date" in stale.control("E010").reason
    unfilled = dict(documents())
    unfilled["E011"] = Document(
        control="E011",
        title="E011 document",
        owner="Ana",
        version=1,
        review_on="2027-01-01",
        signed_by="Ana",
        signed_on="2026-10-01",
        unfilled=["own_systems"],
    )
    assert (
        "still has fields to fill: own_systems" in assess(AIUC, full_inputs(documents=unfilled)).control("E011").reason
    )
    # The data policies also need the retention fact: signed without it is partly met.
    signed_only = assess(AIUC, full_inputs(facts={**facts(), "record_retention": Fact(holds=False, says="")}))
    assert signed_only.control("A001").status == "partly"
    assert FACTS["record_retention"] in signed_only.control("A001").missing


def test_a_third_partys_report_counts_only_within_its_cadence_and_when_it_passed():
    old = assess(AIUC, full_inputs(third_party=reports(on="2026-05-01")))
    found = old.control("A009")
    assert found.status == "third_party" and "older than the cadence of 3 months" in found.reason
    assert found.cadence.overdue and found.cadence.next_due == "2026-07-30"
    failed = assess(AIUC, full_inputs(third_party=reports(outcome="failed")))
    assert failed.control("B001").status == "third_party" and "did not pass" in failed.control("B001").reason


# ---------------------------------------------------------------------------
# A weakened policy drops D003 and B006
# ---------------------------------------------------------------------------


def test_a_policy_weakened_below_the_organizations_drops_d003_and_b006_to_partly_met_with_the_reason():
    loose = Policy(
        scope="team",
        rules=[Rule(name="delete freely", decision="allow", classes=["delete"])],
        limits=Limits(tool_calls=Threshold(soft=1000, hard=2000)),
    )
    assessment = assess(AIUC, full_inputs(policies=[ORGANIZATION, loose, SESSION]))
    for control_id in ("D003", "B006"):
        found = assessment.control(control_id)
        assert found.status == "partly", control_id
        weakening = [
            m for m in found.missing if m.startswith("the application's rules permit more than the organization's")
        ]
        assert weakening, found.missing
        assert any("delete freely" in m for m in weakening)
        assert any("tool_calls" in m or "tool calls" in m for m in weakening)
    # The organization's scope missing altogether is named on B006 too.
    without = assess(AIUC, full_inputs(policies=[SESSION]))
    assert "the organization's scope in force, the strictest first" in without.control("B006").missing


def test_a_control_with_no_policy_at_all_names_the_policy_as_missing():
    assessment = assess(AIUC, full_inputs(policies=[]))
    d003 = assessment.control("D003")
    assert d003.status == "partly"
    assert "a rule deciding by class before an action runs" in d003.missing
    assert "the limits on tool calls and terminals, soft then hard" in d003.missing


def test_a_drill_that_allowed_what_it_tried_is_no_evidence():
    assessment = assess(AIUC, full_inputs(drills=drills(outcome="allowed")))
    assert assessment.control("A008").status == "partly"
    assert any("secret in a tool argument" in m for m in assessment.control("A008").missing)


# ---------------------------------------------------------------------------
# Machine-readable per control
# ---------------------------------------------------------------------------


def test_each_control_is_machine_readable_with_its_evidence_links_crosswalks_and_clock():
    assessment = assess(AIUC, full_inputs())
    data = assessment.to_json()
    assert data["standard"] == "aiuc-1" and data["version"] == "2026.4" and data["disclaimer"] == DISCLAIMER
    d003 = next(c for c in data["controls"] if c["control"] == "D003")
    assert (
        d003["status"] == "met" and d003["status_words"] == "met by evidence" and d003["mandatory"] and not d003["gap"]
    )
    assert {e["kind"] for e in d003["evidence"]} == {"config", "logs", "demonstration"}
    assert any(e["item"] == "D003.4" for e in d003["evidence"])
    assert all(e["collected_at"] == NOW.isoformat(timespec="seconds") for e in d003["evidence"])
    assert d003["crosswalks"]["eu-ai-act"][0].startswith("Article 72")
    assert d003["cadence"] == {
        "months": 12,
        "last": "2026-10-14T10:00:00+00:00",
        "next_due": "2027-10-09",
        "overdue": False,
    }
    json.dumps(data)


# ---------------------------------------------------------------------------
# The report (SH-62) and the assessor's export (SH-65)
# ---------------------------------------------------------------------------


def test_the_report_says_on_its_first_page_that_the_shield_evidences_and_never_certifies():
    report = build_report(AIUC, full_inputs(), scope="deployment", name="Desk", uid="d1")
    markdown = report.markdown()
    first_page = markdown.split("## At a glance")[0]
    assert DISCLAIMER in first_page and "It does not certify" in first_page
    assert "## The Shield" in markdown and "### The policies in force" in markdown
    assert "- **organization** v3: 4 rules; limits tool_calls 100/200, terminals_open 4/8, spend 500/1000" in markdown
    assert "- Decisions: 3 ask me first, 1 do it, 1 leave it to me" in markdown
    assert "- Reached: tool_calls 1 times" in markdown
    assert "### D003 Restrict unsafe tool calls" in markdown
    assert "- EU AI Act: Article 72" in markdown and "- OWASP Top 10 for Agentic Applications: ASI01" in markdown
    assert "## The cadence clocks" in markdown
    state = report.lexical()
    kinds = [node["type"] for node in state["root"]["children"]]
    assert kinds[0] == "heading" and "table" in kinds and "list" in kinds
    assert state["root"]["children"][0]["children"][0]["text"].startswith("Conformance report: Desk")


def test_the_shield_section_says_what_changed_since_the_last_report():
    """§6.5's last part (SH-36): against the last report's JSON, a sentence per change;
    none when nothing changed; said plainly when there is no earlier report."""
    first = build_report(AIUC, full_inputs(), scope="deployment", name="Desk", uid="d1")
    assert first.shield.changed is None and first.to_json()["shield"]["changed"] is None
    assert "### What changed since the last report\n\n- No earlier report to compare with." in first.markdown()
    same = build_report(AIUC, full_inputs(), scope="deployment", name="Desk", uid="d1", previous=first.to_json())
    assert same.shield.changed == []
    assert "- Nothing changed since the last report." in same.markdown()
    later_inputs = full_inputs(
        record=[
            *full_inputs().record,
            row("decision", tool="curl", behaviour="leave it to me", because="rule", classes=["send"]),
            row("approval", tool="curl", state="denied", by="Ana"),
        ],
        validation={**full_inputs().validation, "gate": "failed", "version": 4},
    )
    later = build_report(AIUC, later_inputs, scope="deployment", name="Desk", uid="d1", previous=first.to_json())
    assert later.shield.changed == [
        "The Validate gate is failed on version 4 (was passed on version 3).",
        "In decisions: leave it to me 1 → 2.",
        "In decided by: rule 3 → 4.",
        "In answers: denied 0 → 1.",
    ]
    assert "- In decisions: leave it to me 1 → 2." in later.markdown()
    assert later.to_json()["shield"]["changed"] == later.shield.changed


def test_the_evidence_list_has_aiuc_1s_columns_and_a_row_per_evidence_item():
    report = build_report(AIUC, full_inputs(), scope="deployment", name="Desk", uid="d1")
    rows = report.evidence_rows()
    assert list(rows[0]) == list(ConformanceReport.EVIDENCE_COLUMNS)
    assert len(rows) == 145
    d003 = [r for r in rows if r["Requirement"].startswith("D003:")]
    assert d003[0]["Evidence"].startswith("D003.1 Config: Tool authorization & validation.")
    assert d003[0]["Tags"].startswith("Core control, technical-implementation")
    assert d003[0]["Status"] == "met by evidence" and "Rules holding" in d003[0]["Datalayer evidence"]
    parsed = list(csv.DictReader(io.StringIO(report.evidence_csv())))
    assert len(parsed) == 145 and parsed[0]["Requirement"].startswith("A001:")
    hub = report.audit_hub()
    assert hub["framework"] == {"id": "aiuc-1", "name": "AIUC-1", "version": "2026.4"}
    assert len(hub["controls"]) == 55
    owners = {c["id"]: c["owner"] for c in hub["controls"]}
    assert owners["D003"] == "datalayer" and owners["B003"] == "organization" and owners["C011"] is None
    assert hub["disclaimer"] == DISCLAIMER


def test_an_organizations_report_takes_the_weakest_answer_across_its_deployments():
    met = assess(AIUC, full_inputs())
    weak = assess(AIUC, full_inputs(policies=[SESSION], drills=[]))
    merged = merge_assessments([met, weak])
    assert merged.control("B006").status == "partly"
    assert merged.control("B006").reason.startswith("Across 2 deployments, the weakest answer")
    assert merged.control("E001").status == "met"


def test_lexical_state_keeps_headings_lists_tables_and_text_runs():
    state = lexical_state(
        "# Title\n\nA **bold** word and `code`.\n\n- one\n- two\n\n| A | B |\n| --- | --- |\n| 1 | 2 |\n\n> a quote\n"
    )
    nodes = state["root"]["children"]
    assert [n["type"] for n in nodes] == ["heading", "paragraph", "list", "table", "quote"]
    assert [(t["text"], t["format"]) for t in nodes[1]["children"]] == [
        ("A ", 0),
        ("bold", 1),
        (" word and ", 0),
        ("code", 16),
        (".", 0),
    ]
    assert len(nodes[2]["children"]) == 2 and nodes[3]["children"][0]["children"][0]["headerState"] == 1


# ---------------------------------------------------------------------------
# Continuous (SH-63)
# ---------------------------------------------------------------------------


def test_a_lapse_raises_a_notice_for_the_owners():
    before = assess(AIUC, full_inputs())
    later = NOW + timedelta(days=400)
    loose = Policy(scope="team", rules=[Rule(name="delete freely", decision="allow", classes=["delete"])])
    relaxed = ORGANIZATION.model_copy(
        update={"version": 4, "rules": [r for r in ORGANIZATION.rules if r.name != "nothing deleted"]}
    )
    inputs = full_inputs(
        now=later,
        policies=[relaxed, loose, SESSION],
        drills=drills(outcome="allowed"),
        documents=documents(review_on="2027-01-01"),
    )
    after = assess(AIUC, inputs)
    notices = lapses(before, after, inputs, previous_policies=Snapshot.of(before, full_inputs()).policies_in_force())
    kinds = {n.kind for n in notices}
    assert kinds == {CLOCK_RUN_OUT, STATUS_DROPPED, POLICY_WEAKENED, DRILL_FAILED, DOCUMENT_PAST_REVIEW}
    clock = next(n for n in notices if n.kind == CLOCK_RUN_OUT and n.control == "A009")
    assert "its cadence of 3 months ran out on 2026-11-30" in clock.says
    dropped = next(n for n in notices if n.kind == STATUS_DROPPED and n.control == "D003")
    assert "was met by evidence and is now partly met" in dropped.says and "delete freely" in dropped.says
    assert any("delete freely" in n.says for n in notices if n.kind == POLICY_WEAKENED)
    assert any(
        n.title == "The organization's rules now permit more than before" and "nothing deleted" in n.says
        for n in notices
    ), [n.says for n in notices]
    assert any(n.control == "E010" for n in notices if n.kind == DOCUMENT_PAST_REVIEW)
    keys = notice_keys(notices, "2027-11-19")
    assert len(keys) == len(set(keys)) == len(notices)
    assert lapses(before, before, full_inputs()) == []


def test_the_trend_keeps_one_snapshot_a_day_and_a_point_a_week():
    trend = Trend()
    for day in ("2026-10-01", "2026-10-01", "2026-10-02", "2026-10-09", "2026-10-15"):
        assessment = assess(AIUC, full_inputs(now=datetime.fromisoformat(day + "T10:00:00+00:00")))
        trend.add(Snapshot.of(assessment, full_inputs()))
    assert [s.at[:10] for s in trend.snapshots] == ["2026-10-01", "2026-10-02", "2026-10-09", "2026-10-15"]
    weekly = trend.weekly()
    assert [s.at[:10] for s in weekly] == ["2026-10-02", "2026-10-09", "2026-10-15"]
    assert weekly[-1].mandatory == 42 and weekly[-1].met == 42 - len(weekly[-1].gaps)
    assert weekly[-1].to_json()["by_status"]["not_applicable"] == 5
    again = Snapshot.from_json(json.loads(json.dumps(weekly[-1].to_json())))
    assert [p.scope for p in again.policies_in_force()] == ["organization", "session"] and again.gaps == weekly[-1].gaps


# ---------------------------------------------------------------------------
# ISO/IEC 42001 through the crosswalk (SH-66)
# ---------------------------------------------------------------------------


def test_iso_42001_is_answered_from_the_same_evidence_through_the_crosswalk():
    assessment = assess(ISO, full_inputs())
    assert assessment.standard == "iso-42001" and len(assessment.controls) == 70
    uncovered = assessment.control("4.2")
    assert uncovered.status == "organizations" and "no control of AIUC-1 covers it" in uncovered.reason
    partial = assessment.control("4.1")
    assert partial.status in ("partly", "organizations") and "C001, E010" in partial.reason
    assert (
        assessment.control("A.10.3").status == "met" and "E006 met by evidence" in assessment.control("A.10.3").reason
    )
    assert assessment.control("A.6.2.8").status == "met"
    # A clause fully covered by partly-met controls is partly met, with their missing pieces.
    unsigned = assess(ISO, full_inputs(documents={}))
    assert unsigned.control("A.10.3").status == "organizations"
    report = build_report(ISO, full_inputs(), scope="organization", name="Acme", uid="o1")
    assert "Conformance report: Acme against ISO/IEC 42001:2023 2023" in report.markdown()
    assert report.audit_hub()["framework"]["id"] == "iso-42001"


def test_a_partial_clause_without_a_note_says_the_rest_is_the_organizations():
    from types import SimpleNamespace  # noqa: PLC0415

    from agent_shield.conformance.map import answer_covered  # noqa: PLC0415

    covering = assess(AIUC, full_inputs())
    clause = SimpleNamespace(id="X.1", coverage="partial", covered_by=["E006"], coverage_note="", cadence_months=12)
    status, reason, _evidence, missing, _last = answer_covered(clause, covering, full_inputs())
    assert status == "partly" and "E006 met by evidence" in reason
    assert missing[-1].endswith("partially: the rest is the organization's")
