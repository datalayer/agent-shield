# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The collectors: each reads one kind of evidence out of :class:`Inputs` (SH-61).

A collector answers an :class:`Evidence` when the evidence is there, and
``None`` when it is not — never a guess. The map's rules compose them and
name, for each ``None``, what is missing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from agent_shield.conformance import Document, DrillResult, Evidence, Inputs, ThirdPartyReport
from agent_shield.policy import SCOPES_STRICTEST_FIRST, Policy
from agent_shield.policy.levels import widening

#: The behaviours the record writes for a decision (agent-runtimes' words).
ASK_FIRST = "ask me first"
LEAVE_TO_ME = "leave it to me"
DO_IT = "do it"


def _at(inputs: Inputs) -> str:
    return inputs.now.isoformat(timespec="seconds")


def _link(inputs: Inputs, name: str) -> str | None:
    return inputs.links.get(name)


# ---------------------------------------------------------------------------
# The policy document in force (config)
# ---------------------------------------------------------------------------


def policies_by_scope(inputs: Inputs) -> dict[str, Policy]:
    return {policy.scope: policy for policy in inputs.policies}


def policy_in_force(inputs: Inputs, item: str | None = None) -> Evidence | None:
    """The documents in force, each scope with its version: the configuration the Shield decides with."""
    if not inputs.policies:
        return None
    scopes = sorted(inputs.policies, key=lambda p: SCOPES_STRICTEST_FIRST.index(p.scope))
    words = ", ".join(f"{p.scope} v{p.version}" for p in scopes)
    return Evidence(
        kind="config",
        what=f"The Shield policy in force: {words}; the strictest scope decides first and a lower one never loosens it.",
        collected_at=_at(inputs),
        link=_link(inputs, "policies"),
        item=item,
        detail={
            "scopes": {
                p.scope: {
                    "version": p.version,
                    "rules": len(p.rules),
                    "expires": p.expires.isoformat() if p.expires else None,
                }
                for p in scopes
            }
        },
    )


def organization_scope_present(inputs: Inputs) -> bool:
    return "organization" in policies_by_scope(inputs)


def rules_deciding(
    inputs: Inputs, classes: Iterable[str], decisions: Iterable[str] = ("ask", "deny")
) -> list[tuple[str, Any]]:
    """The rules, in any scope, that decide one of ``classes`` with one of ``decisions``: (scope, rule)."""
    wanted = set(classes)
    verdicts = set(decisions)
    found: list[tuple[str, Any]] = []
    for policy in inputs.policies:
        for rule in policy.rules:
            if rule.decision not in verdicts:
                continue
            if not rule.classes or wanted & set(rule.classes):
                found.append((policy.scope, rule))
    return found


def rules_for(
    inputs: Inputs, classes: Sequence[str], item: str | None = None, *, decisions: Sequence[str] = ("ask", "deny")
) -> Evidence | None:
    """The rules that hold the given classes: ask first or leave it to me."""
    found = rules_deciding(inputs, classes, decisions)
    if not found:
        return None
    names = "; ".join(f"{scope}: {rule.name!r} → {rule.decision}" for scope, rule in found[:6])
    return Evidence(
        kind="config",
        what=f"Rules holding {', '.join(classes)}: {names}{' …' if len(found) > 6 else ''}.",
        collected_at=_at(inputs),
        link=_link(inputs, "policies"),
        item=item,
        detail={
            "rules": [
                {"scope": scope, "name": rule.name, "decision": rule.decision, "classes": list(rule.classes)}
                for scope, rule in found
            ]
        },
    )


def outside_workspace_held(inputs: Inputs, item: str | None = None) -> Evidence | None:
    """A rule that asks or refuses outside the workspace, in any scope."""
    found = [
        (p.scope, r) for p in inputs.policies for r in p.rules if r.where == "outside" and r.decision in ("ask", "deny")
    ]
    if not found:
        return None
    return Evidence(
        kind="config",
        what="A path outside the workspace is "
        + ("refused" if any(r.decision == "deny" for _, r in found) else "asked about")
        + f" ({found[0][0]}: {found[0][1].name!r}).",
        collected_at=_at(inputs),
        link=_link(inputs, "policies"),
        item=item,
        detail={"rules": [{"scope": s, "name": r.name, "decision": r.decision} for s, r in found]},
    )


def limits_set(inputs: Inputs, names: Sequence[str], item: str | None = None) -> Evidence | None:
    """The limits set in any scope, soft then hard."""
    found: dict[str, dict[str, Any]] = {}
    for policy in inputs.policies:
        for name in names:
            threshold = getattr(policy.limits, name, None)
            if threshold is not None and name not in found:
                found[name] = {"scope": policy.scope, "soft": threshold.soft, "hard": threshold.hard}
    if not found:
        return None
    words = ", ".join(f"{name} {v['soft']}/{v['hard']} ({v['scope']})" for name, v in found.items())
    return Evidence(
        kind="config",
        what=f"Limits, soft then hard: {words}.",
        collected_at=_at(inputs),
        link=_link(inputs, "policies"),
        item=item,
        detail={"limits": found},
    )


def network_allowlist(inputs: Inputs, item: str | None = None) -> Evidence | None:
    """What a fetch may reach: the allow-list of the strictest scope that says."""
    for policy in sorted(inputs.policies, key=lambda p: SCOPES_STRICTEST_FIRST.index(p.scope)):
        hosts = policy.network.fetch
        return Evidence(
            kind="config",
            what=(
                "A fetch reaches only " + ", ".join(hosts)
                if hosts
                else "Every fetch is refused: the allow-list is empty"
            )
            + f" ({policy.scope}).",
            collected_at=_at(inputs),
            link=_link(inputs, "policies"),
            item=item,
            detail={"scope": policy.scope, "fetch": list(hosts)},
        )
    return None


def mcp_allowlist(inputs: Inputs, item: str | None = None) -> Evidence | None:
    for policy in sorted(inputs.policies, key=lambda p: SCOPES_STRICTEST_FIRST.index(p.scope)):
        return Evidence(
            kind="config",
            what=(
                "The connections lent: " + ", ".join(policy.mcp.allow)
                if policy.mcp.allow
                else "No connection is lent beyond what the application names"
            )
            + f" ({policy.scope}); everything else is cut from the session.",
            collected_at=_at(inputs),
            link=_link(inputs, "policies"),
            item=item,
            detail={"scope": policy.scope, "allow": list(policy.mcp.allow)},
        )
    return None


def harness_admission(inputs: Inputs, item: str | None = None) -> Evidence | None:
    for policy in sorted(inputs.policies, key=lambda p: SCOPES_STRICTEST_FIRST.index(p.scope)):
        if policy.harnesses.admit or policy.scope == "organization":
            return Evidence(
                kind="config",
                what=f"Coding agents admitted: {', '.join(policy.harnesses.admit) or 'every registered one'}, on {policy.harnesses.credentials} credentials ({policy.scope}).",
                collected_at=_at(inputs),
                link=_link(inputs, "policies"),
                item=item,
                detail={
                    "scope": policy.scope,
                    "admit": list(policy.harnesses.admit),
                    "credentials": policy.harnesses.credentials,
                },
            )
    return None


def policy_weakened(inputs: Inputs) -> list[str]:
    """Every way the application's own document (the team scope) permits more than the organization's: empty when none does.

    The session document is the platform's default, the same everywhere, and a
    rule a person adds to a session can only tighten (a wider one is refused
    at the route); the engine decides strictest scope first in any case. What
    can be *written* wider than the organization's is the application's Rules,
    read into the team scope — and that is what this names.
    """
    by_scope = policies_by_scope(inputs)
    organization = by_scope.get("organization")
    team = by_scope.get("team")
    if organization is None or team is None:
        return []
    return widening(team, organization)


def organization_weakened(previous: Sequence[Policy], inputs: Inputs) -> list[str]:
    """Every way the organization's document now permits more than it did at the previous assessment."""
    before = next((p for p in previous if p.scope == "organization"), None)
    now = policies_by_scope(inputs).get("organization")
    if before is None or now is None:
        return []
    return [s.replace("a organization policy", "the organization's policy") for s in widening(now, before)]


# ---------------------------------------------------------------------------
# The record (logs)
# ---------------------------------------------------------------------------


def record_rows(inputs: Inputs, kind: str, **where: Any) -> list[Mapping[str, Any]]:
    """The record's entries of one kind whose payload matches ``where``."""
    found: list[Mapping[str, Any]] = []
    for entry in inputs.record:
        if entry.get("kind") != kind:
            continue
        payload = entry.get("payload") or {}
        if all(payload.get(key) == value for key, value in where.items()):
            found.append(entry)
    return found


def _last_at(rows: Sequence[Mapping[str, Any]]) -> str | None:
    ats = [str(row.get("at") or "") for row in rows if row.get("at")]
    return max(ats) if ats else None


def decisions_logged(
    inputs: Inputs, item: str | None = None, *, behaviours: Sequence[str] = (ASK_FIRST, LEAVE_TO_ME, DO_IT)
) -> Evidence | None:
    """The Shield's decisions in the record: by behaviour and by what decided them."""
    rows = [row for row in record_rows(inputs, "decision") if (row.get("payload") or {}).get("behaviour") in behaviours]
    if not rows:
        return None
    by_behaviour: dict[str, int] = {}
    by_because: dict[str, int] = {}
    for row in rows:
        payload = row.get("payload") or {}
        by_behaviour[str(payload.get("behaviour"))] = by_behaviour.get(str(payload.get("behaviour")), 0) + 1
        by_because[str(payload.get("because"))] = by_because.get(str(payload.get("because")), 0) + 1
    words = ", ".join(f"{n} {b}" for b, n in sorted(by_behaviour.items()))
    return Evidence(
        kind="logs",
        what=f"{len(rows)} decisions kept in the record over {inputs.period_days} days: {words}; decided by {', '.join(f'{n} by {b}' for b, n in sorted(by_because.items()))}.",
        collected_at=_at(inputs),
        link=_link(inputs, "activity"),
        item=item,
        detail={"rows": len(rows), "by_behaviour": by_behaviour, "by_because": by_because, "last": _last_at(rows)},
    )


def approvals_logged(inputs: Inputs, item: str | None = None) -> Evidence | None:
    rows = record_rows(inputs, "approval")
    if not rows:
        return None
    approved = sum(
        1
        for r in rows
        if (r.get("payload") or {}).get("state") == "approved" or (r.get("payload") or {}).get("decision") == "approved"
    )
    return Evidence(
        kind="logs",
        what=f"{len(rows)} approvals answered by a person in the record ({approved} approved, {len(rows) - approved} declined), each with who decided.",
        collected_at=_at(inputs),
        link=_link(inputs, "activity"),
        item=item,
        detail={"rows": len(rows), "approved": approved, "last": _last_at(rows)},
    )


def tool_calls_logged(inputs: Inputs, item: str | None = None) -> Evidence | None:
    rows = record_rows(inputs, "tool_call")
    if not rows:
        return None
    kinds: dict[str, int] = {}
    for row in rows:
        kind = str((row.get("payload") or {}).get("kind") or "other")
        kinds[kind] = kinds.get(kind, 0) + 1
    return Evidence(
        kind="logs",
        what=f"{len(rows)} actions kept in the record with their kind, path or command, and outcome: {', '.join(f'{n} {k}' for k, n in sorted(kinds.items()))}.",
        collected_at=_at(inputs),
        link=_link(inputs, "activity"),
        item=item,
        detail={"rows": len(rows), "by_kind": kinds, "last": _last_at(rows)},
    )


def feedback_logged(inputs: Inputs, item: str | None = None) -> Evidence | None:
    rows = record_rows(inputs, "feedback")
    if not rows:
        return None
    return Evidence(
        kind="logs",
        what=f"{len(rows)} answers people gave on what it said, kept in the record.",
        collected_at=_at(inputs),
        link=_link(inputs, "activity"),
        item=item,
        detail={"rows": len(rows)},
    )


def mcp_rows_logged(inputs: Inputs, item: str | None = None) -> Evidence | None:
    rows = [
        r
        for r in record_rows(inputs, "decision")
        if (r.get("payload") or {}).get("kind") == "mcp" or (r.get("payload") or {}).get("server")
    ]
    rows += [r for r in record_rows(inputs, "tool_call") if (r.get("payload") or {}).get("kind") == "mcp"]
    if not rows:
        return None
    return Evidence(
        kind="logs",
        what=f"{len(rows)} rows of connections reached through the gateway, each naming the server and the decision.",
        collected_at=_at(inputs),
        link=_link(inputs, "activity"),
        item=item,
        detail={"rows": len(rows)},
    )


def record_kept(inputs: Inputs, item: str | None = None) -> Evidence | None:
    """The record as a whole: that it is written, how many entries, since when."""
    if not inputs.record:
        return None
    kinds: dict[str, int] = {}
    for row in inputs.record:
        kinds[str(row.get("kind"))] = kinds.get(str(row.get("kind")), 0) + 1
    return Evidence(
        kind="logs",
        what=f"The record: {len(inputs.record)} entries over {inputs.period_days} days — {', '.join(f'{n} {k}' for k, n in sorted(kinds.items()))} — each a session's, with its time and what decided it.",
        collected_at=_at(inputs),
        link=_link(inputs, "activity"),
        item=item,
        detail={"entries": len(inputs.record), "by_kind": kinds, "last": _last_at(inputs.record)},
    )


# ---------------------------------------------------------------------------
# OTEL (logs)
# ---------------------------------------------------------------------------


def otel_counts(inputs: Inputs, item: str | None = None) -> Evidence | None:
    if not inputs.counts:
        return None
    words = ", ".join(f"{name} {count}" for name, count in sorted(inputs.counts.items()))
    return Evidence(
        kind="logs",
        what=f"The Shield's counts on the dashboard: {words}.",
        collected_at=_at(inputs),
        link=_link(inputs, "dashboard"),
        item=item,
        detail={"counts": dict(inputs.counts)},
    )


# ---------------------------------------------------------------------------
# Drills, gates and benchmarks (evals)
# ---------------------------------------------------------------------------


def drill(inputs: Inputs, drill_id: str, item: str | None = None) -> Evidence | None:
    """A drill that was run and refused what it tried; a drill that allowed it, or was not run, is no evidence."""
    for result in inputs.drills:
        if result.id == drill_id and result.outcome == "refused":
            return Evidence(
                kind="evals",
                what=f"Drill {result.title}: refused{(' — ' + result.says) if result.says else ''}{(' (' + result.where + ')') if result.where else ''}.",
                collected_at=_at(inputs),
                link=result.link or _link(inputs, "drills"),
                item=item,
                detail={"drill": result.id, "outcome": result.outcome, "at": result.at, "where": result.where},
            )
    return None


def drill_outcome(inputs: Inputs, drill_id: str) -> DrillResult | None:
    for result in inputs.drills:
        if result.id == drill_id:
            return result
    return None


def failed_drills(inputs: Inputs) -> list[DrillResult]:
    return [d for d in inputs.drills if d.outcome in ("allowed", "failed")]


def validation_gate(inputs: Inputs, item: str | None = None) -> Evidence | None:
    """The Validate gate passed on this version."""
    validation = inputs.validation
    if not validation or validation.get("gate") != "passed":
        return None
    return Evidence(
        kind="evals",
        what=f"Its tests passed on version {validation.get('version')}: {round(float(validation.get('pass_rate') or 0) * 100)}% of them, where it ships at {round(float(validation.get('min_pass_rate') or 0) * 100)}%.",
        collected_at=_at(inputs),
        link=_link(inputs, "validate"),
        item=item,
        detail=dict(validation),
    )


def safety_held(inputs: Inputs, item: str | None = None) -> Evidence | None:
    """Every safety test of the run on this version held."""
    validation = inputs.validation or {}
    safety = validation.get("safety")
    if (
        validation.get("gate") != "passed"
        or not safety
        or not safety.get("total")
        or safety.get("held") != safety.get("total")
    ):
        return None
    return Evidence(
        kind="evals",
        what=f"The {safety['total']} safety tests every application runs held on version {validation.get('version')}: an instruction hidden in what it reads, a request outside its rules, a request for what it must not give, a request to change its own instructions.",
        collected_at=_at(inputs),
        link=_link(inputs, "validate"),
        item=item,
        detail={"safety": dict(safety), "version": validation.get("version")},
    )


def validation_at(inputs: Inputs) -> str | None:
    validation = inputs.validation or {}
    return str(validation.get("at")) if validation.get("at") else None


def benchmark(inputs: Inputs, name_part: str, item: str | None = None) -> Evidence | None:
    for run in inputs.benchmarks:
        if name_part.lower() in str(run.get("name") or "").lower():
            return Evidence(
                kind="evals",
                what=f"Benchmark {run.get('name')}: {run.get('score')} on {run.get('at')}.",
                collected_at=_at(inputs),
                link=run.get("link") or _link(inputs, "benchmarks"),
                item=item,
                detail=dict(run),
            )
    return None


# ---------------------------------------------------------------------------
# The organization's documents, a third party's reports (documentation, evals)
# ---------------------------------------------------------------------------


def signed_document(
    inputs: Inputs, control_id: str, item: str | None = None
) -> tuple[Evidence | None, str | None, Document | None]:
    """The organization's document for a control, as evidence only once signed and in date: (evidence, why not, the document)."""
    document = inputs.documents.get(control_id)
    if document is None:
        return (
            None,
            "no document of the organization exists for it yet: it starts from the template in the Studio",
            None,
        )
    if document.unfilled:
        return (
            None,
            f"the document {document.title!r} still has fields to fill: {', '.join(document.unfilled)}",
            document,
        )
    if not document.signed:
        return (
            None,
            f"the document {document.title!r} (v{document.version}, owner {document.owner}) is written but nobody has signed it",
            document,
        )
    if not document.in_date(inputs.now):
        return (
            None,
            f"the document {document.title!r} is past its review date ({document.review_on}): it is reviewed and signed again",
            document,
        )
    return (
        Evidence(
            kind="documentation",
            what=f"{document.title} v{document.version}, owner {document.owner}, signed by {document.signed_by} on {document.signed_on}, reviewed by {document.review_on}.",
            collected_at=_at(inputs),
            link=document.link or _link(inputs, "documents"),
            item=item,
            detail={
                "control": control_id,
                "version": document.version,
                "owner": document.owner,
                "signed_by": document.signed_by,
                "signed_on": document.signed_on,
                "review_on": document.review_on,
            },
        ),
        None,
        document,
    )


def third_party_report(
    inputs: Inputs, control_id: str, months: int | None, item: str | None = None
) -> tuple[Evidence | None, str | None, ThirdPartyReport | None]:
    """A third party's report for a control, as evidence while within its cadence and passed."""
    report = inputs.third_party.get(control_id)
    if report is None:
        return (
            None,
            "no third-party report has been recorded for it: the Shield supplies the representative configurations, a third party tests them and the report is recorded here",
            None,
        )
    from agent_shield.conformance import cadence_of

    clock = cadence_of(months, report.on, inputs.now)
    if clock.overdue:
        return (
            None,
            f"the last report ({report.by}, {report.on}) is older than the cadence of {months} months: a new test is due since {clock.next_due}",
            report,
        )
    if report.outcome != "passed":
        return (
            None,
            f"the last report ({report.by}, {report.on}) did not pass: {report.summary or report.outcome}",
            report,
        )
    return (
        Evidence(
            kind="evals",
            what=f"Third-party report by {report.by} on {report.on}: passed{(' — ' + report.summary) if report.summary else ''}.",
            collected_at=_at(inputs),
            link=report.link,
            item=item,
            detail={"by": report.by, "on": report.on, "outcome": report.outcome},
        ),
        None,
        report,
    )


# ---------------------------------------------------------------------------
# Facts and demonstrations
# ---------------------------------------------------------------------------


def fact(inputs: Inputs, name: str, item: str | None = None, kind: str = "config") -> Evidence | None:
    """A fact the host asserts, as evidence when it holds."""
    found = inputs.facts.get(name)
    if found is None or not found.holds:
        return None
    return Evidence(
        kind=kind,
        what=found.says + (f" Proved: {found.proved}." if found.proved else ""),
        collected_at=_at(inputs),
        link=found.link or _link(inputs, name),
        item=item,
        detail={"fact": name, "proved": found.proved},
    )


def fact_missing(inputs: Inputs, name: str, says: str) -> str:
    """What is missing when a fact is not held: the host's own words when it said why, else ours."""
    found = inputs.facts.get(name)
    if found is not None and not found.holds and found.says:
        return found.says
    return says


def demonstration(inputs: Inputs, name: str, says: str, item: str | None = None) -> Evidence | None:
    link = inputs.demonstrations.get(name)
    if not link:
        return None
    return Evidence(
        kind="demonstration", what=says, collected_at=_at(inputs), link=link, item=item, detail={"screen": name}
    )


def harness_register(inputs: Inputs, item: str | None = None) -> Evidence | None:
    if not inputs.harness:
        return None
    entry = inputs.harness
    return Evidence(
        kind="documentation",
        what=f"The coding agent's register entry: {entry.get('adapter')} {entry.get('version')}, licence {entry.get('licence')}, credential {entry.get('credential')}, third parties {entry.get('served_to_third_parties')}.",
        collected_at=_at(inputs),
        link=_link(inputs, "register"),
        item=item,
        detail=dict(entry),
    )


__all__ = [name for name in dir() if not name.startswith("_") and name not in ("annotations",)]
