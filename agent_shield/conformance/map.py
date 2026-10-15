# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The evidence map: AIUC-1's 55 controls, each with its collectors and its status rule (SHIELD §6.9, SH-61).

A rule answers ``(status, reason, evidence, missing, last)``: the status, why
in a sentence, the evidence attached, what is missing named, and when the
control was last demonstrated (the cadence clock reads it). The five statuses
are honest by construction:

- a **documentation** control (``_organizations``) is *the organization's*
  until a person's signed, in-date document exists — never auto-met;
- a **third-party testing** control (``_third_party``) is *a third party's*
  until a report recorded within its cadence says it passed;
- a **technical** control is *met by evidence* only when every piece its rule
  asks for was collected, else *partly met* with the missing pieces named;
- a control the standard **retired** is *not applicable*, with the release.

ISO/IEC 42001's clauses are answered through the crosswalk (SH-66,
:func:`answer_covered`): a clause's status is the weakest of the AIUC-1
controls that cover it, *partly met* at most where the crosswalk says the
coverage is partial, and *the organization's* where nothing covers it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from agent_shield.conformance import STATUS_ORDER, Assessment, Evidence, Inputs
from agent_shield.conformance import collect as c

Answer = tuple[str, str, list[Evidence], list[str], str | None]
Rule = Callable[[Any, Inputs], Answer]

#: The drills of SH-37, by id, as the map names them.
DRILLS = {
    "outside-curl": "an outside curl from the pod",
    "write-outside-workspace": "a write outside the workspace",
    "secret-in-argument": "a secret in a tool argument",
    "own-port": "a runtime reached at its own port",
    "others-notebook": "a read of another person's notebook",
    "git-push": "a git push without asking",
    "subagent-write-read-only": "a sub-agent's write under a read-only manifest",
}

#: The facts a host asserts, each with what is missing when it does not.
FACTS = {
    "egress_boundary": "the pod's egress boundary (the operator's init container and NetworkPolicy)",
    "iam_custody": "credentials kept by IAM and declared secrets reaching only the process",
    "redaction_at_row": "every record row redacted before it is kept",
    "pod_non_root": "the runtime pod running as a non-root user with its secrets from IAM",
    "own_routes_only": "a deployment's runtime answering only its application's own routes",
    "workspace_is_sandbox": "the workspace being the runtime's sandbox, with the companion's mounts the only data reached",
    "execution_credential_scope": "the execution credential narrowed to the deployment's task grant",
    "record_per_account": "the record kept per account, a conversation readable by whoever opened it only",
    "runtime_per_deployment": "a runtime per deployment, never shared between customers",
    "narrowed_tokens_fail_closed": "narrowed tokens failing closed at IAM",
    "input_output_safety": "the input and output safety guardrail on every turn",
    "gateway_refusals": "the MCP gateway refusing a call outside the manifest",
    "rate_limits": "a rate limit on the deployment's routes and the visitors' ceilings",
    "record_include": "the record keeping only what `record.include` names, in A-01's safe vocabulary",
    "sandboxed_execution": "code and commands running in the runtime's sandbox",
    "waiting_for_you": "Waiting for you: an action asked about waits for a person on the page, the phone and the Approvals page",
    "stop_and_barge_in": "Stop and barge-in on a running session, the phone's inbox",
    "dashboard": "the Shield dashboard on the observability service",
    "trace_across_chain": "one trace from the caller to the tool, through the gateway",
    "versions_kept": "every shipped version kept with who shipped it and when",
    "mcp_audit": "the gateway's audit of every connection reached (MCP, PAP, PACT, commerce)",
    "disclosure": "the presence line, *Live*, the embed's notice and the assistant's own words saying it is an application",
    "signed_fetch_only": "outside requests only as signed fetches through the gateway",
    "record_retention": "the record deleted after its retention period",
}


def _missing_fact(inputs: Inputs, name: str) -> str:
    return c.fact_missing(inputs, name, FACTS[name])


def _collect(inputs: Inputs, wanted: Sequence[tuple[str, Evidence | None]]) -> tuple[list[Evidence], list[str]]:
    """Evidence found and, for each piece not found, what is missing in words."""
    evidence: list[Evidence] = []
    missing: list[str] = []
    for words, found in wanted:
        if found is None:
            missing.append(words)
        else:
            evidence.append(found)
    return evidence, missing


def _technical(
    control: Any,
    inputs: Inputs,
    wanted: Sequence[tuple[str, Evidence | None]],
    *,
    also_missing: Sequence[str] = (),
    last: str | None = None,
) -> Answer:
    """Met when every piece is there; partly met otherwise, the missing named."""
    evidence, missing = _collect(inputs, wanted)
    missing = [*missing, *also_missing]
    if not missing:
        return (
            "met",
            f"{control.id} is met by the evidence attached: {len(evidence)} pieces, each collected automatically.",
            evidence,
            [],
            last,
        )
    if evidence:
        return (
            "partly",
            f"{control.id} is partly met: {len(evidence)} pieces attached; missing {len(missing)} — "
            + "; ".join(missing)
            + ".",
            evidence,
            missing,
            last,
        )
    return (
        "partly",
        f"{control.id} is not met yet: nothing could be attached — " + "; ".join(missing) + ".",
        evidence,
        missing,
        last,
    )


def _organizations(control: Any, inputs: Inputs, *, also: Sequence[tuple[str, Evidence | None]] = ()) -> Answer:
    """A document a person writes and signs: the organization's until then, met once signed and in date (and the technical pieces, if any, there)."""
    document, why_not, found = c.signed_document(
        inputs, control.id, item=next((e.id for e in control.evidence if e.kind == "documentation"), None)
    )
    evidence, missing = _collect(inputs, also)
    last = found.signed_on if found and found.signed else None
    if document is None:
        return (
            "organizations",
            f"{control.id} is the organization's: {why_not}.",
            evidence,
            [why_not or "the organization's document", *missing],
            last,
        )
    if missing:
        return (
            "partly",
            f"{control.id} is partly met: the organization's document is signed, but " + "; ".join(missing) + ".",
            [document, *evidence],
            missing,
            last,
        )
    return (
        "met",
        f"{control.id} is met: the organization's document is signed and in date, with the evidence attached.",
        [document, *evidence],
        [],
        last,
    )


def _third_party(control: Any, inputs: Inputs) -> Answer:
    """The standard's third-party testing: a third party's until a report recorded within the cadence passed."""
    report, why_not, found = c.third_party_report(
        inputs,
        control.id,
        control.cadence_months,
        item=next((e.id for e in control.evidence if e.kind == "evals"), None),
    )
    last = found.on if found else None
    evidence = [e for e in (c.harness_register(inputs), c.policy_in_force(inputs)) if e is not None]
    if report is None:
        return (
            "third_party",
            f"{control.id} is a third party's: {why_not}. The representative configurations are in the assessor's export.",
            evidence,
            [why_not or "a third party's report"],
            last,
        )
    return (
        "met",
        f"{control.id} is met: a third party's report within the cadence says it passed.",
        [report, *evidence],
        [],
        last,
    )


def _organizations_only(control: Any, inputs: Inputs) -> Answer:
    return _organizations(control, inputs)


# ---------------------------------------------------------------------------
# A. Data & Privacy
# ---------------------------------------------------------------------------


def a001(control: Any, inputs: Inputs) -> Answer:
    return _organizations(
        control,
        inputs,
        also=[(_missing_fact(inputs, "record_retention"), c.fact(inputs, "record_retention", item="A001.2"))],
    )


def a002(control: Any, inputs: Inputs) -> Answer:
    return _organizations(control, inputs)


def a003(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "workspace_is_sandbox"), c.fact(inputs, "workspace_is_sandbox", item="A003.1")),
            (
                _missing_fact(inputs, "execution_credential_scope"),
                c.fact(inputs, "execution_credential_scope", item="A003.1"),
            ),
            ("a rule asking or refusing outside the workspace", c.outside_workspace_held(inputs, item="A003.1")),
            ("the connections lent, as an allow-list", c.mcp_allowlist(inputs, item="A003.1")),
            ("the Shield policy in force", c.policy_in_force(inputs)),
        ],
    )


def a004(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            ("a rule asking or refusing outside the workspace", c.outside_workspace_held(inputs, item="A004.1")),
            (_missing_fact(inputs, "redaction_at_row"), c.fact(inputs, "redaction_at_row", item="A004.1")),
            ("what a fetch may reach", c.network_allowlist(inputs, item="A004.1")),
        ],
        also_missing=[
            "what the organization counts as a trade secret, and where it may not go: the organization's output policy (A002) names it"
        ],
    )


def a005(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "record_per_account"), c.fact(inputs, "record_per_account", item="A005.1")),
            (_missing_fact(inputs, "runtime_per_deployment"), c.fact(inputs, "runtime_per_deployment", item="A005.1")),
            (_missing_fact(inputs, "iam_custody"), c.fact(inputs, "iam_custody", item="A005.1")),
        ],
    )


def a006(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "redaction_at_row"), c.fact(inputs, "redaction_at_row", item="A006.1")),
            (_missing_fact(inputs, "record_include"), c.fact(inputs, "record_include", item="A006.1")),
            (_missing_fact(inputs, "input_output_safety"), c.fact(inputs, "input_output_safety", item="A006.1")),
        ],
        also_missing=[
            "what the model itself does with personal data in an answer: the provider's, read in the vendor due diligence (E006)"
        ],
    )


def a007(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            ("a benchmark on intellectual-property outputs", c.benchmark(inputs, "intellectual", item="A007.1")),
        ],
        also_missing=["the organization's output policy (A002) saying what may be reproduced"],
    )


def a008(control: Any, inputs: Inputs) -> Answer:
    drill_result = c.drill_outcome(inputs, "secret-in-argument")
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "iam_custody"), c.fact(inputs, "iam_custody", item="A008.3")),
            (_missing_fact(inputs, "redaction_at_row"), c.fact(inputs, "redaction_at_row", item="A008.5")),
            ("a rule asking about a command naming a credential", c.rules_for(inputs, ["execute"], item="A008.1")),
            (
                f"the drill {DRILLS['secret-in-argument']}, refused",
                c.drill(inputs, "secret-in-argument", item="A008.5"),
            ),
        ],
        last=drill_result.at if drill_result and drill_result.outcome == "refused" else None,
    )


def a009(control: Any, inputs: Inputs) -> Answer:
    return _third_party(control, inputs)


# ---------------------------------------------------------------------------
# B. Security
# ---------------------------------------------------------------------------


def b001(control: Any, inputs: Inputs) -> Answer:
    return _third_party(control, inputs)


def b002(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "input_output_safety"), c.fact(inputs, "input_output_safety", item="B002.1")),
            (_missing_fact(inputs, "gateway_refusals"), c.fact(inputs, "gateway_refusals", item="B002.1")),
            ("the safety tests held on this version", c.safety_held(inputs, item="B002.1")),
        ],
        also_missing=["the detection rules reviewed quarterly: the organization's review, recorded"],
    )


def b003(control: Any, inputs: Inputs) -> Answer:
    return _organizations(control, inputs)


def b004(control: Any, inputs: Inputs) -> Answer:
    own_port = c.drill_outcome(inputs, "own-port")
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "own_routes_only"), c.fact(inputs, "own_routes_only", item="B004.1")),
            (_missing_fact(inputs, "rate_limits"), c.fact(inputs, "rate_limits", item="B004.1")),
            ("the tool-call limit, soft then hard", c.limits_set(inputs, ["tool_calls"], item="B004.1")),
            (f"the drill {DRILLS['own-port']}, refused", c.drill(inputs, "own-port", item="B004.1")),
        ],
        last=own_port.at if own_port and own_port.outcome == "refused" else None,
    )


def b005(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "input_output_safety"), c.fact(inputs, "input_output_safety", item="B005.1")),
        ],
        also_missing=["the organization's own filter rules, beyond the platform's"],
    )


def b006(control: Any, inputs: Inputs) -> Answer:
    weakened = c.policy_weakened(inputs)
    outside = c.drill_outcome(inputs, "write-outside-workspace")
    wanted = [
        (_missing_fact(inputs, "egress_boundary"), c.fact(inputs, "egress_boundary", item="B006.1")),
        (
            "a rule asking or refusing before the agent sends, buys or deletes",
            c.rules_for(inputs, ["send", "buy", "delete"], item="B006.1"),
        ),
        (
            "the organization's scope in force, the strictest first",
            c.policy_in_force(inputs, item="B006.1") if c.organization_scope_present(inputs) else None,
        ),
        (_missing_fact(inputs, "own_routes_only"), c.fact(inputs, "own_routes_only", item="B006.1")),
        (f"the drill {DRILLS['outside-curl']}, refused", c.drill(inputs, "outside-curl", item="B006.2")),
        (
            f"the drill {DRILLS['write-outside-workspace']}, refused",
            c.drill(inputs, "write-outside-workspace", item="B006.2"),
        ),
        ("the Shield's decisions in the record", c.decisions_logged(inputs, item="B006.1")),
    ]
    also = [f"the application's rules permit more than the organization's: {s}" for s in weakened]
    return _technical(
        control,
        inputs,
        wanted,
        also_missing=also,
        last=outside.at if outside and outside.outcome == "refused" else None,
    )


def b007(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (
                _missing_fact(inputs, "narrowed_tokens_fail_closed"),
                c.fact(inputs, "narrowed_tokens_fail_closed", item="B007.1"),
            ),
            (_missing_fact(inputs, "iam_custody"), c.fact(inputs, "iam_custody", item="B007.1")),
        ],
        also_missing=["the quarterly access review of who may reach the applications: the organization's, recorded"],
    )


def b008(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "pod_non_root"), c.fact(inputs, "pod_non_root", item="B008.1")),
            (_missing_fact(inputs, "egress_boundary"), c.fact(inputs, "egress_boundary", item="B008.1")),
            (_missing_fact(inputs, "iam_custody"), c.fact(inputs, "iam_custody", item="B008.1")),
        ],
    )


def b009(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "record_include"), c.fact(inputs, "record_include", item="B009.1")),
            (_missing_fact(inputs, "redaction_at_row"), c.fact(inputs, "redaction_at_row", item="B009.1")),
        ],
    )


def b010(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            ("a benchmark on secure patterns in generated code", c.benchmark(inputs, "secure", item="B010.1")),
            (_missing_fact(inputs, "sandboxed_execution"), c.fact(inputs, "sandboxed_execution", item="B010.1")),
        ],
    )


# ---------------------------------------------------------------------------
# C. Safety
# ---------------------------------------------------------------------------


def c001(control: Any, inputs: Inputs) -> Answer:
    return _organizations(control, inputs)


def c002(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            ("its tests passed on this version", c.validation_gate(inputs, item="C002.1")),
            ("the safety tests held on this version", c.safety_held(inputs, item="C002.1")),
            (f"the drill {DRILLS['outside-curl']}, refused", c.drill(inputs, "outside-curl", item="C002.1")),
        ],
        last=c.validation_at(inputs),
    )


def c003(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            ("the safety tests held on this version", c.safety_held(inputs, item="C003.1")),
            (_missing_fact(inputs, "input_output_safety"), c.fact(inputs, "input_output_safety", item="C003.1")),
        ],
        last=c.validation_at(inputs),
    )


def _scope_outputs(control: Any, inputs: Inputs, item: str) -> Answer:
    taxonomy, why_not, _ = c.signed_document(inputs, "C001", item=item)
    return _technical(
        control,
        inputs,
        [
            (
                "a rule deciding by class: do it, ask me first, leave it to me",
                c.rules_for(inputs, ["read", "write", "send", "buy", "delete", "execute"], item=item),
            ),
            (
                "the safety tests held on this version (a request outside its rules among them)",
                c.safety_held(inputs, item=item),
            ),
            (
                f"the organization's risk taxonomy (C001): {why_not}"
                if why_not
                else "the organization's risk taxonomy (C001)",
                taxonomy,
            ),
        ],
        last=c.validation_at(inputs),
    )


def c004(control: Any, inputs: Inputs) -> Answer:
    return _scope_outputs(control, inputs, "C004.1")


def c005(control: Any, inputs: Inputs) -> Answer:
    return _scope_outputs(control, inputs, "C005.1")


def c006(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "sandboxed_execution"), c.fact(inputs, "sandboxed_execution", item="C006.1")),
            (_missing_fact(inputs, "redaction_at_row"), c.fact(inputs, "redaction_at_row", item="C006.1")),
            (_missing_fact(inputs, "record_include"), c.fact(inputs, "record_include", item="C006.1")),
        ],
    )


def c007(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (
                "a rule asking first before a sensitive action",
                c.rules_for(inputs, ["send", "buy", "delete", "execute"], item="C007.1", decisions=("ask",)),
            ),
            (
                _missing_fact(inputs, "waiting_for_you"),
                c.fact(inputs, "waiting_for_you", item="C007.1", kind="demonstration"),
            ),
            ("the approvals people answered, in the record", c.approvals_logged(inputs, item="C007.1")),
        ],
    )


def c008(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "dashboard"), c.fact(inputs, "dashboard", item="C008.1", kind="demonstration")),
            ("the Shield's counts on the dashboard", c.otel_counts(inputs, item="C008.1")),
        ],
    )


def c009(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (
                _missing_fact(inputs, "stop_and_barge_in"),
                c.fact(inputs, "stop_and_barge_in", item="C009.1", kind="demonstration"),
            ),
            (
                _missing_fact(inputs, "waiting_for_you"),
                c.fact(inputs, "waiting_for_you", item="C009.1", kind="demonstration"),
            ),
            ("what people said of its answers, in the record", c.feedback_logged(inputs, item="C009.1")),
        ],
    )


def c010(control: Any, inputs: Inputs) -> Answer:
    return _third_party(control, inputs)


# ---------------------------------------------------------------------------
# D. Reliability
# ---------------------------------------------------------------------------


def d001(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            ("its tests passed on this version, against what it knows", c.validation_gate(inputs, item="D001.1")),
            ("a benchmark on hallucinated outputs", c.benchmark(inputs, "hallucin", item="D001.1")),
        ],
        last=c.validation_at(inputs),
    )


def d003(control: Any, inputs: Inputs) -> Answer:
    weakened = c.policy_weakened(inputs)
    wanted = [
        (
            "a rule deciding by class before an action runs",
            c.rules_for(inputs, ["execute", "delete", "send", "buy", "write"], item="D003.1"),
        ),
        ("the connections lent, as an allow-list", c.mcp_allowlist(inputs, item="D003.1")),
        (
            "the limits on tool calls and terminals, soft then hard",
            c.limits_set(inputs, ["tool_calls", "terminals_open"], item="D003.2"),
        ),
        (
            "every tool call kept in the record with its kind, path or command and outcome",
            c.tool_calls_logged(inputs, item="D003.3"),
        ),
        ("the Shield's decisions in the record, by what decided them", c.decisions_logged(inputs, item="D003.3")),
        (
            "a rule asking a person first before a sensitive action",
            c.rules_for(inputs, ["execute", "delete", "send", "buy"], item="D003.4", decisions=("ask",)),
        ),
        (
            _missing_fact(inputs, "waiting_for_you"),
            c.fact(inputs, "waiting_for_you", item="D003.4", kind="demonstration"),
        ),
    ]
    also = [f"the application's rules permit more than the organization's: {s}" for s in weakened]
    return _technical(control, inputs, wanted, also_missing=also, last=c.validation_at(inputs))


def d004(control: Any, inputs: Inputs) -> Answer:
    return _third_party(control, inputs)


# ---------------------------------------------------------------------------
# E. Accountability
# ---------------------------------------------------------------------------


def e004(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "versions_kept"), c.fact(inputs, "versions_kept", item="E004.1")),
            ("the approvals people answered, in the record", c.approvals_logged(inputs, item="E004.1")),
        ],
        also_missing=["who owns the review of each change: the organization's, named in its documents"],
    )


def e005(control: Any, inputs: Inputs) -> Answer:
    return _organizations(
        control, inputs, also=[(_missing_fact(inputs, "iam_custody"), c.fact(inputs, "iam_custody", item="E005.1"))]
    )


def e006(control: Any, inputs: Inputs) -> Answer:
    return _organizations(
        control,
        inputs,
        also=[("the coding agent's register entry", c.harness_register(inputs, item="E006.1"))]
        if inputs.harness
        else (),
    )


def e009(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "mcp_audit"), c.fact(inputs, "mcp_audit", item="E009.1", kind="logs")),
            ("the connections reached, in the record", c.mcp_rows_logged(inputs, item="E009.1")),
        ],
    )


def e015(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            ("the record of what it did", c.record_kept(inputs, item="E015.1")),
            (
                _missing_fact(inputs, "trace_across_chain"),
                c.fact(inputs, "trace_across_chain", item="E015.1", kind="logs"),
            ),
            ("the Shield's counts on the dashboard", c.otel_counts(inputs, item="E015.1")),
        ],
    )


def e016(control: Any, inputs: Inputs) -> Answer:
    return _technical(
        control,
        inputs,
        [
            (_missing_fact(inputs, "disclosure"), c.fact(inputs, "disclosure", item="E016.1", kind="demonstration")),
            (
                "the page where the presence line is seen",
                c.demonstration(
                    inputs,
                    "presence_line",
                    "The page says it is an application, in the presence line and in its own words.",
                    item="E016.1",
                ),
            ),
        ],
    )


def e018(control: Any, inputs: Inputs) -> Answer:
    return _third_party(control, inputs)


# ---------------------------------------------------------------------------
# F. Society
# ---------------------------------------------------------------------------


def _misuse(control: Any, inputs: Inputs, item: str) -> Answer:
    return _technical(
        control,
        inputs,
        [
            ("a rule asking or refusing before a command runs", c.rules_for(inputs, ["execute"], item=item)),
            ("what a fetch may reach", c.network_allowlist(inputs, item=item)),
            (_missing_fact(inputs, "egress_boundary"), c.fact(inputs, "egress_boundary", item=item)),
            (_missing_fact(inputs, "signed_fetch_only"), c.fact(inputs, "signed_fetch_only", item=item)),
        ],
        also_missing=[
            "the model provider's own guardrails against misuse: the provider's, read in the vendor due diligence (E006)"
        ],
    )


def f001(control: Any, inputs: Inputs) -> Answer:
    return _misuse(control, inputs, "F001.1")


def f002(control: Any, inputs: Inputs) -> Answer:
    return _misuse(control, inputs, "F002.1")


#: The map: every control of AIUC-1 at its 2026.4 version, to its rule. The retired ones
#: (C011, C012, D002, E007, E014) are answered before the map is read (not applicable).
MAP: dict[str, Rule] = {
    "A001": a001,
    "A002": a002,
    "A003": a003,
    "A004": a004,
    "A005": a005,
    "A006": a006,
    "A007": a007,
    "A008": a008,
    "A009": a009,
    "B001": b001,
    "B002": b002,
    "B003": b003,
    "B004": b004,
    "B005": b005,
    "B006": b006,
    "B007": b007,
    "B008": b008,
    "B009": b009,
    "B010": b010,
    "C001": c001,
    "C002": c002,
    "C003": c003,
    "C004": c004,
    "C005": c005,
    "C006": c006,
    "C007": c007,
    "C008": c008,
    "C009": c009,
    "C010": c010,
    "D001": d001,
    "D003": d003,
    "D004": d004,
    "E001": _organizations_only,
    "E002": _organizations_only,
    "E003": _organizations_only,
    "E004": e004,
    "E005": e005,
    "E006": e006,
    "E008": _organizations_only,
    "E009": e009,
    "E010": _organizations_only,
    "E011": _organizations_only,
    "E012": _organizations_only,
    "E013": _organizations_only,
    "E015": e015,
    "E016": e016,
    "E017": _organizations_only,
    "E018": e018,
    "F001": f001,
    "F002": f002,
}

#: The evidence kinds each control takes, as the map reads them (the standard's own are on the spec).
KINDS: dict[str, tuple[str, ...]] = {
    control_id: ("documentation",)
    if rule is _organizations_only
    else ("evals", "report")
    if rule in (a009, b001, c010, d004, e018)
    else ("config", "logs", "evals", "demonstration")
    for control_id, rule in MAP.items()
}


def rule_for(control_id: str) -> Rule | None:
    return MAP.get(control_id)


def covering_standard(standard_id: str) -> Any:
    """The standard whose controls cover another's clauses, from the catalogue."""
    try:
        from agentspecs.standards import get_standard
    except ImportError as error:
        raise ImportError(
            'the standards catalogue needs agentspecs: pip install "datalayer-agent-shield[register]"'
        ) from error
    spec = get_standard(standard_id)
    if spec is None:
        raise ValueError(f"the catalogue has no standard {standard_id!r}")
    return spec


def answer_covered(control: Any, covering: Assessment | None, inputs: Inputs) -> Answer:
    """A clause answered through the controls that cover it (SH-66): the weakest of them, bounded by the coverage."""
    if covering is None:
        raise ValueError(f"the clause {control.id} is covered by another standard, which was not assessed")
    if control.coverage == "none" or not control.covered_by:
        note = f" {control.coverage_note}" if control.coverage_note else ""
        return (
            "organizations",
            f"{control.id} is the organization's: no control of {covering.standard_name} covers it.{note}",
            [],
            ["the organization's own record of this clause, beyond what the Shield evidences"],
            None,
        )
    answers = [covering.control(other) for other in control.covered_by]
    weakest = min(answers, key=lambda a: STATUS_ORDER.index(a.status))
    status = weakest.status
    evidence = [e for a in answers for e in a.evidence]
    missing = [m for a in answers for m in a.missing]
    if control.coverage == "partial" and status == "met":
        status = "partly"
        missing = [
            *missing,
            f"the crosswalk says {covering.standard_name} covers this clause partially: {control.coverage_note or "the rest is the organization's"}",
        ]
    reason = (
        f"{control.id} is {_words(status)} through {', '.join(control.covered_by)} of {covering.standard_name} ({control.coverage} coverage): "
        + "; ".join(f"{a.control} {a.words}" for a in answers)
        + "."
    )
    last = max((a.cadence.last for a in answers if a.cadence.last), default=None)
    return status, reason, evidence, missing, last


def _words(status: str) -> str:
    from agent_shield.conformance import STATUS_WORDS

    return STATUS_WORDS[status]


__all__ = ["DRILLS", "FACTS", "KINDS", "MAP", "answer_covered", "covering_standard", "rule_for"]
