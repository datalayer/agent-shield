# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The temporal evaluator (AC-42): Dogwood's grammar, AgentCore's quotas, the published examples
with their expected decisions, self-reference, forbid overriding permit, window expiry, log_only,
and the session's history fed by the Shield's decisions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cedarpy")

from agent_shield.policy import (
    Action,
    CedarCall,
    Context,
    Dogwood,
    DogwoodRefused,
    Event,
    EventLog,
    Policy,
    PolicyRefused,
    Rule,
    Subject,
    call_from_request,
    decide,
    evaluate,
    parse_policies,
    parse_set,
    request_for,
)

T0 = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)
GW = 'AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:111122223333:gateway/insurance-gw-a1b2c3d4e5"'
DISBURSE = 'AgentCore::Action::"InsuranceAPI___disburse_payment"'
APPROVE = 'AgentCore::Action::"InsuranceAPI___approve_claim"'
STATUS = 'AgentCore::Action::"InsuranceAPI___get_claim_status"'
USER = 'AgentCore::OAuthUser::"alice"'


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


# -- a session as AgentCore keeps it: authorized requests, denied errors, completed responses -------


class Session:
    """A policy session over one set: every request decided, its outcome recorded as AgentCore does."""

    def __init__(self, text: str, principal: str = USER, resource: str = GW) -> None:
        self.parsed = parse_set(text)
        self.log = EventLog()
        self.principal = principal
        self.resource = resource
        self.n = 0

    def call(self, action: str, **inputs: object) -> CedarCall:
        return CedarCall(
            principal=self.principal, action=action, resource=self.resource, context={"input": dict(inputs)}
        )

    def request(self, seconds: float, action: str, output: dict | None = None, **inputs: object) -> str:
        """Decide one request; a permitted one completes a second later (with ``output``)."""
        self.n += 1
        key = f"r{self.n}"
        call = self.call(action, **inputs)
        answer = evaluate(self.parsed, call, self.log.events, at(seconds))
        self.log.decided(key, call, allowed=answer.allowed, at=at(seconds))
        if answer.allowed:
            self.log.ended(key, at(seconds + 1), ok=True, output=output or {})
        return "ALLOW" if answer.allowed else "DENY"


PERMIT_APPROVE = f"permit (principal, action == {APPROVE}, resource == {GW});\n"
PERMIT_STATUS = f"permit (principal, action == {STATUS}, resource == {GW});\n"
PERMIT_DISBURSE = f"permit (principal, action == {DISBURSE}, resource == {GW});\n"


def test_approval_before_disbursal_for_the_same_claim() -> None:
    """AgentCore's 'Require a prior approval for the same claim', its three sequences."""
    text = (
        PERMIT_APPROVE
        + f"""permit (principal, action == {DISBURSE}, resource == {GW})
when temporal {{
    formerly within 1h {APPROVE}::response{{
        eventResource: resource,
        output.claimId: context.input.claimId
    }}
}};"""
    )
    s = Session(text)
    assert s.request(0, DISBURSE, claimId="c1") == "DENY"
    s = Session(text)
    assert s.request(0, APPROVE, output={"claimId": "c1"}, claimId="c1") == "ALLOW"
    assert s.request(10, DISBURSE, claimId="c1") == "ALLOW"
    s = Session(text)
    assert s.request(0, APPROVE, output={"claimId": "c1"}, claimId="c1") == "ALLOW"
    assert s.request(10, DISBURSE, claimId="c2") == "DENY"


def test_a_successful_prerequisite_lapses_with_its_window() -> None:
    """'Require a successful prerequisite, recently': the permission lapses after five minutes."""
    text = (
        PERMIT_STATUS
        + f"""permit (principal, action == {APPROVE}, resource == {GW})
when temporal {{ formerly within 5m {STATUS}::response{{ eventResource: resource }} }};"""
    )
    s = Session(text)
    assert s.request(0, APPROVE) == "DENY"
    assert s.request(10, STATUS) == "ALLOW"
    assert s.request(20, APPROVE) == "ALLOW"
    # The lookup's response was at 11s: 5 minutes later it is exactly on the edge (closed window)...
    assert s.request(11 + 300, APPROVE) == "ALLOW"
    # ...and one second further it is out.
    assert s.request(11 + 301, APPROVE) == "DENY"


def test_at_most_three_disbursements_in_five_minutes_the_current_request_counted() -> None:
    """'Cap how many times an action runs': the fourth call in a window is the first denied."""
    text = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{
    exists (n: Long).
        (count for (t: Timepoint).
            where (formerly within 5m ({DISBURSE}::request{{ eventResource: resource }} && tp(t)))) == n
        && n > 3
}};"""
    )
    s = Session(text)
    assert [s.request(i * 10, DISBURSE) for i in range(5)] == ["ALLOW", "ALLOW", "ALLOW", "DENY", "DENY"]
    # The denied ones were recorded as errors, so once the first three leave the window it opens again.
    assert s.request(10 * 2 + 301, DISBURSE) == "ALLOW"
    kinds = [e.kind for e in s.log.events if e.action == DISBURSE]
    assert kinds.count("error") == 2


def test_a_running_total_stops_the_request_that_would_cross_it() -> None:
    """'Cap a running total': with a 300000-cent cap and 100000 each, the third is denied."""
    text = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{
    exists (total: Long).
        (sum amt for (amt: Long), (t: Timepoint).
            where (formerly within 5m ({DISBURSE}::request{{ eventResource: resource, input.amountCents: amt }} && tp(t)))) == total
        && total >= 300000
}};"""
    )
    s = Session(text)
    assert [s.request(i, DISBURSE, amountCents=100000) for i in (0, 10, 20)] == ["ALLOW", "ALLOW", "DENY"]


def test_one_disbursement_per_approval_since_the_anchor() -> None:
    """'Make each approval good for one use': the negated response since the anchor."""
    text = (
        PERMIT_APPROVE
        + f"""permit (principal, action == {DISBURSE}, resource == {GW})
when temporal {{
    !{DISBURSE}::response{{ eventResource: resource }}
    since within 1h {APPROVE}::response{{ eventResource: resource }}
}};"""
    )
    s = Session(text)
    assert s.request(0, APPROVE) == "ALLOW"
    assert s.request(10, DISBURSE) == "ALLOW"
    assert s.request(20, DISBURSE) == "DENY"
    assert s.request(30, APPROVE) == "ALLOW"
    assert s.request(40, DISBURSE) == "ALLOW"


def test_a_cool_down_does_not_block_itself_on_its_own_request() -> None:
    """'Enforce a cool-down': matching ::response, the current request does not match itself."""
    text = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{ formerly within 1m {DISBURSE}::response{{ eventResource: resource }} }};"""
    )
    s = Session(text)
    assert s.request(0, DISBURSE) == "ALLOW"
    assert s.request(30, DISBURSE) == "DENY"
    assert s.request(62, DISBURSE) == "ALLOW"


def test_self_reference_counts_the_current_request() -> None:
    """A ::request condition on the action decided matches the request being decided."""
    text = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{ formerly within 1m {DISBURSE}::request{{ eventResource: resource }} }};"""
    )
    s = Session(text)
    assert s.request(0, DISBURSE) == "DENY"


def test_after_a_denial_the_sensitive_action_is_cut_off() -> None:
    """'Block an action after an earlier denial': the refused approval is an error event."""
    text = (
        PERMIT_DISBURSE
        + f"""forbid (principal, action == {DISBURSE}, resource == {GW})
when temporal {{ formerly within 3m {APPROVE}::error{{ eventResource: resource }} }};"""
    )
    s = Session(text)
    assert s.request(0, DISBURSE) == "ALLOW"
    assert s.request(10, APPROVE) == "DENY"  # no permit: deny by default, recorded as an error
    assert s.request(20, DISBURSE) == "DENY"
    assert s.request(10 + 181, DISBURSE) == "ALLOW"


def test_a_forbid_overrides_any_permit() -> None:
    text = f"""permit (principal, action, resource);
@id("never disburse")
forbid (principal, action == {DISBURSE}, resource);"""
    s = Session(text)
    assert s.request(0, APPROVE) == "ALLOW"
    call = s.call(DISBURSE)
    answer = evaluate(s.parsed, call, s.log.events, at(5))
    assert not answer.allowed
    assert answer.decided_by == ("never disburse",)
    assert "a forbid overrides any permit" in answer.sentence


def test_distinct_payees_in_an_hour() -> None:
    """A distinct count: the domain without the timepoint deduplicates equal payees."""
    transfer = 'Datalayer::Action::"bank___transfer"'
    text = f"""permit (principal, action, resource);
@id("at most two payees an hour")
forbid (principal, action == {transfer}, resource)
when temporal {{
    exists (n: Long).
        (count for (p: String). where (formerly within 1h {transfer}::request{{ eventResource: resource, input.payee: p }})) == n
        && n > 2
}};"""
    s = Session(text, principal='Datalayer::User::"alice"', resource='Datalayer::Runtime::"r1"')
    assert s.request(0, transfer, payee="ann") == "ALLOW"
    assert s.request(10, transfer, payee="bob") == "ALLOW"
    assert s.request(20, transfer, payee="ann") == "ALLOW"  # still two payees
    assert s.request(30, transfer, payee="cy") == "DENY"  # a third
    assert s.request(3611, transfer, payee="cy") == "ALLOW"  # ann's first left the window, bob at 10 too


# -- Dogwood's published examples (dogwood-docs/examples), replayed as the reference does ----------


def replay(text: str, trace: list[tuple]) -> list[str]:
    """Replay a trace as Dogwood's reference interpreter: requests decided, every event kept."""
    parsed = parse_set(text)
    events: list[Event] = []
    verdicts: list[str] = []
    for n, (ts, kind, action, principal, inputs, output) in enumerate(trace):
        name = f'Drupe::Action::"{action}"'
        who = f'Drupe::OAuthUser::"{principal}"'
        if kind == "request":
            call = CedarCall(principal=who, action=name, resource='Drupe::Gateway::"gw1"', context={"input": inputs})
            answer = evaluate(parsed, call, events, at(ts))
            verdicts.append(f"@{ts} {'ALLOW' if answer.allowed else 'DENY'}")
        events.append(
            Event(
                kind=kind,
                action=name,
                principal=who,
                resource='Drupe::Gateway::"gw1"',
                at=at(ts),
                key=f"e{n}",
                input=inputs,
                output=output or {},
            )
        )
    return verdicts


def test_dogwood_refund_budget_settled_plus_current() -> None:
    text = """@id("refund_budget_settled_plus_current")
permit (principal, action == Drupe::Action::"Refund", resource)
when temporal {
    (sum a for (a: Long), (t: Timepoint). where (
        formerly within 24h (Drupe::Action::"Refund"::response{ output.amount: a } && tp(t))
    )) + context.input.amount <= 100
};"""
    trace = [
        (0, "request", "Refund", "alice", {"user": "alice", "amount": 60}, None),
        (1, "response", "Refund", "alice", {"user": "alice", "amount": 60}, {"amount": 60}),
        (10, "request", "Refund", "alice", {"user": "alice", "amount": 50}, None),
        (20, "request", "Refund", "alice", {"user": "alice", "amount": 30}, None),
        (21, "response", "Refund", "alice", {"user": "alice", "amount": 30}, {"amount": 30}),
        (30, "request", "Refund", "alice", {"user": "alice", "amount": 15}, None),
        (40, "request", "Refund", "alice", {"user": "alice", "amount": 10}, None),
    ]
    assert replay(text, trace) == ["@0 ALLOW", "@10 DENY", "@20 ALLOW", "@30 DENY", "@40 ALLOW"]


def test_dogwood_alert_exactly_three_transfers() -> None:
    text = """@id("alert_exactly_three_transfers")
permit (principal, action == Drupe::Action::"Alert", resource)
when temporal {
    (count for (t: Timepoint). where (
        formerly within 1h (Drupe::Action::"Transfer"::request{ input.amount: * } && tp(t))
    )) == 3
};"""
    alert = {"level": 1, "server": "s1"}
    trace = [
        (0, "request", "Transfer", "alice", {"amount": 5, "user": "alice"}, None),
        (100, "request", "Transfer", "bob", {"amount": 42, "user": "bob"}, None),
        (200, "request", "Alert", "alice", alert, None),
        (300, "request", "Transfer", "carol", {"amount": 9, "user": "carol"}, None),
        (400, "request", "Alert", "alice", alert, None),
        (500, "request", "Transfer", "dave", {"amount": 1, "user": "dave"}, None),
        (600, "request", "Alert", "alice", {"level": 2, "server": "s2"}, None),
        (3700, "request", "Alert", "alice", alert, None),
    ]
    assert replay(text, trace) == [
        "@0 DENY",
        "@100 DENY",
        "@200 DENY",
        "@300 DENY",
        "@400 ALLOW",
        "@500 DENY",
        "@600 DENY",
        "@3700 ALLOW",
    ]


def test_dogwood_access_not_revoked_since_grant() -> None:
    text = """@id("access_not_revoked_since_grant")
permit (principal, action == Drupe::Action::"Access", resource)
when temporal {
    !Drupe::Action::"Revoke"::response{ input.user: context.input.user, input.resource: context.input.resource }
    since within 1h
    Drupe::Action::"Grant"::response{ input.user: context.input.user, input.resource: context.input.resource }
};"""
    doc = {"resource": "doc1", "user": "alice"}
    trace = [
        (35940, "response", "Grant", "alice", doc, None),
        (36060, "request", "Access", "alice", doc, None),
        (36120, "response", "Revoke", "alice", doc, None),
        (36180, "request", "Access", "alice", doc, None),
    ]
    assert replay(text, trace) == ["@36060 ALLOW", "@36180 DENY"]


def test_dogwood_transfer_sum_over_100_inlined_from_its_macro() -> None:
    """temporal_sum_formerly_transfer, its sum_formerly macro written out (macros are not read)."""
    text = """@id("transfer_sum_over_100")
permit (principal, action == Drupe::Action::"Alert", resource)
when temporal {
    exists (total: Long). (
        (sum a for (a: Long), (t: Timepoint). where (formerly within 1h (Drupe::Action::"Transfer"::request{
            input.user: _, input.amount: a
        } && tp(t)))) == total
        && total > 100
    )
};"""
    trace = [
        (0, "request", "Transfer", "s1", {"amount": 40, "user": "alice"}, None),
        (1, "response", "Transfer", "s1", {"amount": 40, "user": "alice"}, None),
        (2, "request", "Alert", "s1", {"level": 1, "server": "s1"}, None),
        (3, "response", "Alert", "s1", {"level": 1, "server": "s1"}, None),
        (4, "request", "Transfer", "s1", {"amount": 80, "user": "bob"}, None),
        (5, "response", "Transfer", "s1", {"amount": 80, "user": "bob"}, None),
        (6, "request", "Alert", "s1", {"level": 2, "server": "s1"}, None),
        (7, "response", "Alert", "s1", {"level": 2, "server": "s1"}, None),
    ]
    assert replay(text, trace) == ["@0 DENY", "@2 DENY", "@4 DENY", "@6 ALLOW"]


def test_dogwood_count_at_the_current_timepoint_alone() -> None:
    """alert_heartbeat_and_login_rate: a count with no formerly reads the current timepoint only."""
    text = """@id("alert_heartbeat_and_login_rate")
permit (principal, action == Drupe::Action::"Alert", resource)
when temporal {
    formerly within 1h Drupe::Action::"Heartbeat"::request{ input.server: context.input.server }
    && exists (n: Long). (
        (count for (t: Timepoint). where (
            Drupe::Action::"Login"::request{ input.user: _, input.server: context.input.server } && tp(t)
        )) == n && n > 2
    )
};"""
    trace = [
        (0, "request", "Heartbeat", "s1", {"server": "s1"}, None),
        (2, "request", "Login", "alice", {"server": "s1", "user": "alice"}, None),
        (4, "request", "Login", "bob", {"server": "s1", "user": "bob"}, None),
        (10, "request", "Alert", "s1", {"level": 1, "server": "s1"}, None),
        (20, "request", "Login", "carol", {"server": "s1", "user": "carol"}, None),
        (30, "request", "Alert", "s1", {"level": 2, "server": "s1"}, None),
    ]
    assert replay(text, trace) == ["@0 DENY", "@2 DENY", "@4 DENY", "@10 DENY", "@20 DENY", "@30 DENY"]


# -- the grammar and the quotas, held as the set is read -------------------------------------------


def _temporal(n: int, window: str = "1h") -> str:
    body = " && ".join(
        f'formerly within {window} X::Action::"a{i}"::request{{ eventResource: resource }}' for i in range(n)
    )
    return f"permit (principal, action, resource) when temporal {{ {body} }};"


def test_the_quotas_are_held_as_the_set_is_read() -> None:
    parse_set(_temporal(3))
    with pytest.raises(DogwoodRefused, match="4 temporal operators, over AgentCore's quota of 3"):
        parse_set(_temporal(4))
    parse_set(_temporal(1, "24h"))
    with pytest.raises(DogwoodRefused, match="looks back 25h, over the 24-hour window"):
        parse_set(_temporal(1, "25h"))
    with pytest.raises(DogwoodRefused, match="looks back 2d"):
        parse_set(_temporal(1, "2d"))
    parse_set("\n".join([_temporal(1)] * 20))
    with pytest.raises(DogwoodRefused, match="21 temporal policies, over AgentCore's quota of 20"):
        parse_set("\n".join([_temporal(1)] * 21))


@pytest.mark.parametrize(
    ("text", "said"),
    [
        (
            'permit (principal, action, resource) when temporal { formerly within 1h X::Action::"a"::request{ input.u: u } };',
            "bound by no 'exists' or 'for'",
        ),
        (
            'permit (principal, action, resource) when temporal { formerly within 1h X::Action::"a"::request{} || formerly within 1h X::Action::"b"::request{} };',
            "no '||'",
        ),
        ("def temporal once(?w, ?s) { formerly within ?w ?s };", "macros"),
        (
            'permit (principal, action, resource) when temporal { formerly within ?w X::Action::"a"::request{} };',
            "macro parameters",
        ),
        (
            'permit (principal, action, resource) when temporal { exists (n: Long). (sum a for (t: Timepoint). where (X::Action::"a"::request{ input.a: a } && tp(t))) == n };',
            "sums a variable",
        ),
        ("permit (principal, action, resource)", "ends with ';'"),
        ("allow (principal, action, resource);", "starts with permit or forbid"),
        ("   ", "empty"),
    ],
)
def test_what_is_not_read_is_refused_in_a_sentence(text: str, said: str) -> None:
    with pytest.raises(DogwoodRefused, match=said):
        parse_set(text)


def test_the_set_lowers_to_cedar_with_one_slot_per_temporal_clause() -> None:
    parsed = parse_set(
        """@id("p")
permit (principal, action, resource)
when { context.input.n > 1 }
when temporal { formerly within 1h X::Action::"a"::response{ eventResource: resource } }
unless temporal { formerly within 1m X::Action::"b"::error{ eventResource: resource } };"""
    )
    assert [slot for slot, _ in parsed.slots()] == ["p0c1", "p0c2"]
    assert "when { context.dogwood.p0c1 }" in parsed.lowered
    assert "unless { context.dogwood.p0c2 }" in parsed.lowered
    assert "when { context.input.n > 1 }" in parsed.lowered
    assert parsed.policies[0].operators == 2


def test_a_policy_document_reads_its_dogwood_section_and_refuses_cedar_it_cannot_parse() -> None:
    doc = Policy(scope="organization", dogwood={"policies": "permit (principal, action, resource);"})
    assert doc.dogwood is not None and doc.dogwood.mode == "enforce"
    with pytest.raises(PolicyRefused, match="Cedar refuses the set"):
        parse_policies(
            {"scope": "team", "dogwood": {"policies": "permit (principal, action, resource) when { ) };"}}, "f"
        )
    with pytest.raises(PolicyRefused, match="over the 24-hour window"):
        parse_policies({"scope": "team", "dogwood": {"policies": _temporal(1, "48h")}}, "f")
    with pytest.raises(PolicyRefused):
        parse_policies(
            {"scope": "team", "dogwood": {"policies": "permit (principal, action, resource);", "mode": "loud"}}, "f"
        )


# -- the Shield's decide path: the history fed, log_only, deny wins over the rules --------------------


PAY = "bank___pay"
APPROVE_TOOL = "bank___approve"
GUARD = f"""permit (principal, action, resource) unless {{ action == Datalayer::Action::"{PAY}" }};
@id("approved before paying")
permit (principal, action == Datalayer::Action::"{PAY}", resource)
when temporal {{
    formerly within 1h Datalayer::Action::"{APPROVE_TOOL}"::response{{ eventResource: resource, input.claim: context.input.claim }}
}};"""


def _context(log: EventLog, seconds: float) -> Context:
    return Context(
        workspace="/w",
        session_id="s1",
        history=log,
        now=at(seconds),
        runtime="r1",
        subject=Subject(type="account", id="alice", properties={"org_uid": "o1"}),
    )


def _tool(tool: str, **inputs: object) -> Action:
    return Action(kind="other", title=tool, tool=tool, input=dict(inputs), **{"class": "send"})


def _shield_step(policies: list[Policy], log: EventLog, seconds: float, key: str, action: Action):
    context = _context(log, seconds)
    decision = decide(action, context, policies)
    log.decided(
        key, call_from_request(request_for(action, context)), allowed=decision.verdict != "deny", at=at(seconds)
    )
    if decision.verdict != "deny":
        log.ended(key, at(seconds + 1), ok=True)
    return decision


def test_the_shield_decides_with_the_set_over_its_own_history() -> None:
    policy = Policy(scope="organization", dogwood=Dogwood(policies=GUARD), rules=[Rule(name="go", decision="allow")])
    log = EventLog()
    refused = _shield_step([policy], log, 0, "k1", _tool(PAY, claim="c1"))
    assert refused.verdict == "deny" and refused.decided_by == "dogwood"
    assert "deny by default" in refused.sentence
    assert log.events[-1].kind == "error"
    approved = _shield_step([policy], log, 10, "k2", _tool(APPROVE_TOOL, claim="c1"))
    assert approved.verdict == "allow" and approved.temporal == "permit" and approved.rule == "go"
    paid = _shield_step([policy], log, 20, "k3", _tool(PAY, claim="c1"))
    assert paid.verdict == "allow"
    other = _shield_step([policy], log, 30, "k4", _tool(PAY, claim="c2"))
    assert other.verdict == "deny"
    assert [e.kind for e in log.events] == ["error", "request", "response", "request", "response", "error"]
    assert log.events[1].action == f'Datalayer::Action::"{APPROVE_TOOL}"'
    assert log.events[1].principal == 'Datalayer::User::"alice"'
    assert log.events[1].resource == 'Datalayer::Runtime::"r1"'


def test_a_permit_loosens_nothing_and_the_rules_still_decide() -> None:
    policy = Policy(
        scope="organization",
        dogwood=Dogwood(policies=GUARD),
        rules=[Rule(name="no sends", decision="deny", classes=["send"])],
    )
    decision = decide(_tool(APPROVE_TOOL, claim="c1"), _context(EventLog(), 0), [policy])
    assert decision.verdict == "deny" and decision.rule == "no sends" and decision.temporal == "permit"


def test_log_only_decides_records_and_lets_through() -> None:
    policy = Policy(
        scope="organization",
        dogwood=Dogwood(policies=GUARD, mode="log_only"),
        rules=[Rule(name="go", decision="allow")],
    )
    log = EventLog()
    decision = _shield_step([policy], log, 0, "k1", _tool(PAY, claim="c1"))
    assert decision.verdict == "allow" and decision.rule == "go"
    assert decision.temporal is not None and decision.temporal.startswith("deny (log only)")
    assert log.events[0].kind == "request"


def test_the_strictest_scope_set_denies_first() -> None:
    org = Policy(
        scope="organization",
        dogwood=Dogwood(
            policies=f'permit (principal, action, resource);\n@id("org")\nforbid (principal, action == Datalayer::Action::"{PAY}", resource);'
        ),
    )
    team = Policy(scope="team", dogwood=Dogwood(policies=GUARD), rules=[Rule(name="go", decision="allow")])
    decision = decide(_tool(PAY, claim="c1"), _context(EventLog(), 0), [team, org])
    assert decision.verdict == "deny" and decision.scope == "organization" and decision.rule == "org"


def test_the_event_log_records_refusals_failures_and_keeps_24_hours() -> None:
    log = EventLog()
    call = CedarCall(principal=USER, action=DISBURSE, resource=GW, context={"input": {"a": 1}})
    log.decided("a", call, allowed=True, at=at(0))
    log.refused("a", at(1))
    assert [e.kind for e in log.events] == ["error"]
    assert log.ended("a", at(2), ok=True) is None  # a refused call never responds
    log.decided("b", call, allowed=True, at=at(3))
    log.ended("b", at(4), ok=False)
    assert [e.kind for e in log.events] == ["error", "request", "error"]
    log.decided("c", call, allowed=True, at=at(5))
    log.decided("c", call, allowed=True, at=at(6))  # decided again: replaced, not doubled
    assert sum(1 for e in log.events if e.key == "c") == 1
    log.decided("d", call, allowed=True, at=at(5))  # a clock that stepped back is moved on
    assert log.events[-1].at > log.events[-2].at
    log.decided("e", call, allowed=True, at=at(24 * 3600 + 10))
    assert [e.key for e in log.events] == ["e"]


def test_without_cedarpy_the_set_refuses_in_a_sentence(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real = builtins.__import__

    def without_cedarpy(name, *args, **kwargs):
        if name == "cedarpy":
            raise ImportError("no cedarpy")
        return real(name, *args, **kwargs)

    policy = Policy(scope="organization", dogwood=Dogwood(policies="permit (principal, action, resource);"))
    monkeypatch.setattr(builtins, "__import__", without_cedarpy)
    decision = decide(_tool(APPROVE_TOOL), _context(EventLog(), 0), [policy])
    assert decision.verdict == "deny"
    assert "cedarpy is not installed" in decision.sentence


# -- the proxy feeds the session's history --------------------------------------------------------


def test_the_proxy_records_requests_responses_and_refusals(tmp_path) -> None:
    from types import SimpleNamespace

    from agent_shield.acp.proxy import ShieldProxy, action_of_tool_call
    from agent_shield.acp.workspace import Workspace
    from agent_shield.audit import AuditLog
    from agent_shield.policy import LoadedPolicy

    policy = Policy(scope="organization", dogwood=Dogwood(policies=GUARD), rules=[Rule(name="go", decision="allow")])
    proxy = ShieldProxy(
        ["agent"],
        policies=[LoadedPolicy(policy, "test")],
        audit=AuditLog(tmp_path / "audit.jsonl", persist=False),
        subject=Subject(type="account", id="alice"),
        tool_class=lambda name: ("send", None) if name.startswith("bank___") else None,
    )
    (tmp_path / "ws").mkdir()
    session = proxy._open("s1", Workspace(tmp_path / "ws"))

    def said(tool: str, **inputs: object):
        call = SimpleNamespace(kind="other", input={"name": tool, **inputs}, title=tool, locations=[])
        action, problem = action_of_tool_call(call, session.workspace, tool_class=proxy.tool_class)
        assert problem is None and action is not None
        return action

    pay = said(PAY, claim="c1")
    assert pay.tool == PAY and pay.input == {"name": PAY, "claim": "c1"}
    assert proxy.decide(session, pay, key="t1").verdict == "deny"
    assert proxy.decide(session, said(APPROVE_TOOL, claim="c1"), key="t2").verdict == "allow"
    proxy.ended(session, "t2", ok=True, output={"approved": True})
    assert proxy.decide(session, said(PAY, claim="c1"), key="t3").verdict == "allow"
    proxy.ended(session, "t3", ok=False)
    assert [(e.key, e.kind) for e in session.history.events] == [
        ("t1", "error"),
        ("t2", "request"),
        ("t2", "response"),
        ("t3", "request"),
        ("t3", "error"),
    ]
    assert session.history.events[2].output == {"approved": True}
