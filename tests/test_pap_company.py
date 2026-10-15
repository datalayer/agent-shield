# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Shield as a PAP company in front of any agent (SHIELD §6.10, SH-71): an
operation decided by the company's policy, held for review and released by a
person, refused in a sentence, answered signed and recorded; the agent never
sees a credential or the protocol."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("personal_agent_protocol", reason="the PAP SDK is the company's; `pip install personal-agent-protocol`")

from personal_agent_protocol.company import OperationFailed, OperationOutcomeUnknown, ProposedOperation, Reply, Turn
from personal_agent_protocol.models import Operation, OperationResult

from agent_shield.audit import AuditLog
from agent_shield.pap import (
    CompanyShield,
    ReviewRefused,
    ShieldCompanyPlugin,
    ShieldedCompanyAgent,
    ShieldedOperationExecutor,
    Signer,
    money_moves,
    operation_class,
)
from agent_shield.policy import Policy, Rule

NOW = datetime(2026, 10, 16, 9, 0, tzinfo=timezone.utc)


def operation(action: str = "orders.exchange", terms=None, uid: str = "op-1") -> Operation:
    return Operation(
        operation_id=uid,
        revision=1,
        state="in_progress",
        summary=f"{action} for the person",
        terms=terms,
        expires_at=NOW + timedelta(minutes=10),
        confirmation=None,
        result=None,
    )


class Inner:
    """The application behind the Shield: it performs, and it answers."""

    def __init__(self) -> None:
        self.performed: list[str] = []
        self.turns: list[Turn] = []

    async def perform(self, op: Operation, account_id: str) -> OperationResult:
        self.performed.append(op.operation_id)
        return OperationResult(summary=f"Exchanged for {account_id}.")

    async def respond(self, turn: Turn):
        self.turns.append(turn)
        return [
            Reply(text="Sure, I can exchange it."),
            Reply(
                text="Or I can refund you.",
                operation=ProposedOperation(action="orders.refund", summary="Refund", terms={"amount": "10", "currency": "EUR"}),
            ),
        ]


def company(*rules: Rule, audit_path) -> CompanyShield:
    return CompanyShield(
        [Policy(scope="team", rules=list(rules))],
        company="acme.example",
        audit=AuditLog(audit_path),
        signer=Signer(b"the-companys-key", key_id="acme-2026"),
        clock=lambda: NOW,
    )


def turn(client_id: str = "pa-1", account_id: str | None = "alice") -> Turn:
    return Turn(
        conversation_id="c1", text="Can I exchange my order?", data=None, sender="agent", account_id=account_id,
        scopes=("orders:write",), client_id=client_id, is_direct=False, supports_operations=True,
    )


def test_an_operation_is_classed_by_whether_money_moves():
    assert money_moves({"amount": "10", "currency": "EUR"}) and money_moves({"items": [{"price": {"amount": 1, "currency": "USD"}}]})
    assert not money_moves({"size": "M"}) and not money_moves(None)
    assert operation_class({"amount": "10", "currency": "EUR"}) == "buy" and operation_class({"size": "M"}) == "write"
    assert operation_class(None) == "buy", "an operation without terms is the most restricted"


@pytest.mark.asyncio
async def test_do_it_performs_and_the_answer_is_signed_and_recorded(tmp_path):
    shield = company(Rule(name="exchanges are fine", decision="allow", classes=["write"]), audit_path=tmp_path / "a.jsonl")
    inner = Inner()
    executor = ShieldedOperationExecutor(shield, inner, action="orders.exchange")
    result = await executor.perform(operation(terms={"size": "M"}), "alice")
    assert result.summary == "Exchanged for alice." and inner.performed == ["op-1"]
    rows = shield.audit.rows()
    kinds = [row["event"] for row in rows]
    assert kinds == ["tool_call", "operation"]
    assert rows[0]["decision"] == "allow" and rows[0]["class"] == "write" and rows[0]["rule"] == "exchanges are fine"
    signature = rows[1]["signature"]
    assert signature["kid"] == "acme-2026" and shield.signer.verify({"operation": "op-1", "revision": 1, "summary": "Exchanged for alice.", "signature": signature})
    assert shield.state.tool_calls == 1


@pytest.mark.asyncio
async def test_ask_me_first_holds_the_operation_for_review_and_a_person_releases_it(tmp_path):
    shield = company(Rule(name="refunds are reviewed", decision="ask", classes=["buy"]), audit_path=tmp_path / "a.jsonl")
    inner = Inner()
    executor = ShieldedOperationExecutor(shield, inner, action="orders.refund")
    with pytest.raises(OperationOutcomeUnknown, match="held for review by the company \\(ticket "):
        await executor.perform(operation("orders.refund", terms={"amount": "10", "currency": "EUR"}, uid="op-2"), "alice")
    assert inner.performed == [], "nothing is performed while a person has not released it"
    (ticket,) = shield.held()
    assert ticket.action == "orders.refund" and ticket.action_class == "buy" and ticket.state == "held"
    settled = []
    answer = await shield.release(ticket.ticket_id, released_by="bob@acme.example", settle=lambda uid, result: settled.append((uid, result.summary)))
    assert inner.performed == ["op-2"] and settled == [("op-2", "Exchanged for alice.")]
    assert answer["state"] == "released" and answer["released_by"] == "bob@acme.example" and shield.signer.verify(answer)
    assert shield.held() == []
    with pytest.raises(ReviewRefused):
        await shield.release(ticket.ticket_id, released_by="bob@acme.example")
    events = [(row["event"], row.get("what")) for row in shield.audit.rows()]
    assert ("review", "held") in events and ("review", "released") in events


@pytest.mark.asyncio
async def test_a_person_may_refuse_a_held_operation(tmp_path):
    shield = company(Rule(name="refunds are reviewed", decision="ask", classes=["buy"]), audit_path=tmp_path / "a.jsonl")
    inner = Inner()
    executor = ShieldedOperationExecutor(shield, inner, action="orders.refund")
    with pytest.raises(OperationOutcomeUnknown):
        await executor.perform(operation("orders.refund", terms={"amount": "10", "currency": "EUR"}, uid="op-3"), "alice")
    (ticket,) = shield.held()
    settled = []
    answer = await shield.refuse(ticket.ticket_id, refused_by="bob", reason="Not within 30 days.", settle=lambda uid, why: settled.append((uid, why)))
    assert inner.performed == [] and settled == [("op-3", "Not within 30 days.")]
    assert answer["state"] == "refused" and shield.signer.verify(answer) and not shield.signer.verify({**answer, "state": "released"})


@pytest.mark.asyncio
async def test_leave_it_to_me_refuses_the_operation_in_the_policys_sentence(tmp_path):
    shield = company(Rule(name="no buying by the agent", decision="deny", classes=["buy"]), audit_path=tmp_path / "a.jsonl")
    executor = ShieldedOperationExecutor(shield, Inner(), action="orders.refund")
    with pytest.raises(OperationFailed) as failed:
        await executor.perform(operation("orders.refund", terms={"amount": "10", "currency": "EUR"}), "alice")
    assert failed.value.result.summary.startswith("Refused by the company's policy: orders.refund for alice: leave it to me — team rule 'no buying by the agent'")


@pytest.mark.asyncio
async def test_the_agent_answers_only_when_the_policy_lets_it_and_a_refused_proposal_is_not_proposed(tmp_path):
    shield = company(
        Rule(name="answer everyone", decision="allow", classes=["send"]),
        Rule(name="no refunds", decision="deny", classes=["buy"]),
        audit_path=tmp_path / "a.jsonl",
    )
    inner = Inner()
    agent = ShieldedCompanyAgent(shield, inner)
    replies = await agent.respond(turn())
    assert [reply.text for reply in replies][0] == "Sure, I can exchange it."
    assert replies[1].operation is None and "Not proposed: orders.refund for alice: leave it to me" in replies[1].text
    assert inner.turns[0].account_id == "alice" and not hasattr(inner.turns[0], "token"), "the agent sees the turn, never a credential"
    quiet = company(Rule(name="nobody is answered", decision="deny", classes=["send"]), audit_path=tmp_path / "b.jsonl")
    (reply,) = await ShieldedCompanyAgent(quiet, inner).respond(turn(client_id="pa-9"))
    assert reply.text.startswith("The company does not answer this: answer pa-9: leave it to me") and len(inner.turns) == 1
    held = company(Rule(name="new agents are reviewed", decision="ask", classes=["send"]), audit_path=tmp_path / "c.jsonl")
    (reply,) = await ShieldedCompanyAgent(held, inner).respond(turn(client_id="pa-2"))
    assert reply.text.startswith("The company holds this for a person to review")


def test_the_plugin_wraps_the_applications_contributions(tmp_path):
    shield = company(audit_path=tmp_path / "a.jsonl")
    seen = []

    class Contributions:
        def contribute(self, point, value, *, contribution_id, order=None):
            seen.append((point.id, type(value).__name__, contribution_id))

    ShieldCompanyPlugin(shield, agent=Inner(), executors={"orders.exchange": Inner()}).provide_contributions(Contributions())
    assert seen == [
        ("pap.company.agent", "ShieldedCompanyAgent", "shielded-application"),
        ("pap.company.operationExecutor", "ShieldedOperationExecutor", "shielded-operation-orders.exchange"),
    ]
