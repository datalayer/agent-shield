# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Shield as a PAP company, standing in front of any agent (SHIELD §6.10, SH-71).

A company puts *any* agent behind the Personal Agent Protocol by running it
behind the Shield in the company role: the PAP SDK's company service does
discovery, identity, sessions and operations; this module stands at the
SDK's two points where the agent is asked — ``pap.company.agent`` (a turn
of a conversation) and ``pap.company.operationExecutor`` (an operation the
person confirmed) — and **decides each incoming operation as an action of
the company's policy** before the agent sees it:

- a turn to answer is a ``send`` (the company's words to a person); an
  operation the agent proposes in its answer is classed by what it does;
- a confirmed operation is a ``buy`` when a term moves money (an amount with
  a currency), else a ``write`` — an operation without terms says nothing of
  what it does and is the most restricted, a ``buy`` (the gateway's rule);
- *do it* lets the agent act, and what it answers is signed and recorded;
- *ask me first* **holds** the operation for review: a ticket is kept, the
  operation stays ``in_progress`` (PAP's own state for an outcome not yet
  known), and a person of the company **releases** it — performed then and
  settled — or refuses it;
- *leave it to me* refuses it, in the policy's sentence.

The agent sees a :class:`Turn` and an :class:`Operation` only: never the
personal agent's credential, never the protocol.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agent_shield.audit import AuditLog
from agent_shield.policy import Action, Context, Decision, LimitState, Policy, Subject, decide

#: The classes of a company's actions (§6.10): the company's own words.
OPERATION_WRITE = "write"
OPERATION_BUY = "buy"
ANSWER_SEND = "send"


def money_moves(terms: Any) -> bool:
    """Whether a term carries an amount with a currency, anywhere in the terms."""
    if isinstance(terms, Mapping):
        if "amount" in terms and "currency" in terms:
            return True
        return any(money_moves(item) for item in terms.values())
    if isinstance(terms, (list, tuple)):
        return any(money_moves(item) for item in terms)
    return False


def operation_class(terms: Any) -> str:
    """``buy`` when a term moves money, or when there are no terms; ``write`` otherwise."""
    return OPERATION_BUY if not terms or money_moves(terms) else OPERATION_WRITE


class ReviewRefused(ValueError):
    """A ticket that is not held, or not this company's."""


@dataclass
class ReviewTicket:
    """An operation held for a person of the company to release or refuse."""

    ticket_id: str
    operation_id: str
    revision: int
    action: str
    account_id: str
    action_class: str
    sentence: str
    held_at: datetime
    state: str = "held"
    settled_at: datetime | None = None
    #: What performing it answered, once released.
    summary: str | None = None
    #: The perform the ticket holds back: the inner executor and the operation.
    _perform: Callable[[], Any] | None = field(default=None, repr=False)

    def describe(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "operation_id": self.operation_id,
            "revision": self.revision,
            "action": self.action,
            "account_id": self.account_id,
            "class": self.action_class,
            "sentence": self.sentence,
            "held_at": self.held_at.isoformat(),
            "state": self.state,
            "settled_at": self.settled_at.isoformat() if self.settled_at else None,
            "summary": self.summary,
        }


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Signer:
    """The company's signature on what the Shield answers: HMAC-SHA256 over the canonical JSON."""

    def __init__(self, key: bytes, *, key_id: str = "shield") -> None:
        if not key:
            raise ValueError("a company signs its answers with a key")
        self._key = key
        self.key_id = key_id

    def sign(self, value: Mapping[str, Any]) -> dict[str, Any]:
        body = {k: v for k, v in value.items() if k != "signature"}
        digest = hmac.new(self._key, canonical(body), hashlib.sha256).digest()
        return {**body, "signature": {"alg": "HS256", "kid": self.key_id, "sig": base64.urlsafe_b64encode(digest).decode().rstrip("=")}}

    def verify(self, value: Mapping[str, Any]) -> bool:
        signature = value.get("signature")
        if not isinstance(signature, Mapping) or signature.get("kid") != self.key_id:
            return False
        body = {k: v for k, v in value.items() if k != "signature"}
        digest = hmac.new(self._key, canonical(body), hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return hmac.compare_digest(expected, str(signature.get("sig") or ""))


class CompanyShield:
    """The company's policy in front of its agent: decides, holds, releases, signs, records."""

    def __init__(
        self,
        policies: Sequence[Policy],
        *,
        company: str,
        audit: AuditLog,
        signer: Signer,
        clock: Callable[[], datetime] | None = None,
        authorize: Any = None,
    ) -> None:
        if not company:
            raise ValueError("the company's domain names the company")
        self.policies = list(policies)
        self.company = company
        self.audit = audit
        self.signer = signer
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.state = LimitState()
        self.authorize = authorize
        self.tickets: dict[str, ReviewTicket] = {}

    # -- deciding ------------------------------------------------------------------------

    def _context(self, account_id: str | None) -> Context:
        return Context(
            workspace=f"/pap/{self.company}",
            session_id=account_id or None,
            state=self.state,
            subject=Subject(type="connection", id=self.company),
            authorize=self.authorize,
        )

    def decide_operation(self, action: str, terms: Any, *, account_id: str, summary: str = "") -> Decision:
        """What the company's policy says of performing this operation for this account."""
        cls = operation_class(terms)
        decision = decide(
            Action(kind="other", title=f"{action} for {account_id}", resource=f"operation:{action}", **{"class": cls}),
            self._context(account_id),
            self.policies,
        )
        self.audit.write(
            "tool_call",
            company=self.company,
            account=account_id,
            action=action,
            **{"class": cls},
            summary=summary,
            decision=decision.verdict,
            sentence=decision.sentence,
            rule=decision.rule,
            scope=decision.scope,
            decided_by=decision.decided_by,
            by="policy",
        )
        return decision

    def decide_answer(self, client_id: str, *, account_id: str | None) -> Decision:
        """What the policy says of the company answering this personal agent at all."""
        decision = decide(
            Action(kind="other", title=f"answer {client_id}", resource=f"client:{client_id}", **{"class": ANSWER_SEND}),
            self._context(account_id),
            self.policies,
        )
        self.audit.write(
            "tool_call",
            company=self.company,
            account=account_id,
            client=client_id,
            **{"class": ANSWER_SEND},
            decision=decision.verdict,
            sentence=decision.sentence,
            rule=decision.rule,
            scope=decision.scope,
            decided_by=decision.decided_by,
            by="policy",
        )
        return decision

    # -- holding and releasing -----------------------------------------------------------

    def hold(
        self,
        *,
        operation_id: str,
        revision: int,
        action: str,
        account_id: str,
        action_class: str,
        sentence: str,
        perform: Callable[[], Any],
    ) -> ReviewTicket:
        ticket = ReviewTicket(
            ticket_id=secrets.token_urlsafe(12),
            operation_id=operation_id,
            revision=revision,
            action=action,
            account_id=account_id,
            action_class=action_class,
            sentence=sentence,
            held_at=self.clock(),
            _perform=perform,
        )
        self.tickets[ticket.ticket_id] = ticket
        self.audit.write("review", company=self.company, what="held", **ticket.describe(), by="shield")
        return ticket

    def held(self) -> list[ReviewTicket]:
        return [ticket for ticket in self.tickets.values() if ticket.state == "held"]

    async def release(self, ticket_id: str, *, released_by: str, settle: Callable[[str, Any], Any] | None = None) -> dict[str, Any]:
        """A person of the company lets the held operation go on: performed now, settled, signed."""
        ticket = self.tickets.get(ticket_id)
        if ticket is None or ticket.state != "held" or ticket._perform is None:
            raise ReviewRefused(f"no operation is held under the ticket {ticket_id!r}")
        result = await ticket._perform()
        ticket.state = "released"
        ticket.settled_at = self.clock()
        ticket.summary = str(getattr(result, "summary", "") or "Done.")
        if settle is not None:
            settled = settle(ticket.operation_id, result)
            if hasattr(settled, "__await__"):
                await settled
        answer = self.signer.sign({**ticket.describe(), "released_by": released_by})
        self.audit.write("review", company=self.company, what="released", released_by=released_by, **ticket.describe(), by="person")
        return answer

    async def refuse(self, ticket_id: str, *, refused_by: str, reason: str = "", settle: Callable[[str, Any], Any] | None = None) -> dict[str, Any]:
        """A person of the company refuses the held operation: failed, with the reason, signed."""
        ticket = self.tickets.get(ticket_id)
        if ticket is None or ticket.state != "held":
            raise ReviewRefused(f"no operation is held under the ticket {ticket_id!r}")
        ticket.state = "refused"
        ticket.settled_at = self.clock()
        ticket.summary = reason or f"Refused by {refused_by} at review."
        if settle is not None:
            settled = settle(ticket.operation_id, ticket.summary)
            if hasattr(settled, "__await__"):
                await settled
        answer = self.signer.sign({**ticket.describe(), "refused_by": refused_by})
        self.audit.write("review", company=self.company, what="refused", refused_by=refused_by, **ticket.describe(), by="person")
        return answer


class ShieldedOperationExecutor:
    """``pap.company.operationExecutor`` in front of the application's: decided first."""

    def __init__(self, shield: CompanyShield, inner: Any, *, action: str) -> None:
        self.shield = shield
        self.inner = inner
        self.action = action

    async def perform(self, operation: Any, account_id: str) -> Any:
        from personal_agent_protocol.company import OperationFailed, OperationOutcomeUnknown  # noqa: PLC0415
        from personal_agent_protocol.models import OperationResult  # noqa: PLC0415

        terms = getattr(operation, "terms", None)
        decision = self.shield.decide_operation(
            self.action, terms, account_id=account_id, summary=str(getattr(operation, "summary", "") or "")
        )
        if decision.verdict == "deny":
            raise OperationFailed(OperationResult(summary=f"Refused by the company's policy: {decision.sentence}"))
        if decision.verdict == "ask":
            ticket = self.shield.hold(
                operation_id=str(operation.operation_id),
                revision=int(operation.revision),
                action=self.action,
                account_id=account_id,
                action_class=operation_class(terms),
                sentence=decision.sentence,
                perform=lambda: self.inner.perform(operation, account_id),
            )
            raise OperationOutcomeUnknown(f"held for review by the company (ticket {ticket.ticket_id}): {decision.sentence}")
        result = await self.inner.perform(operation, account_id)
        self.shield.state.count(
            Action(kind="other", title=self.action, **{"class": operation_class(terms)}), decision
        )
        self.shield.audit.write(
            "operation",
            company=self.shield.company,
            account=account_id,
            action=self.action,
            operation=str(operation.operation_id),
            revision=int(operation.revision),
            summary=str(getattr(result, "summary", "") or ""),
            signature=self.shield.signer.sign({"operation": str(operation.operation_id), "revision": int(operation.revision), "summary": str(getattr(result, "summary", "") or "")})["signature"],
            by="agent",
        )
        return result


class ShieldedCompanyAgent:
    """``pap.company.agent`` in front of the application's: a turn is answered only when the policy lets it."""

    def __init__(self, shield: CompanyShield, inner: Any) -> None:
        self.shield = shield
        self.inner = inner

    async def respond(self, turn: Any) -> Sequence[Any]:
        from personal_agent_protocol.company import Reply  # noqa: PLC0415

        decision = self.shield.decide_answer(str(turn.client_id), account_id=getattr(turn, "account_id", None))
        if decision.verdict == "deny":
            return [Reply(text=f"The company does not answer this: {decision.sentence}")]
        if decision.verdict == "ask":
            return [Reply(text=f"The company holds this for a person to review: {decision.sentence}")]
        replies = list(await self.inner.respond(turn))
        kept: list[Any] = []
        for reply in replies:
            proposed = getattr(reply, "operation", None)
            if proposed is None:
                kept.append(reply)
                continue
            # An operation the agent proposes is classed by what it does; one the
            # policy refuses outright is not proposed, and the person is told why.
            proposal = self.shield.decide_operation(
                str(proposed.action), proposed.terms, account_id=str(getattr(turn, "account_id", "") or ""), summary=proposed.summary
            )
            if proposal.verdict == "deny":
                kept.append(Reply(text=f"{reply.text or ''}\n\nNot proposed: {proposal.sentence}".strip(), data=reply.data))
            else:
                kept.append(reply)
        return kept


class ShieldCompanyPlugin:
    """A Reactor plugin wrapping an application's company contributions behind the Shield.

    ``agent`` is the application's ``pap.company.agent``; ``executors`` its
    ``pap.company.operationExecutor`` per declared action. Everything else of
    the company (accounts, client policy, stores) is the host's, contributed
    as before.
    """

    def __init__(self, shield: CompanyShield, *, agent: Any, executors: Mapping[str, Any]) -> None:
        self.shield = shield
        self.agent = agent
        self.executors = dict(executors)

    def provide_contributions(self, contributions: Any) -> None:
        from personal_agent_protocol.company import COMPANY_AGENTS, OPERATION_EXECUTORS  # noqa: PLC0415

        contributions.contribute(
            COMPANY_AGENTS, ShieldedCompanyAgent(self.shield, self.agent), contribution_id="shielded-application"
        )
        for action, executor in self.executors.items():
            contributions.contribute(
                OPERATION_EXECUTORS,
                ShieldedOperationExecutor(self.shield, executor, action=action),
                contribution_id=f"shielded-operation-{action}",
            )


__all__ = [
    "ANSWER_SEND",
    "OPERATION_BUY",
    "OPERATION_WRITE",
    "CompanyShield",
    "ReviewRefused",
    "ReviewTicket",
    "ShieldCompanyPlugin",
    "ShieldedCompanyAgent",
    "ShieldedOperationExecutor",
    "Signer",
    "canonical",
    "money_moves",
    "operation_class",
]
