# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Shield as a PAP company, over the protocol (SHIELD SH-71), PAP draft 0.4.

A personal agent — the PAP SDK's client, its own identity, discovery, a
Session with the extensions it negotiated, Device Sign-In — talks to a company
the PAP SDK serves over HTTP (in one process, the SDK's in-process network),
whose agent and operation executor stand behind `ShieldCompanyPlugin`. The
company's policy says *ask me first* for anything that moves money.

Operations v2: the exchange is asked for at the company's API and refused with
`403 approval_required` and the operation; the person approves that revision,
and the same request with the approval is **held** by the Shield (`503` and
`Retry-After`, a ticket kept, nothing performed); a person of the company
**releases** it; it is performed once and settled, and the same request with
the approval now answers what it came to; the answer is **signed**; the audit
says it in PAP's vocabulary (`review` held, released). In a conversation, the
approval goes in a message: the company says it is still being done, and a
person of the company may refuse it — settled as failed, nothing performed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

pytest.importorskip(
    "personal_agent_protocol", reason="the PAP SDK is the company's; `pip install personal-agent-protocol`"
)

from personal_agent_protocol import (
    DeviceSignInClient,
    DiscoveryClient,
    Message,
    OperationsClient,
    SessionClient,
    SessionHttpClient,
    generate_request_id,
)
from personal_agent_protocol.apis import ApiClient, ApiError
from personal_agent_protocol.company import COMPANY_ACCOUNTS, COMPANY_APIS, build_company, company_app
from personal_agent_protocol.conversations import ConversationClient
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    ClockPlugin,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    ScriptedApprovals,
    ScriptedInput,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import (
    CONFIG,
    DOMAIN,
    ExchangeExecutor,
    ManzanitaAccounts,
    ManzanitaAgent,
    ManzanitaApi,
)
from personal_agent_protocol.extensions import negotiate_extensions
from personal_agent_protocol.models import Approval, Author, operations_content
from personal_agent_protocol.reactor import RATE_LIMIT_BUDGETS, first_contribution
from reactor import PluginManifest

from agent_shield.audit import AuditLog
from agent_shield.pap import CompanyShield, ShieldCompanyPlugin, Signer
from agent_shield.policy import Policy, Rule

TENANT = "atlas-demo"
PAIRWISE = "usr_ada_at_manzanita_000000"
EXCHANGE = f"https://{DOMAIN}/api/orders/ord_7Hk2/exchanges"


class _Manzanita:
    """Manzanita's accounts and API: everything of the company but its agent and executors."""

    def provide_contributions(self, contributions: Any) -> None:
        contributions.contribute(COMPANY_ACCOUNTS, ManzanitaAccounts(), contribution_id="accounts")
        contributions.contribute(COMPANY_APIS, ManzanitaApi(), contribution_id="api")


@dataclass
class World:
    shield: CompanyShield
    exchange: ExchangeExecutor
    service: Any
    company: Any
    session: Any
    token: Any
    reactor: Any
    transport: SessionHttpClient
    host: PersonalAgentHost

    async def approval(self, operation: Any) -> Approval:
        """The person approves exactly this revision, on the personal agent's own surface."""
        return await OperationsClient(reactor=self.reactor).ask_user(
            operation, organization=self.company.document.organization, tenant_id=TENANT
        )

    def message(self, text: str | None = None, **fields: Any) -> Message:
        author = Author(type="human" if text else "agent")
        return Message(id=generate_request_id(self.reactor), author=author, text=text, **fields)


async def signed_in_world(tmp_path) -> World:
    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())

    # The company: Manzanita's accounts, API, agent and exchange — the agent and the
    # executor behind the Shield, whose policy answers a person's agent and asks a
    # person of the company before money moves.
    shield = CompanyShield(
        [
            Policy(
                scope="team",
                rules=[
                    Rule(name="answering a person's agent", decision="allow", classes=["send"]),
                    Rule(name="money is reviewed", decision="ask", classes=["buy"]),
                ],
            )
        ],
        company=DOMAIN,
        audit=AuditLog(tmp_path / "company-audit.jsonl"),
        signer=Signer(b"manzanitas-review-key", key_id="manzanita-2026"),
        clock=lambda: datetime.now(timezone.utc),
    )
    exchange = ExchangeExecutor()
    service = build_company(
        CONFIG,
        http_client=network.client(),
        address_resolver=network.resolve,
        plugins=[
            (PluginManifest(name="manzanita", version="1"), _Manzanita()),
            (PluginManifest(name="manzanita-clock", version="1"), ClockPlugin(clock)),
            (
                PluginManifest(name="manzanita-shielded", version="1"),
                ShieldCompanyPlugin(shield, agent=ManzanitaAgent(), executors={"orders.exchange": exchange}),
            ),
        ],
    )
    network.add(DOMAIN, company_app(service))

    # The personal agent: discovery, a Session with the extensions both sides list,
    # then Device Sign-In approved on the company's page.
    http = network.client()
    host = PersonalAgentHost(atlas, clock, protected_input=ScriptedInput(), approvals=ScriptedApprovals(always=True))
    reactor = personal_agent_reactor(host, network=network, http_client=http)
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(DOMAIN)
    metadata = company.oauth_metadata
    assert metadata is not None
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        tenant_id=TENANT,
        extensions=negotiate_extensions(company.document.extensions, supported=atlas.supported_extensions),
    )
    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        organization=company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await service.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.status == "complete" and done.token is not None

    transport = SessionHttpClient(reactor=reactor, http_client=http)

    async def no_pause(key: str, seconds: float) -> None:
        """The shared budget would hold each retry for the 503's `Retry-After`."""

    first_contribution(reactor, RATE_LIMIT_BUDGETS, "budget").defer = no_pause
    return World(shield, exchange, service, company, session, done.token, reactor, transport, host)


@pytest.mark.asyncio
async def test_an_exchange_at_the_api_is_held_for_review_released_by_a_person_and_signed(tmp_path) -> None:
    world = await signed_in_world(tmp_path)
    api = ApiClient(transport=world.transport)

    # The request: refused with the operation to approve, nothing done.
    asked = await api.call("POST", EXCHANGE, session=world.session, token=world.token, body={})
    assert asked.status == 403 and asked.operation is not None
    operation = asked.operation
    assert operation.terms is not None and operation.terms["order_id"] == "ord_7Hk2"
    assert world.exchange.performed == [] and world.shield.held() == []

    # The person approves exactly that revision; the same request with the approval is
    # held by the Shield for the company's review: 503, nothing performed.
    approval = await world.approval(operation)
    for _ in range(2):
        with pytest.raises(ApiError) as raised:
            await api.call("POST", EXCHANGE, session=world.session, token=world.token, body={}, approval=approval)
        assert raised.value.status_code == 503 and raised.value.details == {"retry_after": "5"}
    assert world.exchange.performed == [], "nothing is performed while no person of the company has released it"
    (ticket,) = world.shield.held()
    assert ticket.operation_id == operation.operation_id and ticket.revision == operation.revision
    assert ticket.action_class == "buy" and ticket.account_id == "acct_ada"

    # A person of the company releases it: performed once, settled, answered to the request.
    async def settle(operation_id: str, result: Any, succeeded: bool) -> None:
        await world.service.settle(operation_id, result, succeeded=succeeded)

    answer = await world.shield.release(ticket.ticket_id, released_by="sam@manzanita.example", settle=settle)
    assert world.exchange.performed == [operation.operation_id]
    done = await api.call("POST", EXCHANGE, session=world.session, token=world.token, body={}, approval=approval)
    assert done.status == 200 and done.body["summary"].startswith("Exchanged the Ridge Jacket (M)")

    # Its answer signed by the company's key, and the audit in PAP's vocabulary.
    assert answer["state"] == "released" and answer["released_by"] == "sam@manzanita.example"
    assert world.shield.signer.verify(answer)
    assert not world.shield.signer.verify({**answer, "released_by": "someone else"})
    events = [
        (row["event"], row.get("what"), row.get("operation_id"))
        for row in world.shield.audit.rows()
        if row["event"] == "review"
    ]
    assert events == [("review", "held", operation.operation_id), ("review", "released", operation.operation_id)]

    # Asked again with the approval, nothing is performed twice.
    again = await api.call("POST", EXCHANGE, session=world.session, token=world.token, body={}, approval=approval)
    assert again.body == done.body and world.exchange.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_an_exchange_approved_in_a_conversation_is_held_and_a_person_may_refuse_it(tmp_path) -> None:
    world = await signed_in_world(tmp_path)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    conversations = ConversationClient(transport=world.transport)

    # The person asks; the company's agent, through the Shield, proposes the exchange.
    page = await conversations.start(
        endpoint, world.message("Exchange my jacket for something warmer"), session=world.session, token=world.token, wait=0
    )
    operation = next(
        event.message.operation
        for event in page.events
        if event.message is not None and event.message.operation is not None
    )
    assert operation.terms is not None and operation.terms["order_id"] == "ord_7Hk2"

    # The approval, in a message: held by the Shield, and the company says it is still being done.
    approval = await world.approval(operation)
    page = await conversations.send(
        endpoint,
        page.conversation_id,
        world.message(extensions=operations_content(approval=approval)),
        session=world.session,
        token=world.token,
        wait=0,
    )
    said = [event.message for event in page.events if event.message is not None and event.message.role == "company"]
    assert said[-1].text.startswith("This is still being done") and said[-1].operation is None
    (ticket,) = world.shield.held()
    assert ticket.operation_id == operation.operation_id and world.exchange.performed == []

    # A person of the company refuses it: settled as failed, nothing performed, signed.
    async def settle(operation_id: str, result: Any, succeeded: bool) -> None:
        await world.service.settle(operation_id, result, succeeded=succeeded)

    answer = await world.shield.refuse(ticket.ticket_id, refused_by="sam", reason="Out of stock in M.", settle=settle)
    assert answer["state"] == "refused" and world.shield.signer.verify(answer)
    record = await world.service.operation_record(operation.operation_id)
    assert record.status == "performed" and record.outcome is not None
    assert (record.outcome.summary, record.outcome.succeeded) == ("Out of stock in M.", False)
    assert world.exchange.performed == []
