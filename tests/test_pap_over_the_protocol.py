# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Shield as a PAP company, over the protocol (SHIELD SH-71).

A personal agent — the PAP SDK's client, its own identity, DPoP, discovery,
a Session, Device Sign-In — talks to a company the PAP SDK serves over HTTP
(in one process, the SDK's in-process network), whose agent and operation
executor stand behind `ShieldCompanyPlugin`. The company's policy says *ask me
first* for anything that moves money: the exchange the agent proposes is
confirmed by the person's agent and **held** (`in_progress`, a ticket kept,
nothing performed); a person of the company **releases** it; it is performed
once, settled `succeeded`, read back so by the personal agent; the answer is
**signed**; the audit says it in PAP's vocabulary (`review` held, released).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

pytest.importorskip(
    "personal_agent_protocol", reason="the PAP SDK is the company's; `pip install personal-agent-protocol`"
)

from personal_agent_protocol import (
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.company import build_company, company_app
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    ClockPlugin,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    ScriptedInput,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import (
    CONFIG,
    DOMAIN,
    ExchangeExecutor,
    ManzanitaAccounts,
    ManzanitaAgent,
)
from personal_agent_protocol.models import ClientMetadata
from personal_agent_protocol.operations import OperationsClient, approve, operations_endpoint
from reactor import PluginManifest

from agent_shield.audit import AuditLog
from agent_shield.pap import CompanyShield, ShieldCompanyPlugin, Signer
from agent_shield.policy import Policy, Rule

TENANT = "atlas-demo"
PAIRWISE = "usr_ada_at_manzanita_000000"


class _Accounts:
    def provide_contributions(self, contributions: object) -> None:
        from personal_agent_protocol.company import COMPANY_ACCOUNTS

        contributions.contribute(COMPANY_ACCOUNTS, ManzanitaAccounts(), contribution_id="accounts")  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_a_personal_agent_s_exchange_is_held_for_review_released_by_a_person_and_signed(tmp_path) -> None:
    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())

    # The company: Manzanita's accounts, its agent and its exchange — the agent and
    # the executor behind the Shield, whose policy answers a person's agent and asks a
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
            (PluginManifest(name="manzanita-accounts", version="1"), _Accounts()),
            (PluginManifest(name="manzanita-clock", version="1"), ClockPlugin(clock)),
            (
                PluginManifest(name="manzanita-shielded", version="1"),
                ShieldCompanyPlugin(shield, agent=ManzanitaAgent(), executors={"orders.exchange": exchange}),
            ),
        ],
    )
    network.add(DOMAIN, company_app(service))

    # The personal agent: discovery, a Session, then Device Sign-In approved on the company's page.
    http = network.client()
    host = PersonalAgentHost(atlas, clock, protected_input=ScriptedInput())
    reactor = personal_agent_reactor(host, network=network, http_client=http)
    transport = DpopHttpClient(reactor=reactor, http_client=http)
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(DOMAIN)
    metadata = company.oauth_metadata
    assert metadata is not None
    who = {"tenant_id": TENANT, "pairwise_user_id": PAIRWISE, "issuer": metadata.issuer}
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=TENANT,
    )
    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    await service.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.status == "complete" and done.token is not None
    signed_in = done.token

    # The person asks; the company's agent, through the Shield, proposes the exchange.
    endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    conversations = ConversationClient(transport=transport)
    page = await conversations.start(
        endpoint,
        Message(id=generate_message_id(reactor), sender="human", text="Exchange my jacket for something warmer"),
        token=signed_in,
        wait=0,
        **who,
    )
    proposal = [event for event in page.events if event.type == "message" and event.message.operation][
        -1
    ].message.operation  # type: ignore[union-attr]
    assert proposal is not None and proposal.state == "proposed" and proposal.terms["order_id"] == "ord_7Hk2"

    # The person's agent confirms exactly that revision: the Shield holds it for the company's review.
    ops = operations_endpoint(company.document, ClientMetadata.model_validate(atlas.metadata))
    assert ops is not None
    operations = OperationsClient(transport=transport)
    outcome = await operations.confirm(ops, proposal, approval=approve(proposal), token=signed_in, **who)
    assert outcome.status == "confirmed"
    assert outcome.operation is not None and outcome.operation.state == "in_progress"
    assert exchange.performed == [], "nothing is performed while no person of the company has released it"
    (ticket,) = shield.held()
    assert (
        ticket.operation_id == proposal.operation_id
        and ticket.action_class == "buy"
        and ticket.account_id == "acct_ada"
    )

    # A person of the company releases it: performed once, settled, read back by the personal agent.
    async def settle(operation_id, result):
        await service.settle(operation_id, result, succeeded=True)

    answer = await shield.release(ticket.ticket_id, released_by="sam@manzanita.example", settle=settle)
    assert exchange.performed == [proposal.operation_id]
    read = await operations.read(ops, proposal.operation_id, token=signed_in, **who)
    assert read.state == "succeeded" and read.result is not None
    assert read.result.summary.startswith("Exchanged the Ridge Jacket (M)")

    # Its answer signed by the company's key, and the audit in PAP's vocabulary.
    assert answer["state"] == "released" and answer["released_by"] == "sam@manzanita.example"
    assert shield.signer.verify(answer)
    assert not shield.signer.verify({**answer, "released_by": "someone else"})
    events = [
        (row["event"], row.get("what"), row.get("operation_id"))
        for row in shield.audit.rows()
        if row["event"] == "review"
    ]
    assert events == [("review", "held", proposal.operation_id), ("review", "released", proposal.operation_id)]

    # Confirmed again, nothing is performed twice.
    again = await operations.confirm(ops, proposal, approval=approve(proposal), token=signed_in, **who)
    assert again.operation is not None and again.operation.state == "succeeded"
    assert exchange.performed == [proposal.operation_id]
