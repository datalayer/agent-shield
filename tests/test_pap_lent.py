# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP through the Shield (SH-70, SH-72): the gateway's ``pap_*`` tools
classed and decided by the Rules, a company named as the authorizer's resource,
the harness's own fetch to a connected company refused."""

from __future__ import annotations

from types import SimpleNamespace

from agent_shield.acp.proxy import ShieldProxy, action_of_tool_call, tool_name_of
from agent_shield.acp.workspace import Workspace
from agent_shield.audit import AuditLog
from agent_shield.policy import (
    PAP_TOOL_CLASSES,
    Action,
    Context,
    LoadedPolicy,
    Network,
    Policy,
    Rule,
    Subject,
    decide,
    hook_for,
    pap_tool_class,
    strictest,
)


def call(title: str, kind: str = "other", **raw):
    return SimpleNamespace(kind=kind, title=title, input=raw or None, locations=[], tool_call_id="c1", status="pending")


def test_the_gateways_pap_tools_are_classed_as_agentspecs_says():
    assert pap_tool_class("pap_confirm") == "buy" and pap_tool_class("pap_ask") == "send"
    assert pap_tool_class("pap_manzanita_examples_datalayer_run_pap_propose") == "send"
    assert pap_tool_class("pap_read") == "read" and pap_tool_class("fetch") is None
    assert strictest(("write", "buy")) == "buy" and strictest(("read",)) == "read" and strictest(()) is None
    assert set(PAP_TOOL_CLASSES) >= {"pap_sign_in", "pap_ask", "pap_propose", "pap_confirm", "pap_read"}


def test_a_tool_call_naming_a_pap_tool_takes_its_class_not_the_kinds(tmp_path):
    workspace = Workspace(tmp_path)
    assert tool_name_of(call("pap_confirm (`orders.exchange`)")) == "pap_confirm"
    assert tool_name_of(call("Confirm", name="pap_confirm")) == "pap_confirm"
    action, problem = action_of_tool_call(call("pap_confirm", kind="other", operation_ref="op-1"), workspace)
    assert problem is None and action is not None
    assert action.action_class == "buy" and action.kind == "other" and action.resource is None
    # A host's own table names the company as the resource (the runtime's pap_connections).
    hosted = lambda name: ("send", "connection:manzanita.examples.datalayer.run") if name.endswith("pap_ask") else None
    action, _ = action_of_tool_call(call("pap_manzanita_pap_ask", kind="read", message="hi"), workspace, tool_class=hosted)
    assert action.action_class == "send" and action.resource == "connection:manzanita.examples.datalayer.run"
    # A tool of no company keeps the kind's class.
    action, _ = action_of_tool_call(call("Read file", kind="read", path="a.py"), workspace, tool_class=hosted)
    assert action.action_class == "read" and action.path == "a.py"


def test_each_pap_operation_is_decided_by_the_rules_like_any_action():
    policies = [
        Policy(
            scope="team",
            rules=[
                Rule(name="ask before sending", decision="ask", classes=["send"]),
                Rule(name="buying is mine", decision="deny", classes=["buy"]),
                Rule(name="reading is fine", decision="allow", classes=["read"]),
            ],
        )
    ]
    ctx = Context(workspace="/w")
    ask = Action(kind="other", title="pap_ask", resource="connection:acme.example", **{"class": "send"})
    assert decide(ask, ctx, policies).verdict == "ask"
    confirm = Action(kind="other", title="pap_confirm", resource="connection:acme.example", **{"class": "buy"})
    assert decide(confirm, ctx, policies).verdict == "deny"
    assert decide(Action(kind="other", title="pap_read", **{"class": "read"}), ctx, policies).verdict == "allow"


def test_the_pap_grant_is_a_decision_input_through_the_authorizer():
    """SH-72: a propose at a company the person did not connect is refused at the
    Rules, through the authorizer, whatever the Rule says."""

    class Grants:
        name = "openfga-through-iam"

        def evaluate(self, request):
            from agent_shield.policy import EvaluationResponse

            held = request.object == "connection:manzanita.examples.datalayer.run" and request.relation in ("can_send", "can_write")
            return EvaluationResponse(decision=held, context={"model_version": "01M", "reason_user": "" if held else "no connection to that company"})

    policies = [Policy(scope="team", authorize=["send", "buy"], rules=[Rule(name="propose freely", decision="allow", classes=["send"])])]
    ctx = Context(workspace="/w", subject=Subject(type="deployment", id="d-1"), authorize=hook_for(Grants()))
    connected = Action(kind="other", title="pap_propose", resource="connection:manzanita.examples.datalayer.run", **{"class": "send"})
    assert decide(connected, ctx, policies).verdict == "allow"
    elsewhere = Action(kind="other", title="pap_propose", resource="connection:other.example", **{"class": "send"})
    refused = decide(elsewhere, ctx, policies)
    assert refused.verdict == "deny" and refused.decided_by == "authorizer" and "no connection to that company" in refused.sentence


def test_the_harnesss_own_fetch_to_a_connected_company_is_refused_whatever_the_allow_list_says():
    policies = [Policy(scope="session", network=Network(fetch=["manzanita.examples.datalayer.run", "*.example"]))]
    ctx = Context(workspace="/w", companies=("manzanita.examples.datalayer.run",))
    fetch = Action(kind="fetch", title="fetch", url="https://manzanita.examples.datalayer.run/orders", **{"class": "read"})
    refused = decide(fetch, ctx, policies)
    assert refused.verdict == "deny" and refused.decided_by == "network" and refused.rule == "pap"
    assert "a company the application connects through PAP" in refused.sentence and "never by a fetch" in refused.sentence
    sub = Action(kind="fetch", title="fetch", url="https://api.manzanita.examples.datalayer.run/x", **{"class": "read"})
    assert decide(sub, ctx, policies).rule == "pap"
    other = Action(kind="fetch", title="fetch", url="https://docs.example/x", **{"class": "read"})
    assert decide(other, ctx, policies).verdict == "allow"
    assert decide(fetch, Context(workspace="/w"), policies).verdict == "allow", "with no company connected the allow-list decides"


def test_the_proxy_carries_the_hook_and_the_companies_into_every_session(tmp_path):
    hosted = lambda name: ("buy", "connection:acme.example") if name == "pap_confirm" else None
    proxy = ShieldProxy(
        ["true"],
        policies=[LoadedPolicy(policy=Policy(scope="session", rules=[Rule(name="buying is mine", decision="deny", classes=["buy"])]), origin="t")],
        audit=AuditLog(tmp_path / "audit.jsonl"),
        workspace=tmp_path,
        tool_class=hosted,
        companies=["acme.example"],
    )
    session = proxy._open("s1", Workspace(tmp_path))
    assert session.companies == ("acme.example",) and session.context.companies == ("acme.example",)
    action, _ = action_of_tool_call(call("pap_confirm"), session.workspace, tool_class=proxy.tool_class)
    assert action.resource == "connection:acme.example" and proxy.decide(session, action).verdict == "deny"
