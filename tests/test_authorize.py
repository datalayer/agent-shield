# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The authorizer port (SH-74): AuthZen's shape, the local grants,
deny wins over any Rule, unreachable is a deny, allows cached until expiry."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agent_shield.policy import (
    ActionName,
    AllowCache,
    AuthorizerConfig,
    AuthorizerUnreachable,
    AuthZenAuthorizer,
    Action,
    Context,
    EvaluationRequest,
    EvaluationResponse,
    Grant,
    LocalAuthorizer,
    OpenFgaAuthorizer,
    Policy,
    PolicyRefused,
    Resource,
    Rule,
    Subject,
    authorize,
    decide,
    hook_for,
    parse_policies,
    request_for,
    widening,
)

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
ALICE = Subject(type="account", id="alice")


def action(kind: str, cls: str, **fields) -> Action:
    return Action(kind=kind, title="t", **{"class": cls}, **fields)


def request(cls: str = "execute", resource: str = "workspace:w") -> EvaluationRequest:
    kind, _, ident = resource.partition(":")
    return EvaluationRequest(subject=ALICE, action=ActionName(name=cls), resource=Resource(type=kind, id=ident))


class Fake:
    """A decision point that answers what it is told, or is down."""

    name = "fake"

    def __init__(self, decision: bool | None = True) -> None:
        self.decision = decision
        self.asked: list[EvaluationRequest] = []

    def evaluate(self, req: EvaluationRequest) -> EvaluationResponse:
        self.asked.append(req)
        if self.decision is None:
            raise AuthorizerUnreachable("connection refused")
        return EvaluationResponse(decision=self.decision, context={"model_version": "m1", "reason_user": "said so"})


# -- the shape -----------------------------------------------------------------------------


def test_the_request_is_authzens_and_maps_to_a_relationship():
    req = request("read", "workspace:home/alice/p")
    assert req.model_dump() == {
        "subject": {"type": "account", "id": "alice", "properties": {}},
        "action": {"name": "read", "properties": {}},
        "resource": {"type": "workspace", "id": "home/alice/p", "properties": {}},
        "context": {},
    }
    assert req.user == "account:alice" and req.relation == "can_read" and req.object == "workspace:home/alice/p"
    assert request("can_call", "tool:earthdata/search").relation == "can_call"
    assert EvaluationResponse(decision=False, context={"reason_admin": {"en": "no tuple"}}).reason == "no tuple"
    assert EvaluationResponse(decision=True).reason is None


def test_an_action_becomes_a_request_from_its_path_command_url_or_resource():
    ctx = Context(workspace="/home/alice/p", session_id="s1", subject=ALICE)
    assert request_for(action("edit", "write", path="src/a.py", inside=True), ctx).object == "workspace:home/alice/p"
    assert request_for(action("edit", "write", path="/etc/hosts", inside=False), ctx).object == "workspace:etc/hosts"
    assert request_for(action("execute", "execute", command="ls"), ctx).object == "workspace:home/alice/p"
    assert request_for(action("fetch", "read", url="https://acme.example/x"), ctx).object == "host:acme.example"
    assert request_for(action("other", "write", resource="tool:earthdata/search"), ctx).object == "tool:earthdata/search"
    assert request_for(action("other", "send", resource="connection:acme.example"), ctx).relation == "can_send"
    # A file action whose path the request does not carry acts in the workspace.
    plain = request_for(action("other", "write"), Context(workspace="/w"))
    assert plain.object == "workspace:w" and plain.user == "account:local"
    # Claude Code's own Write asks permission as "Preparing file…", kind edit, no path yet.
    preparing = request_for(Action(kind="edit", title="Preparing file…", **{"class": "write"}), ctx)
    assert preparing.object == "workspace:home/alice/p" and preparing.relation == "can_write"
    assert request_for(action("read", "read"), ctx).object == "workspace:home/alice/p"
    # Nothing else of a session is an object of the model: only a class with no workspace relation asks about it.
    assert request_for(action("other", "send"), ctx).object == "session:s1"
    with pytest.raises(ValueError, match="type:id"):
        request_for(action("other", "write", resource="no-colon"), ctx)


# -- the port's rules ----------------------------------------------------------------------


def test_a_deny_is_a_deny_and_an_allow_is_cached_until_its_expiry():
    cache = AllowCache(ttl=timedelta(seconds=60))
    fake = Fake(True)
    first = authorize(request(), fake, cache=cache, now=NOW)
    assert first.verdict == "allow" and first.model_version == "m1" and not first.cached
    assert first.expires == NOW + timedelta(seconds=60) and len(cache) == 1
    fake.decision = False
    denied = authorize(request(), fake, cache=cache, now=NOW + timedelta(seconds=1))
    assert denied.verdict == "deny" and denied.reason == "said so" and denied.model_version == "m1"
    assert len(cache) == 1, "a deny is never cached, and does not evict the allow"


def test_unreachable_is_a_deny_naming_the_authorizer_unless_an_unexpired_allow_is_held():
    cache = AllowCache(ttl=timedelta(seconds=60))
    down = Fake(None)
    refused = authorize(request(), down, cache=cache, now=NOW)
    assert refused.verdict == "deny"
    assert "the authorizer fake could not be reached (connection refused)" in refused.reason
    assert "no unexpired allow is held for account:alice can_execute workspace:w" in refused.reason
    # An allow made while it answered is honoured through the outage, until it expires.
    up = Fake(True)
    authorize(request(), up, cache=cache, now=NOW)
    kept = authorize(request(), down, cache=cache, now=NOW + timedelta(seconds=59))
    assert kept.verdict == "allow" and kept.cached and "is honoured" in kept.reason
    expired = authorize(request(), down, cache=cache, now=NOW + timedelta(seconds=61))
    assert expired.verdict == "deny" and len(cache) == 0
    # Without a cache nothing is kept.
    assert authorize(request(), down, now=NOW).verdict == "deny"
    with pytest.raises(ValueError, match="only an allow is cached"):
        cache.put(("a", "b", "c"), refused)


def test_the_hook_asks_one_authorizer_through_one_cache():
    fake = Fake(True)
    cache = AllowCache()
    hook = hook_for(fake, cache=cache)
    assert hook(request()).verdict == "allow" and len(cache) == 1 and len(fake.asked) == 1


# -- decide ----------------------------------------------------------------------------------


def policies(*, authorize_classes=("execute",), rule: str = "allow") -> list[Policy]:
    return [
        Policy(
            scope="organization",
            authorize=list(authorize_classes),
            rules=[Rule(name="run", decision=rule, classes=["execute"])],
        )
    ]


def test_a_deny_wins_over_a_rule_saying_do_it():
    fake = Fake(False)
    ctx = Context(workspace="/w", subject=ALICE, authorize=hook_for(fake))
    decision = decide(action("execute", "execute", command="ls"), ctx, policies(rule="allow"))
    assert decision.verdict == "deny" and decision.decided_by == "authorizer"
    assert decision.rule == "authorize" and decision.scope == "organization"
    assert decision.authorizer == "fake" and decision.authorization == "deny" and decision.model_version == "m1"
    assert decision.sentence == "t (`ls`): leave it to me — said so"
    assert fake.asked[0].relation == "can_execute"


def test_an_allow_lets_the_rules_decide_and_loosens_nothing():
    fake = Fake(True)
    ctx = Context(workspace="/w", subject=ALICE, authorize=hook_for(fake))
    allowed = decide(action("execute", "execute", command="ls"), ctx, policies(rule="allow"))
    assert allowed.verdict == "allow" and allowed.decided_by == "rule" and allowed.rule == "run"
    assert allowed.authorizer == "fake" and allowed.authorization == "allow" and allowed.model_version == "m1"
    asked = decide(action("execute", "execute", command="ls"), ctx, policies(rule="ask"))
    assert asked.verdict == "ask" and asked.decided_by == "rule" and asked.authorization == "allow"
    denied = decide(action("execute", "execute", command="ls"), ctx, policies(rule="deny"))
    assert denied.verdict == "deny" and denied.decided_by == "rule"
    # The default, with nothing said, still asks.
    nothing = decide(action("delete", "delete", path="x"), ctx, [Policy(scope="organization", authorize=["delete"])])
    assert nothing.verdict == "ask" and nothing.decided_by == "default" and nothing.authorization == "allow"


def test_a_class_the_policy_does_not_list_asks_no_authorizer():
    fake = Fake(False)
    ctx = Context(workspace="/w", subject=ALICE, authorize=hook_for(fake))
    decision = decide(action("read", "read", path="a", inside=True), ctx, policies(authorize_classes=("execute",)))
    assert decision.verdict == "ask" and decision.decided_by == "default" and decision.authorizer is None
    assert fake.asked == []


def test_no_authorizer_configured_is_a_deny_for_a_listed_class_never_a_fail_open():
    decision = decide(action("execute", "execute", command="ls"), Context(workspace="/w"), policies(rule="allow"))
    assert decision.verdict == "deny" and decision.decided_by == "authorizer"
    assert "no authorizer is configured; nothing is authorized unsaid" in decision.sentence


def test_an_unreachable_authorizer_is_a_deny_in_decide_and_a_cached_allow_is_honoured():
    cache = AllowCache(ttl=timedelta(seconds=60))
    up = Fake(True)
    ctx = Context(workspace="/w", subject=ALICE, authorize=hook_for(up, cache=cache))
    assert decide(action("execute", "execute", command="ls"), ctx, policies()).verdict == "allow"
    down = Fake(None)
    ctx_down = Context(workspace="/w", subject=ALICE, authorize=hook_for(down, cache=cache))
    kept = decide(action("execute", "execute", command="ls"), ctx_down, policies())
    assert kept.verdict == "allow" and kept.authorization == "cached allow"
    # The same relationship (the workspace's can_execute) is honoured whatever the command;
    # another resource was never allowed, so it is a deny naming the authorizer.
    same = decide(action("execute", "execute", command="rm x"), ctx_down, policies())
    assert same.verdict == "allow" and same.authorization == "cached allow"
    other = decide(action("delete", "delete", path="a", inside=True), ctx_down, [Policy(scope="organization", authorize=["delete"])])
    assert other.verdict == "deny" and "could not be reached" in other.sentence and "fake" in other.sentence


def test_the_strictest_scope_listing_the_class_decides_and_the_deny_comes_before_limits():
    from agent_shield.policy import Limits, Threshold

    fake = Fake(False)
    ctx = Context(workspace="/w", subject=ALICE, authorize=hook_for(fake))
    docs = [
        Policy(scope="session", authorize=["execute"]),
        Policy(scope="organization", limits=Limits(tool_calls=Threshold(soft=0, hard=0))),
    ]
    decision = decide(action("execute", "execute", command="ls"), ctx, docs)
    assert decision.decided_by == "authorizer" and decision.scope == "session"


# -- the local contribution ----------------------------------------------------------------


def test_local_grants_are_patterns_on_subject_relation_and_object():
    local = LocalAuthorizer(
        [
            Grant(subject="account:alice", relation="execute", object="workspace:home/alice/*"),
            Grant(subject="deployment:*", relation="can_call", object="tool:earthdata/*"),
        ]
    )
    assert local.evaluate(request("execute", "workspace:home/alice/p")).decision is True
    refused = local.evaluate(request("execute", "workspace:home/bob/p"))
    assert refused.decision is False and "add one to authorizer.local.grants" in refused.reason
    assert local.evaluate(request("write", "workspace:home/alice/p")).decision is False
    tool = EvaluationRequest(
        subject=Subject(type="deployment", id="d1"), action=ActionName(name="can_call"), resource=Resource(type="tool", id="earthdata/search")
    )
    assert local.evaluate(tool).decision is True and local.evaluate(tool).model_version == "local:2"


def test_the_file_names_its_authorizer_and_the_schema_holds_it(tmp_path):
    text = """
scope: session
authorize: [execute, send]
authorizer:
  local:
    grants:
      - {subject: "account:*", relation: execute, object: "workspace:*"}
rules:
  - {name: run, decision: allow, classes: [execute]}
"""
    import yaml

    loaded = parse_policies(yaml.safe_load(text), "agent-shield.yaml")
    policy = loaded[0].policy
    assert policy.authorize == ["execute", "send"] and policy.authorizer is not None
    assert policy.authorizer.kind == "local" and isinstance(policy.authorizer.build(), LocalAuthorizer)
    ctx = Context(workspace="/w", subject=ALICE, authorize=hook_for(policy.authorizer.build()))
    assert decide(action("execute", "execute", command="ls"), ctx, [policy]).verdict == "allow"
    with pytest.raises(PolicyRefused, match="exactly one decision point"):
        parse_policies({"scope": "session", "authorizer": {}}, "f")
    with pytest.raises(PolicyRefused, match="exactly one decision point"):
        parse_policies(
            {"scope": "session", "authorizer": {"local": {"grants": []}, "authzen": {"url": "https://x"}}}, "f"
        )
    with pytest.raises(PolicyRefused):
        parse_policies({"scope": "session", "authorize": ["fly"]}, "f")
    assert AuthorizerConfig(authzen={"url": "https://pdp.example/evaluate"}).kind == "authzen"
    assert isinstance(AuthorizerConfig(openfga={"url": "http://fga", "store": "s"}).build(), OpenFgaAuthorizer)


def test_a_lower_scope_dropping_an_authorized_class_widens():
    above = Policy(scope="organization", authorize=["execute", "send"])
    assert widening(Policy(scope="team", authorize=["execute"]), above) == [
        "the team policy needs no authorizer's allow for send actions where the organization's does; "
        "a scope below drops no class the one above authorizes"
    ]
    assert widening(Policy(scope="team"), above) == [], "a document saying nothing drops nothing"
    assert widening(Policy(scope="team", authorize=["execute", "send", "buy"]), above) == []


# -- AuthZen over HTTP, and OpenFGA's check API ---------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    answers: dict[str, object] = {}
    seen: list[dict] = []

    def do_POST(self) -> None:  # noqa: N802 - http.server's name
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0")) or 0) or b"{}")
        _Handler.seen.append({"path": self.path, "body": body, "authorization": self.headers.get("Authorization")})
        answer = _Handler.answers.get(self.path)
        if answer is None:
            self.send_response(404)
            self.end_headers()
            return
        status, payload = answer  # type: ignore[misc]
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def log_message(self, *args) -> None:
        return None


@pytest.fixture
def pdp():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Handler.answers = {}
    _Handler.seen = []
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_an_authzen_endpoint_is_asked_in_the_shape_and_its_answer_read(pdp):
    _Handler.answers["/access/v1/evaluation"] = (200, {"decision": True, "context": {"model_version": "01HX"}})
    pdp_client = AuthZenAuthorizer(f"{pdp}/access/v1/evaluation", name="pdp", token=lambda: "tok")
    answer = pdp_client.evaluate(request("send", "connection:acme.example"))
    assert answer.decision is True and answer.model_version == "01HX"
    sent = _Handler.seen[-1]
    assert sent["authorization"] == "Bearer tok"
    assert sent["body"]["subject"] == {"type": "account", "id": "alice", "properties": {}}
    assert sent["body"]["action"] == {"name": "send", "properties": {}}
    assert sent["body"]["resource"] == {"type": "connection", "id": "acme.example", "properties": {}}
    _Handler.answers["/access/v1/evaluation"] = (200, {"decision": False, "context": {"reason_admin": {"en": "no"}}})
    assert pdp_client.evaluate(request()).reason == "no"
    _Handler.answers["/access/v1/evaluation"] = (200, {"nope": 1})
    with pytest.raises(AuthorizerUnreachable, match="no boolean 'decision'"):
        pdp_client.evaluate(request())
    _Handler.answers["/access/v1/evaluation"] = (503, {"detail": "down"})
    with pytest.raises(AuthorizerUnreachable, match="answered 503"):
        pdp_client.evaluate(request())
    with pytest.raises(AuthorizerUnreachable, match="could not be reached"):
        AuthZenAuthorizer("http://127.0.0.1:9/evaluate", timeout=0.5).evaluate(request())
    with pytest.raises(ValueError, match="http"):
        AuthZenAuthorizer("ftp://x")


def test_openfgas_check_api_is_asked_with_the_tuple(pdp):
    _Handler.answers["/stores/s1/check"] = (200, {"allowed": True, "resolution": ""})
    fga = OpenFgaAuthorizer(pdp, "s1", "m1")
    answer = fga.evaluate(request("read", "workspace:w/a"))
    assert answer.decision is True and answer.model_version == "m1"
    assert _Handler.seen[-1]["body"] == {
        "tuple_key": {"user": "account:alice", "relation": "can_read", "object": "workspace:w/a"},
        "authorization_model_id": "m1",
    }
    _Handler.answers["/stores/s1/check"] = (200, {"allowed": False})
    assert fga.evaluate(request()).decision is False
