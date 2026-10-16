# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Shield's authorizer on Datalayer, against a fake IAM over HTTP (SHIELD §6.11, SH-75).

``IamAuthorizer`` asks IAM's evaluation route (``POST /api/iam/v1/authz/evaluate``)
with the runtime's token, read afresh at each question; IAM answers AuthZen's
shape. Held here over a real socket: the route and the bearer, the request's
shape, the allow with the model's version, a deny with IAM's sentence, an IAM
that refuses the token or is down is a deny naming ``openfga-through-iam``, never
an allow — save one already given, kept until it expires.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_shield.policy import ActionName, AllowCache, EvaluationRequest, Resource, Subject, authorize
from agent_shield.saas import IamAuthorizer, evaluate_url

TOKEN = "runtime-token-1"  # noqa: S105 - a fake IAM's token


class FakeIam:
    """IAM's evaluation route: a relationship table, a token, and a switch to fail."""

    def __init__(self) -> None:
        self.held = {("account:u-1", "can_send", "connection:manzanita.example")}
        self.tokens = {TOKEN}
        self.status = 200
        self.asked: list[tuple[str, dict]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.asked.append((self.path, {"authorization": self.headers.get("Authorization"), **body}))
                if fake.status != 200:
                    return self._answer(fake.status, {"detail": "OpenFGA at http://fga did not answer the check"})
                if self.path != "/api/iam/v1/authz/evaluate":
                    return self._answer(404, {"detail": "Not Found"})
                if self.headers.get("Authorization", "")[7:] not in fake.tokens:
                    return self._answer(
                        403, {"detail": "This token is narrowed (acting): this route does not take it."}
                    )
                relation = {"send": "can_send", "buy": "can_buy", "read": "can_read"}[body["action"]["name"]]
                user = f"{body['subject']['type']}:{body['subject']['id']}"
                target = f"{body['resource']['type']}:{body['resource']['id']}"
                allowed = (user, relation, target) in fake.held
                reason = (
                    f"OpenFGA holds {user} {relation} {target}"
                    if allowed
                    else f"OpenFGA holds no relationship {user} {relation} {target}; a share, a grant or a mount would make one"
                )
                self._answer(200, {"decision": allowed, "context": {"model_version": "01MODEL", "reason_user": reason}})

            def _answer(self, status, payload):
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> FakeIam:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def iam():
    with FakeIam() as fake:
        yield fake


def send(company="manzanita.example", action="send", who="u-1"):
    return EvaluationRequest(
        subject=Subject(type="account", id=who),
        action=ActionName(name=action),
        resource=Resource(type="connection", id=company),
    )


def test_it_asks_iams_route_with_the_token_and_the_request_as_authzen_says_it(iam):
    tokens = iter(["runtime-token-1", "runtime-token-1"])
    authorizer = IamAuthorizer(iam.url + "/", lambda: next(tokens))
    assert authorizer.name == "openfga-through-iam"
    assert authorizer.url == evaluate_url(iam.url) == iam.url + "/api/iam/v1/authz/evaluate"
    allowed = authorize(send(), authorizer)
    assert allowed.verdict == "allow" and allowed.authorizer == "openfga-through-iam"
    assert allowed.model_version == "01MODEL"
    assert allowed.reason == "OpenFGA holds account:u-1 can_send connection:manzanita.example"
    path, body = iam.asked[0]
    assert path == "/api/iam/v1/authz/evaluate"
    assert body["authorization"] == f"Bearer {TOKEN}"
    assert body["subject"] == {"type": "account", "id": "u-1", "properties": {}}
    assert body["action"]["name"] == "send" and body["resource"]["id"] == "manzanita.example"
    # The token is read at each question (a runtime's token is refreshed under it).
    authorize(send(action="buy"), authorizer)
    assert len(iam.asked) == 2


def test_a_deny_is_iams_sentence_and_never_cached(iam):
    authorizer = IamAuthorizer(iam.url, TOKEN)
    cache = AllowCache()
    denied = authorize(send(company="northwind.example"), authorizer, cache=cache)
    assert denied.verdict == "deny"
    assert denied.reason.startswith("OpenFGA holds no relationship account:u-1 can_send connection:northwind.example")
    assert denied.model_version == "01MODEL" and len(cache) == 0


@pytest.mark.parametrize("status", [403, 503])
def test_an_iam_that_refuses_the_token_or_is_down_is_a_deny_naming_it(iam, status):
    iam.status = status
    denied = authorize(send(), IamAuthorizer(iam.url, TOKEN))
    assert denied.verdict == "deny"
    assert "the authorizer openfga-through-iam could not be reached" in denied.reason
    assert f"answered {status}" in denied.reason and "so nothing is authorized" in denied.reason


def test_a_token_iam_does_not_take_is_a_deny_too(iam):
    denied = authorize(send(), IamAuthorizer(iam.url, "someone-elses"))
    assert denied.verdict == "deny" and "answered 403" in denied.reason and "narrowed" in denied.reason


def test_an_allow_already_given_is_honoured_through_an_outage_until_it_expires(iam):
    authorizer = IamAuthorizer(iam.url, TOKEN)
    cache = AllowCache(ttl=timedelta(minutes=5))
    now = datetime(2026, 10, 16, 9, 0, tzinfo=timezone.utc)
    assert authorize(send(), authorizer, cache=cache, now=now).verdict == "allow"
    iam.status = 503
    kept = authorize(send(), authorizer, cache=cache, now=now + timedelta(minutes=4))
    assert kept.verdict == "allow" and kept.cached and "could not be reached" in kept.reason
    expired = authorize(send(), authorizer, cache=cache, now=now + timedelta(minutes=6))
    assert expired.verdict == "deny"
    # Another question was never allowed: refused through the outage.
    assert authorize(send(action="buy"), authorizer, cache=cache, now=now).verdict == "deny"


def test_it_needs_iams_url_and_a_token():
    with pytest.raises(ValueError, match="IAM's URL"):
        IamAuthorizer("", TOKEN)
    with pytest.raises(ValueError, match="a token"):
        IamAuthorizer("http://iam", "")
