# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Managed from the SaaS: pulled from IAM, cached until it expires, fail closed (SH-50)."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from agent_shield.policy import Policy, Rule
from agent_shield.saas import (
    IamPolicySource,
    ManagedPolicies,
    PolicyUnavailable,
    ServedPolicies,
    fingerprint,
    shield_policies_path,
)

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def served(*policies: Policy, minutes: float = 10) -> ServedPolicies:
    expires = NOW + timedelta(minutes=minutes)
    return ServedPolicies(policies=[p.model_copy(update={"expires": expires}) for p in policies], expires=expires)


ORG = Policy(scope="organization", version=3, rules=[Rule(name="execute asks", decision="ask", classes=["execute"])])


class FakeSource:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = 0

    @property
    def where(self) -> str:
        return "IAM at https://iam.test"

    def fetch(self) -> ServedPolicies:
        self.calls += 1
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer


class Clock:
    def __init__(self, at: datetime = NOW):
        self.at = at

    def __call__(self) -> datetime:
        return self.at


def test_pull_keeps_what_iam_served_and_in_force_reads_the_copy_until_it_expires():
    source = FakeSource(served(ORG))
    clock = Clock()
    managed = ManagedPolicies(source, clock=clock)
    assert [p.scope for p in managed.pull()] == ["organization"]
    assert managed.in_force()[0].version == 3 and source.calls == 1
    clock.at = NOW + timedelta(minutes=11)
    source.answers = [served(ORG.model_copy(update={"version": 4}))]
    assert managed.in_force()[0].version == 4 and source.calls == 2


def test_iam_unreachable_with_an_unexpired_copy_honours_the_copy_and_says_so(caplog):
    source = FakeSource(served(ORG), PolicyUnavailable("IAM at https://iam.test could not be reached (timed out)"))
    managed = ManagedPolicies(source, clock=Clock())
    managed.pull()
    assert managed.pull()[0].version == 3
    assert managed.last_refusal is None


def test_iam_unreachable_with_no_unexpired_copy_fails_closed_in_a_sentence_naming_iam():
    source = FakeSource(PolicyUnavailable("IAM at https://iam.test could not be reached (timed out)"))
    managed = ManagedPolicies(source, clock=Clock())
    with pytest.raises(PolicyUnavailable) as refused:
        managed.pull()
    assert str(refused.value) == (
        "The Shield cannot read its policy from IAM at https://iam.test (IAM at https://iam.test could not be reached "
        "(timed out)) and it holds no copy: no unexpired policy is held, so nothing is decided"
    )
    clock = Clock()
    managed = ManagedPolicies(
        FakeSource(served(ORG, minutes=1), PolicyUnavailable("IAM at https://iam.test answered 503")), clock=clock
    )
    managed.pull()
    clock.at = NOW + timedelta(minutes=2)
    with pytest.raises(PolicyUnavailable, match="its copy expired at 2026-10-15T12:01:00\\+00:00"):
        managed.in_force()


def test_a_pushed_answer_replaces_the_copy_as_a_pull_would():
    managed = ManagedPolicies(FakeSource(served(ORG)), clock=Clock())
    pushed = managed.push(
        {
            "policies": [
                {
                    **json.loads(ORG.model_dump_json(exclude_none=True)),
                    "version": 9,
                    "expires": (NOW + timedelta(minutes=5)).isoformat(),
                    "subject": "org1",
                }
            ]
        }
    )
    assert pushed[0].version == 9 and managed.kept.versions == {"organization/org1": 9}
    with pytest.raises(PolicyUnavailable, match="holds no 'policies' list"):
        managed.push({"nothing": True})
    with pytest.raises(PolicyUnavailable, match="carries no 'expires'"):
        managed.push({"policies": [json.loads(ORG.model_dump_json(exclude_none=True))]})


@pytest.mark.asyncio
async def test_the_watcher_hands_a_changed_policy_on_and_an_outage_once():
    changed = served(ORG.model_copy(update={"version": 4}))
    source = FakeSource(
        served(ORG),
        served(ORG),
        changed,
        PolicyUnavailable("IAM at https://iam.test answered 503"),
        PolicyUnavailable("still"),
        changed,
    )
    clock = Clock()
    managed = ManagedPolicies(source, clock=clock)
    managed.pull()
    seen: list = []
    refused: list = []
    clock.at = NOW + timedelta(hours=1)  # every copy expired: an outage has nothing to honour
    await managed.watch(
        lambda p: seen.append([x.version for x in p]), on_unavailable=refused.append, poll_seconds=0, rounds=5
    )
    assert seen == [[4], [4]]  # the change, then the answer after the outage
    assert len(refused) == 1 and refused[0].startswith("The Shield cannot read its policy from IAM at https://iam.test")


def test_the_fingerprint_ignores_expires_and_nothing_else():
    assert fingerprint([ORG]) == fingerprint([ORG.model_copy(update={"expires": NOW})])
    assert fingerprint([ORG]) != fingerprint([ORG.model_copy(update={"version": 4})])


# --- the HTTP source ------------------------------------------------------------------


class _Iam(BaseHTTPRequestHandler):
    answer: ClassVar[dict] = {}
    status = 200
    seen: ClassVar[list] = []

    def do_GET(self):
        _Iam.seen.append((self.path, self.headers.get("Authorization")))
        body = json.dumps(self.answer).encode()
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return None


@pytest.fixture
def iam():
    server = HTTPServer(("127.0.0.1", 0), _Iam)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_the_iam_source_reads_the_accounts_documents_with_the_token(iam):
    _Iam.answer = {
        "success": True,
        "policies": [
            {
                **json.loads(ORG.model_dump_json(exclude_none=True)),
                "expires": (NOW + timedelta(minutes=10)).isoformat(),
                "subject": "org1",
            }
        ],
        "expires": (NOW + timedelta(minutes=10)).isoformat(),
    }
    _Iam.status = 200
    _Iam.seen = []
    source = IamPolicySource(iam, "tok", "acct1")
    answer = source.fetch()
    assert answer.policies[0].rules[0].name == "execute asks" and answer.versions == {"organization/org1": 3}
    assert _Iam.seen == [(shield_policies_path("acct1"), "Bearer tok")]


def test_an_iam_that_answers_an_error_or_cannot_be_reached_is_said_by_name(iam):
    _Iam.status = 503
    with pytest.raises(PolicyUnavailable, match=f"IAM at {iam} answered 503"):
        IamPolicySource(iam, "tok", "acct1").fetch()
    with pytest.raises(PolicyUnavailable, match="IAM at http://127.0.0.1:9 could not be reached"):
        IamPolicySource("http://127.0.0.1:9", "tok", "acct1", timeout=1).fetch()
    with pytest.raises(ValueError, match="http\\(s\\)"):
        IamPolicySource("ftp://iam", "tok", "acct1")
    with pytest.raises(ValueError, match="token"):
        IamPolicySource(iam, "", "acct1")
