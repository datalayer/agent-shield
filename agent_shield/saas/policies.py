# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Shield's policy, pulled from IAM and honoured until it expires.

IAM serves one document per scope at ``/mcp-policies/{scope}/{subject_uid}``,
its ``shield`` part the policy document of :mod:`agent_shield.policy`, and
for an account it answers every document in force at once —
``GET /mcp-policies/shield/accounts/{account_uid}``: the organization's and
the teams' documents, each with its ``version`` and an ``expires`` stamped at
the serve. :class:`ManagedPolicies` pulls them (:meth:`pull`), keeps the last
answer until its ``expires``, takes a document pushed over a socket
(:meth:`push`), and polls while a watcher runs (:meth:`watch`), so a change an
administrator saves reaches a running Shield within the poll interval.

**Fail closed.** A Shield that cannot read IAM and holds no unexpired copy
gets :class:`PolicyUnavailable`, a sentence naming IAM: at creation the
harness is refused with it; while running, the watcher hands it to the host,
which refuses every further action with it until IAM answers again. Nothing
here reads a file, an environment variable or a default in IAM's place.
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_shield.policy import Policy, PolicyRefused, parse_policy

logger = logging.getLogger(__name__)

#: How often a Shield that holds no socket asks IAM again (polled otherwise).
POLL_SECONDS = 30.0

#: IAM's route for an account's documents, under its API prefix.
_ACCOUNTS_ROUTE = "/api/iam/v1/mcp-policies/shield/accounts/{account_uid}"


def shield_policies_path(account_uid: str) -> str:
    return _ACCOUNTS_ROUTE.format(account_uid=account_uid)


class PolicyUnavailable(RuntimeError):
    """No policy can be honoured: IAM did not answer and no unexpired copy is held."""


@dataclass(frozen=True)
class ServedPolicies:
    """What IAM answered: the documents in force, and until when they are honoured."""

    policies: list[Policy]
    expires: datetime
    #: ``scope/subject`` → version, as IAM served them (for the audit and the sentence).
    versions: dict[str, int] = field(default_factory=dict)

    def fresh(self, now: datetime) -> bool:
        return now < self.expires


class PolicySource(Protocol):
    """Where the documents come from: IAM over HTTP, or a fake in a test."""

    @property
    def where(self) -> str: ...

    def fetch(self) -> ServedPolicies: ...


def fingerprint(policies: Sequence[Policy]) -> str:
    """What makes two answers the same policy: the documents' content, scope-ordered."""
    return json.dumps([json.loads(policy.model_dump_json(exclude={"expires"})) for policy in policies], sort_keys=True)


def _parse_served(data: Any, where: str) -> ServedPolicies:
    if not isinstance(data, dict) or not isinstance(data.get("policies"), list):
        raise PolicyRefused(f"{where}: the answer holds no 'policies' list")
    policies: list[Policy] = []
    versions: dict[str, int] = {}
    for item in data["policies"]:
        if not isinstance(item, dict):
            raise PolicyRefused(f"{where}: a served policy is a mapping, not {type(item).__name__}")
        document = dict(item)
        subject = str(document.pop("subject", "") or "")
        if document.get("authorizer") is not None:
            raise PolicyRefused(
                f"{where}: the {document.get('scope', '?')} document names an authorizer; on Datalayer the "
                "authorizer is IAM's (OpenFGA through IAM) and a managed document names none"
            )
        policy = parse_policy(document, where)
        if policy.expires is None:
            raise PolicyRefused(f"{where}: the {policy.scope} document carries no 'expires'")
        policies.append(policy)
        versions[f"{policy.scope}/{subject or '?'}"] = policy.version
    expires_text = data.get("expires")
    if isinstance(expires_text, str) and expires_text:
        expires = datetime.fromisoformat(expires_text.replace("Z", "+00:00"))
    elif policies:
        expires = min(policy.expires for policy in policies if policy.expires is not None)
    else:
        raise PolicyRefused(f"{where}: an answer with no document says until when it holds ('expires')")
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return ServedPolicies(policies=policies, expires=expires, versions=versions)


class IamPolicySource:
    """IAM over HTTP, with the runtime's token: the one source on Datalayer."""

    def __init__(self, iam_url: str, token: str, account_uid: str, *, timeout: float = 10.0) -> None:
        if not iam_url:
            raise ValueError("IAM's URL is needed to pull the Shield's policy")
        if not token:
            raise ValueError("a token is needed to pull the Shield's policy from IAM")
        if not account_uid:
            raise ValueError("the account whose policies are pulled must be named")
        if not iam_url.startswith(("https://", "http://")):
            raise ValueError(f"IAM's URL is http(s), not {iam_url!r}")
        self.iam_url = iam_url.rstrip("/")
        self._token = token
        self.account_uid = account_uid
        self.timeout = timeout

    @property
    def where(self) -> str:
        return f"IAM at {self.iam_url}"

    @property
    def url(self) -> str:
        return self.iam_url + shield_policies_path(self.account_uid)

    def fetch(self) -> ServedPolicies:
        request = urllib.request.Request(  # noqa: S310 - the scheme is checked at construction: http(s) only
            self.url, headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as answer:  # noqa: S310 - http(s) only, see above
                body = answer.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            raise PolicyUnavailable(
                f"{self.where} answered {error.code} to {shield_policies_path(self.account_uid)}"
            ) from None
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            reason = getattr(error, "reason", None) or error
            raise PolicyUnavailable(f"{self.where} could not be reached ({reason})") from None
        try:
            data = json.loads(body)
        except ValueError:
            raise PolicyUnavailable(f"{self.where} answered something that is not JSON") from None
        try:
            return _parse_served(data, self.where)
        except PolicyRefused as refused:
            raise PolicyUnavailable(str(refused)) from None


class ManagedPolicies:
    """The documents in force for one Shield, pulled, cached until ``expires``, fail closed."""

    def __init__(
        self,
        source: PolicySource,
        *,
        clock: Callable[[], datetime] | None = None,
        poll_seconds: float = POLL_SECONDS,
    ) -> None:
        self.source = source
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.poll_seconds = poll_seconds
        self.kept: ServedPolicies | None = None
        self.last_refusal: str | None = None

    # -- reading -----------------------------------------------------------------------

    def _sentence(self, reason: str) -> str:
        held = f"its copy expired at {self.kept.expires.isoformat()}" if self.kept is not None else "it holds no copy"
        return (
            f"The Shield cannot read its policy from {self.source.where} ({reason}) and {held}: "
            f"no unexpired policy is held, so nothing is decided"
        )

    def pull(self) -> list[Policy]:
        """Ask the source now; keep what it answers; fall back to an unexpired copy, else refuse."""
        try:
            served = self.source.fetch()
        except PolicyUnavailable as unavailable:
            if self.kept is not None and self.kept.fresh(self.clock()):
                logger.warning("Shield policy: %s; the copy held until %s is honoured", unavailable, self.kept.expires)
                self.last_refusal = None
                return list(self.kept.policies)
            self.last_refusal = self._sentence(str(unavailable))
            raise PolicyUnavailable(self.last_refusal) from None
        self.kept = served
        self.last_refusal = None
        return list(served.policies)

    def in_force(self) -> list[Policy]:
        """The documents to decide with: the unexpired copy, else a pull (which may refuse)."""
        if self.kept is not None and self.kept.fresh(self.clock()):
            return list(self.kept.policies)
        return self.pull()

    def push(self, data: Any) -> list[Policy]:
        """Take an answer pushed over a socket (ai-agents' ``/ws``), as if pulled."""
        try:
            served = _parse_served(data, "the policy pushed over the socket")
        except PolicyRefused as refused:
            raise PolicyUnavailable(str(refused)) from None
        self.kept = served
        self.last_refusal = None
        return list(served.policies)

    @property
    def expires(self) -> datetime | None:
        return self.kept.expires if self.kept is not None else None

    # -- watching ----------------------------------------------------------------------

    async def watch(
        self,
        on_change: Callable[[list[Policy]], Any],
        *,
        on_unavailable: Callable[[str], Any] | None = None,
        poll_seconds: float | None = None,
        rounds: int | None = None,
    ) -> None:
        """Poll the source every ``poll_seconds``; a changed answer reaches ``on_change``.

        A pull that fails with no unexpired copy reaches ``on_unavailable`` with
        the sentence, once per outage; the next answer reaches ``on_change``
        again. ``rounds`` bounds the loop for a test; unbounded, it runs until
        cancelled.
        """
        interval = self.poll_seconds if poll_seconds is None else poll_seconds
        before = fingerprint(self.kept.policies) if self.kept is not None else None
        refused_said = False
        done = 0
        while rounds is None or done < rounds:
            await asyncio.sleep(interval)
            done += 1
            try:
                policies = await asyncio.to_thread(self.pull)
            except PolicyUnavailable as unavailable:
                if not refused_said and on_unavailable is not None:
                    result = on_unavailable(str(unavailable))
                    if asyncio.iscoroutine(result):
                        await result
                refused_said = True
                continue
            now = fingerprint(policies)
            if now != before or refused_said:
                before = now
                refused_said = False
                result = on_change(policies)
                if asyncio.iscoroutine(result):
                    await result


__all__ = [
    "POLL_SECONDS",
    "IamPolicySource",
    "ManagedPolicies",
    "PolicySource",
    "PolicyUnavailable",
    "ServedPolicies",
    "fingerprint",
    "shield_policies_path",
]
