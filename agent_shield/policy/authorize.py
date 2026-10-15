# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The authorizer port (SHIELD §6.11, SH-74): *may this principal act on this object?*

Policy and authorization are two questions. The policy document says what
kind of action needs what decision; it does not say whether this person may
read this path, whether this deployment may call this tool, whether this
agent may talk to this company. That is **authorization**, relationship-
based, and it is asked here through one port in the shape of the OpenID
**AuthZen** evaluation API (``authorization-api-1_0``): a request naming a
``subject``, an ``action``, a ``resource`` and a ``context``, an answer that
is a ``decision`` with a ``context`` of its own. Any policy decision point
that speaks it is a contribution: :class:`LocalAuthorizer` (grants in
``agent-shield.yaml``, the standalone proxy's), :class:`AuthZenAuthorizer`
(any AuthZen endpoint: IAM's on Datalayer, OPA or Cedar elsewhere),
:class:`OpenFgaAuthorizer` (an organization running its own OpenFGA).

The rules of the port, held by :func:`authorize` and by ``decide``:

- a **deny wins over any Rule**: a Rule saying *do it* does not let an
  action through that the authorizer refuses;
- an authorizer that **cannot be reached is a deny** with a sentence naming
  it — never a fail-open;
- **allows are cached** with an expiry and honoured until it, so a short
  outage does not stop what was already authorized; denies are never
  cached, so a grant made during a session is seen at the next action.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: The relation each action class asks for, in OpenFGA's vocabulary (§6.11's model).
RELATIONS: dict[str, str] = {
    "read": "can_read",
    "write": "can_write",
    "execute": "can_execute",
    "send": "can_send",
    "buy": "can_buy",
    "delete": "can_delete",
}
#: How long a cached allow is honoured when nothing else is said.
ALLOW_TTL = timedelta(seconds=300)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# -- AuthZen's shape -----------------------------------------------------------------------


class Subject(_Strict):
    """Who acts: ``{type, id}`` as AuthZen names it (``account``, ``deployment``, ``agent``)."""

    type: str = Field(min_length=1)
    id: str = Field(min_length=1)
    properties: dict[str, Any] = Field(default_factory=dict)


class ActionName(_Strict):
    """What is done: an action class of the policy, or a relation's own name."""

    name: str = Field(min_length=1)
    properties: dict[str, Any] = Field(default_factory=dict)


class Resource(_Strict):
    """What it is done to: ``{type, id}`` (``workspace``, ``tool``, ``connection``, ``deployment``, ``host``)."""

    type: str = Field(min_length=1)
    id: str = Field(min_length=1)
    properties: dict[str, Any] = Field(default_factory=dict)


class EvaluationRequest(_Strict):
    """One AuthZen evaluation request."""

    subject: Subject
    action: ActionName
    resource: Resource
    context: dict[str, Any] = Field(default_factory=dict)

    @property
    def relation(self) -> str:
        """The relation asked: the class's, or the action's own name when it is already one."""
        return RELATIONS.get(self.action.name, self.action.name)

    @property
    def user(self) -> str:
        return f"{self.subject.type}:{self.subject.id}"

    @property
    def object(self) -> str:
        return f"{self.resource.type}:{self.resource.id}"

    def key(self) -> tuple[str, str, str]:
        return (self.user, self.relation, self.object)


class EvaluationResponse(_Strict):
    """One AuthZen evaluation response: the decision, and what the decision point adds."""

    decision: bool
    context: dict[str, Any] = Field(default_factory=dict)

    @property
    def reason(self) -> str | None:
        for key in ("reason_user", "reason_admin", "reason"):
            value = self.context.get(key)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, Mapping):
                text = next((str(v) for v in value.values() if v), None)
                if text:
                    return text
        return None

    @property
    def model_version(self) -> str | None:
        value = self.context.get("model_version")
        return str(value) if value else None


class AuthorizerUnreachable(RuntimeError):
    """The decision point did not answer; said in a sentence, never read as an allow."""


class Authorizer(Protocol):
    """A policy decision point behind the port."""

    @property
    def name(self) -> str: ...

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse: ...


# -- the answer, and the cache of allows ---------------------------------------------------


@dataclass(frozen=True)
class Authorization:
    """What the port answered for one action, for the decision and the audit."""

    verdict: Literal["allow", "deny"]
    reason: str
    authorizer: str
    cached: bool = False
    model_version: str | None = None
    expires: datetime | None = None


class AllowCache:
    """Allows kept until their expiry; a deny is never kept (SHIELD §6.11)."""

    def __init__(self, ttl: timedelta = ALLOW_TTL) -> None:
        self.ttl = ttl
        self._allows: dict[tuple[str, str, str], Authorization] = {}

    def get(self, key: tuple[str, str, str], now: datetime) -> Authorization | None:
        kept = self._allows.get(key)
        if kept is None:
            return None
        if kept.expires is None or now >= kept.expires:
            del self._allows[key]
            return None
        return kept

    def put(self, key: tuple[str, str, str], authorization: Authorization) -> None:
        if authorization.verdict != "allow":
            raise ValueError("only an allow is cached")
        self._allows[key] = authorization

    def clear(self) -> None:
        self._allows.clear()

    def __len__(self) -> int:
        return len(self._allows)


def authorize(
    request: EvaluationRequest,
    authorizer: Authorizer,
    *,
    cache: AllowCache | None = None,
    now: datetime | None = None,
) -> Authorization:
    """Ask the authorizer, with the port's rules: deny wins, unreachable is a deny, allows cached."""
    moment = now or datetime.now(timezone.utc)
    key = request.key()
    kept = cache.get(key, moment) if cache is not None else None
    try:
        answer = authorizer.evaluate(request)
    except AuthorizerUnreachable as unreachable:
        if kept is not None:
            return Authorization(
                verdict="allow",
                reason=f"{kept.reason} (the authorizer {authorizer.name} could not be reached; the allow kept "
                f"until {kept.expires.isoformat() if kept.expires else '?'} is honoured)",
                authorizer=authorizer.name,
                cached=True,
                model_version=kept.model_version,
                expires=kept.expires,
            )
        return Authorization(
            verdict="deny",
            reason=(
                f"the authorizer {authorizer.name} could not be reached ({unreachable}) and no unexpired "
                f"allow is held for {request.user} {request.relation} {request.object}, so nothing is authorized"
            ),
            authorizer=authorizer.name,
        )
    if not answer.decision:
        return Authorization(
            verdict="deny",
            reason=answer.reason
            or f"{authorizer.name} holds no relationship {request.user} {request.relation} {request.object}",
            authorizer=authorizer.name,
            model_version=answer.model_version,
        )
    ttl = cache.ttl if cache is not None else ALLOW_TTL
    allowed = Authorization(
        verdict="allow",
        reason=answer.reason or f"{authorizer.name} holds {request.user} {request.relation} {request.object}",
        authorizer=authorizer.name,
        model_version=answer.model_version,
        expires=moment + ttl,
    )
    if cache is not None:
        cache.put(key, allowed)
    return allowed


#: The hook ``decide`` calls: the request in, the authorization out.
AuthorizeHook = Callable[[EvaluationRequest], Authorization]


def hook_for(authorizer: Authorizer, *, cache: AllowCache | None = None) -> AuthorizeHook:
    """The hook a ``Context`` carries: one authorizer, one cache of allows."""
    kept = cache if cache is not None else AllowCache()

    def ask(request: EvaluationRequest) -> Authorization:
        return authorize(request, authorizer, cache=kept)

    return ask


# -- the contributions ---------------------------------------------------------------------


class Grant(_Strict):
    """One line of the ``local`` authorizer: who may do what to what, as patterns (fnmatch)."""

    subject: str = Field(min_length=1, description="user:alice, account:*, deployment:01…")
    relation: str = Field(min_length=1, description="can_read, can_execute, can_call, can_act, or an action class")
    object: str = Field(min_length=1, description="workspace:*/src/*, tool:earthdata/*, connection:acme.example")

    @property
    def relation_name(self) -> str:
        return RELATIONS.get(self.relation, self.relation)


class LocalAuthorizer:
    """Grants in ``agent-shield.yaml`` (§6.11's ``local``): the standalone proxy's own."""

    name = "local"

    def __init__(self, grants: Sequence[Grant]) -> None:
        self.grants = list(grants)

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        for grant in self.grants:
            if (
                fnmatchcase(request.user, grant.subject)
                and grant.relation_name == request.relation
                and fnmatchcase(request.object, grant.object)
            ):
                return EvaluationResponse(
                    decision=True,
                    context={
                        "reason_user": (
                            f"a local grant lets {request.user} {request.relation} {request.object} "
                            f"({grant.subject} {grant.relation} {grant.object})"
                        ),
                        "model_version": f"local:{len(self.grants)}",
                    },
                )
        return EvaluationResponse(
            decision=False,
            context={
                "reason_user": (
                    f"no local grant lets {request.user} {request.relation} {request.object}; add one to "
                    f"authorizer.local.grants in agent-shield.yaml to let it through"
                ),
                "model_version": f"local:{len(self.grants)}",
            },
        )


def _post_json(url: str, body: Mapping[str, Any], headers: Mapping[str, str], timeout: float, who: str) -> Any:
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"{who}: the URL is http(s), not {url!r}")
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - the scheme is checked above
        url, data=data, method="POST", headers={"Content-Type": "application/json", "Accept": "application/json", **headers}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as answer:  # noqa: S310 - http(s) only
            raw = answer.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        detail = ""
        try:
            detail = error.read().decode("utf-8")[:300]
        except Exception:  # noqa: BLE001 - the body is a courtesy
            detail = ""
        raise AuthorizerUnreachable(f"{who} answered {error.code}{': ' + detail if detail else ''}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        reason = getattr(error, "reason", None) or error
        raise AuthorizerUnreachable(f"{who} could not be reached ({reason})") from None
    try:
        return json.loads(raw)
    except ValueError:
        raise AuthorizerUnreachable(f"{who} answered something that is not JSON") from None


class AuthZenAuthorizer:
    """Any AuthZen evaluation endpoint (``POST <url>``): IAM's on Datalayer, OPA or Cedar elsewhere (SH-78)."""

    def __init__(
        self,
        url: str,
        *,
        name: str = "authzen",
        headers: Mapping[str, str] | None = None,
        token: Callable[[], str] | str | None = None,
        timeout: float = 5.0,
    ) -> None:
        if not url:
            raise ValueError("an AuthZen authorizer names its URL")
        if not url.startswith(("https://", "http://")):
            raise ValueError(f"an AuthZen authorizer's URL is http(s), not {url!r}")
        self.url = url
        self._name = name
        self._headers = dict(headers or {})
        self._token = token
        self.timeout = timeout

    @property
    def name(self) -> str:
        return self._name

    def _bearer(self) -> dict[str, str]:
        token = self._token() if callable(self._token) else self._token
        return {"Authorization": f"Bearer {token}"} if token else {}

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        who = f"the authorizer {self.name} at {self.url}"
        data = _post_json(self.url, request.model_dump(), {**self._headers, **self._bearer()}, self.timeout, who)
        if not isinstance(data, Mapping) or not isinstance(data.get("decision"), bool):
            raise AuthorizerUnreachable(f"{who} answered no boolean 'decision'")
        context = data.get("context")
        return EvaluationResponse(decision=data["decision"], context=dict(context) if isinstance(context, Mapping) else {})


class OpenFgaAuthorizer:
    """An organization's own OpenFGA, asked at its check API (``openfga: {url, store, model}``)."""

    name = "openfga"

    def __init__(self, url: str, store: str, model: str | None = None, *, timeout: float = 5.0) -> None:
        if not url or not store:
            raise ValueError("an OpenFGA authorizer names its URL and its store")
        self.url = url.rstrip("/")
        self.store = store
        self.model = model
        self.timeout = timeout

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        who = f"the authorizer openfga at {self.url} (store {self.store})"
        body: dict[str, Any] = {
            "tuple_key": {"user": request.user, "relation": request.relation, "object": request.object}
        }
        if self.model:
            body["authorization_model_id"] = self.model
        data = _post_json(f"{self.url}/stores/{self.store}/check", body, {}, self.timeout, who)
        if not isinstance(data, Mapping) or not isinstance(data.get("allowed"), bool):
            raise AuthorizerUnreachable(f"{who} answered no boolean 'allowed'")
        return EvaluationResponse(
            decision=data["allowed"],
            context={"model_version": self.model or "", "reason_user": None},
        )


class OpaAuthorizer(AuthZenAuthorizer):
    """Open Policy Agent behind the port (SH-78): a second decision point, not OpenFGA-shaped.

    OPA's data API takes a document as ``input`` and answers its ``result``:
    the AuthZen request is the input, and a Rego package answering
    ``{"decision": bool, "context": {...}}`` — ``data.<package>`` at
    ``POST /v1/data/<package>`` — is the evaluation. The adapter is the
    wrapping and the unwrapping; everything else is the port's.
    """

    def __init__(self, url: str, *, package: str = "authzen/evaluation", headers: Mapping[str, str] | None = None, timeout: float = 5.0) -> None:
        base = url.rstrip("/")
        path = package.strip("/").replace(".", "/")
        super().__init__(f"{base}/v1/data/{path}", name="opa", headers=headers, timeout=timeout)

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        who = f"the authorizer opa at {self.url}"
        data = _post_json(self.url, {"input": request.model_dump()}, {**self._headers, **self._bearer()}, self.timeout, who)
        result = data.get("result") if isinstance(data, Mapping) else None
        if not isinstance(result, Mapping) or not isinstance(result.get("decision"), bool):
            raise AuthorizerUnreachable(
                f"{who} answered no boolean 'decision' in its result: the package names none, or Rego refused the input"
            )
        context = result.get("context")
        return EvaluationResponse(decision=result["decision"], context=dict(context) if isinstance(context, Mapping) else {})


# -- the file's `authorizer:` section ------------------------------------------------------


class LocalAuthorizerConfig(_Strict):
    grants: list[Grant] = Field(default_factory=list)


class OpenFgaAuthorizerConfig(_Strict):
    url: str = Field(min_length=1)
    store: str = Field(min_length=1)
    model: str | None = None


class AuthZenAuthorizerConfig(_Strict):
    url: str = Field(min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)


class OpaAuthorizerConfig(_Strict):
    url: str = Field(min_length=1, description="OPA's address: http://opa:8181")
    package: str = Field(default="authzen/evaluation", description="The Rego package answering decision and context.")
    headers: dict[str, str] = Field(default_factory=dict)


AUTHORIZER_KINDS = ("local", "openfga", "authzen", "opa")


class AuthorizerConfig(_Strict):
    """``authorizer:`` in a policy document: exactly one decision point (§6.11, standalone)."""

    local: LocalAuthorizerConfig | None = None
    openfga: OpenFgaAuthorizerConfig | None = None
    authzen: AuthZenAuthorizerConfig | None = None
    opa: OpaAuthorizerConfig | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> AuthorizerConfig:
        named = [name for name in AUTHORIZER_KINDS if getattr(self, name) is not None]
        if len(named) != 1:
            raise ValueError(
                f"'authorizer' names exactly one decision point ({', '.join(AUTHORIZER_KINDS)}), not {len(named)}"
            )
        return self

    @property
    def kind(self) -> str:
        return next(name for name in AUTHORIZER_KINDS if getattr(self, name) is not None)

    def build(self) -> Authorizer:
        if self.local is not None:
            return LocalAuthorizer(self.local.grants)
        if self.openfga is not None:
            return OpenFgaAuthorizer(self.openfga.url, self.openfga.store, self.openfga.model)
        if self.opa is not None:
            return OpaAuthorizer(self.opa.url, package=self.opa.package, headers=self.opa.headers)
        assert self.authzen is not None
        return AuthZenAuthorizer(self.authzen.url, headers=self.authzen.headers)


__all__ = [
    "ALLOW_TTL",
    "AUTHORIZER_KINDS",
    "RELATIONS",
    "ActionName",
    "AllowCache",
    "AuthZenAuthorizer",
    "AuthZenAuthorizerConfig",
    "Authorization",
    "AuthorizeHook",
    "Authorizer",
    "AuthorizerConfig",
    "AuthorizerUnreachable",
    "EvaluationRequest",
    "EvaluationResponse",
    "Grant",
    "LocalAuthorizer",
    "LocalAuthorizerConfig",
    "OpaAuthorizer",
    "OpaAuthorizerConfig",
    "OpenFgaAuthorizer",
    "OpenFgaAuthorizerConfig",
    "Resource",
    "Subject",
    "authorize",
    "hook_for",
]
