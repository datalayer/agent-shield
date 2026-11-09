# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Cedar behind the authorizer port (AC-41): the ``cedar`` authorizer.

AgentCore Policy decides every tool call at its Gateway in **Cedar**:
``permit``/``forbid`` over a principal, an action and a resource, with the
tool's arguments under ``context.input``; deny by default, a ``forbid``
overriding any ``permit``. The Shield asks the same question of the same
policies, in process, through ``cedarpy`` (Cedar 4, the ``[cedar]`` extra):

- the **principal** is the identity's subject, ``Datalayer::User::"<sub>"``
  (an agent ``Datalayer::Agent``, a deployment ``Datalayer::Deployment``),
  with ``org_uid``, ``app_uid`` and ``agent_uid`` as its attributes;
- the **action** is ``Datalayer::Action::"<server>___<tool>"`` as AgentCore
  names a Gateway's tools — the Shield's own actions (a file read, a
  terminal) are ``Datalayer::Action::"shield___<kind>"``;
- the **resource** is the runtime, ``Datalayer::Runtime::"<uid>"`` (``local``
  for a standalone Shield), as AgentCore's is its Gateway;
- the **context** holds ``input`` (the tool's arguments), the action's
  ``class`` and ``kind``, and what the AuthZen request names (``target``,
  ``path``, ``command``, ``url``, ``session``).

Decisions are stateless (the temporal ones are ``temporal.py``'s). Without
``cedarpy`` every request is a deny that says so: the port fails closed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .authorize import EvaluationRequest, EvaluationResponse
from .dogwood import DogwoodRefused, cedar_problem, parse_set

#: The namespace the Shield's entities and actions live in.
NAMESPACE = "Datalayer"
#: The principal's attributes taken from the subject's properties.
PRINCIPAL_ATTRIBUTES = ("org_uid", "app_uid", "agent_uid")
#: The entity type of each AuthZen subject type.
PRINCIPAL_TYPES = {"account": "User", "user": "User", "agent": "Agent", "deployment": "Deployment"}
#: The server name of the Shield's own actions.
SHIELD_SERVER = "shield"
#: What a Shield without cedarpy says, every time it is asked.
UNAVAILABLE = (
    "the cedar authorizer cannot decide: cedarpy is not installed (pip install "
    "'datalayer-agent-shield[cedar]'), and nothing is authorized unsaid"
)


def uid(kind: str, ident: str) -> str:
    """``Datalayer::<kind>::"<ident>"``, quoted as Cedar quotes it."""
    return f"{NAMESPACE}::{kind}::{json.dumps(ident)}"


def action_uid(tool: str | None, kind: str) -> str:
    """The Cedar action of a call: the tool as AgentCore names it, else the Shield's own kind."""
    return uid("Action", tool if tool else f"{SHIELD_SERVER}___{kind}")


def cedar_value(value: Any) -> Any:
    """A value as Cedar's JSON takes it: no null, no float (a float becomes its text)."""
    if isinstance(value, bool) or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else repr(value)
    if isinstance(value, Mapping):
        return {str(k): cedar_value(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple)):
        return [cedar_value(item) for item in value if item is not None]
    return str(value)


@dataclass(frozen=True)
class CedarCall:
    """One call as Cedar sees it: principal, action, resource, context, and the principal's attributes."""

    principal: str
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)
    principal_attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def input(self) -> dict[str, Any]:
        found = self.context.get("input")
        return dict(found) if isinstance(found, Mapping) else {}

    def entities(self) -> list[dict[str, Any]]:
        kind, _, ident = self.principal.rpartition("::")
        return [
            {
                "uid": {"type": kind, "id": json.loads(ident)},
                "attrs": cedar_value(self.principal_attrs),
                "parents": [],
            }
        ]

    def request(self, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "action": self.action,
            "resource": self.resource,
            "context": {**cedar_value(self.context), **(dict(extra) if extra else {})},
        }


def call_from_request(request: EvaluationRequest) -> CedarCall:
    """The Cedar call an AuthZen request is (the context ``request_for`` writes)."""
    subject = request.subject
    principal = uid(PRINCIPAL_TYPES.get(subject.type, subject.type.capitalize()), subject.id)
    attrs = {key: subject.properties[key] for key in PRINCIPAL_ATTRIBUTES if subject.properties.get(key)}
    said = dict(request.context)
    tool = said.pop("tool", None)
    kind = str(said.get("kind") or request.action.name)
    runtime = said.pop("runtime", None)
    context: dict[str, Any] = {
        "input": dict(said.pop("input", None) or {}),
        "class": request.action.name,
        "target": {"type": request.resource.type, "id": request.resource.id},
        **said,
    }
    return CedarCall(
        principal=principal,
        action=action_uid(str(tool) if tool else None, kind),
        resource=uid("Runtime", str(runtime) if runtime else "local"),
        context=context,
        principal_attrs=attrs,
    )


@dataclass(frozen=True)
class CedarAnswer:
    """What Cedar decided: allowed or not, the policies that decided, and its errors."""

    allowed: bool
    reasons: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    unavailable: bool = False


def cedar_decide(policies: str, call: CedarCall, extra: Mapping[str, Any] | None = None) -> CedarAnswer:
    """Decide one call against a Cedar policy set; no cedarpy, or an error, is a deny."""
    try:
        import cedarpy  # the [cedar] extra
    except ImportError:
        return CedarAnswer(allowed=False, unavailable=True)
    result = cedarpy.is_authorized(call.request(extra), policies, call.entities())
    diagnostics = result.diagnostics
    errors = tuple(str(error) for error in (diagnostics.errors or []))
    allowed = result.decision == cedarpy.Decision.Allow and not errors
    return CedarAnswer(allowed=allowed, reasons=tuple(diagnostics.reasons or []), errors=errors)


class CedarAuthorizer:
    """A Cedar policy set behind the port (``authorizer: {cedar: {policies}}``)."""

    name = "cedar"

    def __init__(self, policies: str, *, origin: str = "the cedar authorizer's policies") -> None:
        if not policies.strip():
            raise ValueError("a cedar authorizer names its policies: deny by default would refuse everything")
        self.policies = policies
        self.origin = origin
        said = cedar_problem(policies)
        if said not in (None, "unavailable"):
            raise ValueError(f"{origin}: Cedar refuses them: {said}")
        try:
            self.names = [policy.name for policy in parse_set(policies).policies]
        except DogwoodRefused as refused:
            raise ValueError(f"{origin}: {refused}") from None
        self.version = f"cedar:{len(policies)}"

    def _named(self, reasons: tuple[str, ...]) -> str:
        digits = [reason.removeprefix("policy") for reason in reasons]
        return ", ".join(
            self.names[int(d)] if d.isdigit() and int(d) < len(self.names) else reason
            for d, reason in zip(digits, reasons, strict=True)
        )

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        call = call_from_request(request)
        answer = cedar_decide(self.policies, call)
        who = f"{call.principal} {call.action} on {call.resource}"
        if answer.unavailable:
            return EvaluationResponse(
                decision=False, context={"reason_user": UNAVAILABLE, "model_version": self.version}
            )
        if answer.errors:
            return EvaluationResponse(
                decision=False,
                context={
                    "reason_user": f"Cedar could not decide {who} ({'; '.join(answer.errors)}), so it is denied",
                    "model_version": self.version,
                },
            )
        if not answer.allowed:
            why = (
                f"a forbid in {self.origin} ({self._named(answer.reasons)}) refuses {who}"
                if answer.reasons
                else f"no permit in {self.origin} lets {who} (Cedar denies by default)"
            )
            return EvaluationResponse(decision=False, context={"reason_user": why, "model_version": self.version})
        return EvaluationResponse(
            decision=True,
            context={
                "reason_user": f"{self.origin} permit {who} ({self._named(answer.reasons)})",
                "model_version": self.version,
            },
        )


__all__ = [
    "NAMESPACE",
    "PRINCIPAL_ATTRIBUTES",
    "SHIELD_SERVER",
    "UNAVAILABLE",
    "CedarAnswer",
    "CedarAuthorizer",
    "CedarCall",
    "action_uid",
    "call_from_request",
    "cedar_decide",
    "cedar_value",
    "uid",
]
