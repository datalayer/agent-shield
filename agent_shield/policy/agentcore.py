# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""An organization's policy compiled for AgentCore Policy (AC-44) and its Gateway rate limits (AC-45).

On Datalayer the Shield decides an organization's document in process. On
Amazon Bedrock AgentCore the same document is compiled here into the policies
an AgentCore **policy engine** takes — one Cedar or Dogwood statement per
policy — and pushed to the engine attached to the organization's Gateways.
The Shield still decides in the runtime: the stricter wins.

What a Gateway's policy sees is not what the Shield sees. A Gateway names
its principal (``AgentCore::OAuthUser``), the tool called
(``AgentCore::Action::"<target>___<tool>"``), itself as the resource
(``AgentCore::Gateway::"<arn>"``) and the tool's arguments as
``context.input`` — nothing else: no action class, no ACP kind, no path,
no side of the workspace. So:

- the document's **dogwood** set is carried statement by statement:
  ``Datalayer::Action`` becomes ``AgentCore::Action``, ``Datalayer::User``
  ``AgentCore::OAuthUser``, ``Datalayer::Runtime`` the Gateway, an
  unconstrained resource is scoped to the Gateway, and each temporal
  predicate carries ``eventResource: resource`` (AgentCore requires it). A
  policy whose scope names only the Shield's own actions (``shield___<kind>``)
  decides nothing a Gateway sees and stays the Shield's (said in a note);
- the **rules**: a rule conditioned on classes, kinds, a side of the
  workspace, paths or commands cannot be said at a Gateway. With none, the
  first rule decides every call: *do it* permits every call (or, beside a
  dogwood set, lets the set decide, as the Shield does), *leave it to me*
  forbids every call, *ask me first* cannot be said (a Gateway has nobody to
  ask);
- the **tool_calls** limit's hard threshold: a ``forbid`` per tool named,
  counted over the policy session, as ``agent-shield policy export
  --dogwood`` writes it;
- the model budget, the spend, the terminals and the bytes written count
  what never passes a Gateway (model requests, the Shield's own actions):
  they stay the Shield's, said in notes.

What cannot be said is **refused**, every part of it in one sentence: a
Gateway that decided otherwise than the document would be worse than none.
AgentCore's quotas are held over everything the engine will hold: at most 20
temporal policies, 3 temporal operators in one, a 24-hour window.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Literal

from .dogwood import (
    MAX_TEMPORAL_POLICIES,
    DogwoodPolicy,
    _lex,
    _Tok,
    parse_set,
)
from .export_dogwood import _count_forbid
from .model import RATE_NAMES, Policy, RateLimits

#: An AgentCore Gateway's ARN.
GATEWAY_ARN = re.compile(
    r"^arn:aws:bedrock-agentcore:(?P<region>[a-z0-9-]+):(?P<account>\d{12}):"
    r"gateway/(?P<id>(?:[0-9a-z]-?){1,100}-(?P<suffix>[0-9a-z]{10}))$"
)
#: A Gateway tool, as AgentCore names it.
GATEWAY_TOOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*___[A-Za-z0-9_.-]+$")
#: AgentCore's rule for a policy's name.
POLICY_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
#: The longest statement AgentCore takes.
MAX_STATEMENT = 10_000
#: The temporal event kinds a predicate names.
EVENT_KINDS = ("request", "response", "error")
#: What a Gateway policy's context holds.
GATEWAY_CONTEXT = "input"
#: The principal's methods an OAuth user has in AgentCore's schema.
PRINCIPAL_METHODS = ("hasTag", "getTag")
#: The Shield's own action server: its actions never reach a Gateway.
SHIELD_PREFIX = 'Datalayer::Action::"shield___'
#: The Datalayer entity types and their AgentCore counterparts (``None``: the Gateway, by ARN).
ENTITY_TYPES: dict[str, str | None] = {"Action": "AgentCore::Action", "User": "AgentCore::OAuthUser", "Runtime": None}
#: The limits that count what never passes a Gateway.
SHIELD_LIMITS = {
    "model_tokens": "the model budget counts model requests, which never pass a Gateway",
    "spend": "the spend counts model requests, which never pass a Gateway",
    "terminals_open": "terminals are the Shield's own actions",
    "bytes_written": "bytes written are the Shield's own actions",
}

#: The rate limit pushed to each Gateway (one, upserted by this id).
RATE_LIMIT_ID = "datalayer-per-user"
#: The dimension a person is counted by, for each Gateway authorizer type.
USER_DIMENSIONS = {"CUSTOM_JWT": "$.context.jwt.sub", "AWS_IAM": "$.context.iam.principal"}


class AgentCoreRefused(ValueError):
    """A document AgentCore's Gateway cannot decide as the Shield does, said in a sentence."""


@dataclass(frozen=True)
class AgentCoreStatement:
    """One AgentCore policy: its name in the engine, its statement, and where it came from."""

    name: str
    statement: str
    temporal: bool
    gateway: str
    description: str

    @property
    def definition(self) -> dict[str, dict[str, str]]:
        """The ``definition`` of CreatePolicy / UpdatePolicy: ``policy`` (Dogwood) when temporal, else ``cedar``."""
        return {"policy" if self.temporal else "cedar": {"statement": self.statement}}


@dataclass(frozen=True)
class AgentCorePolicies:
    """What the document compiles to for one policy engine."""

    statements: tuple[AgentCoreStatement, ...]
    mode: Literal["enforce", "log_only"]
    notes: tuple[str, ...] = field(default=())

    @property
    def temporal_count(self) -> int:
        return sum(1 for statement in self.statements if statement.temporal)


# -- statements --------------------------------------------------------------------------------


def split_statements(text: str) -> list[str]:
    """Each policy of a set as its own text, its annotations kept, comments between policies dropped."""
    tokens = _lex(text)
    found: list[str] = []
    start: int | None = None
    depth = 0
    for tok in tokens:
        if start is None:
            start = tok.start
        if tok.kind == "op" and tok.value in "({[":
            depth += 1
        elif tok.kind == "op" and tok.value in ")}]":
            depth -= 1
        elif tok.kind == "op" and tok.value == ";" and depth == 0:
            found.append(text[start : tok.end])
            start = None
    if start is not None:
        raise AgentCoreRefused("the policy set ends without ';'")
    return found


def _is(tokens: list[_Tok], at: int, value: str) -> bool:
    return 0 <= at < len(tokens) and tokens[at].value == value and tokens[at].kind in ("op", "name")


def _matching(tokens: list[_Tok], at: int) -> int:
    opening, closing = tokens[at].value, {"(": ")", "{": "}", "[": "]"}[tokens[at].value]
    depth = 0
    for index in range(at, len(tokens)):
        if tokens[index].kind != "op":
            continue
        if tokens[index].value == opening:
            depth += 1
        elif tokens[index].value == closing:
            depth -= 1
            if depth == 0:
                return index
    raise AgentCoreRefused(f"an unclosed {opening!r}")


class _Translation:
    """One statement in AgentCore's names: the edits to make, and what cannot be said."""

    def __init__(self, text: str, gateway: str, where: str) -> None:
        self.text = text
        self.gateway = gateway
        self.where = where
        self.tokens = _lex(text)
        self.edits: list[tuple[int, int, str]] = []
        self.problems: list[str] = []

    def refuse(self, said: str) -> None:
        if said not in self.problems:
            self.problems.append(said)

    def run(self) -> str:
        tokens = self.tokens
        effect = next((i for i, t in enumerate(tokens) if t.kind == "name" and t.value in ("permit", "forbid")), None)
        if effect is None:
            raise AgentCoreRefused(f"{self.where}: a policy starts with permit or forbid")
        self._scope_resource(effect + 1)
        at = effect
        while at < len(tokens):
            at = self._step(at)
        if self.problems:
            return ""
        text = self.text
        for start, end, replacement in sorted(self.edits, reverse=True):
            text = text[:start] + replacement + text[end:]
        return text[tokens[effect].start :].strip()

    def _scope_resource(self, open_at: int) -> None:
        tokens = self.tokens
        if not _is(tokens, open_at, "("):
            raise AgentCoreRefused(f"{self.where}: the scope is in parentheses")
        close = _matching(tokens, open_at)
        for index in range(open_at + 1, close):
            if tokens[index].kind == "name" and tokens[index].value == "resource":
                if tokens[index + 1].value in (")", ","):
                    self.edits.append((tokens[index].end, tokens[index].end, f" == {self._gateway_uid()}"))
                return

    def _gateway_uid(self) -> str:
        return f"AgentCore::Gateway::{json.dumps(self.gateway)}"

    def _step(self, at: int) -> int:
        tokens = self.tokens
        tok = tokens[at]
        if tok.kind != "name":
            return at + 1
        if tok.value == "context":
            self._context(at)
            return at + 1
        if tok.value == "principal":
            self._principal(at)
            return at + 1
        if _is(tokens, at + 1, "::"):
            return self._path(at)
        return at + 1

    def _context(self, at: int) -> None:
        tokens = self.tokens
        if _is(tokens, at + 1, ".") or _is(tokens, at + 1, "has"):
            name = tokens[at + 2].value if at + 2 < len(tokens) else ""
            if name != GATEWAY_CONTEXT:
                self.refuse(f"context.{name}")
        elif _is(tokens, at + 1, "["):
            self.refuse("context[…]")

    def _principal(self, at: int) -> None:
        tokens = self.tokens
        if _is(tokens, at + 1, "."):
            name = tokens[at + 2].value if at + 2 < len(tokens) else ""
            if name not in PRINCIPAL_METHODS:
                self.refuse(f"principal.{name}")
        elif _is(tokens, at + 1, "has"):
            self.refuse("principal has …")

    def _path(self, at: int) -> int:
        tokens = self.tokens
        parts: list[str] = []
        index = at
        while index < len(tokens) and tokens[index].kind == "name" and _is(tokens, index + 1, "::"):
            parts.append(tokens[index].value)
            index += 2
        if index >= len(tokens):
            return index
        last = tokens[index]
        ident: str | None = None
        if last.kind == "string":
            ident = json.loads(last.value)
        elif last.kind == "name":
            parts.append(last.value)
        else:
            return index
        if parts[0] == "Datalayer":
            self._entity(parts, ident, tokens[at].start, last.end)
        if ident is not None and parts[-1] == "Action" and _is(tokens, index + 1, "::"):
            kind = tokens[index + 2] if index + 2 < len(tokens) else None
            if kind is not None and kind.value in EVENT_KINDS:
                self._event_resource(index + 2)
                return index + 3
        return index + 1

    def _entity(self, parts: list[str], ident: str | None, start: int, end: int) -> None:
        kind = "::".join(parts[1:])
        if kind not in ENTITY_TYPES:
            self.refuse(f"Datalayer::{kind}")
            return
        if kind == "Action" and ident is not None and ident.startswith("shield___"):
            self.refuse(f'the Shield\'s own action Datalayer::Action::"{ident}"')
            return
        target = ENTITY_TYPES[kind]
        if target is None:
            replacement = self._gateway_uid() if ident is not None else "AgentCore::Gateway"
        else:
            replacement = target if ident is None else f"{target}::{json.dumps(ident)}"
        self.edits.append((start, end, replacement))

    def _event_resource(self, kind_at: int) -> None:
        tokens = self.tokens
        groups: list[tuple[int, int]] = []
        index = kind_at + 1
        while _is(tokens, index, "{"):
            close = _matching(tokens, index)
            groups.append((index, close))
            index = close + 1
        for open_at, close in groups:
            depth = 0
            for at in range(open_at + 1, close):
                value = tokens[at].value
                if tokens[at].kind == "op" and value in "({[":
                    depth += 1
                elif tokens[at].kind == "op" and value in ")}]":
                    depth -= 1
                elif depth == 0 and tokens[at].kind == "name" and value == "eventResource" and _is(tokens, at + 1, ":"):
                    named = tokens[at + 2] if at + 2 < close else None
                    following = tokens[at + 3].value if at + 3 <= close else ""
                    if named is None or named.value != "resource" or following not in (",", "}"):
                        self.refuse("eventResource other than resource")
                    return
        if groups:
            open_at, close = groups[0]
            empty = close == open_at + 1
            insert = " eventResource: resource " if empty else " eventResource: resource,"
            self.edits.append((tokens[open_at].end, tokens[open_at].end, insert))
        else:
            self.edits.append((tokens[kind_at].end, tokens[kind_at].end, " { eventResource: resource }"))


def _effect(text: str) -> str:
    return next((t.value for t in _lex(text) if t.kind == "name" and t.value in ("permit", "forbid")), "")


def gateway_suffix(gateway: str) -> str:
    """The ten characters AgentCore ends a Gateway's id with: what a policy's name carries."""
    match = GATEWAY_ARN.match(gateway)
    if match is None:
        raise AgentCoreRefused(
            f"{gateway!r} is not an AgentCore Gateway ARN (arn:aws:bedrock-agentcore:<region>:<account>:gateway/<id>)"
        )
    return match["suffix"]


def _slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")
    return slug[:30] or "policy"


@dataclass
class _Source:
    text: str
    origin: str
    name: str


def _rule_sources(policy: Policy, problems: list[str], notes: list[str]) -> list[_Source]:
    conditioned = [
        rule.name
        for rule in policy.rules
        if rule.classes or rule.kinds or rule.where != "any" or rule.paths or rule.commands
    ]
    if conditioned:
        problems.append(
            "the rules "
            + ", ".join(repr(name) for name in conditioned)
            + " are conditioned on the action's class, kind, side of the workspace, path or command, which an "
            "AgentCore Gateway does not give its policies (it gives context.input alone)"
        )
        return []
    if not policy.rules:
        return []
    first, *shadowed = policy.rules
    if shadowed:
        notes.append(
            f"the rule {first.name!r} matches every call, so "
            + ", ".join(repr(rule.name) for rule in shadowed)
            + " never decide"
        )
    if first.decision == "ask":
        problems.append(f"the rule {first.name!r} asks a person first, and an AgentCore Gateway has nobody to ask")
        return []
    if first.decision == "deny":
        return [_Source("forbid (principal, action, resource);", f"rule {first.name!r}: leave it to me", first.name)]
    if policy.dogwood is not None:
        notes.append(f"the rule {first.name!r} lets the dogwood set decide every call, as the Shield does")
        return []
    return [_Source("permit (principal, action, resource);", f"rule {first.name!r}: do it", first.name)]


def _limit_sources(policy: Policy, tools: list[str], problems: list[str], notes: list[str]) -> list[_Source]:
    for name, why in SHIELD_LIMITS.items():
        if getattr(policy.limits, name) is not None:
            notes.append(f"the {name} limit stays the Shield's: {why}")
    calls = policy.limits.tool_calls
    if calls is None:
        return []
    if not tools:
        problems.append(
            "the tool_calls limit counts every call, and a Dogwood count holds one tool: name the Gateway tools "
            "(<target>___<tool>) it holds"
        )
        return []
    wrong = [tool for tool in tools if not GATEWAY_TOOL.match(tool)]
    if wrong:
        problems.append("the tools " + ", ".join(repr(t) for t in wrong) + " are not Gateway tools (<target>___<tool>)")
        return []
    if calls.soft < calls.hard:
        notes.append(
            f"the tool_calls soft threshold ({calls.soft}) asks a person, which a Gateway cannot: only the hard "
            "one is pushed"
        )
    return [
        _Source(_count_forbid(tool, calls.hard), f"tool_calls: at most {calls.hard} of {tool}", f"calls {tool}")
        for tool in tools
    ]


def _dogwood_sources(policy: Policy, notes: list[str]) -> list[_Source]:
    if policy.dogwood is None:
        return []
    sources: list[_Source] = []
    for index, text in enumerate(split_statements(policy.dogwood.policies)):
        parsed: DogwoodPolicy = parse_set(text).policies[0]
        name = parsed.annotations.get("id") or f"policy {index}"
        if parsed.actions and all(action.startswith(SHIELD_PREFIX) for action in parsed.actions):
            notes.append(
                f"the dogwood policy {name!r} decides only the Shield's own actions, which never reach a Gateway"
            )
            continue
        sources.append(_Source(text, f"dogwood policy {name!r}", name))
    return sources


def _statement(
    source: _Source, gateway: str, suffix: str, version: int, names: set[str], problems: list[str]
) -> AgentCoreStatement | None:
    """One source as a Gateway's policy, named uniquely in the engine; ``None`` with its problem said."""
    translation = _Translation(source.text, gateway, source.origin)
    text = translation.run()
    if translation.problems:
        said = f"{source.origin} names {', '.join(translation.problems)}, which a Gateway's policy cannot read"
        if said not in problems:
            problems.append(said)
        return None
    if len(text) > MAX_STATEMENT:
        problems.append(f"{source.origin} is {len(text)} characters long, over AgentCore's {MAX_STATEMENT}")
        return None
    parsed = parse_set(text).policies[0]
    base = f"dl_{_slug(source.name)}"
    name = f"{base}_{suffix}"
    counter = 2
    while name in names:
        name = f"{base}_{counter}_{suffix}"
        counter += 1
    names.add(name)
    return AgentCoreStatement(
        name=name,
        statement=text,
        temporal=parsed.temporal,
        gateway=gateway,
        description=f"Datalayer, the organization's policy (version {version}): {source.origin}",
    )


def compile_for_agentcore(policy: Policy, gateways: list[str], *, tools: list[str] | None = None) -> AgentCorePolicies:
    """An organization's document as the policies of one AgentCore policy engine, one per statement and Gateway.

    Parameters
    ----------
    policy : Policy
        The organization's Shield document.
    gateways : list of str
        The ARNs of the Gateways the engine is attached to; each policy is scoped to one.
    tools : list of str, optional
        The Gateway tools (``<target>___<tool>``) ``limits.tool_calls`` holds.

    Returns
    -------
    AgentCorePolicies
        The statements, each named for the engine (``dl_<what>_<gateway suffix>``), the document's mode, and
        notes on what stays the Shield's.

    Raises
    ------
    AgentCoreRefused
        When a part of the document that decides tool calls cannot be said at a Gateway, or a quota is passed:
        every such part in one sentence.
    """
    if policy.scope != "organization":
        raise AgentCoreRefused(f"a {policy.scope} policy is not pushed to AgentCore: an organization's is")
    if not gateways:
        raise AgentCoreRefused("no Gateway to attach the policies to: the organization registers none")
    suffixes = {gateway: gateway_suffix(gateway) for gateway in gateways}
    problems: list[str] = []
    notes: list[str] = []
    sources = [
        *_dogwood_sources(policy, notes),
        *_rule_sources(policy, problems, notes),
        *_limit_sources(policy, list(tools or []), problems, notes),
    ]
    if not problems and not any(_effect(source.text) == "permit" for source in sources):
        problems.append(
            "nothing in the document permits a call, and AgentCore denies by default: every call would be refused"
        )
    names: set[str] = set()
    compiled = [
        _statement(source, gateway, suffixes[gateway], policy.version, names, problems)
        for gateway in gateways
        for source in sources
    ]
    statements = [statement for statement in compiled if statement is not None]
    if not problems:
        temporal = sum(1 for statement in statements if statement.temporal)
        if temporal > MAX_TEMPORAL_POLICIES:
            problems.append(
                f"the engine would hold {temporal} temporal policies ({len(gateways)} Gateway(s)), over AgentCore's "
                f"quota of {MAX_TEMPORAL_POLICIES}"
            )
    if problems:
        raise AgentCoreRefused(
            "AgentCore's Gateway cannot decide this document as the Shield does: " + "; ".join(problems)
        )
    mode = policy.dogwood.mode if policy.dogwood is not None else "enforce"
    return AgentCorePolicies(statements=tuple(statements), mode=mode, notes=tuple(notes))


# -- rate limits (AC-45) -----------------------------------------------------------------------


def gateway_rate_limit(rate_limits: RateLimits, authorizer_type: str) -> dict:
    """The document's ``rate_limits`` as one ``BatchPutLimitEntry`` of ``BatchPutGatewayRateLimits``.

    Parameters
    ----------
    rate_limits : RateLimits
        The organization's per-user rates.
    authorizer_type : str
        The Gateway's ``authorizerType``: ``CUSTOM_JWT`` counts a person by the token's ``sub``,
        ``AWS_IAM`` by the IAM principal.

    Returns
    -------
    dict
        ``{rateLimitId, description, dimensionKeys, entries}``, every person (``*``) held to the rates.

    Raises
    ------
    AgentCoreRefused
        When the Gateway's authorizer names no person to count.
    """
    dimension = USER_DIMENSIONS.get(authorizer_type)
    if dimension is None:
        raise AgentCoreRefused(
            f"a Gateway whose authorizer is {authorizer_type} names no person to count: rate limits per user need "
            "CUSTOM_JWT or AWS_IAM"
        )
    entry: dict = {"dimensions": {dimension: "*"}}
    for name in RATE_NAMES:
        rate = getattr(rate_limits, name)
        if rate is not None:
            entry[name] = [{"rate": float(rate.rate), "period": rate.per}]
    return {
        "rateLimitId": RATE_LIMIT_ID,
        "description": "Datalayer: the organization's rate limits, per user",
        "dimensionKeys": [dimension],
        "entries": [entry],
    }


__all__ = [
    "GATEWAY_ARN",
    "RATE_LIMIT_ID",
    "USER_DIMENSIONS",
    "AgentCorePolicies",
    "AgentCoreRefused",
    "AgentCoreStatement",
    "compile_for_agentcore",
    "gateway_rate_limit",
    "gateway_suffix",
    "split_statements",
]
