# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The policy document: one schema, three scopes, first decision wins.

A **policy** is one document per scope — ``organization``, ``team`` or
``session`` — holding the rules that decide an agent's actions, the stateful
limits with their soft and hard thresholds, the hosts a fetch may reach and
the MCP servers the agent is lent. The document is the same whether it comes
from ``agent-shield.yaml`` beside a project or from IAM (SHIELD §6.7); its
JSON Schema is published as ``schema/policy.schema.json`` so agentspecs can
carry it as ``policies/``.

Every model refuses a key it does not know (``extra="forbid"``): a misspelt
rule is a refusal in a sentence, never a rule that silently applies to
nothing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: The three scopes, strictest first: the organization decides before the
#: team, the team before the session (SHIELD §6.3).
Scope = Literal["organization", "team", "session"]
SCOPES_STRICTEST_FIRST: tuple[Scope, ...] = ("organization", "team", "session")

#: The action classes of STUDIO F-10, as SHIELD §4.5 takes them.
ActionClass = Literal["read", "write", "send", "buy", "delete", "execute"]
ACTION_CLASSES: tuple[ActionClass, ...] = ("read", "write", "send", "buy", "delete", "execute")

#: What a decision says: *do it*, *ask me first*, *leave it to me* (R-05).
Verdict = Literal["allow", "ask", "deny"]
VERDICT_WORDS: dict[str, str] = {"allow": "do it", "ask": "ask me first", "deny": "leave it to me"}

#: Where an action's path lies, against the workspace.
Where = Literal["inside", "outside", "any"]

#: The ACP tool kinds a rule may name (SHIELD §2.3).
ToolKind = Literal["read", "edit", "delete", "move", "search", "execute", "think", "fetch", "switch_mode", "other"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Rule(_Strict):
    """One line of a policy: what it matches and what it decides."""

    name: str = Field(description="A short name; every sentence quotes it.")
    decision: Verdict
    classes: list[ActionClass] = Field(
        default_factory=list,
        description="The classes the rule names; empty names every class.",
    )
    kinds: list[ToolKind] = Field(
        default_factory=list, description="The ACP tool kinds the rule names; empty names every kind."
    )
    where: Where = Field(
        default="any",
        description=(
            "inside: only a path inside the workspace; outside: only one outside; any: both, and actions with no path."
        ),
    )
    paths: list[str] = Field(
        default_factory=list,
        description="Globs on the path relative to the workspace (fnmatch); any matches.",
    )
    commands: list[str] = Field(
        default_factory=list,
        description="Regular expressions on the whole command line; any matches.",
    )
    reason: str | None = Field(default=None, description="Why; shown in the sentence.")


class Threshold(_Strict):
    """A soft threshold asks once; a hard one refuses each call that would cross it."""

    soft: int = Field(ge=0)
    hard: int = Field(ge=0)

    @model_validator(mode="after")
    def _soft_before_hard(self) -> Threshold:
        if self.soft > self.hard:
            raise ValueError(f"a soft threshold ({self.soft}) cannot be above the hard one ({self.hard})")
        return self


class Limits(_Strict):
    """The stateful limits of a session (SHIELD §6.3).

    Three count the harness's actions; two count what its model costs: the
    **model budget** in tokens and the **spend** in credits (the deployment's
    spend limit; 100 credits are one USD). Each has a soft threshold, where the
    next call asks the person, and a hard one, where each further call is
    refused and the sentence says what would let it go on.
    """

    tool_calls: Threshold | None = Field(default=None, description="Classed actions per session.")
    terminals_open: Threshold | None = Field(default=None, description="Terminals open at once.")
    bytes_written: Threshold | None = Field(default=None, description="Bytes written to the workspace.")
    model_tokens: Threshold | None = Field(
        default=None, description="The model budget: tokens the session's model requests spend, in and out."
    )
    spend: Threshold | None = Field(
        default=None, description="The spend limit: credits the session spends on models (100 credits a USD)."
    )


#: The limit names, in the order they are checked.
LIMIT_NAMES: tuple[str, ...] = ("tool_calls", "terminals_open", "bytes_written", "model_tokens", "spend")
LIMIT_WORDS: dict[str, str] = {
    "tool_calls": "tool calls",
    "terminals_open": "terminals open at once",
    "bytes_written": "bytes written",
    "model_tokens": "model tokens spent",
    "spend": "credits spent",
}
#: What would let the session go on past each hard limit (§6.3): said in the sentence.
LIMIT_RELIEF: dict[str, str] = {
    "tool_calls": "a person can widen the limit or start a new session",
    "terminals_open": "a terminal can be released, or a person can widen the limit",
    "bytes_written": "a person can widen the limit or start a new session",
    "model_tokens": "a cheaper model, a wider budget, or a person's word would let it go on",
    "spend": "a wider spend limit or a person's word would let it go on",
}
#: The limits a model request is held to; the others count the harness's actions.
MODEL_LIMITS: tuple[str, ...] = ("model_tokens", "spend")


class Network(_Strict):
    """What the agent may reach over the network, through the Shield."""

    fetch: list[str] = Field(
        default_factory=list,
        description="Hosts a fetch may reach (exact host, or *.example.com); empty refuses every fetch.",
    )


class Mcp(_Strict):
    """The MCP servers the agent is lent, by name; everything else is cut from session/new."""

    allow: list[str] = Field(default_factory=list)


#: Whose key may run a harness (SHIELD decision 3): the account's own declared
#: secret, the platform's, or either.
Credentials = Literal["account", "platform", "either"]


class Harnesses(_Strict):
    """The harnesses an organization admits, and whose credentials run them (§6.7)."""

    admit: list[str] = Field(
        default_factory=list,
        description="Harness ids of the catalogue this scope admits; empty admits every registered harness.",
    )
    credentials: Credentials = Field(
        default="account",
        description=(
            "Whose key runs a harness: the account's own declared secret (decision 3), the platform's, or either."
        ),
    )


class Policy(_Strict):
    """One policy document, one scope."""

    scope: Scope
    version: int = Field(default=1, ge=1)
    expires: datetime | None = Field(default=None, description="When a pulled copy stops being honoured (decision 11).")
    rules: list[Rule] = Field(default_factory=list)
    limits: Limits = Field(default_factory=Limits)
    network: Network = Field(default_factory=Network)
    mcp: Mcp = Field(default_factory=Mcp)
    harnesses: Harnesses = Field(default_factory=Harnesses)

    @model_validator(mode="after")
    def _rule_names_unique(self) -> Policy:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.name in seen:
                raise ValueError(f"the {self.scope} policy names the rule {rule.name!r} twice")
            seen.add(rule.name)
        return self


class Action(_Strict):
    """What the agent wants to do, as the engine sees it.

    ``inside`` is decided by the caller against the workspace (``acp.workspace``),
    so the engine stays pure: it never touches a filesystem.
    """

    kind: str = Field(description="The ACP tool kind, or fs_read, fs_write, terminal, mcp.")
    action_class: ActionClass | None = Field(default=None, alias="class")
    title: str
    path: str | None = None
    inside: bool | None = Field(default=None, description="The path's side of the workspace; None without a path.")
    command: str | None = None
    url: str | None = None
    bytes: int | None = Field(default=None, ge=0, description="Bytes a write carries.")
    tokens: int | None = Field(default=None, ge=0, description="Tokens a model request spent, in and out.")
    credits: int | None = Field(default=None, ge=0, description="Credits a model request cost (100 a USD).")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Decision(_Strict):
    """What the engine answered, and from where."""

    verdict: Verdict
    sentence: str
    scope: Scope | None = Field(default=None, description="The scope that decided; None for the default.")
    rule: str | None = Field(default=None, description="The rule's name, or the limit's, or None for the default.")
    decided_by: Literal["rule", "limit", "network", "default"]
    counted: bool = Field(default=False, description="Whether a session state should count this action.")

    @property
    def word(self) -> str:
        return VERDICT_WORDS[self.verdict]


class Settings:
    """Bounds that keep the schema's text readable in a sentence."""

    #: A command longer than this is cut in a sentence, never in the audit.
    COMMAND_IN_A_SENTENCE = 120


__all__ = [
    "ACTION_CLASSES",
    "LIMIT_NAMES",
    "LIMIT_RELIEF",
    "LIMIT_WORDS",
    "MODEL_LIMITS",
    "SCOPES_STRICTEST_FIRST",
    "VERDICT_WORDS",
    "Action",
    "ActionClass",
    "Credentials",
    "Decision",
    "Harnesses",
    "Limits",
    "Mcp",
    "Network",
    "Policy",
    "Rule",
    "Scope",
    "Settings",
    "Threshold",
    "ToolKind",
    "Verdict",
    "Where",
]
