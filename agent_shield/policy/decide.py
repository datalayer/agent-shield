# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""``decide(action, context, policies)``: pure, strictest scope first, first decision wins.

The order (SHIELD §6.3):

1. The **limits**, strictest scope first. A hard threshold the action would
   cross refuses it, and the sentence says what would let it go on; a soft
   threshold crossed asks once per limit and scope, then lets the session run
   on to the hard one.
2. The **rules**, strictest scope first, in the order written; the first rule
   that matches decides.
3. A **fetch** no rule named is decided by the strictest policy that lists
   any host: on the list, do it; off it, or with no list anywhere, leave it
   to me.
4. Nothing said: **ask me first**. An action with no rule never falls to
   *do it* (R-05).

The engine never touches a filesystem, a clock or a socket: ``inside`` and
the counters arrive in the action and the context.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

from .model import (
    LIMIT_NAMES,
    LIMIT_RELIEF,
    LIMIT_WORDS,
    MODEL_LIMITS,
    SCOPES_STRICTEST_FIRST,
    VERDICT_WORDS,
    Action,
    Decision,
    Policy,
    Rule,
    Scope,
    Settings,
    Threshold,
)


@dataclass
class LimitState:
    """What a session has used so far; the caller counts, the engine reads."""

    tool_calls: int = 0
    terminals_open: int = 0
    bytes_written: int = 0
    #: What the session's model requests spent so far (SH-32): tokens and credits.
    model_tokens: int = 0
    spend: int = 0
    #: ``(scope, limit)`` pairs whose soft threshold was already asked about.
    soft_asked: set[tuple[str, str]] = field(default_factory=set)

    def count(self, action: Action, decision: Decision) -> None:
        """Count an action the agent went on with (allowed, or asked and granted)."""
        if decision.verdict == "deny" or not decision.counted:
            return
        if action.kind == MODEL_KIND:
            self.model_tokens += action.tokens or 0
            self.spend += action.credits or 0
            return
        self.tool_calls += 1
        if action.kind == "terminal":
            self.terminals_open += 1
        if action.bytes and action.action_class == "write":
            self.bytes_written += action.bytes

    def spent(self, *, tokens: int = 0, cost: int = 0) -> None:
        """Count what a model request spent, once it is known (after the response)."""
        self.model_tokens += max(0, tokens)
        self.spend += max(0, cost)

    def terminal_released(self) -> None:
        if self.terminals_open > 0:
            self.terminals_open -= 1


@dataclass(frozen=True)
class Context:
    """What surrounds an action: the workspace, the session and its state."""

    workspace: str
    session_id: str | None = None
    state: LimitState = field(default_factory=LimitState)


def _rank(policy: Policy) -> int:
    return SCOPES_STRICTEST_FIRST.index(policy.scope)


def _short(text: str) -> str:
    limit = Settings.COMMAND_IN_A_SENTENCE
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _subject(action: Action) -> str:
    if action.command:
        return f"{action.title} (`{_short(action.command)}`)"
    if action.path:
        return f"{action.title} ({action.path})"
    if action.url:
        return f"{action.title} ({action.url})"
    return action.title


#: The kind of a model request, held to the model limits alone (SH-32): never
#: a tool call, never a rule's business.
MODEL_KIND = "model"


def _would_use(action: Action, name: str, state: LimitState) -> int | None:
    """What the limit would read after this action, or ``None`` when the action does not touch it."""
    is_model = action.kind == MODEL_KIND
    if name in MODEL_LIMITS:
        if not is_model:
            return None
        if name == "model_tokens":
            return state.model_tokens + (action.tokens or 0)
        return state.spend + (action.credits or 0)
    if is_model:
        return None
    if name == "tool_calls":
        return state.tool_calls + 1
    if name == "terminals_open":
        return state.terminals_open + (1 if action.kind == "terminal" else 0)
    if name == "bytes_written":
        return state.bytes_written + (action.bytes or 0 if action.action_class == "write" else 0)
    raise ValueError(f"no limit named {name!r}")


def _limit_decision(action: Action, context: Context, policy: Policy) -> Decision | None:
    for name in LIMIT_NAMES:
        threshold: Threshold | None = getattr(policy.limits, name)
        if threshold is None:
            continue
        after = _would_use(action, name, context.state)
        if after is None or after <= threshold.soft:
            continue
        words = LIMIT_WORDS[name]
        scope = policy.scope
        if after > threshold.hard:
            return Decision(
                verdict="deny",
                decided_by="limit",
                scope=scope,
                rule=name,
                sentence=(
                    f"{_subject(action)}: refused — the session's {words} would reach {after}, "
                    f"over the hard limit of {threshold.hard} in the {scope} policy; {LIMIT_RELIEF[name]}"
                ),
            )
        if (scope, name) not in context.state.soft_asked:
            return Decision(
                verdict="ask",
                decided_by="limit",
                scope=scope,
                rule=name,
                counted=True,
                sentence=(
                    f"{_subject(action)}: ask me first — the session's {words} would reach {after}, "
                    f"past the soft limit of {threshold.soft} in the {scope} policy; the hard limit is "
                    f"{threshold.hard}"
                ),
            )
    return None


def _matches(rule: Rule, action: Action) -> bool:
    if rule.classes and action.action_class not in rule.classes:
        return False
    if rule.kinds and action.kind not in rule.kinds:
        return False
    if rule.where == "inside" and action.inside is not True:
        return False
    if rule.where == "outside" and action.inside is not False:
        return False
    if rule.paths:
        if action.path is None or not any(fnmatchcase(action.path, glob) for glob in rule.paths):
            return False
    if rule.commands:
        if action.command is None or not any(re.search(pattern, action.command) for pattern in rule.commands):
            return False
    return True


def _rule_decision(action: Action, policy: Policy) -> Decision | None:
    for rule in policy.rules:
        if not _matches(rule, action):
            continue
        reason = f" ({rule.reason})" if rule.reason else ""
        return Decision(
            verdict=rule.decision,
            decided_by="rule",
            scope=policy.scope,
            rule=rule.name,
            counted=True,
            sentence=f"{_subject(action)}: {VERDICT_WORDS[rule.decision]} — {policy.scope} rule '{rule.name}'{reason}",
        )
    return None


def _host_allowed(host: str, allowed: Sequence[str]) -> bool:
    host = host.lower()
    for entry in allowed:
        entry = entry.lower()
        if entry.startswith("*.") and (host == entry[2:] or host.endswith(entry[1:])):
            return True
        if host == entry:
            return True
    return False


def _fetch_decision(action: Action, policies: Sequence[Policy]) -> Decision | None:
    if action.kind != "fetch" and action.url is None:
        return None
    host = urlsplit(action.url).hostname if action.url else None
    if host is None:
        return Decision(
            verdict="deny",
            decided_by="network",
            sentence=f"{_subject(action)}: leave it to me — a fetch names no host the allow-list could hold",
        )
    for policy in policies:
        if not policy.network.fetch:
            continue
        if _host_allowed(host, policy.network.fetch):
            return Decision(
                verdict="allow",
                decided_by="network",
                scope=policy.scope,
                rule="network.fetch",
                counted=True,
                sentence=f"{_subject(action)}: do it — {host} is on the {policy.scope} policy's fetch allow-list",
            )
        return Decision(
            verdict="deny",
            decided_by="network",
            scope=policy.scope,
            rule="network.fetch",
            sentence=(
                f"{_subject(action)}: leave it to me — {host} is not on the {policy.scope} policy's "
                f"fetch allow-list; add it to network.fetch to let it through"
            ),
        )
    return Decision(
        verdict="deny",
        decided_by="network",
        sentence=(
            f"{_subject(action)}: leave it to me — no policy lists a host a fetch may reach; "
            f"add {host} to network.fetch to let it through"
        ),
    )


def decide(action: Action, context: Context, policies: Sequence[Policy]) -> Decision:
    """Decide one action against the policies in force (see the module)."""
    if action.action_class is None:
        raise ValueError(f"{action.title}: an action with no class has nothing to decide")
    ordered = sorted(policies, key=_rank)
    for policy in ordered:
        found = _limit_decision(action, context, policy)
        if found is not None:
            return found
    for policy in ordered:
        found = _rule_decision(action, policy)
        if found is not None:
            return found
    found = _fetch_decision(action, ordered)
    if found is not None:
        return found
    return Decision(
        verdict="ask",
        decided_by="default",
        counted=True,
        sentence=f"{_subject(action)}: ask me first — no rule names it, and nothing unsaid is done",
    )


def decide_budget(
    context: Context, policies: Sequence[Policy], *, tokens: int = 0, cost: int = 0, title: str = "a model request"
) -> Decision:
    """Decide the next model request against the model limits alone (SH-32, SH-54).

    ``tokens`` and ``cost`` (in credits) are what the request is expected to add — the
    last request's cost is the usual estimate; ``0`` asks whether what was
    spent already crossed a threshold. The limits are read strictest scope
    first; the rules, the allow-list and the default are not consulted: a
    model request is not a classed action. Under every limit the answer is
    *do it*; past a soft one, *ask me first* once per limit and scope; past a
    hard one, refused with what would let it go on.
    """
    action = Action(kind=MODEL_KIND, title=title, tokens=tokens, credits=cost)
    for policy in sorted(policies, key=_rank):
        found = _limit_decision(action, context, policy)
        if found is not None:
            return found
    return Decision(
        verdict="allow",
        decided_by="default",
        counted=True,
        sentence=f"{title}: do it — within every model limit",
    )


def scopes_present(policies: Sequence[Policy]) -> list[Scope]:
    return [policy.scope for policy in sorted(policies, key=_rank)]


__all__ = ["MODEL_KIND", "Context", "LimitState", "decide", "decide_budget", "scopes_present"]
