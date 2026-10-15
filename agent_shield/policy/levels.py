# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Three levels, nothing loosening below the one above (SHIELD §6.3, SH-31).

The engine already holds the order: the organization's policy decides before
the team's (an Appspec's Rules), the team's before the session's, and the
first decision wins — so a lower scope never *applies* more than the one
above it. What a lower scope could do is be **written and shown**: a team
policy saying *do it* where the organization says *ask me first*, a session
rule lifting a limit, a page saying one thing while the engine does another.
:func:`widening` says, in sentences, every way a lower document would permit
more than the one above; IAM refuses the write with them (``WidensPolicy``),
the runtime refuses a session rule with them, and a test holds the engine to
the same answer in every order.

Also here: which harnesses the policies in force admit, and whose credentials
run them (§6.7's ``harnesses`` section), decided by the strictest scope that
says anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from fnmatch import fnmatchcase

from .classify import KIND_CLASS
from .model import (
    LIMIT_NAMES,
    LIMIT_WORDS,
    SCOPES_STRICTEST_FIRST,
    VERDICT_WORDS,
    Credentials,
    Policy,
    Rule,
    Verdict,
)

#: How much a verdict permits: *do it* the most, *leave it to me* the least.
_PERMITS: dict[Verdict, int] = {"allow": 2, "ask": 1, "deny": 0}

_GLOB = frozenset("*?[")


class PolicyWidens(ValueError):
    """A lower document that would permit more than the one above it, in sentences."""

    def __init__(self, sentences: Sequence[str]) -> None:
        self.sentences = list(sentences)
        super().__init__("; ".join(self.sentences))


def _classes_of_kinds(kinds: Sequence[str]) -> set[str]:
    return {KIND_CLASS[kind] for kind in kinds if KIND_CLASS.get(kind) is not None}


def _disjoint_paths(lower: Sequence[str], above: Sequence[str]) -> bool:
    """Only literal paths can be told apart; a glob is taken to overlap anything."""
    if not lower or not above:
        return False
    if any(_GLOB & set(path) for path in (*lower, *above)):
        return not any(fnmatchcase(a, b) or fnmatchcase(b, a) for a in lower for b in above)
    return not (set(lower) & set(above))


def overlaps(lower: Rule, above: Rule) -> bool:
    """Whether some action both rules match. Conservative: a pattern is taken to overlap."""
    if lower.classes and above.classes and not (set(lower.classes) & set(above.classes)):
        return False
    if lower.kinds and above.kinds and not (set(lower.kinds) & set(above.kinds)):
        return False
    if lower.kinds and above.classes and not (_classes_of_kinds(lower.kinds) & set(above.classes)):
        return False
    if above.kinds and lower.classes and not (_classes_of_kinds(above.kinds) & set(lower.classes)):
        return False
    if {lower.where, above.where} == {"inside", "outside"}:
        return False
    if _disjoint_paths(lower.paths, above.paths):
        return False
    return True


def _rule_widening(lower: Policy, above: Policy) -> list[str]:
    found: list[str] = []
    for rule in lower.rules:
        for ceiling in above.rules:
            if _PERMITS[rule.decision] > _PERMITS[ceiling.decision] and overlaps(rule, ceiling):
                found.append(
                    f"the {lower.scope} rule '{rule.name}' says {VERDICT_WORDS[rule.decision]} where the "
                    f"{above.scope} rule '{ceiling.name}' says {VERDICT_WORDS[ceiling.decision]}; "
                    f"a {lower.scope} policy tightens the {above.scope}'s and cannot loosen it"
                )
                break
    return found


def _limit_widening(lower: Policy, above: Policy) -> list[str]:
    found: list[str] = []
    for name in LIMIT_NAMES:
        mine, ceiling = getattr(lower.limits, name), getattr(above.limits, name)
        if mine is None or ceiling is None:
            continue
        if mine.soft > ceiling.soft or mine.hard > ceiling.hard:
            found.append(
                f"the {lower.scope} limit on {LIMIT_WORDS[name]} ({mine.soft} then {mine.hard}) is above the "
                f"{above.scope}'s ({ceiling.soft} then {ceiling.hard}); a limit below may only be lower"
            )
    return found


def _host_covered(host: str, allowed: Sequence[str]) -> bool:
    host = host.lower()
    for entry in allowed:
        entry = entry.lower()
        if host == entry:
            return True
        if entry.startswith("*.") and (host.endswith(entry[1:]) or host == entry[2:]):
            return True
        if host.startswith("*.") and entry.startswith("*.") and host.endswith(entry[1:]):
            return True
    return False


def _list_widening(lower: Policy, above: Policy) -> list[str]:
    found: list[str] = []
    if above.network.fetch:
        extra = [host for host in lower.network.fetch if not _host_covered(host, above.network.fetch)]
        if extra:
            found.append(
                f"the {lower.scope} fetch allow-list names {', '.join(extra)}, which the {above.scope}'s does not; "
                f"a scope below cannot reach a host the one above does not list"
            )
    if above.mcp.allow:
        extra = [name for name in lower.mcp.allow if name not in above.mcp.allow]
        if extra:
            found.append(
                f"the {lower.scope} policy lends the MCP server{'s' if len(extra) > 1 else ''} {', '.join(extra)}, "
                f"which the {above.scope}'s does not; a scope below lends no server the one above does not"
            )
    if above.harnesses.admit:
        extra = [name for name in lower.harnesses.admit if name not in above.harnesses.admit]
        if extra:
            found.append(
                f"the {lower.scope} policy admits the harness{'es' if len(extra) > 1 else ''} {', '.join(extra)}, "
                f"which the {above.scope}'s does not; a scope below admits no harness the one above does not"
            )
    if above.authorize and lower.authorize:
        dropped = [name for name in above.authorize if name not in lower.authorize]
        if dropped:
            found.append(
                f"the {lower.scope} policy needs no authorizer's allow for {', '.join(dropped)} actions where the "
                f"{above.scope}'s does; a scope below drops no class the one above authorizes"
            )
    if above.harnesses.credentials != "either" and lower.harnesses.credentials != above.harnesses.credentials:
        found.append(
            f"the {lower.scope} policy runs harnesses on {lower.harnesses.credentials} credentials where the "
            f"{above.scope}'s says {above.harnesses.credentials}; a scope below keeps the credentials rule "
            f"of the one above"
        )
    return found


def widening(lower: Policy, above: Policy) -> list[str]:
    """Every way ``lower`` would permit more than ``above``; empty when it only tightens.

    The two documents are compared as written, scope by scope: a lower rule
    that permits more than an overlapping rule above, a limit above the one
    above, a fetch host, an MCP server or a harness the scope above does not
    list, a credentials rule it does not keep. A document that says nothing
    about something tightens nothing and loosens nothing.
    """
    if SCOPES_STRICTEST_FIRST.index(lower.scope) < SCOPES_STRICTEST_FIRST.index(above.scope):
        raise ValueError(f"a {lower.scope} policy is not below a {above.scope} one")
    return [*_rule_widening(lower, above), *_limit_widening(lower, above), *_list_widening(lower, above)]


def check_tightens(lower: Policy, above: Sequence[Policy]) -> None:
    """Refuse ``lower`` with :class:`PolicyWidens` when it loosens any document above it."""
    sentences: list[str] = []
    for ceiling in above:
        if SCOPES_STRICTEST_FIRST.index(ceiling.scope) < SCOPES_STRICTEST_FIRST.index(lower.scope):
            sentences.extend(widening(lower, ceiling))
    if sentences:
        raise PolicyWidens(sentences)


def admits(policies: Sequence[Policy], harness_id: str) -> str | None:
    """Why the policies in force refuse ``harness_id``, or ``None`` when it is admitted.

    The strictest scope that lists any harness decides; a scope listing none
    says nothing (every registered harness is admitted by the register).
    """
    for policy in sorted(policies, key=lambda p: SCOPES_STRICTEST_FIRST.index(p.scope)):
        if policy.harnesses.admit:
            if harness_id in policy.harnesses.admit:
                return None
            return (
                f"the harness {harness_id!r} is not one the {policy.scope} policy admits "
                f"({', '.join(policy.harnesses.admit)})"
            )
    return None


def credentials_rule(policies: Sequence[Policy]) -> Credentials:
    """Whose key may run a harness: the strictest scope's rule (``account`` when none says)."""
    for policy in sorted(policies, key=lambda p: SCOPES_STRICTEST_FIRST.index(p.scope)):
        return policy.harnesses.credentials
    return "account"


__all__ = ["PolicyWidens", "admits", "check_tightens", "credentials_rule", "overlaps", "widening"]
