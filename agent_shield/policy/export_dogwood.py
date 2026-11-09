# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A Shield document's rules and limits as a Dogwood policy set (AC-43).

``agent-shield policy export --dogwood <document>`` writes what AgentCore
Policy would decide the same way, for the part of a document Dogwood can say:

- the **rules**, first match wins: a rule deciding *do it* is a ``permit``
  whose condition is the rule's match and the negation of every earlier rule
  that decides anything else; *ask me first* and *leave it to me* are not
  permitted (Dogwood denies by default, and has no *ask*). A rule matches on
  the Shield's own context — ``context.class``, ``context.kind``,
  ``context.inside``, ``context.path`` (a glob of ``*`` becomes Cedar's
  ``like``);
- **tool_calls**' hard threshold: a ``forbid`` per tool named (``--tool``)
  when its ``request`` events in the window, the current one counted, pass
  it — Dogwood counts one action per predicate and has no disjunction, so
  with several tools each is held to the threshold on its own;
- **model_tokens** and **spend**'s hard thresholds: a ``forbid`` on the
  Shield's model action (``shield___model``) when the running total of its
  requests' ``input.tokens`` / ``input.credits``, the current one counted,
  passes it, and a plain ``permit`` of that action under it.

A soft threshold asks a person, which Dogwood cannot, so it is not exported
(it is said in a comment). A rule naming ``commands`` (regular expressions)
or a path glob with ``?`` or ``[`` cannot be said in Cedar, and a document
that already carries a ``dogwood`` set is not merged with another: each is
refused in a sentence. The other sections — the other limits, the network,
the authorizer, the MCP servers, the harnesses, the firewall — are the
Shield's, and the set's header says so. The window is 24 hours, AgentCore's
most; a Shield limit is per session.
"""

from __future__ import annotations

import json

from .cedar import SHIELD_SERVER, uid
from .dogwood import parse_set
from .model import Policy, Rule

#: The Shield's model requests, as a Cedar action.
MODEL_TOOL = f"{SHIELD_SERVER}___model"
#: The window a session's limit is exported with: AgentCore's most.
LIMIT_WINDOW = "24h"
#: The fields a model request's running total is read from.
MODEL_FIELDS = {"model_tokens": "tokens", "spend": "credits"}


class ExportRefused(ValueError):
    """A document the export cannot say in Dogwood, said in a sentence."""


def _set_of(values: list[str]) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def _like(glob: str, rule: Rule) -> str:
    if any(char in glob for char in "?[]"):
        raise ExportRefused(
            f"the rule {rule.name!r} names the path glob {glob!r}: Cedar's like knows '*' alone, "
            "so it cannot be exported"
        )
    escaped = json.dumps(glob)
    return f"context.path like {escaped}"


def rule_match(rule: Rule) -> str:
    """The rule's match as a Cedar condition over the Shield's context."""
    if rule.commands:
        raise ExportRefused(
            f"the rule {rule.name!r} matches commands by regular expression, which Cedar cannot say, "
            "so it cannot be exported"
        )
    parts: list[str] = []
    if rule.classes:
        parts.append(f"context has class && {_set_of(list(rule.classes))}.contains(context.class)")
    if rule.kinds:
        parts.append(f"context has kind && {_set_of(list(rule.kinds))}.contains(context.kind)")
    if rule.where == "inside":
        parts.append("context has inside && context.inside")
    elif rule.where == "outside":
        parts.append("context has inside && !context.inside")
    if rule.paths:
        likes = " || ".join(_like(glob, rule) for glob in rule.paths)
        parts.append(f"context has path && ({likes})")
    return " && ".join(f"({part})" for part in parts) if parts else "true"


def _rules(policy: Policy) -> list[str]:
    out: list[str] = []
    others: list[tuple[Rule, str]] = []
    for rule in policy.rules:
        match = rule_match(rule)
        if rule.decision != "allow":
            others.append((rule, match))
            continue
        guards = [f"!({earlier})" for _, earlier in others]
        condition = " && ".join([f"({match})", *guards])
        shadowed = f" (after {', '.join(r.name for r, _ in others)})" if others else ""
        out.append(
            f"// rule {rule.name!r}: do it{shadowed}\n"
            f"@id({json.dumps('rule: ' + rule.name)})\n"
            f"permit (principal, action, resource)\nwhen {{ {condition} }};"
        )
    for rule, _ in others:
        out.append(
            f"// rule {rule.name!r}: {'ask me first' if rule.decision == 'ask' else 'leave it to me'} — not permitted "
            "(deny by default)"
        )
    return out


def _count_forbid(tool: str, hard: int) -> str:
    action = uid("Action", tool)
    return (
        f"@id({json.dumps('tool_calls: ' + tool)})\n"
        f"forbid (principal, action == {action}, resource)\n"
        "when temporal {\n"
        "    exists (n: Long).\n"
        "        (count for (t: Timepoint).\n"
        f"            where (formerly within {LIMIT_WINDOW} ({action}::request{{ eventResource: resource }} "
        "&& tp(t)))) == n\n"
        f"        && n > {hard}\n"
        "};"
    )


def _sum_forbid(name: str, hard: int) -> str:
    action = uid("Action", MODEL_TOOL)
    field = MODEL_FIELDS[name]
    return (
        f"@id({json.dumps(name)})\n"
        f"forbid (principal, action == {action}, resource)\n"
        "when temporal {\n"
        "    exists (total: Long).\n"
        "        (sum v for (v: Long), (t: Timepoint).\n"
        f"            where (formerly within {LIMIT_WINDOW} ({action}::request{{ eventResource: resource, "
        f"input.{field}: v }} && tp(t)))) == total\n"
        f"        && total > {hard}\n"
        "};"
    )


def _limits(policy: Policy, tools: list[str]) -> list[str]:
    out: list[str] = []
    calls = policy.limits.tool_calls
    if calls is not None:
        if not tools:
            raise ExportRefused(
                "tool_calls counts every action, and Dogwood counts one action per predicate: name the tools "
                "the limit holds with --tool <server>___<tool>"
            )
        out.append(f"// tool_calls: hard {calls.hard} per tool (soft {calls.soft} asks a person: not exported)")
        out.extend(_count_forbid(tool, calls.hard) for tool in tools)
    model = [name for name in MODEL_FIELDS if getattr(policy.limits, name) is not None]
    for name in model:
        threshold = getattr(policy.limits, name)
        out.append(f"// {name}: hard {threshold.hard} (soft {threshold.soft} asks a person: not exported)")
        out.append(_sum_forbid(name, threshold.hard))
    if model:
        out.append(f'@id("model requests")\npermit (principal, action == {uid("Action", MODEL_TOOL)}, resource);')
    return out


def export_dogwood(policy: Policy, *, tools: list[str] | None = None) -> str:
    """A document's rules and limits as a Dogwood policy set, read back before it is returned.

    Parameters
    ----------
    policy : Policy
        The Shield's document.
    tools : list of str, optional
        The tools (``<server>___<tool>``) ``limits.tool_calls`` holds.

    Returns
    -------
    str
        The policy set; it parses, and holds AgentCore's quotas.

    Raises
    ------
    ExportRefused
        When a part of the document that decides cannot be said in Dogwood.
    """
    if policy.dogwood is not None:
        raise ExportRefused(
            "the document already carries a dogwood set; the export compiles the rules and limits alone, "
            "and a set is not merged with another"
        )
    named = list(tools or [])
    header = [
        f"// The {policy.scope} policy (version {policy.version}), exported by agent-shield: its rules and its",
        "// tool_calls / model_tokens / spend limits. The other limits, the network, the authorizer, the MCP",
        "// servers, the harnesses and the firewall stay the Shield's.",
    ]
    body = [*_rules(policy), *_limits(policy, named)]
    text = "\n".join(header) + "\n\n" + "\n\n".join(body) + "\n"
    parse_set(text)
    return text


__all__ = ["LIMIT_WINDOW", "MODEL_FIELDS", "MODEL_TOOL", "ExportRefused", "export_dogwood", "rule_match"]
