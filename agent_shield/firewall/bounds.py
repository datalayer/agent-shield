# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""An agent's rules held to its organization's ceiling (Agent Firewall N3-01).

An organization's policy document may carry ``firewall: {egress, ingress}``
(:class:`~agent_shield.firewall.model.FirewallCeiling`): the most any agent of
the organization may be granted. :func:`bounded` is the intersection of an
agent's ``policy.shield`` with it, the strictest winning, as the scopes do for
``network.fetch``:

- ``*`` in the ceiling allows anything the rules ask (every egress entry is
  public, :mod:`.model` refuses the rest);
- otherwise an entry holds as far as a ceiling entry covers it: an exact host
  only by the same host, an address or CIDR by a CIDR that covers it (or the
  part of it the ceiling's narrower CIDR names), and a port only by the same
  port (an entry with no port, every port, is narrowed to the ceiling's port);
- the rules' ``*`` is the ceiling itself: any public address, as far as the
  ceiling goes;
- ``platform`` stays in ingress whatever the ceiling says: the platform's own
  sources are the base layer's, as its endpoints are in egress;
- no ceiling, or a direction the ceiling leaves out, leaves the rules as they are.

A host is never matched against a CIDR: the firewall resolves names where it
applies them, so the ceiling cannot know a host's addresses here.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Protocol

from agent_shield.firewall.model import ANY, PLATFORM, Direction, Entry, FirewallCeiling, FirewallRules, parse_entry

_CONFLICT = object()


class _HasCeiling(Protocol):
    scope: str
    firewall: FirewallCeiling | None


def _port(spec: int | None, ceiling: int | None) -> Any:
    if spec is None:
        return ceiling
    if ceiling is None or ceiling == spec:
        return spec
    return _CONFLICT


def _render(target: str, port: int | None) -> str:
    return f"{target}:{port}" if port is not None else target


def _network_text(network: ipaddress.IPv4Network) -> str:
    return str(network.network_address) if network.prefixlen == 32 else str(network)


def _meet(spec: Entry, ceiling: Entry) -> str | None:
    """What of ``spec`` the ceiling entry allows, as an entry's text; ``None`` when nothing."""
    if ceiling.kind == "any":
        return spec.text
    if spec.kind == "any":
        return ceiling.text
    if PLATFORM in (spec.kind, ceiling.kind):
        return None
    port = _port(spec.port, ceiling.port)
    if port is _CONFLICT:
        return None
    if spec.kind == "host" and ceiling.kind == "host":
        if spec.value != ceiling.value:
            return None
        return spec.text if port == spec.port else _render(spec.value, port)
    if spec.kind == "network" and ceiling.kind == "network":
        asked = ipaddress.IPv4Network(spec.value)
        allowed = ipaddress.IPv4Network(ceiling.value)
        if asked.subnet_of(allowed):
            return spec.text if port == spec.port else _render(_network_text(asked), port)
        if allowed.subnet_of(asked):
            return _render(_network_text(allowed), port)
    return None


def _bounded_list(asked: Sequence[str], ceiling: Sequence[str], direction: Direction) -> list[str]:
    allowed = [parse_entry(item, direction) for item in ceiling]
    if any(entry.kind == "any" for entry in allowed):
        return list(asked)
    held: list[str] = []
    for item in asked:
        entry = parse_entry(item, direction)
        if entry.kind == "platform":
            meets = [entry.text]
        else:
            meets = [meet for cap in allowed if (meet := _meet(entry, cap)) is not None]
        for meet in meets:
            if meet not in held:
                held.append(meet)
    return held


def bounded(
    rules: FirewallRules | Mapping[str, Any],
    ceiling: FirewallCeiling | Mapping[str, Any] | None,
) -> FirewallRules:
    """``rules`` held to ``ceiling``: each entry only as far as the ceiling allows it; unchanged with no ceiling."""
    rules = rules if isinstance(rules, FirewallRules) else FirewallRules.model_validate(dict(rules))
    if ceiling is None:
        return rules
    ceiling = ceiling if isinstance(ceiling, FirewallCeiling) else FirewallCeiling.model_validate(dict(ceiling))
    egress = list(rules.egress) if ceiling.egress is None else _bounded_list(rules.egress, ceiling.egress, "egress")
    ingress = (
        list(rules.ingress) if ceiling.ingress is None else _bounded_list(rules.ingress, ceiling.ingress, "ingress")
    )
    if ANY in egress:
        egress = [ANY]
    if ANY in ingress:
        ingress = [ANY]
    return FirewallRules(egress=egress, ingress=ingress)


def organization_ceilings(policies: Iterable[_HasCeiling]) -> list[FirewallCeiling]:
    """The ceilings the organization documents among ``policies`` carry, in their order."""
    return [policy.firewall for policy in policies if policy.scope == "organization" and policy.firewall is not None]


def bounded_by(
    rules: FirewallRules | Mapping[str, Any], ceilings: Iterable[FirewallCeiling | Mapping[str, Any]]
) -> FirewallRules:
    """``rules`` held to every ceiling in turn: an account in two organizations gets what both allow."""
    held = rules if isinstance(rules, FirewallRules) else FirewallRules.model_validate(dict(rules))
    for ceiling in ceilings:
        held = bounded(held, ceiling)
    return held


__all__ = ["bounded", "bounded_by", "organization_ceilings"]
