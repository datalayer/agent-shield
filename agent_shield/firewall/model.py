# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The firewall's rules: what an agent's pod may reach, and who may reach it.

An agent spec says them under ``policy.shield``::

    policy:
      shield:
        egress: ["*"]
        ingress: ["platform", "10.42.0.0/16:8765"]

An egress entry is an exact host, ``host:port``, an IPv4 address, ``ip:port``,
a CIDR, ``cidr:port``, or ``*`` alone — any *public* address on any TCP port.
A private, loopback, link-local, shared or multicast address is never an
agent's to ask for: the platform's own internal endpoints are the base layer's
(:class:`~agent_shield.firewall.compile.BaseLayer`), and ``*`` leaves them
refused. A wildcard host (``*.example.com``) is refused with the reason: a
firewall sees addresses, not names; a name-level allow-list is the policy
document's ``network.fetch``.

An ingress entry is ``platform`` (the platform's ingress and probes, the
default), ``*``, or an address or CIDR with an optional ``:port`` — the
agent's own port it may be reached on. Private sources are the rule there.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Any public address.
ANY = "*"
#: The platform's own sources of ingress, which the base names.
PLATFORM = "platform"

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOST = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
_PORT = r"(?::(?P<port>\d{1,5}))?"
#: The grammar both lists share; a JSON Schema pattern as well.
ENTRY_PATTERN = r"^(\*|platform|[A-Za-z0-9.\-]+(/\d{1,2})?(:\d{1,5})?)$"

#: The ranges ``*`` leaves refused and an egress entry may not name.
NON_PUBLIC = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

Direction = Literal["egress", "ingress"]


class FirewallError(ValueError):
    """An entry the firewall cannot take, said in a sentence."""


@dataclass(frozen=True)
class Entry:
    """One parsed entry: ``any``, ``platform``, a ``host`` or a ``network``, and its port."""

    kind: Literal["any", "platform", "host", "network"]
    value: str
    port: int | None = None
    text: str = ""

    @property
    def label(self) -> str:
        """How a rule and a row name it."""
        return self.text or self.value


def _non_public(network: ipaddress.IPv4Network) -> bool:
    return any(network.overlaps(ipaddress.IPv4Network(item)) for item in NON_PUBLIC)


def parse_entry(text: str, direction: Direction = "egress") -> Entry:
    """One entry of ``egress`` or ``ingress``, parsed, or :class:`FirewallError` saying why not."""
    raw = (text or "").strip()
    if not raw:
        raise FirewallError("an empty entry names nothing")
    if raw == ANY:
        return Entry("any", ANY, None, raw)
    if raw == PLATFORM:
        if direction != "ingress":
            raise FirewallError("'platform' is an ingress source; the platform's own egress is the base layer's")
        return Entry("platform", PLATFORM, None, raw)
    if "*" in raw:
        raise FirewallError(
            f"{raw!r}: a firewall sees addresses, not names, so a wildcard host cannot hold; "
            "name each host, or use the policy's network.fetch for a name-level allow-list"
        )
    match = re.match(rf"^(?P<target>[^:]+){_PORT}$", raw)
    if not match:
        raise FirewallError(f"{raw!r} is not host, host:port, address, CIDR or CIDR:port (IPv6 is not taken)")
    target = match.group("target").lower()
    port: int | None = None
    if match.group("port") is not None:
        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            raise FirewallError(f"{raw!r}: port {port} is not between 1 and 65535")
    network: ipaddress.IPv4Network | None = None
    if re.match(r"^[0-9./]+$", target):
        try:
            network = ipaddress.IPv4Network(target, strict=True)
        except ValueError as error:
            raise FirewallError(f"{raw!r} is not an IPv4 address or CIDR: {error}") from None
    if network is not None:
        if direction == "egress" and _non_public(network):
            raise FirewallError(
                f"{raw!r} is a private or reserved address: the platform's own addresses are the base layer's, "
                "and an agent cannot ask for them"
            )
        return Entry("network", str(network), port, raw)
    if not _HOST.match(target) or "." not in target:
        raise FirewallError(f"{raw!r} is not an exact, fully qualified host name")
    if direction == "ingress":
        raise FirewallError(f"{raw!r}: an ingress source is 'platform', '*', an address or a CIDR, not a host name")
    return Entry("host", target, port, raw)


def _check(values: list[str], direction: Direction) -> list[str]:
    seen: set[str] = set()
    for value in values:
        parse_entry(value, direction)
        if value in seen:
            raise FirewallError(f"{value!r} is named twice")
        seen.add(value)
    if ANY in values and len(values) > 1:
        raise FirewallError("'*' stands alone: it already allows every public address")
    return values


class FirewallRules(BaseModel):
    """An agent's ``policy.shield``: its pod's egress and ingress."""

    model_config = ConfigDict(extra="forbid")

    egress: list[str] = Field(
        default_factory=list,
        description=(
            "What the agent's pod may reach beyond the platform's own endpoints: '*' (any public address, any TCP "
            "port) alone, or exact hosts, host:port, IPv4 addresses, CIDRs, each with an optional :port. Private "
            "and reserved addresses are refused; empty keeps the platform's endpoints only."
        ),
        json_schema_extra={"items": {"type": "string", "pattern": ENTRY_PATTERN}},
    )
    ingress: list[str] = Field(
        default_factory=list,
        description=(
            "Who may reach the agent's ports: 'platform' (the platform's ingress and probes), '*', or an address "
            "or CIDR with an optional :port (the agent's port). Empty means 'platform'."
        ),
        json_schema_extra={"items": {"type": "string", "pattern": ENTRY_PATTERN}},
    )

    @field_validator("egress")
    @classmethod
    def _egress(cls, value: list[str]) -> list[str]:
        try:
            return _check(value, "egress")
        except FirewallError as error:
            raise ValueError(str(error)) from None

    @field_validator("ingress")
    @classmethod
    def _ingress(cls, value: list[str]) -> list[str]:
        try:
            return _check(value, "ingress")
        except FirewallError as error:
            raise ValueError(str(error)) from None

    def egress_entries(self) -> list[Entry]:
        return [parse_entry(item, "egress") for item in self.egress]

    def ingress_entries(self) -> list[Entry]:
        return [parse_entry(item, "ingress") for item in (self.ingress or [PLATFORM])]

    @property
    def open_egress(self) -> bool:
        return ANY in self.egress


def firewall_json_schema() -> dict[str, Any]:
    """The JSON Schema of ``policy.shield``, which agentspecs carries verbatim."""
    schema = FirewallRules.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://agent-shield.datalayer.tech/schema/firewall.schema.json"
    schema["title"] = "Agent Shield firewall rules"
    return schema


def rules_of_spec(spec: dict[str, Any]) -> FirewallRules:
    """An agent spec's ``policy.shield``, or the empty rules when it has none."""
    policy = spec.get("policy") or {}
    if not isinstance(policy, dict):
        raise FirewallError("an agent's policy is a mapping")
    return FirewallRules.model_validate(policy.get("shield") or {})


__all__ = [
    "ANY",
    "ENTRY_PATTERN",
    "NON_PUBLIC",
    "PLATFORM",
    "Entry",
    "FirewallError",
    "FirewallRules",
    "firewall_json_schema",
    "parse_entry",
    "rules_of_spec",
]
