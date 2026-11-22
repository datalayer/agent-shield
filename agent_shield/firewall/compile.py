# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Base and spec, compiled into one ``iptables-restore`` script.

The *base* is what the platform's runtime always reaches — DNS, its own
endpoints at the addresses they resolved to when the pod was made, and what is
always refused (the cloud metadata address). On Datalayer the Operator writes
it (its egress table) and hands it over as JSON; no spec removes any of it.
The *spec* is the agent's ``policy.shield`` (:class:`FirewallRules`), its
hosts resolved by the controller.

A spec host's answers are filtered before any rule is written (DNS rebinding):
a public name checked once can later resolve to a private, loopback,
link-local (the metadata address among them), shared or reserved address, or
into the cluster's own networks (``cluster_ranges``), and such an address is
dropped and said (``Compiled.non_public``). A host left with no public
address gets no rule (``Compiled.non_public_only``). The base layer's
addresses are the platform's and are never filtered: its endpoints (a
cluster-internal database, a message broker) are legitimately private.

The firewall owns three chains in the ``filter`` table:

``SHIELD-EGRESS`` (from ``OUTPUT``)
    loopback and established traffic; the refused list, logged; DNS to the
    resolvers; each base allowance and each spec entry, logged on a new
    connection; for ``*``, the non-public ranges sent to refuse, then the rest
    accepted and logged (for ``*:port``, the same on that TCP port only);
    everything else refused.
``SHIELD-INGRESS`` (from ``INPUT``, only when ingress is enforced)
    loopback and established traffic; each source, logged; refused.
``SHIELD-REFUSE``
    log, then ``REJECT`` — a TCP reset, port-unreachable otherwise — so a
    caller fails at once.

Every logged rule sends the packet to ``NFLOG`` group :data:`NFLOG_GROUP`
with the prefix ``shield allow <rule>`` or ``shield refuse <rule>``, which the
listener (:mod:`agent_shield.firewall.nflog`) turns into audit rows. The script
is applied whole with ``iptables-restore --noflush``: a re-apply swaps the
chains in one commit, and the pod is never open nor shut in between.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agent_shield.firewall.model import NON_PUBLIC, FirewallRules, is_public_address

EGRESS_CHAIN = "SHIELD-EGRESS"
INGRESS_CHAIN = "SHIELD-INGRESS"
REFUSE_CHAIN = "SHIELD-REFUSE"
#: The ``NFLOG`` group the listener binds.
NFLOG_GROUP = 7
#: The longest prefix ``NFLOG`` keeps.
PREFIX_MAX = 63
#: The metadata address, refused whatever the base says.
METADATA = "169.254.169.254/32"


@dataclass(frozen=True)
class BaseAllowance:
    """One platform endpoint: its name, host, resolved addresses and ports."""

    name: str
    host: str
    addresses: tuple[str, ...]
    ports: tuple[int, ...]
    protocol: str = "tcp"


@dataclass(frozen=True)
class BaseLayer:
    """What the platform's runtime always reaches, and what is always refused."""

    dns: tuple[str, ...] = ()
    allow: tuple[BaseAllowance, ...] = ()
    refuse: tuple[str, ...] = (METADATA,)
    #: Sources of ingress the ``platform`` entry stands for (the ingress, the nodes' probes).
    platform_sources: tuple[str, ...] = ()
    #: The cluster's own networks (pods, services), when known: never a spec host's address, and
    #: refused under ``*`` as the non-public ranges are.
    cluster_ranges: tuple[str, ...] = ()

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> BaseLayer:
        """The Operator's JSON (``egress.base_layer``) as a layer; a wrong shape is refused."""
        if not isinstance(data, dict):
            raise ValueError("a base layer is a mapping")
        unknown = set(data) - {"dns", "allow", "refuse", "platform_sources", "cluster_ranges"}
        if unknown:
            raise ValueError(f"a base layer has no {', '.join(sorted(unknown))}")
        allow = []
        for item in data.get("allow") or []:
            allow.append(
                BaseAllowance(
                    name=str(item["name"]),
                    host=str(item.get("host", "")),
                    addresses=tuple(str(a) for a in item["addresses"]),
                    ports=tuple(int(p) for p in item["ports"]),
                    protocol=str(item.get("protocol", "tcp")),
                )
            )
        refuse = tuple(str(r) for r in data.get("refuse") or ())
        if METADATA not in refuse:
            refuse = (METADATA, *refuse)
        return cls(
            dns=tuple(str(d) for d in data.get("dns") or ()),
            allow=tuple(allow),
            refuse=refuse,
            platform_sources=tuple(str(s) for s in data.get("platform_sources") or ()),
            cluster_ranges=tuple(str(c) for c in data.get("cluster_ranges") or ()),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "dns": list(self.dns),
            "allow": [
                {
                    "name": a.name,
                    "host": a.host,
                    "addresses": list(a.addresses),
                    "ports": list(a.ports),
                    "protocol": a.protocol,
                }
                for a in self.allow
            ],
            "refuse": list(self.refuse),
            "platform_sources": list(self.platform_sources),
            "cluster_ranges": list(self.cluster_ranges),
        }


@dataclass
class Compiled:
    """The script, and what a row needs to name a destination."""

    script: str
    #: Address → the hosts it was resolved from (base and spec), for the record.
    hosts: dict[str, list[str]] = field(default_factory=dict)
    #: Spec hosts that resolved to nothing: refused.
    unresolved: list[str] = field(default_factory=list)
    rules: int = 0
    #: Spec host → the non-public addresses it resolved to, dropped (DNS rebinding).
    non_public: dict[str, list[str]] = field(default_factory=dict)
    #: Spec hosts that resolved only to non-public addresses: no rule.
    non_public_only: list[str] = field(default_factory=list)


def _cidr(address: str) -> str:
    return address if "/" in address else f"{address}/32"


def prefix(decision: str, rule: str) -> str:
    """The ``NFLOG`` prefix of a rule: ``shield <decision> <rule>``, quoted-safe and short."""
    clean = re.sub(r"[^A-Za-z0-9.:*,_/\-]", "_", rule)
    return f"shield {decision} {clean}"[:PREFIX_MAX]


def _log(chain: str, match: str, decision: str, rule: str) -> str:
    head = f"-A {chain} {match}".rstrip()
    return f'{head} -m conntrack --ctstate NEW -j NFLOG --nflog-group {NFLOG_GROUP} --nflog-prefix "{prefix(decision, rule)}"'


def compile_rules(
    base: BaseLayer,
    rules: FirewallRules | None = None,
    *,
    resolved: dict[str, list[str]] | None = None,
    enforce_ingress: bool = False,
) -> Compiled:
    """The ``iptables-restore --noflush`` script for base + spec.

    Parameters
    ----------
    base : BaseLayer
        The platform's layer.
    rules : FirewallRules, optional
        The agent's ``policy.shield``; none keeps the base alone.
    resolved : dict, optional
        Each spec host's addresses, as the controller resolved them; a host
        missing or empty here is refused and listed in ``unresolved``. A
        non-public answer is dropped (``non_public``); a host with only such
        answers gets no rule (``non_public_only``).
    enforce_ingress : bool
        Write ``SHIELD-INGRESS``; off, ingress is left as the pod has it.
    """
    rules = rules or FirewallRules()
    resolved = resolved or {}
    hosts: dict[str, list[str]] = {}
    unresolved: list[str] = []
    non_public: dict[str, list[str]] = {}
    non_public_only: list[str] = []

    def remember(address: str, host: str) -> None:
        if host and host not in hosts.setdefault(address, []):
            hosts[address].append(host)

    egress_chain, refuse = EGRESS_CHAIN, REFUSE_CHAIN
    lines = ["*filter", f":{egress_chain} - [0:0]", f":{refuse} - [0:0]"]
    if enforce_ingress:
        lines.append(f":{INGRESS_CHAIN} - [0:0]")
    # The refuse chain: logged by whoever jumped with a rule name, then rejected.
    lines += [
        f"-A {refuse} -p tcp -j REJECT --reject-with tcp-reset",
        f"-A {refuse} -j REJECT --reject-with icmp-port-unreachable",
    ]
    lines += [
        f"-A {egress_chain} -o lo -j ACCEPT",
        f"-A {egress_chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    for item in base.refuse:
        lines.append(_log(egress_chain, f"-d {_cidr(item)}", "refuse", "base:refused"))
        lines.append(f"-A {egress_chain} -d {_cidr(item)} -j {refuse}")
    for resolver in base.dns:
        for proto in ("udp", "tcp"):
            lines.append(f"-A {egress_chain} -d {_cidr(resolver)} -p {proto} --dport 53 -j ACCEPT")
    for allowance in base.allow:
        rule = f"base:{allowance.name}"
        for address in allowance.addresses:
            remember(address, allowance.host)
            for port in allowance.ports:
                match = f"-d {_cidr(address)} -p {allowance.protocol} --dport {port}"
                lines.append(_log(egress_chain, match, "allow", rule))
                lines.append(f"-A {egress_chain} {match} -j ACCEPT")
    for entry in rules.egress_entries():
        rule = f"spec:{entry.label}"
        port = f" --dport {entry.port}" if entry.port else ""
        if entry.kind == "any":
            # ``*`` refuses the non-public ranges on every protocol; ``*:port``
            # on its port only, so an entry for another port is left to decide.
            scope = f" -p tcp{port}" if entry.port else ""
            for network in (*NON_PUBLIC, *base.cluster_ranges):
                lines.append(_log(egress_chain, f"-d {network}{scope}", "refuse", f"{rule} non-public"))
                lines.append(f"-A {egress_chain} -d {network}{scope} -j {refuse}")
            lines.append(_log(egress_chain, f"-p tcp{port}", "allow", rule))
            lines.append(f"-A {egress_chain} -p tcp{port} -j ACCEPT")
            continue
        if entry.kind == "network":
            addresses = [entry.value]
        else:
            answers = sorted(set(resolved.get(entry.value) or []))
            if not answers:
                unresolved.append(entry.value)
                continue
            addresses = [a for a in answers if is_public_address(a, base.cluster_ranges)]
            dropped = [a for a in answers if a not in addresses]
            if dropped:
                non_public[entry.value] = sorted(set(non_public.get(entry.value, []) + dropped))
            if not addresses:
                if entry.value not in non_public_only:
                    non_public_only.append(entry.value)
                continue
        for address in addresses:
            if entry.kind == "host":
                remember(address, entry.value)
            match = f"-d {_cidr(address)} -p tcp{port}"
            lines.append(_log(egress_chain, match, "allow", rule))
            lines.append(f"-A {egress_chain} {match} -j ACCEPT")
    lines.append(_log(egress_chain, "", "refuse", "default"))
    lines.append(f"-A {egress_chain} -j {refuse}")
    if enforce_ingress:
        ingress_chain = INGRESS_CHAIN
        lines += [
            f"-A {ingress_chain} -i lo -j ACCEPT",
            f"-A {ingress_chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        ]
        for entry in rules.ingress_entries():
            rule = f"ingress:{entry.label}"
            port = f" -p tcp --dport {entry.port}" if entry.port else ""
            if entry.kind == "any":
                sources = ["0.0.0.0/0"]
            elif entry.kind == "platform":
                sources = list(base.platform_sources)
            else:
                sources = [entry.value]
            for source in sources:
                match = f"-s {_cidr(source)}{port}"
                lines.append(_log(ingress_chain, match, "allow", rule))
                lines.append(f"-A {ingress_chain} {match} -j ACCEPT")
        lines.append(_log(ingress_chain, "", "refuse", "ingress:default"))
        lines.append(f"-A {ingress_chain} -j {refuse}")
    lines.append("COMMIT")
    count = sum(1 for line in lines if line.startswith("-A "))
    return Compiled(
        script="\n".join(lines) + "\n",
        hosts=hosts,
        unresolved=unresolved,
        rules=count,
        non_public=non_public,
        non_public_only=non_public_only,
    )


__all__ = [
    "EGRESS_CHAIN",
    "INGRESS_CHAIN",
    "METADATA",
    "NFLOG_GROUP",
    "REFUSE_CHAIN",
    "BaseAllowance",
    "BaseLayer",
    "Compiled",
    "compile_rules",
    "prefix",
]
