# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The firewall's controller: apply base + spec, keep it current, record every connection.

It runs where ``NET_ADMIN`` is held in the agent's network namespace — on
Datalayer, the ``shield-firewall`` sidecar of the runtime pod — and nowhere
else does anything change the rules:

* :meth:`Controller.apply` resolves the spec's hosts (a host that resolves to
  nothing is refused and said), compiles base + spec, applies the script with
  ``iptables-restore --noflush`` in one commit, hooks the chains from
  ``OUTPUT`` (and ``INPUT`` when ingress is enforced) once, keeps the address →
  host map the record names destinations by, and writes a ``firewall`` row;
* :meth:`Controller.refresh` resolves again and re-applies only when an answer
  changed;
* :class:`ConnectionRecorder` turns each logged connection into a
  ``connection`` row — allow or refuse, the rule, the destination and its
  host — folding repeats of the same decision, destination and rule within a
  window into the next row's ``repeated`` count.
"""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_shield.audit import AuditLog
from agent_shield.firewall.compile import EGRESS_CHAIN, INGRESS_CHAIN, BaseLayer, Compiled, compile_rules
from agent_shield.firewall.model import FirewallRules
from agent_shield.firewall.nflog import Connection

logger = logging.getLogger(__name__)

#: A command's runner: the argv and its stdin, returning (exit code, output).
Runner = Callable[[Sequence[str], str], tuple[int, str]]
#: How long the same connection is folded into one row.
FOLD_SECONDS = 60.0


def run_command(argv: Sequence[str], stdin: str = "") -> tuple[int, str]:
    done = subprocess.run(list(argv), input=stdin, capture_output=True, text=True, check=False)  # noqa: S603
    return done.returncode, (done.stdout + done.stderr).strip()


def lookup(host: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return []
    return sorted({str(item[4][0]) for item in answers})


class FirewallRefused(RuntimeError):
    """The kernel did not take the rules: said with what ``iptables`` said."""


@dataclass
class Applied:
    """What the last apply wrote."""

    rules: FirewallRules
    resolved: dict[str, list[str]]
    compiled: Compiled
    at: float = field(default_factory=time.time)
    #: The revision the rules file named, echoed in ``applied.json`` for whoever waits on it.
    revision: str | None = None


class Controller:
    """Applies and keeps the rules; the only writer of the firewall's chains."""

    def __init__(
        self,
        base: BaseLayer,
        *,
        audit: AuditLog | None = None,
        runner: Runner | None = None,
        resolver: Callable[[str], list[str]] = lookup,
        enforce_ingress: bool = False,
        state_dir: Path | None = None,
        iptables: str = "iptables",
    ) -> None:
        self.base = base
        self.audit = audit
        self.runner = runner or run_command
        self.resolver = resolver
        self.enforce_ingress = enforce_ingress
        self.state_dir = state_dir
        self.iptables = iptables
        self.applied: Applied | None = None

    def _resolve(self, rules: FirewallRules) -> dict[str, list[str]]:
        return {entry.value: self.resolver(entry.value) for entry in rules.egress_entries() if entry.kind == "host"}

    def _hook(self, parent: str, chain: str) -> None:
        code, _ = self.runner([self.iptables, "-C", parent, "-j", chain], "")
        if code != 0:
            code, said = self.runner([self.iptables, "-I", parent, "1", "-j", chain], "")
            if code != 0:
                raise FirewallRefused(f"{parent} could not be hooked to {chain}: {said}")

    def apply(
        self, rules: FirewallRules | None = None, *, reason: str = "apply", revision: str | None = None
    ) -> Applied:
        """Apply base + ``rules`` atomically; the previous rules stay if the kernel refuses."""
        rules = rules or FirewallRules()
        resolved = self._resolve(rules)
        compiled = compile_rules(self.base, rules, resolved=resolved, enforce_ingress=self.enforce_ingress)
        code, said = self.runner([f"{self.iptables}-restore", "--noflush"], compiled.script)
        if code != 0:
            raise FirewallRefused(f"iptables-restore refused the rules: {said}")
        self._hook("OUTPUT", EGRESS_CHAIN)
        if self.enforce_ingress:
            self._hook("INPUT", INGRESS_CHAIN)
        for host in compiled.unresolved:
            logger.warning("firewall: %s resolves to nothing; it is refused", host)
        self.applied = Applied(rules, resolved, compiled, revision=revision)
        if self.state_dir is not None:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            (self.state_dir / "applied.json").write_text(json.dumps(self.state(), indent=2), encoding="utf-8")
        if self.audit is not None:
            self.audit.write(
                "firewall",
                by="shield",
                reason=reason,
                revision=revision,
                egress=list(rules.egress),
                ingress=list(rules.ingress) if self.enforce_ingress else None,
                base=[a.name for a in self.base.allow],
                rules=compiled.rules,
                unresolved=compiled.unresolved or None,
            )
        return self.applied

    def refresh(self) -> bool:
        """Resolve the spec's hosts again; re-apply and say so only when an answer changed."""
        if self.applied is None:
            return False
        resolved = self._resolve(self.applied.rules)
        if resolved == self.applied.resolved:
            return False
        self.apply(self.applied.rules, reason="refresh", revision=self.applied.revision)
        return True

    def state(self) -> dict[str, Any]:
        if self.applied is None:
            return {"applied": False}
        return {
            "applied": True,
            "at": self.applied.at,
            "revision": self.applied.revision,
            "egress": list(self.applied.rules.egress),
            "ingress": list(self.applied.rules.ingress),
            "enforce_ingress": self.enforce_ingress,
            "resolved": self.applied.resolved,
            "unresolved": self.applied.compiled.unresolved,
            "rules": self.applied.compiled.rules,
        }

    def host_of(self, address: str) -> str | None:
        if self.applied is None:
            return None
        names = self.applied.compiled.hosts.get(address)
        return ", ".join(names) if names else None


class ConnectionRecorder:
    """Each logged connection as a ``connection`` row; repeats within a window folded."""

    def __init__(
        self,
        audit: AuditLog,
        *,
        host_of: Callable[[str], str | None] = lambda address: None,
        window: float = FOLD_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.audit = audit
        self.host_of = host_of
        self.window = window
        self.clock = clock
        self._last: dict[tuple[str, str, str, str], tuple[float, int]] = {}

    def record(self, connection: Connection) -> dict[str, Any] | None:
        """The row written, or None when the connection was folded into a later one."""
        key = (connection.decision, connection.rule, connection.protocol, connection.target)
        now = self.clock()
        seen = self._last.get(key)
        if seen is not None and now - seen[0] < self.window:
            self._last[key] = (seen[0], seen[1] + 1)
            return None
        repeated = seen[1] if seen is not None else 0
        self._last[key] = (now, 0)
        return self.audit.write(
            "connection",
            by="shield",
            # The Shield's vocabulary: a refused connection is a deny, counted with the refusals.
            decision="allow" if connection.decision == "allow" else "deny",
            rule=connection.rule,
            protocol=connection.protocol,
            destination=connection.target,
            host=self.host_of(connection.destination),
            source=connection.source,
            repeated=repeated or None,
        )


__all__ = [
    "FOLD_SECONDS",
    "Applied",
    "ConnectionRecorder",
    "Controller",
    "FirewallRefused",
    "lookup",
    "run_command",
]
