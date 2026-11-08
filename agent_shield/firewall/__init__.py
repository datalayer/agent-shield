# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The firewall: an agent's ``policy.shield`` enforced in its pod and every connection recorded.

The Shield decides a connection the way it decides an action: the rules
(:mod:`.model`), compiled with the platform's base layer (:mod:`.compile`),
applied and kept by one controller (:mod:`.controller`), and every allowed and
refused connection read back from the kernel's log (:mod:`.nflog`) into the
audit. ``agent-shield firewall`` is the command.
"""

from agent_shield.firewall.compile import (
    EGRESS_CHAIN,
    INGRESS_CHAIN,
    NFLOG_GROUP,
    REFUSE_CHAIN,
    BaseAllowance,
    BaseLayer,
    Compiled,
    compile_rules,
)
from agent_shield.firewall.controller import Applied, ConnectionRecorder, Controller, FirewallRefused
from agent_shield.firewall.model import (
    ANY,
    PLATFORM,
    Entry,
    FirewallError,
    FirewallRules,
    firewall_json_schema,
    parse_entry,
    rules_of_spec,
)
from agent_shield.firewall.nflog import Connection

__all__ = [
    "ANY",
    "EGRESS_CHAIN",
    "INGRESS_CHAIN",
    "NFLOG_GROUP",
    "PLATFORM",
    "REFUSE_CHAIN",
    "Applied",
    "BaseAllowance",
    "BaseLayer",
    "Compiled",
    "Connection",
    "ConnectionRecorder",
    "Controller",
    "Entry",
    "FirewallError",
    "FirewallRefused",
    "FirewallRules",
    "compile_rules",
    "firewall_json_schema",
    "parse_entry",
    "rules_of_spec",
]
