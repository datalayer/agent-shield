# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The policy document and the decision engine (SHIELD §5.1, §6.2, §6.3)."""

from __future__ import annotations

import json
from pathlib import Path

from .classify import FLAGGED_COMMANDS, KIND_CLASS, SHIELD_KINDS, UnknownKind, class_of, flagged
from .decide import MODEL_KIND, Context, LimitState, decide, decide_budget, scopes_present
from .default import default_policy
from .files import LoadedPolicy, PolicyRefused, dump_policy, load_policies, parse_policies, parse_policy
from .levels import PolicyWidens, admits, check_tightens, credentials_rule, overlaps, widening
from .model import (
    ACTION_CLASSES,
    LIMIT_NAMES,
    LIMIT_RELIEF,
    LIMIT_WORDS,
    MODEL_LIMITS,
    SCOPES_STRICTEST_FIRST,
    VERDICT_WORDS,
    Action,
    ActionClass,
    Credentials,
    Decision,
    Harnesses,
    Limits,
    Mcp,
    Network,
    Policy,
    Rule,
    Scope,
    Threshold,
    Verdict,
)

#: Where the published schema lives in the repository (``schema/policy.schema.json``).
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schema" / "policy.schema.json"


def policy_json_schema() -> dict:
    """The document's JSON Schema, the one agentspecs carries as ``policies/``."""
    schema = Policy.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://agent-shield.datalayer.tech/schema/policy.schema.json"
    schema["title"] = "Agent Shield policy"
    return schema


def policy_json_schema_text() -> str:
    return json.dumps(policy_json_schema(), indent=2, sort_keys=True) + "\n"


__all__ = [
    "ACTION_CLASSES",
    "FLAGGED_COMMANDS",
    "KIND_CLASS",
    "LIMIT_NAMES",
    "LIMIT_RELIEF",
    "LIMIT_WORDS",
    "MODEL_KIND",
    "MODEL_LIMITS",
    "SCHEMA_PATH",
    "SCOPES_STRICTEST_FIRST",
    "SHIELD_KINDS",
    "VERDICT_WORDS",
    "Action",
    "ActionClass",
    "Context",
    "Credentials",
    "Decision",
    "Harnesses",
    "LimitState",
    "Limits",
    "LoadedPolicy",
    "Mcp",
    "Network",
    "Policy",
    "PolicyRefused",
    "PolicyWidens",
    "Rule",
    "Scope",
    "Threshold",
    "UnknownKind",
    "Verdict",
    "admits",
    "check_tightens",
    "class_of",
    "credentials_rule",
    "decide",
    "decide_budget",
    "default_policy",
    "dump_policy",
    "flagged",
    "load_policies",
    "overlaps",
    "parse_policies",
    "parse_policy",
    "policy_json_schema",
    "policy_json_schema_text",
    "scopes_present",
    "widening",
]
