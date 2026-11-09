# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The policy document and the decision engine."""

from __future__ import annotations

import json
from pathlib import Path

from .authorize import (
    ALLOW_TTL,
    RELATIONS,
    ActionName,
    AllowCache,
    Authorization,
    AuthorizeHook,
    Authorizer,
    AuthorizerConfig,
    AuthorizerUnreachable,
    AuthZenAuthorizer,
    CedarAuthorizerConfig,
    EvaluationRequest,
    EvaluationResponse,
    Grant,
    LocalAuthorizer,
    OpaAuthorizer,
    OpenFgaAuthorizer,
    Resource,
    Subject,
    authorize,
    hook_for,
)
from .cedar import CedarAuthorizer, CedarCall, action_uid, call_from_request, cedar_decide
from .classify import (
    CLASS_STRICTNESS,
    DELETING_COMMANDS,
    FLAGGED_COMMANDS,
    KIND_CLASS,
    PAP_TOOL_CLASSES,
    SHIELD_KINDS,
    UnknownKind,
    class_of,
    command_class,
    deleting,
    flagged,
    pap_tool_class,
    strictest,
)
from .decide import LOCAL_SUBJECT, MODEL_KIND, Context, LimitState, decide, decide_budget, request_for, scopes_present
from .default import default_policy
from .dogwood import DogwoodRefused, DogwoodSet, parse_set, parse_temporal
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
    Dogwood,
    DogwoodMode,
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
from .temporal import Event, EventLog, TemporalAnswer, evaluate

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
    "ALLOW_TTL",
    "CLASS_STRICTNESS",
    "DELETING_COMMANDS",
    "FLAGGED_COMMANDS",
    "KIND_CLASS",
    "LIMIT_NAMES",
    "LIMIT_RELIEF",
    "LIMIT_WORDS",
    "LOCAL_SUBJECT",
    "MODEL_KIND",
    "MODEL_LIMITS",
    "PAP_TOOL_CLASSES",
    "RELATIONS",
    "SCHEMA_PATH",
    "SCOPES_STRICTEST_FIRST",
    "SHIELD_KINDS",
    "VERDICT_WORDS",
    "Action",
    "ActionClass",
    "ActionName",
    "AllowCache",
    "AuthZenAuthorizer",
    "Authorization",
    "AuthorizeHook",
    "Authorizer",
    "AuthorizerConfig",
    "AuthorizerUnreachable",
    "CedarAuthorizer",
    "CedarAuthorizerConfig",
    "CedarCall",
    "Context",
    "Credentials",
    "Decision",
    "Dogwood",
    "DogwoodMode",
    "DogwoodRefused",
    "DogwoodSet",
    "EvaluationRequest",
    "EvaluationResponse",
    "Event",
    "EventLog",
    "Grant",
    "Harnesses",
    "LimitState",
    "Limits",
    "LoadedPolicy",
    "LocalAuthorizer",
    "Mcp",
    "Network",
    "OpaAuthorizer",
    "OpenFgaAuthorizer",
    "Policy",
    "PolicyRefused",
    "PolicyWidens",
    "Resource",
    "Rule",
    "Scope",
    "Subject",
    "TemporalAnswer",
    "Threshold",
    "UnknownKind",
    "Verdict",
    "action_uid",
    "admits",
    "authorize",
    "call_from_request",
    "cedar_decide",
    "check_tightens",
    "class_of",
    "command_class",
    "credentials_rule",
    "decide",
    "decide_budget",
    "default_policy",
    "deleting",
    "dump_policy",
    "evaluate",
    "flagged",
    "hook_for",
    "load_policies",
    "overlaps",
    "pap_tool_class",
    "parse_policies",
    "parse_policy",
    "parse_set",
    "parse_temporal",
    "policy_json_schema",
    "policy_json_schema_text",
    "request_for",
    "scopes_present",
    "strictest",
    "widening",
]
