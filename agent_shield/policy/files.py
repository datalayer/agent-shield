# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Policy documents on disk: ``agent-shield.yaml``.

A file holds one document (a mapping) or several under ``policies:``, one per
scope. Anything else, a key the schema does not know, or two documents of one
scope is refused in a sentence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .model import SCOPES_STRICTEST_FIRST, Policy


class PolicyRefused(ValueError):
    """A policy file that cannot be read, said in a sentence."""


@dataclass(frozen=True)
class LoadedPolicy:
    """A document and where it came from, for ``policy show`` and the audit."""

    policy: Policy
    origin: str


def _sentence(exc: ValidationError, origin: str) -> str:
    first = exc.errors()[0]
    where = ".".join(str(part) for part in first["loc"]) or "the document"
    return f"{origin}: {where}: {first['msg']}"


def parse_policy(data: Any, origin: str) -> Policy:
    """One document from parsed YAML or JSON."""
    if not isinstance(data, dict):
        raise PolicyRefused(f"{origin}: a policy is a mapping with a scope, not {type(data).__name__}")
    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyRefused(_sentence(exc, origin)) from None


def parse_policies(data: Any, origin: str) -> list[LoadedPolicy]:
    """Every document of a file, strictest scope first."""
    if isinstance(data, dict) and "policies" in data:
        if set(data) != {"policies"}:
            raise PolicyRefused(f"{origin}: a file with 'policies' holds nothing else")
        documents = data["policies"]
        if not isinstance(documents, list) or not documents:
            raise PolicyRefused(f"{origin}: 'policies' is a non-empty list of documents")
    else:
        documents = [data]
    loaded = [LoadedPolicy(parse_policy(document, origin), origin) for document in documents]
    seen: set[str] = set()
    for item in loaded:
        if item.policy.scope in seen:
            raise PolicyRefused(f"{origin}: two documents of the {item.policy.scope} scope; one per scope")
        seen.add(item.policy.scope)
    return sorted(loaded, key=lambda item: SCOPES_STRICTEST_FIRST.index(item.policy.scope))


def load_policies(path: Path) -> list[LoadedPolicy]:
    """Read a policy file; a missing file is a refusal naming it."""
    if not path.is_file():
        raise PolicyRefused(f"{path}: no policy file; `agent-shield setup` writes the default one")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyRefused(f"{path}: not YAML: {exc}") from None
    if data is None:
        raise PolicyRefused(f"{path}: the file is empty")
    return parse_policies(data, str(path))


def dump_policy(policy: Policy) -> str:
    """The document as YAML, as ``setup`` writes it."""
    data = json.loads(policy.model_dump_json(exclude_none=True, exclude_defaults=True))
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


__all__ = ["LoadedPolicy", "PolicyRefused", "dump_policy", "load_policies", "parse_policies", "parse_policy"]
