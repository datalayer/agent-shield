# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Where the Shield keeps its things: ``~/.agent-shield`` (or ``$AGENT_SHIELD_HOME``).

``config.yaml`` says what ``setup`` found and chose; ``harnesses/<id>@<version>``
holds each adapter installed with ``npm install --prefix`` — never a global
``npx``; ``agent-shield.yaml`` is the home policy a project without its own
falls back to; ``audit.jsonl`` is the audit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

POLICY_FILE = "agent-shield.yaml"
CONFIG_FILE = "config.yaml"
AUDIT_FILE = "audit.jsonl"


def home() -> Path:
    return Path(os.environ.get("AGENT_SHIELD_HOME", str(Path.home() / ".agent-shield")))


def harness_prefix(harness_id: str, version: str, base: Path | None = None) -> Path:
    return (base or home()) / "harnesses" / f"{harness_id}@{version}"


def harness_bin(prefix: Path, executable: str) -> Path:
    return prefix / "node_modules" / ".bin" / executable


@dataclass
class Config:
    """``config.yaml``, as a mapping the commands read and write."""

    path: Path
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, base: Path | None = None) -> Config:
        path = (base or home()) / CONFIG_FILE
        data: dict[str, Any] = {}
        if path.is_file():
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError(f"{path}: the config is a mapping")
            data = loaded
        return cls(path=path, data=data)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(yaml.safe_dump(self.data, sort_keys=False), encoding="utf-8")

    @property
    def harnesses(self) -> dict[str, dict[str, Any]]:
        return self.data.setdefault("harnesses", {})

    def installed(self, harness_id: str) -> dict[str, Any] | None:
        return self.harnesses.get(harness_id)


def find_policy_file(workspace: Path, base: Path | None = None) -> Path | None:
    """The project's policy, else the home one, else none."""
    project = workspace / POLICY_FILE
    if project.is_file():
        return project
    fallback = (base or home()) / POLICY_FILE
    if fallback.is_file():
        return fallback
    return None


__all__ = [
    "AUDIT_FILE",
    "CONFIG_FILE",
    "POLICY_FILE",
    "Config",
    "find_policy_file",
    "harness_bin",
    "harness_prefix",
    "home",
]
