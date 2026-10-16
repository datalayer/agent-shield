# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The audit: every action and decision, one JSON line each, nothing secret.

The vocabulary is A-01's safe one, extended with ACP's kinds: a row says the
event, the kind and class, the decision and who decided it, a path or a
command, a diff's hash and size — never a file's content, never a credential.
Every string of a row goes through :func:`redact` before it is written; the
Shield's own environment values whose names look like secrets are redacted
by value as well, so a key the agent echoes never lands in the log.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_shield.tracing import observe

#: The events a row may carry.
EVENTS = (
    "session",
    "turn",
    "tool_call",
    "permission",
    "fs_read",
    "fs_write",
    "terminal",
    "fetch",
    "limit",
    "mcp",
    "refusal",
    # The policies themselves: replaced from IAM, unavailable, a session rule added or removed.
    "policy",
    # The agent's plan: how many steps, their status; never their text.
    "plan",
    # PAP's vocabulary, the company role (SH-71): an operation performed
    # for a person, signed; a review held for a person of the company, released or refused.
    "operation",
    "review",
)

#: Who decided: the policy, a person asked, the agent itself (a notification), or the Shield.
DECIDERS = ("policy", "person", "agent", "shield")

REDACTED = "[redacted]"

#: A credential's prefix starts a token, never the middle of an identifier: a
#: random id such as a PAP operation's (``…-sk-…``) is not a key, and redacting
#: it lost the operation from the record now and then.
_START = r"(?<![A-Za-z0-9_\-])"

_PATTERNS = [
    re.compile(_START + r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(_START + r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(_START + r"AKIA[0-9A-Z]{16}\b"),
    re.compile(_START + r"gh[pousr]_[A-Za-z0-9]{16,}\b"),
    re.compile(_START + r"xox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(_START + r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9_\-\.=]{8,}"),
    re.compile(
        r"(?i)((?:api[_-]?key|secret|token|password|passwd|credential)[A-Za-z0-9_]*\s*[=:]\s*[\"']?)([^\s\"']{4,})"
    ),
]
_SECRET_NAME = re.compile(r"(?i)(key|token|secret|password|passwd|credential)")


def _environment_values() -> list[str]:
    return [value for name, value in os.environ.items() if _SECRET_NAME.search(name) and len(value) >= 8]


def redact(text: str, *, environment: Mapping[str, str] | None = None) -> str:
    """The text with every credential-looking span replaced by ``[redacted]``."""
    values = (
        [value for name, value in environment.items() if _SECRET_NAME.search(name) and len(value) >= 8]
        if environment is not None
        else _environment_values()
    )
    for value in sorted(values, key=len, reverse=True):
        text = text.replace(value, REDACTED)
    for pattern in _PATTERNS:
        if pattern.groups == 2:
            text = pattern.sub(lambda m: m.group(1) + REDACTED, text)
        elif pattern.groups == 1:
            text = pattern.sub(lambda m: m.group(1) + REDACTED, text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


def redacted_row(row: Mapping[str, Any], *, environment: Mapping[str, str] | None = None) -> dict[str, Any]:
    """A row with every string of it redacted, however deep: what any audit writes, whoever keeps it."""
    return dict(_redacted(dict(row), environment))


def _redacted(value: Any, environment: Mapping[str, str] | None) -> Any:
    if isinstance(value, str):
        return redact(value, environment=environment)
    if isinstance(value, Mapping):
        return {str(k): _redacted(v, environment) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redacted(v, environment) for v in value]
    return value


def diff_summary(path: str, new_text: str, old_text: str | None = None) -> dict[str, Any]:
    """A diff as the audit keeps it: its path, hash and size, never its text."""
    data = new_text.encode("utf-8")
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "old_bytes": len(old_text.encode("utf-8")) if old_text is not None else None,
    }


def default_audit_path() -> Path:
    return Path(os.environ.get("AGENT_SHIELD_HOME", str(Path.home() / ".agent-shield"))) / "audit.jsonl"


class AuditLog:
    """Rows appended to a JSON Lines file."""

    def __init__(self, path: Path | None = None, *, environment: Mapping[str, str] | None = None) -> None:
        self.path = path or default_audit_path()
        self._environment = environment
        self.rows_written = 0

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        if event not in EVENTS:
            raise ValueError(f"{event!r} is not an audit event; one of {', '.join(EVENTS)}")
        by = fields.get("by")
        if by is not None and by not in DECIDERS:
            raise ValueError(f"{by!r} is not a decider; one of {', '.join(DECIDERS)}")
        row = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "event": event}
        row.update({k: v for k, v in fields.items() if v is not None})
        row = _redacted(row, self._environment)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n")
        self.rows_written += 1
        # The same row, after the same redaction, to the trace and the counts.
        observe(row)
        return row

    def rows(self, *, last: int | None = None) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if last is not None:
            lines = lines[-last:]
        return [json.loads(line) for line in lines if line.strip()]


__all__ = ["DECIDERS", "EVENTS", "REDACTED", "AuditLog", "default_audit_path", "diff_summary", "redact", "redacted_row"]
