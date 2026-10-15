# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""ACP kinds to classes, and the commands the default policy asks about.

SHIELD §4.5: ``read``, ``search``, ``fetch`` → **read**; ``edit``, ``move`` →
**write**; ``delete`` → **delete**; ``execute`` → **execute**; ``think`` and
``switch_mode`` → none (nothing to decide); ``other`` → **write**, because a
kind the agent could not name fails closed.

The command patterns are the one source the default policy's rules are built
from (``default.py``), so the classifier and the policy cannot drift.
"""

from __future__ import annotations

import re

from .model import ActionClass

#: ACP ``ToolKind`` → F-10 class; ``None`` means nothing to decide.
KIND_CLASS: dict[str, ActionClass | None] = {
    "read": "read",
    "search": "read",
    "fetch": "read",
    "edit": "write",
    "move": "write",
    "delete": "delete",
    "execute": "execute",
    "think": None,
    "switch_mode": None,
    "other": "write",
}

#: The Shield's own kinds for what it answers itself (SHIELD §4.6).
SHIELD_KINDS: dict[str, ActionClass] = {
    "fs_read": "read",
    "fs_write": "write",
    "terminal": "execute",
}


class UnknownKind(ValueError):
    """A tool kind the protocol does not name: the turn ends with this sentence."""


def class_of(kind: str) -> ActionClass | None:
    """The class of an ACP kind or a Shield kind, or ``None`` when nothing is to decide."""
    if kind in KIND_CLASS:
        return KIND_CLASS[kind]
    if kind in SHIELD_KINDS:
        return SHIELD_KINDS[kind]
    raise UnknownKind(f"'{kind}' is not a tool kind ACP names, so it cannot be classed")


#: The commands that ask first whatever the execute rule says (decision 5),
#: each a name the sentence uses and a regular expression on the command line.
FLAGGED_COMMANDS: dict[str, str] = {
    "a command naming a credential": (
        r"(?i)(api[_-]?key|secret|token|password|passwd|credential|\.env\b|id_(rsa|ed25519)|"
        r"\.ssh/|\.aws/|\.netrc|\.datalayer/|datalayerrc)"
    ),
    "sudo": r"(?:^|[\s;&|(])(?:sudo|doas|su)\b",
    "a package install from the network": (
        r"\b(?:pip3?|pipx|uv|npm|pnpm|yarn|bun|apt(?:-get)?|brew|cargo|gem|conda|mamba|go)"
        r"(?:\s+pip)?\s+(?:install|add|i|get)\b"
    ),
    "git push": r"\bgit\b[^;&|]*\bpush\b",
}

_COMPILED = {name: re.compile(pattern) for name, pattern in FLAGGED_COMMANDS.items()}


def flagged(command: str) -> str | None:
    """The name of the first flag a command line raises, or ``None``."""
    for name, pattern in _COMPILED.items():
        if pattern.search(command):
            return name
    return None


__all__ = ["FLAGGED_COMMANDS", "KIND_CLASS", "SHIELD_KINDS", "UnknownKind", "class_of", "flagged"]
