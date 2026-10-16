# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The default policy of as a session document.

Read and search inside the workspace — do it; edit and move inside it — do
it, shown as diffs; delete, execute, and any path outside the workspace —
ask me first; a command naming a credential, ``sudo``, a package install from
the network, or ``git push`` — ask me first with the command shown; fetch —
through the allow-list, which is empty, so refused; send and buy — ask me
first. The limits: 100 then 200 tool calls, 4 then 8 terminals, 5 then 20
MiB written.
"""

from __future__ import annotations

from .classify import FLAGGED_COMMANDS
from .model import Limits, Mcp, Network, Policy, Rule, Threshold

MIB = 1024 * 1024


def default_policy() -> Policy:
    """The document ``agent-shield setup`` writes beside a project."""
    flagged = [
        Rule(name=name, decision="ask", classes=["execute"], commands=[pattern], reason="the command is shown")
        for name, pattern in FLAGGED_COMMANDS.items()
    ]
    return Policy(
        scope="session",
        rules=[
            Rule(name="read inside the workspace", decision="allow", classes=["read"], where="inside"),
            Rule(
                name="edit and move inside the workspace",
                decision="allow",
                classes=["write"],
                where="inside",
                reason="shown as diffs",
            ),
            Rule(name="delete", decision="ask", classes=["delete"]),
            *flagged,
            Rule(name="run a command", decision="ask", classes=["execute"]),
            Rule(name="outside the workspace", decision="ask", where="outside"),
            Rule(name="send or buy", decision="ask", classes=["send", "buy"]),
        ],
        limits=Limits(
            tool_calls=Threshold(soft=100, hard=200),
            terminals_open=Threshold(soft=4, hard=8),
            bytes_written=Threshold(soft=5 * MIB, hard=20 * MIB),
        ),
        network=Network(fetch=[]),
        mcp=Mcp(allow=[]),
    )


__all__ = ["MIB", "default_policy"]
