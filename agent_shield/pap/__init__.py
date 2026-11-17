# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP through the Shield: the company role, standing in front of any agent, on PAP draft 0.4.

The personal-agent role is not here: a harness is **lent** the gateway's
``pap`` tools through the lent MCP (agent-runtimes), and the
standalone proxy has it once registered (:mod:`agent_shield.registration`).
"""

from __future__ import annotations

from .company import (
    ANSWER_SEND,
    OPERATION_BUY,
    OPERATION_WRITE,
    CompanyShield,
    ReviewRefused,
    ReviewTicket,
    Settle,
    ShieldCompanyPlugin,
    ShieldedCompanyAgent,
    ShieldedOperationExecutor,
    Signer,
    canonical,
    money_moves,
    operation_class,
)

__all__ = [
    "ANSWER_SEND",
    "OPERATION_BUY",
    "OPERATION_WRITE",
    "CompanyShield",
    "ReviewRefused",
    "ReviewTicket",
    "Settle",
    "ShieldCompanyPlugin",
    "ShieldedCompanyAgent",
    "ShieldedOperationExecutor",
    "Signer",
    "canonical",
    "money_moves",
    "operation_class",
]
