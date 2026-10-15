# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What agent-shield contributes to the Datalayer CLI, as a reactor plugin.

``datalayer agent-shield …`` and ``reactor agent-shield …`` are the same
Typer application ``agent-shield`` runs, added as a group. Advertised by
this distribution's entry points (``datalayer.cli`` and
``datalayer.reactor.cli``), so installing agent-shield beside the Datalayer
CLI is all it takes. This module imports nothing optional at import time:
the reactor is imported when the host asks for the plugin, and a host
without it gets a sentence.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from agent_shield.__version__ import __version__

if TYPE_CHECKING:  # pragma: no cover - typing only
    import typer

logger = logging.getLogger(__name__)

DESCRIPTION = (
    "Agent Shield for the Datalayer CLI: run any ACP agent behind the Shield, "
    "set it up, read the audit, show the policy in force."
)


class AgentShieldCliExtension:
    """The plugin: registers the `agent-shield` group into the host CLI."""

    def provide_cli(self, cli: typer.Typer) -> None:
        from agent_shield.cli import app

        cli.add_typer(app)


def manifest() -> Any:
    try:
        from reactor import PluginManifest
    except ImportError:
        raise ImportError(
            "the `datalayer agent-shield` group needs the reactor, which the Datalayer CLI brings; "
            "`agent-shield` itself runs without it"
        ) from None
    return PluginManifest(
        name="agent-shield",
        version=__version__,
        description=DESCRIPTION,
        author="Datalayer",
        tags=["cli", "agents", "shield", "acp"],
    )


def plugin() -> tuple[Any, AgentShieldCliExtension]:
    """What the `datalayer.cli` and `datalayer.reactor.cli` entry points resolve to."""
    return manifest(), AgentShieldCliExtension()


__all__ = ["DESCRIPTION", "AgentShieldCliExtension", "manifest", "plugin"]
