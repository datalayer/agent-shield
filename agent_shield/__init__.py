# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Datalayer Agent Shield: a runtime firewall for every agent.

The engine of the Shield: ``policy`` decides, ``acp`` runs
an ACP agent behind the Shield and answers its files and terminals against
the workspace, ``audit`` writes every action, ``register`` says which
harnesses are served and on what terms, ``cli`` is ``agent-shield``.
"""

from .__version__ import __version__

__all__ = ["__version__"]
