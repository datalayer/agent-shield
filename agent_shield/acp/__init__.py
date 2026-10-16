# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""ACP: the client-side channels, the normaliser, the workspace and the proxy."""

from .channel import (
    SHIELD_CLIENT_CAPABILITIES,
    SHIELD_CLIENT_INFO,
    ACPChannel,
    ChannelRefused,
    ConnectionChannel,
    StdioACPChannel,
    WebSocketACPChannel,
    build_handler,
)
from .events import Event
from .normalize import MalformedUpdate, normalize
from .workspace import OutsideWorkspace, Terminals, Workspace

__all__ = [
    "SHIELD_CLIENT_CAPABILITIES",
    "SHIELD_CLIENT_INFO",
    "ACPChannel",
    "ChannelRefused",
    "ConnectionChannel",
    "Event",
    "MalformedUpdate",
    "OutsideWorkspace",
    "StdioACPChannel",
    "Terminals",
    "WebSocketACPChannel",
    "Workspace",
    "build_handler",
    "normalize",
]
