# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""``agent-shield connect <url>``: a remote Shield (``serve``) as a local stdio agent (SHIELD SH-56).

Any ACP client that only knows how to start a command — an editor, a
notebook, the TCK — reaches a Shield served elsewhere through this: one
WebSocket, one JSON-RPC message per text frame, the token in the
``Authorization`` header (never in the address), stdin's lines sent as frames
and frames written as lines. Nothing is decided here: the Shield at the
other end decides.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


class RemoteRefused(RuntimeError):
    """A remote the mirror will not connect to, said in a sentence."""


#: The query parameters a token must never travel in (the server refuses them too).
ADDRESS_TOKENS = ("token", "access_token", "bearer", "api_key", "apikey")


def remote_url(url: str) -> str:
    """The URL checked: ``ws``/``wss``, no token in it."""
    parts = urlsplit(url)
    if parts.scheme not in ("ws", "wss"):
        raise RemoteRefused(f"a Shield is reached over ws:// or wss://, not {parts.scheme or 'nothing'}://")
    keys = {pair.partition("=")[0].lower() for pair in parts.query.split("&") if pair}
    if keys & set(ADDRESS_TOKENS) or parts.username or parts.password:
        raise RemoteRefused("the token travels in the Authorization header, never in the address")
    return url


async def _inbound(socket: Any, out: Any) -> None:
    async for frame in socket:
        data = frame if isinstance(frame, bytes) else frame.encode("utf-8")
        out.write(data.rstrip(b"\n") + b"\n")
        out.flush()


async def _outbound(stdin: asyncio.StreamReader, socket: Any) -> None:
    while True:
        line = await stdin.readline()
        if not line:
            return
        if line.strip():
            await socket.send(line.decode("utf-8").rstrip("\n"))


async def mirror_stdio(url: str, *, token: str | None = None, headers: Mapping[str, str] | None = None) -> int:
    """Relay this process's stdio to the Shield at ``url`` until either side ends; the exit status."""
    try:
        from websockets.asyncio.client import connect
    except ImportError:  # pragma: no cover - the extra says so
        raise RemoteRefused("`agent-shield connect` needs `datalayer-agent-shield[websocket]`") from None
    extra = dict(headers or {})
    if token:
        extra["Authorization"] = f"Bearer {token}"
    loop = asyncio.get_running_loop()
    stdin = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(stdin), sys.stdin.buffer)
    out = sys.stdout.buffer
    async with connect(remote_url(url), additional_headers=extra, max_size=None) as socket:
        tasks = [asyncio.create_task(_inbound(socket, out)), asyncio.create_task(_outbound(stdin, socket))]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            if task.exception() is not None:
                return 1
    return 0


__all__ = ["ADDRESS_TOKENS", "RemoteRefused", "mirror_stdio", "remote_url"]
