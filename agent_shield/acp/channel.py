# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The client-side ``ACPChannel``: stdio and WebSocket, on the official SDK.

One channel is one connection to one ACP agent. It speaks the typed verbs a
client has — ``initialize``, ``session/new|load|prompt|cancel|set_mode`` —
and the raw ones an orchestrator wants (``request``, ``notify``, ``listen``,
``close``), and it dispatches what the agent asks of the client
(``session/update``, ``session/request_permission``, ``fs/*``, ``terminal/*``,
``elicitation/create``) to one **handler**: any object with the SDK
:class:`acp.Client`'s methods, plus ``elicitation(session_id, params)`` for the
one method the SDK's router does not know.

The stdio channel launches the agent as a subprocess of the Shield and ends
it cleanly (stdin closed, then a wait, then terminate, then kill). The
WebSocket channel connects to an agent served at a URL — agent-runtimes'
ACP route, or ``agent-shield serve`` once built — with the same interface.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from acp import PROTOCOL_VERSION
from acp.client.router import build_client_router
from acp.connection import Connection, StreamDirection, StreamEvent
from acp.exceptions import RequestError
from acp.meta import AGENT_METHODS, CLIENT_METHODS
from acp.schema import (
    AgentCapabilities,
    ClientCapabilities,
    FileSystemCapability,
    Implementation,
    InitializeRequest,
    InitializeResponse,
    LoadSessionRequest,
    LoadSessionResponse,
    NewSessionRequest,
    NewSessionResponse,
    PromptRequest,
    PromptResponse,
    SetSessionModeRequest,
    SetSessionModeResponse,
)
from acp.schema import (
    Implementation as _Implementation,
)
from acp.transports import spawn_stdio_transport
from acp.utils import request_model, request_model_from_dict, serialize_params

from agent_shield.__version__ import __version__

logger = logging.getLogger(__name__)

#: The one extra client method the SDK's router does not route.
ELICITATION_CREATE = "elicitation/create"

#: What the Shield tells an agent it can do: files and terminals, answered by the Shield.
SHIELD_CLIENT_CAPABILITIES = ClientCapabilities(
    fs=FileSystemCapability(read_text_file=True, write_text_file=True), terminal=True
)
SHIELD_CLIENT_INFO = Implementation(name="agent-shield", title="Agent Shield", version=__version__)

RawListener = Callable[[dict[str, Any]], None]
#: A channel's connection is wired right after construction by ``launch`` / ``connect``.
_UNBUILT = None


class ChannelRefused(RuntimeError):
    """A connection the Shield will not keep, said in a sentence."""


def build_handler(
    handler: Any, handled: Callable[[dict[str, Any]], None] | None = None
) -> Callable[[str, Any, bool], Awaitable[Any]]:
    """The SDK's client router, with ``elicitation/create`` dispatched to ``handler.elicitation``.

    ``handled`` is told each ``session/update`` once the handler is done with it.
    """
    router = build_client_router(handler)

    async def route(method: str, params: Any, is_notification: bool) -> Any:
        if method == CLIENT_METHODS["session_update"] and is_notification and handled is not None:
            try:
                return await router(method, params, is_notification)
            finally:
                handled(params if isinstance(params, dict) else {})
        if method == ELICITATION_CREATE and not is_notification:
            elicitation = getattr(handler, "elicitation", None)
            if elicitation is None:
                raise RequestError.method_not_found(method)
            payload = params if isinstance(params, dict) else {}
            session_id = payload.get("sessionId")
            if not isinstance(session_id, str):
                raise RequestError.invalid_params({"details": "elicitation/create names no sessionId"})
            return await elicitation(session_id, payload)
        return await router(method, params, is_notification)

    return route


class ACPChannel(ABC):
    """One ACP connection, client side (see the module)."""

    @abstractmethod
    async def request(self, method: str, params: Mapping[str, Any] | None = None) -> Any:
        """Send a request and wait for its result."""

    @abstractmethod
    async def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        """Send a notification."""

    @abstractmethod
    def listen(self, listener: RawListener) -> Callable[[], None]:
        """Hear every raw message both ways; returns the way to stop."""

    @abstractmethod
    async def close(self) -> None:
        """End the connection and, for stdio, the agent's process."""

    @property
    @abstractmethod
    def initialized(self) -> InitializeResponse | None:
        """What the agent answered to ``initialize``, once it did."""

    @property
    def agent_capabilities(self) -> AgentCapabilities | None:
        answer = self.initialized
        return answer.agent_capabilities if answer else None

    @property
    def agent_info(self) -> _Implementation | None:
        answer = self.initialized
        return answer.agent_info if answer else None

    async def initialize(
        self,
        *,
        client_capabilities: ClientCapabilities = SHIELD_CLIENT_CAPABILITIES,
        client_info: Implementation = SHIELD_CLIENT_INFO,
        meta: Mapping[str, Any] | None = None,
    ) -> InitializeResponse:
        """``initialize`` with protocol version 1; an agent answering another version is refused."""
        answer = await self._request_model(
            AGENT_METHODS["initialize"],
            InitializeRequest(
                protocol_version=PROTOCOL_VERSION,
                client_capabilities=client_capabilities,
                client_info=client_info,
                field_meta=dict(meta) if meta else None,
            ),
            InitializeResponse,
        )
        if answer.protocol_version != PROTOCOL_VERSION:
            await self.close()
            raise ChannelRefused(
                f"the agent answers protocol version {answer.protocol_version}; the Shield speaks {PROTOCOL_VERSION}"
            )
        self._set_initialized(answer)
        return answer

    async def new_session(
        self, cwd: str | Path, mcp_servers: Sequence[Any] = (), *, meta: Mapping[str, Any] | None = None
    ) -> NewSessionResponse:
        return await self._request_model(
            AGENT_METHODS["session_new"],
            NewSessionRequest(cwd=str(cwd), mcp_servers=list(mcp_servers), field_meta=dict(meta) if meta else None),
            NewSessionResponse,
        )

    async def load_session(
        self, session_id: str, cwd: str | Path, mcp_servers: Sequence[Any] = ()
    ) -> LoadSessionResponse:
        capabilities = self.agent_capabilities
        if capabilities is None or not capabilities.load_session:
            raise ChannelRefused("the agent did not advertise loadSession, so a session cannot be loaded")
        return await self._request_model_from_dict(
            AGENT_METHODS["session_load"],
            LoadSessionRequest(cwd=str(cwd), mcp_servers=list(mcp_servers), session_id=session_id),
            LoadSessionResponse,
        )

    async def prompt(
        self, session_id: str, prompt: Sequence[Any], *, meta: Mapping[str, Any] | None = None
    ) -> PromptResponse:
        """``session/prompt``; the answer is held until every update received before it was handled.

        The SDK resolves a response as soon as it is read, while the
        notifications read before it are still queued for dispatch; without
        this, a turn's last updates would follow its answer.
        """
        answer = await self._request_model(
            AGENT_METHODS["session_prompt"],
            PromptRequest(session_id=session_id, prompt=list(prompt), field_meta=dict(meta) if meta else None),
            PromptResponse,
        )
        await self.drain(session_id)
        return answer

    async def drain(self, session_id: str, timeout: float = 5.0) -> None:
        """Wait until the updates received for a session were all handled."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while self._received.get(session_id, 0) > self._handled.get(session_id, 0) and loop.time() < deadline:
            await asyncio.sleep(0.002)

    async def cancel(self, session_id: str) -> None:
        await self.notify(AGENT_METHODS["session_cancel"], {"sessionId": session_id})

    async def set_mode(self, session_id: str, mode_id: str) -> SetSessionModeResponse:
        return await self._request_model_from_dict(
            AGENT_METHODS["session_set_mode"],
            SetSessionModeRequest(session_id=session_id, mode_id=mode_id),
            SetSessionModeResponse,
        )

    @abstractmethod
    def _set_initialized(self, answer: InitializeResponse) -> None: ...

    @abstractmethod
    async def _request_model(self, method: str, params: Any, model: type) -> Any: ...

    @abstractmethod
    async def _request_model_from_dict(self, method: str, params: Any, model: type) -> Any: ...


class ConnectionChannel(ACPChannel):
    """An ``ACPChannel`` over the SDK's :class:`acp.connection.Connection`, whatever carries it.

    Built with :func:`channel_connection`, which wires the handler's router and
    the update counters ``prompt`` drains on.
    """

    def __init__(self, connection: Connection | None) -> None:
        self._initialized: InitializeResponse | None = None
        self._listeners: list[RawListener] = []
        self._received: dict[str, int] = {}
        self._handled: dict[str, int] = {}
        self._closed = False
        if connection is not None:
            self._conn = connection
            self._conn.add_observer(self._observe)

    def _observe(self, event: StreamEvent) -> None:
        message = event.message
        if event.direction == StreamDirection.INCOMING and message.get("method") == CLIENT_METHODS["session_update"]:
            session_id = (message.get("params") or {}).get("sessionId", "")
            self._received[session_id] = self._received.get(session_id, 0) + 1
        for listener in list(self._listeners):
            listener({"direction": event.direction.value, **message})

    def _handled_update(self, params: dict[str, Any]) -> None:
        session_id = params.get("sessionId", "")
        self._handled[session_id] = self._handled.get(session_id, 0) + 1

    @property
    def initialized(self) -> InitializeResponse | None:
        return self._initialized

    def _set_initialized(self, answer: InitializeResponse) -> None:
        self._initialized = answer

    async def request(self, method: str, params: Mapping[str, Any] | None = None) -> Any:
        return await self._conn.send_request(method, dict(params) if params is not None else None)

    async def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        await self._conn.send_notification(method, dict(params) if params is not None else None)

    def listen(self, listener: RawListener) -> Callable[[], None]:
        self._listeners.append(listener)

        def stop() -> None:
            with contextlib.suppress(ValueError):
                self._listeners.remove(listener)

        return stop

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._conn.close()

    async def _request_model(self, method: str, params: Any, model: type) -> Any:
        return await request_model(self._conn, method, params, model)

    async def _request_model_from_dict(self, method: str, params: Any, model: type) -> Any:
        return await request_model_from_dict(self._conn, method, params, model)


class StdioACPChannel(ConnectionChannel):
    """The agent as a subprocess of the Shield, its stdio the wire."""

    def __init__(self, connection: Connection, process: asyncio.subprocess.Process) -> None:
        super().__init__(connection)
        self.process = process

    @classmethod
    @asynccontextmanager
    async def launch(
        cls,
        handler: Any,
        command: str,
        *args: str,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        stderr: Callable[[str], None] | None = None,
        shutdown_timeout: float = 2.0,
    ) -> AsyncIterator[StdioACPChannel]:
        """Launch ``command args…`` and bind its stdio; the agent's stderr goes to ``stderr`` (default: the log).

        The agent's environment is the SDK's trimmed one (HOME, PATH, USER, …)
        plus ``env``: nothing of the Shield's own environment reaches the agent
        unless named.
        """
        say = stderr or (lambda line: logger.debug("agent stderr: %s", line.rstrip()))
        async with spawn_stdio_transport(command, *args, env=env, cwd=cwd, shutdown_timeout=shutdown_timeout) as (
            reader,
            writer,
            process,
        ):
            drain = asyncio.create_task(_drain(process.stderr, say), name="agent-shield.stderr")
            channel = cls(_UNBUILT, process)
            channel._conn = Connection(build_handler(handler, channel._handled_update), writer, reader)
            channel._conn.add_observer(channel._observe)
            try:
                yield channel
            finally:
                await channel.close()
                drain.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await drain


async def _drain(stream: asyncio.StreamReader | None, say: Callable[[str], None]) -> None:
    if stream is None:
        return
    while True:
        line = await stream.readline()
        if not line:
            return
        say(line.decode("utf-8", "replace"))


class _WebSocketWriter:
    """What the SDK's sender needs of a writer: ``write`` buffers a frame, ``drain`` sends it."""

    def __init__(self, socket: Any) -> None:
        self._socket = socket
        self._buffer = bytearray()

    def write(self, data: bytes) -> None:
        self._buffer.extend(data)

    async def drain(self) -> None:
        if not self._buffer:
            return
        payload = bytes(self._buffer)
        self._buffer.clear()
        for line in payload.split(b"\n"):
            if line:
                await self._socket.send(line.decode("utf-8"))

    def close(self) -> None:  # pragma: no cover - the socket is closed by the channel
        return


class WebSocketACPChannel(ConnectionChannel):
    """An agent served over a WebSocket, one JSON-RPC message per text frame."""

    def __init__(self, connection: Connection, socket: Any, feeder: asyncio.Task[None]) -> None:
        super().__init__(connection)
        self._socket = socket
        self._feeder = feeder

    @classmethod
    @asynccontextmanager
    async def connect(
        cls, handler: Any, url: str, *, headers: Mapping[str, str] | None = None
    ) -> AsyncIterator[WebSocketACPChannel]:
        try:
            from websockets.asyncio.client import connect
        except ImportError:  # pragma: no cover - the extra says so
            raise ChannelRefused("the WebSocket channel needs `datalayer-agent-shield[websocket]`") from None
        async with connect(url, additional_headers=dict(headers or {}), max_size=None) as socket:
            reader = asyncio.StreamReader()
            feeder = asyncio.create_task(_feed(socket, reader), name="agent-shield.websocket")
            channel = cls(_UNBUILT, socket, feeder)
            channel._conn = Connection(
                build_handler(handler, channel._handled_update), _WebSocketWriter(socket), reader
            )  # type: ignore[arg-type]
            channel._conn.add_observer(channel._observe)
            try:
                yield channel
            finally:
                await channel.close()
                feeder.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await feeder


async def _feed(socket: Any, reader: asyncio.StreamReader) -> None:
    try:
        async for message in socket:
            data = message if isinstance(message, bytes) else message.encode("utf-8")
            reader.feed_data(data.rstrip(b"\n") + b"\n")
    finally:
        reader.feed_eof()


def stderr_to_our_stderr(line: str) -> None:
    """A stderr sink that passes the agent's lines through, for ``agent-shield run --verbose``."""
    sys.stderr.write(line)
    sys.stderr.flush()


def wire(model: Any) -> dict[str, Any]:
    """A schema model as the wire spells it (camelCase, no nulls)."""
    return serialize_params(model)


__all__ = [
    "ELICITATION_CREATE",
    "SHIELD_CLIENT_CAPABILITIES",
    "SHIELD_CLIENT_INFO",
    "ACPChannel",
    "ChannelRefused",
    "ConnectionChannel",
    "StdioACPChannel",
    "WebSocketACPChannel",
    "build_handler",
    "stderr_to_our_stderr",
    "wire",
]
