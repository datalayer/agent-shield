# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""``agent-shield serve``: the proxy as a server, over WebSocket and ACP Streamable HTTP (SH-52, SH-56).

One listener, two transports on one path, as the ecosystem's bridges speak
them (``acp_rpc_bridge``'s Streamable HTTP, ACP Remote's WebSocket, and
the ACP project's RFD *streamable-http-websocket-transport*):

- **WebSocket** — ``GET /acp`` with ``Upgrade: websocket`` (and ``/acp/ws``,
  ACP Remote's default path): one JSON-RPC message per text frame, binary
  frames ignored, the ``Acp-Connection-Id`` in the 101's headers.
- **Streamable HTTP** — ``POST /acp`` carries a JSON-RPC message in: an
  ``initialize`` with no ``Acp-Connection-Id`` makes a connection and is
  answered ``200`` with the result and the id in that header; every other
  message needs the header and is answered ``202`` at once, its response
  arriving on a stream. ``GET /acp`` with ``Accept: text/event-stream`` opens
  the stream — connection-scoped with the connection header alone, session-
  scoped with ``Acp-Session-Id`` too — and each SSE event's ``data`` holds one
  JSON-RPC message. ``DELETE /acp`` ends the connection.

**One harness per connection**: each connection gets a :class:`ShieldProxy`
of its own, which launches the agent on the client's ``initialize`` and ends
it when the connection goes — a WebSocket closing, a ``DELETE``, or an HTTP
connection idle past its allowance. With several harnesses served, each has
its path: ``/acp/<harness>``.

**The token travels in the ``Authorization: Bearer`` header, or in the first
WebSocket message — ``authenticate`` with ``methodId`` ``bearer`` and the token
in ``_meta.token`` — and never in the address**: a token in the query string
is refused before anything is read. A listener bound beyond the loopback
refuses to start without a token.

**The bridge** (``--bridge``, SH-40): the same server with no Shield in it —
each connection's frames relayed verbatim to a harness it spawns — for the
``datalayer-harnesses`` sidecar, where the runtime's own Shield decides.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from acp.agent.router import build_agent_router
from acp.connection import Connection
from acp.meta import CLIENT_METHODS
from acp.schema import (
    PermissionOption,
    RequestPermissionRequest,
    RequestPermissionResponse,
    SessionNotification,
    ToolCallUpdate,
)
from acp.transports import spawn_stdio_transport
from acp.utils import notify_model, request_model

from agent_shield.acp.proxy import ShieldProxy
from agent_shield.audit import AuditLog

logger = logging.getLogger(__name__)

try:
    from aiohttp import WSMsgType, web
except ImportError:  # pragma: no cover - the extra says so
    web = None  # type: ignore[assignment]
    WSMsgType = None  # type: ignore[assignment]

#: The one path, as the RFD and the bridges have it.
ACP_PATH = "/acp"
#: marimo's path: its agents panel opens ``ws://<host>:<port>/message`` (one port per agent).
MARIMO_PATH = "/message"
HEADER_CONNECTION = "Acp-Connection-Id"
HEADER_SESSION = "Acp-Session-Id"
#: The challenge an unauthenticated HTTP request is answered with.
CHALLENGE = 'Bearer realm="agent-shield"'
#: The ``authenticate`` method id a WebSocket client without headers uses.
AUTH_METHOD = "bearer"
#: The query parameters a token must never travel in.
ADDRESS_TOKENS = ("token", "access_token", "bearer", "api_key", "apikey")
#: The methods a POST may only send with ``Acp-Session-Id``.
SESSION_SCOPED = frozenset(
    {"session/prompt", "session/cancel", "session/set_mode", "session/set_model", "session/set_config_option"}
)
#: JSON-RPC errors the server itself answers.
UNAUTHENTICATED = -32001
#: How long an HTTP connection with no stream open and no message may sit before it is ended.
DEFAULT_IDLE_SECONDS = 300.0
#: Messages kept for a session's stream before it opens.
QUEUE_LIMIT = 10_000

ProxyFactory = Callable[[], ShieldProxy]


class ServeRefused(RuntimeError):
    """What stops the server before it listens, said in a sentence."""


def _needs_aiohttp() -> None:
    if web is None:
        raise ServeRefused("`agent-shield serve` needs `datalayer-agent-shield[serve]` (aiohttp)")


# -- the backends: a Shield, or a bare relay ---------------------------------------------------


class _ClientFace:
    """What the proxy calls to reach its client, over whichever transport the connection has."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    async def session_update(self, session_id: str, update: Any, **kwargs: Any) -> None:
        await notify_model(
            self._conn,
            CLIENT_METHODS["session_update"],
            SessionNotification(session_id=session_id, update=update, field_meta=kwargs or None),
        )

    async def request_permission(
        self, options: list[PermissionOption], session_id: str, tool_call: ToolCallUpdate, **kwargs: Any
    ) -> RequestPermissionResponse:
        return await request_model(
            self._conn,
            CLIENT_METHODS["session_request_permission"],
            RequestPermissionRequest(
                options=options, session_id=session_id, tool_call=tool_call, field_meta=kwargs or None
            ),
            RequestPermissionResponse,
        )

    async def ext_method(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        result = await self._conn.send_request(f"_{method}", params)
        return result if isinstance(result, dict) else {}

    async def ext_notification(self, method: str, params: dict[str, Any]) -> None:
        await self._conn.send_notification(f"_{method}", params)


class _Sink:
    """What the SDK's sender needs of a writer: ``write`` buffers, ``drain`` hands each line to ``deliver``."""

    def __init__(self, deliver: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        self._deliver = deliver
        self._buffer = bytearray()

    def write(self, data: bytes) -> None:
        self._buffer.extend(data)

    async def drain(self) -> None:
        if not self._buffer:
            return
        payload = bytes(self._buffer)
        self._buffer.clear()
        for line in payload.split(b"\n"):
            if line.strip():
                await self._deliver(json.loads(line))

    def close(self) -> None:
        return


class ShieldBackend:
    """A connection's Shield: a proxy of its own, the SDK's agent router in front of it."""

    def __init__(self, proxy: ShieldProxy, deliver: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        self.proxy = proxy
        self.reader = asyncio.StreamReader()
        self.conn = Connection(build_agent_router(proxy), _Sink(deliver), self.reader, listening=False)  # type: ignore[arg-type]
        proxy.on_connect(_ClientFace(self.conn))
        self._loop = asyncio.create_task(self._run(), name="agent-shield.serve.connection")

    async def _run(self) -> None:
        with contextlib.suppress(Exception):
            await self.conn.main_loop()

    def feed(self, message: Mapping[str, Any]) -> None:
        self.reader.feed_data(json.dumps(message).encode("utf-8") + b"\n")

    async def close(self) -> None:
        self.reader.feed_eof()
        with contextlib.suppress(Exception):
            await self.proxy.stop_agent()
        with contextlib.suppress(Exception):
            await self.conn.close()
        self._loop.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._loop


class BridgeBackend:
    """No Shield: the harness spawned for this connection, every line relayed both ways (SH-40)."""

    def __init__(
        self,
        command: list[str],
        deliver: Callable[[dict[str, Any]], Awaitable[None]],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.command = command
        self._deliver = deliver
        self._cwd = cwd
        self._env = dict(env or {})
        self._writer: asyncio.StreamWriter | None = None
        self._launch: Any = None
        self._pump: asyncio.Task[None] | None = None
        self.started = asyncio.Event()
        self.pid: int | None = None

    async def start(self) -> None:
        self._launch = spawn_stdio_transport(
            self.command[0], *self.command[1:], env=self._env or None, cwd=self._cwd, shutdown_timeout=2.0
        )
        reader, writer, process = await self._launch.__aenter__()
        self._writer = writer
        self.pid = process.pid
        self._pump = asyncio.create_task(self._relay(reader), name="agent-shield.bridge.relay")
        self.started.set()

    async def _relay(self, reader: asyncio.StreamReader) -> None:
        while True:
            line = await reader.readline()
            if not line:
                return
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except ValueError:
                logger.warning("the harness wrote a line that is not JSON-RPC; dropped")
                continue
            await self._deliver(message)

    def feed(self, message: Mapping[str, Any]) -> None:
        if self._writer is None:
            raise RuntimeError("the bridge's harness is not started")
        self._writer.write(json.dumps(message).encode("utf-8") + b"\n")

    async def close(self) -> None:
        if self._pump is not None:
            self._pump.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._pump
        if self._launch is not None:
            launch, self._launch = self._launch, None
            with contextlib.suppress(Exception):
                await launch.__aexit__(None, None, None)


# -- one served connection --------------------------------------------------------------------


class Served:
    """One client connection: its backend, its streams, what it is waiting for."""

    def __init__(self, server: ShieldServer, agent: str, transport: str) -> None:
        self.server = server
        self.agent = agent
        self.transport = transport
        self.id = secrets.token_urlsafe(18)
        self.authenticated = False
        self.backend: ShieldBackend | BridgeBackend | None = None
        self.last_seen = time.monotonic()
        self.closed = False
        #: Outgoing messages per stream key: ``""`` the connection's, a session id its own.
        self.queues: dict[str, asyncio.Queue[dict[str, Any] | None]] = {}
        self.streams_open = 0
        #: Which stream a response goes to, by the request's JSON-RPC id.
        self.pending: dict[Any, str] = {}
        #: Who waits for a response inline (``initialize`` over HTTP).
        self.waiting: dict[Any, asyncio.Future[dict[str, Any]]] = {}
        self.socket: Any = None

    def queue(self, key: str) -> asyncio.Queue[dict[str, Any] | None]:
        found = self.queues.get(key)
        if found is None:
            found = self.queues[key] = asyncio.Queue(maxsize=QUEUE_LIMIT)
        return found

    def touch(self) -> None:
        self.last_seen = time.monotonic()

    async def deliver(self, message: dict[str, Any]) -> None:
        """A message from the agent side, to the client over this connection's transport."""
        self.touch()
        if self.socket is not None:
            with contextlib.suppress(Exception):
                await self.socket.send_str(json.dumps(message))
            return
        identifier = message.get("id")
        if "method" not in message and identifier in self.waiting:
            self.waiting.pop(identifier).set_result(message)
            return
        if "method" in message:
            params = message.get("params")
            session = params.get("sessionId") if isinstance(params, dict) else None
            key = session if isinstance(session, str) else ""
        else:
            key = self.pending.pop(identifier, "")
            result = message.get("result")
            if isinstance(result, dict) and isinstance(result.get("sessionId"), str):
                # The session's stream can be opened as soon as its id is known.
                self.queue(result["sessionId"])
        queue = self.queue(key)
        if queue.full():
            queue.get_nowait()
        queue.put_nowait(message)

    async def feed(self, message: dict[str, Any], session: str | None = None) -> None:
        self.touch()
        if "method" in message and "id" in message and session is not None:
            self.pending[message["id"]] = session
        if self.backend is None:
            raise RuntimeError("the connection has no backend")
        self.backend.feed(message)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for waiting in self.waiting.values():
            if not waiting.done():
                waiting.cancel()
        for queue in self.queues.values():
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(None)
        if self.backend is not None:
            await self.backend.close()
        self.server.connections.pop(self.id, None)
        self.server.audit.write(
            "session", what="connection_closed", session=self.id, transport=self.transport, by="shield"
        )


# -- the server -------------------------------------------------------------------------------


class ShieldServer:
    """The listener (see the module). ``agents`` maps a path id (``""`` for ``/acp`` alone) to what serves it."""

    def __init__(
        self,
        agents: Mapping[str, ProxyFactory | list[str]],
        *,
        audit: AuditLog,
        token: str | None = None,
        bridge_cwd: str | None = None,
        bridge_env: Mapping[str, str] | None = None,
        idle_seconds: float = DEFAULT_IDLE_SECONDS,
    ) -> None:
        _needs_aiohttp()
        if not agents:
            raise ServeRefused("nothing to serve: a command after `--`, or `--harness <id>`")
        self.agents = dict(agents)
        self.audit = audit
        self._token = token or None
        self.bridge_cwd = bridge_cwd
        self.bridge_env = dict(bridge_env or {})
        self.idle_seconds = idle_seconds
        self.connections: dict[str, Served] = {}
        self.host = ""
        self.port = 0
        self._runner: Any = None
        self._sweeper: asyncio.Task[None] | None = None

    @property
    def needs_token(self) -> bool:
        return self._token is not None

    @property
    def bridge(self) -> bool:
        return any(isinstance(agent, list) for agent in self.agents.values())

    # -- lifecycle ---------------------------------------------------------------------

    def app(self) -> Any:
        application = web.Application(client_max_size=64 * 1024 * 1024)
        application.router.add_get("/healthz", self._health)
        for suffix in ("", "/ws", "/{agent}", "/{agent}/ws"):
            path = ACP_PATH + suffix
            application.router.add_get(path, self._get)
            if not suffix.endswith("/ws"):
                application.router.add_post(path, self._post)
                application.router.add_delete(path, self._delete)
        # marimo's agents panel connects to ws://host:<port>/message (one port per agent, SH-55).
        application.router.add_get(MARIMO_PATH, self._get)
        application.router.add_get("/{agent}" + MARIMO_PATH, self._get)
        return application

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> None:
        if host not in ("127.0.0.1", "localhost", "::1") and not self.needs_token:
            raise ServeRefused(
                f"a Shield listening on {host} needs a token (`--token-env NAME`): beyond the loopback nothing is served to anyone"
            )
        self._runner = web.AppRunner(self.app(), access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, host, port, reuse_address=True)
        await site.start()
        sockets = site._server.sockets if site._server else []
        self.host = host
        self.port = sockets[0].getsockname()[1] if sockets else port
        self._sweeper = asyncio.create_task(self._sweep(), name="agent-shield.serve.sweep")
        self.audit.write(
            "session",
            what="serving",
            host=host,
            port=self.port,
            agents=sorted(self.agents),
            bridge=self.bridge,
            by="shield",
        )

    async def stop(self) -> None:
        if self._sweeper is not None:
            self._sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sweeper
        for served in list(self.connections.values()):
            await served.close()
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    async def serve_forever(self, host: str = "127.0.0.1", port: int = 0) -> None:
        await self.start(host, port)
        try:
            await asyncio.Event().wait()
        finally:
            await self.stop()

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}{ACP_PATH}"

    async def _sweep(self) -> None:
        while True:
            await asyncio.sleep(max(0.5, min(self.idle_seconds / 2, 30.0)))
            now = time.monotonic()
            for served in list(self.connections.values()):
                if served.socket is None and served.streams_open == 0 and now - served.last_seen > self.idle_seconds:
                    logger.info("connection %s idle for %.0f s: ended", served.id, now - served.last_seen)
                    await served.close()

    # -- making a connection -----------------------------------------------------------

    def _agent_of(self, request: Any) -> str:
        agent = request.match_info.get("agent", "")
        if agent not in self.agents:
            raise web.HTTPNotFound(
                text=f"no agent is served at {ACP_PATH}/{agent}; served: {', '.join(sorted(self.agents)) or '/acp'}"
            )
        return agent

    async def _open(self, agent: str, transport: str) -> Served:
        served = Served(self, agent, transport)
        target = self.agents[agent]
        if isinstance(target, list):
            backend = BridgeBackend(target, served.deliver, cwd=self.bridge_cwd, env=self.bridge_env)
            await backend.start()
            served.backend = backend
        else:
            served.backend = ShieldBackend(target(), served.deliver)
        self.connections[served.id] = served
        self.audit.write(
            "session", what="connection", session=served.id, transport=transport, agent=agent or None, by="shield"
        )
        return served

    # -- the token ---------------------------------------------------------------------

    def _refuse_address_token(self, request: Any) -> None:
        for name in ADDRESS_TOKENS:
            if name in request.query:
                raise web.HTTPBadRequest(
                    text="the token travels in the Authorization header or the first message, never in the address"
                )

    def _header_token_ok(self, request: Any) -> bool | None:
        """``True`` with a good header, ``False`` with a bad one, ``None`` with none."""
        header = request.headers.get("Authorization", "")
        if not header:
            return None
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "bearer" or not value.strip():
            return False
        return self.token_matches(value.strip())

    def token_matches(self, value: str) -> bool:
        return self._token is not None and hmac.compare_digest(value.encode(), self._token.encode())

    def _require_header(self, request: Any) -> None:
        self._refuse_address_token(request)
        if not self.needs_token:
            return
        if self._header_token_ok(request) is not True:
            raise web.HTTPUnauthorized(text="a bearer token is needed", headers={"WWW-Authenticate": CHALLENGE})

    def _served_of(self, request: Any) -> Served:
        identifier = request.headers.get(HEADER_CONNECTION, "")
        if not identifier:
            raise web.HTTPBadRequest(text=f"{HEADER_CONNECTION} is needed on every request after initialize")
        served = self.connections.get(identifier)
        if served is None or served.closed:
            raise web.HTTPNotFound(text=f"no connection {identifier!r}")
        return served

    # -- HTTP --------------------------------------------------------------------------

    async def _health(self, request: Any) -> Any:
        return web.json_response({"ok": True, "agents": sorted(self.agents), "connections": len(self.connections)})

    async def _post(self, request: Any) -> Any:
        agent = self._agent_of(request)
        self._require_header(request)
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType(text="a JSON-RPC message is application/json")
        try:
            message = await request.json()
        except ValueError:
            raise web.HTTPBadRequest(text="the body is not JSON") from None
        if isinstance(message, list):
            raise web.HTTPNotImplemented(text="JSON-RPC batches are not served")
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise web.HTTPBadRequest(text="the body is not a JSON-RPC 2.0 message")
        if not request.headers.get(HEADER_CONNECTION):
            if message.get("method") != "initialize" or "id" not in message:
                raise web.HTTPBadRequest(
                    text=f"a connection starts with initialize; after it, send {HEADER_CONNECTION}"
                )
            served = await self._open(agent, "http")
            served.authenticated = True
            waiting: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
            served.waiting[message["id"]] = waiting
            await served.feed(message)
            try:
                answer = await asyncio.wait_for(waiting, timeout=120)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                await served.close()
                raise web.HTTPGatewayTimeout(text="the agent did not answer initialize") from None
            result = answer.get("result")
            if isinstance(result, dict):
                result = {**result, "connectionId": served.id}
                answer = {**answer, "result": result}
            return web.json_response(answer, headers={HEADER_CONNECTION: served.id})
        served = self._served_of(request)
        if served.agent != agent:
            raise web.HTTPNotFound(text=f"connection {served.id!r} is not {ACP_PATH}/{agent}'s")
        session = request.headers.get(HEADER_SESSION) or None
        if message.get("method") in SESSION_SCOPED and session is None:
            raise web.HTTPBadRequest(text=f"{message['method']} needs {HEADER_SESSION}")
        await served.feed(message, session)
        return web.Response(status=202)

    async def _delete(self, request: Any) -> Any:
        self._agent_of(request)
        self._require_header(request)
        served = self._served_of(request)
        await served.close()
        return web.Response(status=202)

    async def _get(self, request: Any) -> Any:
        agent = self._agent_of(request)
        self._refuse_address_token(request)
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return await self._websocket(request, agent)
        if request.path.endswith(("/ws", MARIMO_PATH)):
            raise web.HTTPUpgradeRequired(text="this path is the WebSocket one")
        self._require_header(request)
        if "text/event-stream" not in request.headers.get("Accept", ""):
            raise web.HTTPNotAcceptable(text="a stream is text/event-stream")
        served = self._served_of(request)
        session = request.headers.get(HEADER_SESSION) or ""
        if session and session not in served.queues:
            raise web.HTTPNotFound(text=f"connection {served.id!r} holds no session {session!r}")
        response = web.StreamResponse(
            status=200,
            headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache", HEADER_CONNECTION: served.id},
        )
        await response.prepare(request)
        queue = served.queue(session)
        served.streams_open += 1
        served.touch()
        try:
            while not served.closed:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    await response.write(b": keepalive\n\n")
                    continue
                if message is None:
                    break
                await response.write(b"data: " + json.dumps(message).encode("utf-8") + b"\n\n")
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            served.streams_open -= 1
            served.touch()
        with contextlib.suppress(Exception):
            await response.write_eof()
        return response

    # -- WebSocket ---------------------------------------------------------------------

    async def _websocket(self, request: Any, agent: str) -> Any:
        header = self._header_token_ok(request)
        if header is False:
            raise web.HTTPUnauthorized(text="the bearer token is wrong", headers={"WWW-Authenticate": CHALLENGE})
        served = await self._open(agent, "websocket")
        served.authenticated = header is True or not self.needs_token
        socket = web.WebSocketResponse(max_msg_size=0, heartbeat=30.0)
        await socket.prepare(request)
        served.socket = socket
        try:
            async for frame in socket:
                # A text frame holds one message; a binary frame is UTF-8
                # NDJSON, a message a line — what marimo's agents panel
                # (use-acp's ndJsonStream over the socket) writes (SH-49).
                if frame.type == WSMsgType.TEXT:
                    texts = [frame.data]
                elif frame.type == WSMsgType.BINARY:
                    try:
                        decoded = bytes(frame.data).decode("utf-8")
                    except UnicodeDecodeError:
                        await socket.send_str(json.dumps(_error(None, -32700, "the binary frame is not UTF-8")))
                        continue
                    texts = [line for line in decoded.split("\n") if line.strip()]
                else:
                    break
                closing = False
                for text in texts:
                    try:
                        message = json.loads(text)
                    except ValueError:
                        await socket.send_str(json.dumps(_error(None, -32700, "the frame is not JSON")))
                        continue
                    if not isinstance(message, dict):
                        await socket.send_str(json.dumps(_error(None, -32600, "a frame holds one JSON-RPC message")))
                        continue
                    if not served.authenticated:
                        if not await self._first_message(served, socket, message):
                            closing = True
                            break
                        continue
                    await served.feed(message)
                if closing:
                    break
        finally:
            served.socket = None
            await served.close()
            with contextlib.suppress(Exception):
                await socket.close()
        return socket

    async def _first_message(self, served: Served, socket: Any, message: dict[str, Any]) -> bool:
        """The token in the first message: ``authenticate`` with ``methodId`` ``bearer`` and ``_meta.token``."""
        identifier = message.get("id")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        if message.get("method") == "authenticate" and params.get("methodId") == AUTH_METHOD:
            token = meta.get("token")
            if isinstance(token, str) and self.token_matches(token):
                served.authenticated = True
                await socket.send_str(json.dumps({"jsonrpc": "2.0", "id": identifier, "result": {}}))
                return True
            await socket.send_str(json.dumps(_error(identifier, UNAUTHENTICATED, "the bearer token is wrong")))
            return False
        await socket.send_str(
            json.dumps(
                _error(
                    identifier,
                    UNAUTHENTICATED,
                    "authenticate first: the Authorization header on the upgrade, or a first message "
                    f"`authenticate` with methodId {AUTH_METHOD!r} and the token in `_meta.token`",
                )
            )
        )
        return False


def _error(identifier: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}}


__all__ = [
    "ACP_PATH",
    "AUTH_METHOD",
    "CHALLENGE",
    "DEFAULT_IDLE_SECONDS",
    "HEADER_CONNECTION",
    "HEADER_SESSION",
    "MARIMO_PATH",
    "SESSION_SCOPED",
    "UNAUTHENTICATED",
    "BridgeBackend",
    "ServeRefused",
    "Served",
    "ShieldBackend",
    "ShieldServer",
]
