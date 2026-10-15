# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The proxy: an ACP agent on the Shield's stdio, in front of the agent it launched (SHIELD §5.2).

Any ACP client — Zed, ``vscode-acp``, Marimo, agent-runtimes' adapter — talks
to the Shield; the Shield talks to the agent. In between:

- ``session/request_permission`` is decided by the policy: *do it* is
  answered without the client, *ask me first* is forwarded with the same
  options and answered as the person chose, *leave it to me* is refused
  and the person told why;
- the agent's ``tool_call`` notifications are classed (ACP ``kind`` → F-10
  class, ``other`` → write) and held to the limits; a refusal cancels the
  turn and says so;
- ``fs/*`` and ``terminal/*`` are answered by the Shield against the
  workspace, each a recorded, decided action the client sees as a tool row;
- ``mcpServers`` are rewritten to the policy's allow-list;
- every action and decision is a row of the audit, nothing secret.

``allow_always`` chosen by a person becomes a session rule, gone with the
session (decision 7). A malformed update ends the turn with a sentence.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import sys
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acp import PROTOCOL_VERSION, run_agent, text_block, tool_content, tool_diff_content, tool_terminal_ref
from acp.exceptions import RequestError
from acp.helpers import start_tool_call, update_agent_message_text, update_tool_call
from acp.schema import (
    AllowedOutcome,
    CreateTerminalResponse,
    DeniedOutcome,
    Implementation,
    InitializeResponse,
    KillTerminalCommandResponse,
    LoadSessionResponse,
    NewSessionResponse,
    PermissionOption,
    PromptResponse,
    ReadTextFileResponse,
    ReleaseTerminalResponse,
    RequestPermissionResponse,
    SetSessionModeResponse,
    TerminalExitStatus,
    TerminalOutputResponse,
    ToolCallLocation,
    ToolCallUpdate,
    WaitForTerminalExitResponse,
    WriteTextFileResponse,
)

from agent_shield.__version__ import __version__
from agent_shield.audit import AuditLog, diff_summary
from agent_shield.policy import (
    Action,
    Context,
    Decision,
    LimitState,
    LoadedPolicy,
    Policy,
    Rule,
    UnknownKind,
    check_tightens,
    class_of,
    decide,
    decide_budget,
)
from agent_shield.tracing import with_traceparent

from .channel import SHIELD_CLIENT_CAPABILITIES, SHIELD_CLIENT_INFO, ACPChannel, StdioACPChannel, WebSocketACPChannel
from .events import PlanUpdated, ToolCallSaid, ToolCallUpdated
from .normalize import MalformedUpdate, normalize
from .workspace import OutsideWorkspace, Terminals, Workspace

logger = logging.getLogger(__name__)

#: The JSON-RPC error a refused action answers with.
REFUSED = -32010

#: The options the Shield offers when it asks on its own behalf.
SHIELD_OPTIONS = [
    PermissionOption(option_id="allow", name="Allow", kind="allow_once"),
    PermissionOption(option_id="reject", name="Reject", kind="reject_once"),
]


class ProxyRefused(RuntimeError):
    """What stops the proxy before the agent runs, said in a sentence."""


@dataclass
class SessionState:
    session_id: str
    workspace: Workspace
    policies: list[Policy]
    state: LimitState = field(default_factory=LimitState)
    terminals: Terminals | None = None
    decisions: dict[str, Decision] = field(default_factory=dict)
    counted: set[str] = field(default_factory=set)
    failed: str | None = None
    shield_calls: int = 0
    session_rules: list[Rule] = field(default_factory=list)
    #: Rules a host keeps for this session beside the Shield's own (a person's,
    #: added from a panel while it runs, SH-54): read at every decision.
    rules_from: Callable[[], Sequence[Rule]] | None = None

    @property
    def context(self) -> Context:
        return Context(workspace=str(self.workspace.root), session_id=self.session_id, state=self.state)

    def all_session_rules(self) -> list[Rule]:
        """The session's rules in force: the host's, then the Shield's own (``allow_always``)."""
        hosted = list(self.rules_from()) if self.rules_from is not None else []
        return [*hosted, *self.session_rules]

    def policies_in_force(self) -> list[Policy]:
        rules = self.all_session_rules()
        if not rules:
            return self.policies
        own = [policy for policy in self.policies if policy.scope == "session"]
        others = [policy for policy in self.policies if policy.scope != "session"]
        base = own[0] if own else Policy(scope="session")
        merged = base.model_copy(update={"rules": [*rules, *base.rules]})
        return [*others, merged]

    def next_shield_call_id(self) -> str:
        self.shield_calls += 1
        return f"shield_{self.shield_calls}"


def _raw(value: Any, *names: str) -> str | None:
    if isinstance(value, Mapping):
        for name in names:
            found = value.get(name)
            if isinstance(found, str) and found:
                return found
    return None


def action_of_tool_call(tool_call: Any, workspace: Workspace) -> tuple[Action | None, str | None]:
    """An ``Action`` from a tool call (a ``ToolCallSaid`` event or a ``ToolCallUpdate``), or none to decide."""
    kind = getattr(tool_call, "kind", None)
    if kind is None:
        return None, "the tool call names no kind"
    action_class = class_of(kind)
    if action_class is None:
        return None, None
    raw_input = getattr(tool_call, "input", None)
    if raw_input is None:
        raw_input = getattr(tool_call, "raw_input", None)
    locations = getattr(tool_call, "locations", None) or []
    path = _raw(raw_input, "path", "file_path", "filePath", "file")
    if path is None and locations:
        path = getattr(locations[0], "path", None)
    command = _raw(raw_input, "command", "cmd")
    url = _raw(raw_input, "url")
    inside: bool | None = None
    shown = path
    if path is not None:
        placed = workspace.place(path)
        inside, shown = placed.inside, placed.shown
    title = getattr(tool_call, "title", None) or kind
    return (
        Action(kind=kind, title=title, path=shown, inside=inside, command=command, url=url, **{"class": action_class}),
        None,
    )


def _select(options: Sequence[PermissionOption], *kinds: str) -> PermissionOption | None:
    for kind in kinds:
        for option in options:
            if option.kind == kind:
                return option
    return None


def lend_mcp_servers(servers: Sequence[Any], policies: Sequence[Policy]) -> tuple[list[Any], list[str]]:
    """The servers the strictest policy that lists any lends, and the names cut."""
    allowed: list[str] | None = None
    for policy in sorted(policies, key=lambda p: ("organization", "team", "session").index(p.scope)):
        if policy.mcp.allow:
            allowed = policy.mcp.allow
            break
    kept, cut = [], []
    for server in servers:
        name = getattr(server, "name", None) or "?"
        if allowed is not None and name in allowed:
            kept.append(server)
        else:
            cut.append(name)
    return kept, cut


class ShieldProxy:
    """The ACP agent the client sees (see the module)."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        policies: Sequence[LoadedPolicy],
        audit: AuditLog,
        workspace: Path | None = None,
        agent_env: Mapping[str, str] | None = None,
        agent_stderr: Any = None,
        connect_url: str | None = None,
        connect_headers: Mapping[str, str] | None = None,
    ) -> None:
        if not command and not connect_url:
            raise ProxyRefused("no agent command: `agent-shield run -- <command>`")
        self.command = list(command)
        #: The agent served at a URL instead of launched here (SH-40: the sidecar
        #: bridge, ``ws://127.0.0.1:<port>/acp/<harness>``): the WebSocket
        #: channel, the same interface, the same decisions.
        self.connect_url = connect_url
        self.connect_headers = dict(connect_headers or {})
        self.loaded = list(policies)
        self.policies = [item.policy for item in self.loaded]
        self.audit = audit
        self.pinned_workspace = Workspace(workspace) if workspace is not None else None
        self.agent_env = dict(agent_env or {})
        self.agent_stderr = agent_stderr
        self._client: Any = None
        self._channel: ACPChannel | None = None
        self._launch: Any = None
        self.sessions: dict[str, SessionState] = {}
        self.inner = _InnerClient(self)
        #: The sentence refusing every action while no unexpired policy is held
        #: (SHIELD decision 11), or ``None`` while the policies are in force.
        self.unavailable: str | None = None

    # -- the policies while running (SH-50, SH-54) ---------------------------------------

    def replace_policies(self, policies: Sequence[LoadedPolicy]) -> None:
        """Take a changed set of documents, in force at once in every open session.

        A session's own rules (``allow_always``, the ones a person added from
        the panel) stay with it; the documents under them are the new ones.
        """
        self.loaded = list(policies)
        self.policies = [item.policy for item in self.loaded]
        for session in self.sessions.values():
            session.policies = self.policies
        self.unavailable = None
        self.audit.write("policy", what="replaced", scopes=[policy.scope for policy in self.policies], by="shield")

    def refuse_all(self, sentence: str) -> None:
        """Hold every further action to ``sentence`` until the policies are in force again (decision 11)."""
        self.unavailable = sentence
        self.audit.write("policy", what="unavailable", sentence=sentence, by="shield")

    def add_session_rule(self, session_id: str, rule: Rule) -> list[Rule]:
        """A rule a person adds to a running session (§6.3): in force at once, gone with the session.

        It may only tighten what the organization's documents say: a rule that
        would permit more is refused with :class:`PolicyWidens`'s sentences.
        A rule of the same name replaces the earlier one.
        """
        session = self._session(session_id)
        check_tightens(
            Policy(scope="session", rules=[rule]),
            [policy for policy in session.policies if policy.scope == "organization"],
        )
        session.session_rules = [*(r for r in session.session_rules if r.name != rule.name), rule]
        session.session_rules.sort(key=lambda r: 0 if r.decision != "allow" else 1)
        self.audit.write(
            "policy",
            session=session_id,
            what="session_rule",
            rule=rule.name,
            decision=rule.decision,
            classes=list(rule.classes),
            kinds=list(rule.kinds),
            by="person",
        )
        return list(session.session_rules)

    def remove_session_rule(self, session_id: str, name: str) -> list[Rule]:
        """Take a session rule back; a name that is no rule is refused."""
        session = self._session(session_id)
        kept = [rule for rule in session.session_rules if rule.name != name]
        if len(kept) == len(session.session_rules):
            raise KeyError(f"the session has no rule named {name!r}")
        session.session_rules = kept
        self.audit.write("policy", session=session_id, what="session_rule_removed", rule=name, by="person")
        return list(kept)

    def rules_in_force(self, session_id: str) -> dict[str, Any]:
        """What decides this session: every document, strictest first, and the session's own rules."""
        session = self._session(session_id)
        return {
            "policies": [
                json.loads(policy.model_dump_json(exclude_none=True)) for policy in session.policies_in_force()
            ],
            "session_rules": [
                json.loads(rule.model_dump_json(exclude_none=True)) for rule in session.all_session_rules()
            ],
            "unavailable": self.unavailable,
        }

    def decide_budget(
        self, session_id: str, *, tokens: int = 0, cost: int = 0, title: str = "a model request"
    ) -> Decision:
        """The next model request against the model limits in force (SH-32)."""
        session = self._session(session_id)
        if self.unavailable is not None:
            return Decision(verdict="deny", decided_by="default", sentence=self.unavailable)
        decision = decide_budget(session.context, session.policies_in_force(), tokens=tokens, cost=cost, title=title)
        if decision.decided_by == "limit" and decision.verdict == "ask" and decision.scope and decision.rule:
            session.state.soft_asked.add((decision.scope, decision.rule))
        return decision

    # -- the outer face: the client's agent --------------------------------------------

    def on_connect(self, conn: Any) -> None:
        self._client = conn

    @property
    def client(self) -> Any:
        if self._client is None:
            raise ProxyRefused("no client is connected")
        return self._client

    @property
    def channel(self) -> ACPChannel:
        if self._channel is None:
            raise RequestError(REFUSED, "the Shield was not initialized, so no agent runs behind it")
        return self._channel

    async def start_agent(self) -> ACPChannel:
        """Launch the agent as a subprocess, or connect to it at ``connect_url``; once."""
        if self._channel is not None:
            return self._channel
        if self.connect_url:
            self._launch = WebSocketACPChannel.connect(self.inner, self.connect_url, headers=self.connect_headers)
        else:
            cwd = self.pinned_workspace.root if self.pinned_workspace else None
            self._launch = StdioACPChannel.launch(
                self.inner, self.command[0], *self.command[1:], cwd=cwd, env=self.agent_env, stderr=self.agent_stderr
            )
        self._channel = await self._launch.__aenter__()
        return self._channel

    async def stop_agent(self) -> None:
        for session in list(self.sessions.values()):
            if session.terminals is not None:
                await session.terminals.release_all()
        if self._launch is not None:
            launch, self._launch, self._channel = self._launch, None, None
            with contextlib.suppress(Exception):
                await launch.__aexit__(None, None, None)

    async def initialize(self, protocol_version: int, client_capabilities=None, client_info=None, **kwargs: Any):
        # A client asking another version is answered with the one the Shield speaks (ACP's rule:
        # the agent answers the version it supports; the client decides what to do with it).
        channel = await self.start_agent()
        answer = await channel.initialize(
            client_capabilities=SHIELD_CLIENT_CAPABILITIES, client_info=SHIELD_CLIENT_INFO, meta=kwargs or None
        )
        agent = answer.agent_info
        agent_title = (agent.title or agent.name) if agent else self.command[0]
        self.audit.write(
            "session",
            what="initialize",
            agent={"name": agent.name, "version": agent.version} if agent else {"command": self.command[0]},
            client={"name": client_info.name, "version": client_info.version} if client_info else None,
            scopes=[policy.scope for policy in self.policies],
            by="shield",
        )
        return InitializeResponse(
            protocol_version=PROTOCOL_VERSION,
            agent_capabilities=answer.agent_capabilities,
            auth_methods=answer.auth_methods,
            agent_info=Implementation(
                name="agent-shield", title=f"Agent Shield in front of {agent_title}", version=__version__
            ),
            field_meta={
                "datalayer": {
                    "shield": {
                        "version": __version__,
                        "agent": {"name": agent.name, "version": agent.version} if agent else None,
                        "policies": [{"scope": item.policy.scope, "origin": item.origin} for item in self.loaded],
                    }
                }
            },
        )

    async def authenticate(self, method_id: str, **kwargs: Any):
        result = await self.channel.request(
            "authenticate", {"methodId": method_id, **({"_meta": kwargs} if kwargs else {})}
        )
        self.audit.write("session", what="authenticate", method=method_id, by="shield")
        return result if isinstance(result, dict) else None

    def _workspace_for(self, cwd: str) -> Workspace:
        if self.pinned_workspace is not None:
            if Path(cwd).resolve() != self.pinned_workspace.root:
                raise RequestError(
                    REFUSED,
                    f"the session's cwd {cwd} is not the workspace {self.pinned_workspace.root} this Shield guards",
                )
            return self.pinned_workspace
        try:
            return Workspace(cwd)
        except OutsideWorkspace as exc:
            raise RequestError(REFUSED, str(exc)) from None

    def _open(self, session_id: str, workspace: Workspace) -> SessionState:
        session = SessionState(session_id=session_id, workspace=workspace, policies=self.policies)
        session.terminals = Terminals(workspace)
        self.sessions[session_id] = session
        return session

    def _lend(self, mcp_servers: Sequence[Any], session_id: str | None) -> list[Any]:
        kept, cut = lend_mcp_servers(mcp_servers, self.policies)
        for server in kept:
            self.audit.write(
                "mcp", session=session_id, name=getattr(server, "name", "?"), decision="allow", by="policy"
            )
        for name in cut:
            self.audit.write(
                "mcp",
                session=session_id,
                name=name,
                decision="deny",
                by="policy",
                sentence=f"MCP server {name!r}: leave it to me — not on the policy's mcp.allow list",
            )
        return kept

    async def new_session(self, cwd: str, mcp_servers: list, **kwargs: Any) -> NewSessionResponse:
        workspace = self._workspace_for(cwd)
        lent = self._lend(mcp_servers, None)
        answer = await self.channel.new_session(workspace.root, lent, meta=kwargs or None)
        self._open(answer.session_id, workspace)
        self.audit.write(
            "session",
            session=answer.session_id,
            what="new",
            workspace=str(workspace.root),
            mcp=[getattr(s, "name", "?") for s in lent],
            by="shield",
        )
        return answer

    async def load_session(self, cwd: str, mcp_servers: list, session_id: str, **kwargs: Any):
        workspace = self._workspace_for(cwd)
        self._open(session_id, workspace)
        lent = self._lend(mcp_servers, session_id)
        answer = await self.channel.load_session(session_id, workspace.root, lent)
        self.audit.write("session", session=session_id, what="load", workspace=str(workspace.root), by="shield")
        return answer or LoadSessionResponse()

    async def set_session_mode(self, mode_id: str, session_id: str, **kwargs: Any):
        answer = await self.channel.set_mode(session_id, mode_id)
        self.audit.write("session", session=session_id, what="set_mode", mode=mode_id, by="shield")
        return answer or SetSessionModeResponse()

    async def set_session_model(self, model_id: str, session_id: str, **kwargs: Any):
        result = await self.channel.request("session/set_model", {"sessionId": session_id, "modelId": model_id})
        return result if isinstance(result, dict) else {}

    async def prompt(self, prompt: list, session_id: str, **kwargs: Any) -> PromptResponse:
        session = self._session(session_id)
        session.failed = None
        self.audit.write("turn", session=session_id, what="prompt", blocks=len(prompt), by="shield")
        # The trace the face arrived on, handed to the harness in the key ACP
        # reserves for it (§6.8, SH-51); a caller's own `_meta.traceparent` wins.
        answer = await self.channel.prompt(session_id, prompt, meta=with_traceparent(kwargs))
        if session.failed is not None:
            self.audit.write(
                "turn", session=session_id, what="ended", stop_reason="refusal", sentence=session.failed, by="shield"
            )
            return PromptResponse(stop_reason="refusal")
        self.audit.write("turn", session=session_id, what="ended", stop_reason=answer.stop_reason, by="shield")
        return answer

    async def cancel(self, session_id: str, **kwargs: Any) -> None:
        await self.channel.cancel(session_id)
        self.audit.write("turn", session=session_id, what="cancel", by="shield")

    async def ext_method(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        result = await self.channel.request(f"_{method}", params)
        return result if isinstance(result, dict) else {}

    async def ext_notification(self, method: str, params: dict[str, Any]) -> None:
        await self.channel.notify(f"_{method}", params)

    def _session(self, session_id: str) -> SessionState:
        try:
            return self.sessions[session_id]
        except KeyError:
            raise RequestError(REFUSED, f"no session {session_id!r} is open behind this Shield") from None

    # -- deciding ------------------------------------------------------------------------

    def decide(self, session: SessionState, action: Action, *, count_as: str | None = None) -> Decision:
        if self.unavailable is not None:
            return Decision(verdict="deny", decided_by="default", sentence=self.unavailable)
        decision = decide(action, session.context, session.policies_in_force())
        if decision.decided_by == "limit" and decision.verdict == "ask" and decision.scope and decision.rule:
            session.state.soft_asked.add((decision.scope, decision.rule))
        return decision

    def count(self, session: SessionState, action: Action, decision: Decision, key: str | None) -> None:
        if key is not None:
            if key in session.counted:
                return
            session.counted.add(key)
        session.state.count(action, decision)

    async def tell(self, session_id: str, sentence: str) -> None:
        """Say a sentence to the client, as the agent's own message."""
        await self.client.session_update(
            session_id=session_id, update=update_agent_message_text(f"[Shield] {sentence}")
        )

    async def fail_turn(self, session: SessionState, sentence: str) -> None:
        session.failed = sentence
        self.audit.write("refusal", session=session.session_id, sentence=sentence, by="shield")
        with contextlib.suppress(Exception):
            await self.channel.cancel(session.session_id)
        with contextlib.suppress(Exception):
            await self.tell(session.session_id, sentence)

    async def ask_person(
        self,
        session: SessionState,
        action: Action,
        decision: Decision,
        tool_call: ToolCallUpdate,
        options: Sequence[PermissionOption],
        **meta: Any,
    ) -> RequestPermissionResponse:
        answer = await self.client.request_permission(
            options=list(options), session_id=session.session_id, tool_call=tool_call, **meta
        )
        chosen = answer.outcome
        option_id = getattr(chosen, "option_id", None)
        option = next((o for o in options if o.option_id == option_id), None)
        chosen_kind = option.kind if option else "cancelled"
        granted = chosen_kind in ("allow_once", "allow_always")
        if chosen_kind == "allow_always":
            session.session_rules.append(_always_rule(action))
        self.audit.write(
            "permission",
            session=session.session_id,
            tool_call_id=tool_call.tool_call_id,
            kind=action.kind,
            **{"class": action.action_class},
            title=action.title,
            path=action.path,
            command=action.command,
            url=action.url,
            decision="allow" if granted else "deny",
            chosen=chosen_kind,
            by="person",
            sentence=decision.sentence,
            rule=decision.rule,
            scope=decision.scope,
        )
        return answer


def _always_rule(action: Action) -> Rule:
    if action.command:
        return Rule(
            name=f"always: {action.title}",
            decision="allow",
            commands=[f"^{re.escape(action.command)}$"],
            reason="allowed always by the person, for this session",
        )
    if action.path:
        return Rule(
            name=f"always: {action.title}",
            decision="allow",
            kinds=[action.kind] if action.kind in _KINDS else [],
            paths=[action.path],
            reason="allowed always by the person, for this session",
        )
    return Rule(
        name=f"always: {action.title}",
        decision="allow",
        kinds=[action.kind] if action.kind in _KINDS else [],
        reason="allowed always by the person, for this session",
    )


_KINDS = {"read", "edit", "delete", "move", "search", "execute", "think", "fetch", "switch_mode", "other"}


class _InnerClient:
    """What the agent behind the Shield asks of its client: the Shield answers."""

    def __init__(self, proxy: ShieldProxy) -> None:
        self.proxy = proxy

    def on_connect(self, conn: Any) -> None:
        return None

    # -- notifications ---------------------------------------------------------------

    async def session_update(self, session_id: str, update: Any, **kwargs: Any) -> None:
        proxy = self.proxy
        session = proxy.sessions.get(session_id)
        if session is None:
            raise RequestError(REFUSED, f"session/update for a session {session_id!r} this Shield did not open")
        await self._session_update(session, update, **kwargs)

    async def _session_update(self, session: SessionState, update: Any, **kwargs: Any) -> None:
        proxy = self.proxy
        session_id = session.session_id
        try:
            event = normalize(session_id, update)
        except MalformedUpdate as exc:
            await proxy.fail_turn(session, str(exc))
            return
        if isinstance(event, PlanUpdated):
            proxy.audit.write(
                "plan",
                session=session_id,
                steps=len(event.steps),
                status={
                    status: sum(1 for step in event.steps if step.status == status)
                    for status in sorted({step.status for step in event.steps})
                },
                by="agent",
            )
        if isinstance(event, ToolCallSaid):
            try:
                action, problem = action_of_tool_call(event, session.workspace)
            except UnknownKind as exc:
                await proxy.fail_turn(session, str(exc))
                return
            if problem:
                await proxy.fail_turn(session, problem)
                return
            if action is not None:
                decision = proxy.decide(session, action)
                session.decisions[event.tool_call_id] = decision
                proxy.audit.write(
                    "tool_call",
                    session=session_id,
                    tool_call_id=event.tool_call_id,
                    kind=action.kind,
                    **{"class": action.action_class},
                    title=action.title,
                    path=action.path,
                    command=action.command,
                    url=action.url,
                    status=event.status,
                    decision=decision.verdict,
                    sentence=decision.sentence,
                    rule=decision.rule,
                    scope=decision.scope,
                    decided_by=decision.decided_by,
                    by="policy",
                )
                if decision.verdict == "deny":
                    await proxy.client.session_update(session_id=session_id, update=update, **kwargs)
                    await proxy.fail_turn(session, decision.sentence)
                    return
                if event.status == "in_progress" or decision.verdict == "allow":
                    proxy.count(session, action, decision, event.tool_call_id)
        elif isinstance(event, ToolCallUpdated):
            for display in event.displays:
                if display.display == "diff":
                    proxy.audit.write(
                        "tool_call",
                        session=session_id,
                        tool_call_id=event.tool_call_id,
                        status=event.status,
                        diff=diff_summary(display.path, display.new_text, display.old_text),
                        by="agent",
                    )
            if event.status in ("completed", "failed") and event.tool_call_id in session.decisions:
                decision = session.decisions[event.tool_call_id]
                proxy.audit.write(
                    "tool_call",
                    session=session_id,
                    tool_call_id=event.tool_call_id,
                    status=event.status,
                    decision=decision.verdict,
                    by="agent",
                )
        await proxy.client.session_update(session_id=session_id, update=update, **kwargs)

    # -- permissions (§4.5) -------------------------------------------------------------

    async def request_permission(
        self, options: list[PermissionOption], session_id: str, tool_call: ToolCallUpdate, **kwargs: Any
    ) -> RequestPermissionResponse:
        proxy = self.proxy
        session = proxy._session(session_id)
        try:
            action, problem = action_of_tool_call(tool_call, session.workspace)
        except UnknownKind as exc:
            raise RequestError(REFUSED, str(exc)) from None
        cached = session.decisions.get(tool_call.tool_call_id)
        if problem or action is None:
            if cached is None:
                raise RequestError(REFUSED, problem or f"{tool_call.title}: nothing to decide, so nothing to permit")
            decision = cached
            action = Action(kind="other", title=tool_call.title or "?", **{"class": "write"})
        elif cached is not None and action.path is None and action.command is None and action.url is None:
            # The notification carried the path or the command; the request does not. Its decision holds.
            decision = cached
        else:
            decision = proxy.decide(session, action)
        session.decisions[tool_call.tool_call_id] = decision
        if decision.verdict == "allow":
            option = _select(options, "allow_once", "allow_always")
            if option is None:
                decision = decision.model_copy(
                    update={
                        "verdict": "ask",
                        "sentence": decision.sentence + "; the agent offers no plain allow, so the person is asked",
                    }
                )
            else:
                proxy.count(session, action, decision, tool_call.tool_call_id)
                proxy.audit.write(
                    "permission",
                    session=session_id,
                    tool_call_id=tool_call.tool_call_id,
                    kind=action.kind,
                    **{"class": action.action_class},
                    title=action.title,
                    path=action.path,
                    command=action.command,
                    url=action.url,
                    decision="allow",
                    chosen=option.kind,
                    by="policy",
                    sentence=decision.sentence,
                    rule=decision.rule,
                    scope=decision.scope,
                )
                return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id=option.option_id))
        if decision.verdict == "ask":
            answer = await proxy.ask_person(session, action, decision, tool_call, options, **kwargs)
            if getattr(answer.outcome, "option_id", None) is not None:
                proxy.count(session, action, decision, tool_call.tool_call_id)
            return answer
        option = _select(options, "reject_once", "reject_always")
        proxy.audit.write(
            "permission",
            session=session_id,
            tool_call_id=tool_call.tool_call_id,
            kind=action.kind,
            **{"class": action.action_class},
            title=action.title,
            path=action.path,
            command=action.command,
            url=action.url,
            decision="deny",
            chosen=option.kind if option else "cancelled",
            by="policy",
            sentence=decision.sentence,
            rule=decision.rule,
            scope=decision.scope,
        )
        await proxy.tell(session_id, decision.sentence)
        if option is None:
            return RequestPermissionResponse(outcome=DeniedOutcome(outcome="cancelled"))
        return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id=option.option_id))

    # -- the Shield's own actions (§4.6) --------------------------------------------------

    async def _decide_own(
        self,
        session: SessionState,
        action: Action,
        *,
        locations: list[ToolCallLocation] | None = None,
    ) -> tuple[Decision, str]:
        """Decide an action the Shield answers itself; a row the client sees; a refusal raised.

        A path outside the workspace is refused before any rule: the Shield
        answers files only inside it (§4.6); the policy's *outside* rules are
        for what an agent reaches by itself.
        """
        proxy = self.proxy
        if action.inside is False:
            decision = Decision(
                verdict="deny",
                decided_by="rule",
                scope=None,
                rule="workspace",
                sentence=(
                    f"{action.title}: leave it to me — {action.path} is outside the workspace "
                    f"{session.workspace.root}, and the Shield answers files only inside it"
                ),
            )
        else:
            decision = proxy.decide(session, action)
        call_id = session.next_shield_call_id()
        row_kind = {"fs_read": "read", "fs_write": "edit", "terminal": "execute"}[action.kind]
        event = {"fs_read": "fs_read", "fs_write": "fs_write", "terminal": "terminal"}[action.kind]
        await proxy.client.session_update(
            session_id=session.session_id,
            update=start_tool_call(
                call_id,
                f"{action.title} — {decision.word}",
                kind=row_kind,
                status="pending" if decision.verdict == "ask" else "in_progress",
                locations=locations,
                raw_input={"path": action.path, "command": action.command},
            ),
        )
        if decision.verdict == "ask":
            tool_call = ToolCallUpdate(
                tool_call_id=call_id,
                title=action.title,
                kind=row_kind,
                status="pending",
                raw_input={"path": action.path, "command": action.command},
                content=[tool_content(text_block(decision.sentence))],
            )
            answer = await proxy.ask_person(session, action, decision, tool_call, SHIELD_OPTIONS)
            if getattr(answer.outcome, "option_id", None) != "allow":
                await proxy.client.session_update(
                    session_id=session.session_id, update=update_tool_call(call_id, status="failed")
                )
                raise RequestError(REFUSED, f"{action.title}: the person did not allow it")
            proxy.count(session, action, decision, None)
            return decision, call_id
        proxy.audit.write(
            event,
            session=session.session_id,
            tool_call_id=call_id,
            kind=action.kind,
            **{"class": action.action_class},
            title=action.title,
            path=action.path,
            command=action.command,
            decision=decision.verdict,
            sentence=decision.sentence,
            rule=decision.rule,
            scope=decision.scope,
            decided_by=decision.decided_by,
            by="policy",
        )
        if decision.verdict == "deny":
            await proxy.client.session_update(
                session_id=session.session_id, update=update_tool_call(call_id, status="failed")
            )
            await proxy.tell(session.session_id, decision.sentence)
            raise RequestError(REFUSED, decision.sentence)
        proxy.count(session, action, decision, None)
        return decision, call_id

    async def read_text_file(
        self, path: str, session_id: str, limit: int | None = None, line: int | None = None, **kwargs: Any
    ):
        session = self.proxy._session(session_id)
        placed = session.workspace.place(path)
        action = Action(
            kind="fs_read", title=f"Read {placed.shown}", path=placed.shown, inside=placed.inside, **{"class": "read"}
        )
        _, call_id = await self._decide_own(session, action, locations=[ToolCallLocation(path=path)])
        try:
            content = session.workspace.read_text(path, line=line, limit=limit)
        except (OutsideWorkspace, OSError) as exc:
            await self.proxy.client.session_update(
                session_id=session_id, update=update_tool_call(call_id, status="failed")
            )
            raise RequestError(REFUSED, f"{action.title}: {exc}") from None
        self.proxy.audit.write(
            "fs_read",
            session=session_id,
            tool_call_id=call_id,
            path=placed.shown,
            bytes=len(content.encode("utf-8")),
            what="read",
            by="shield",
        )
        await self.proxy.client.session_update(
            session_id=session_id, update=update_tool_call(call_id, status="completed")
        )
        return ReadTextFileResponse(content=content)

    async def write_text_file(self, content: str, path: str, session_id: str, **kwargs: Any):
        session = self.proxy._session(session_id)
        placed = session.workspace.place(path)
        old_text: str | None = None
        if placed.inside and placed.resolved.is_file():
            with contextlib.suppress(OSError, UnicodeDecodeError):
                old_text = placed.resolved.read_text(encoding="utf-8")
        action = Action(
            kind="fs_write",
            title=f"Write {placed.shown}",
            path=placed.shown,
            inside=placed.inside,
            bytes=len(content.encode("utf-8")),
            **{"class": "write"},
        )
        _, call_id = await self._decide_own(session, action, locations=[ToolCallLocation(path=path)])
        try:
            session.workspace.write_text(path, content)
        except (OutsideWorkspace, OSError) as exc:
            await self.proxy.client.session_update(
                session_id=session_id, update=update_tool_call(call_id, status="failed")
            )
            raise RequestError(REFUSED, f"{action.title}: {exc}") from None
        self.proxy.audit.write(
            "fs_write",
            session=session_id,
            tool_call_id=call_id,
            diff=diff_summary(placed.shown, content, old_text),
            by="shield",
        )
        await self.proxy.client.session_update(
            session_id=session_id,
            update=update_tool_call(call_id, status="completed", content=[tool_diff_content(path, content, old_text)]),
        )
        return WriteTextFileResponse()

    async def create_terminal(
        self,
        command: str,
        session_id: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        env: list | None = None,
        output_byte_limit: int | None = None,
        **kwargs: Any,
    ):
        session = self.proxy._session(session_id)
        if session.terminals is None:  # pragma: no cover - opened with the session
            raise RequestError(REFUSED, f"session {session_id!r} has no terminals")
        shown = " ".join([command, *(args or [])])
        action = Action(kind="terminal", title=f"Run `{shown}`", command=shown, **{"class": "execute"})
        _, call_id = await self._decide_own(session, action)
        try:
            run = await session.terminals.create(
                command, args, cwd, {item.name: item.value for item in env or []}, output_byte_limit
            )
        except (OutsideWorkspace, OSError) as exc:
            await self.proxy.client.session_update(
                session_id=session_id, update=update_tool_call(call_id, status="failed")
            )
            raise RequestError(REFUSED, f"{action.title}: {exc}") from None
        self.proxy.audit.write(
            "terminal",
            session=session_id,
            terminal_id=run.terminal_id,
            tool_call_id=call_id,
            what="create",
            command=shown,
            cwd=str(run.cwd),
            by="shield",
        )
        await self.proxy.client.session_update(
            session_id=session_id,
            update=update_tool_call(call_id, status="in_progress", content=[tool_terminal_ref(run.terminal_id)]),
        )
        return CreateTerminalResponse(terminal_id=run.terminal_id)

    def _terminals(self, session_id: str) -> Terminals:
        session = self.proxy._session(session_id)
        if session.terminals is None:  # pragma: no cover - opened with the session
            raise RequestError(REFUSED, f"session {session_id!r} has no terminals")
        return session.terminals

    async def terminal_output(self, session_id: str, terminal_id: str, **kwargs: Any):
        try:
            run = self._terminals(session_id).get(terminal_id)
        except KeyError as exc:
            raise RequestError(REFUSED, str(exc)) from None
        exit_status = TerminalExitStatus(exit_code=run.exit_code, signal=run.signal) if run.exited else None
        return TerminalOutputResponse(
            output=run.output.decode("utf-8", "replace"), truncated=run.truncated, exit_status=exit_status
        )

    async def wait_for_terminal_exit(self, session_id: str, terminal_id: str, **kwargs: Any):
        try:
            run = await self._terminals(session_id).wait(terminal_id)
        except KeyError as exc:
            raise RequestError(REFUSED, str(exc)) from None
        self.proxy.audit.write(
            "terminal",
            session=session_id,
            terminal_id=terminal_id,
            what="exit",
            exit_code=run.exit_code,
            signal=run.signal,
            by="shield",
        )
        return WaitForTerminalExitResponse(exit_code=run.exit_code, signal=run.signal)

    async def kill_terminal(self, session_id: str, terminal_id: str, **kwargs: Any):
        try:
            await self._terminals(session_id).kill(terminal_id)
        except KeyError as exc:
            raise RequestError(REFUSED, str(exc)) from None
        self.proxy.audit.write("terminal", session=session_id, terminal_id=terminal_id, what="kill", by="shield")
        return KillTerminalCommandResponse()

    async def release_terminal(self, session_id: str, terminal_id: str, **kwargs: Any):
        session = self.proxy._session(session_id)
        try:
            run = await self._terminals(session_id).release(terminal_id)
        except KeyError as exc:
            raise RequestError(REFUSED, str(exc)) from None
        session.state.terminal_released()
        self.proxy.audit.write(
            "terminal",
            session=session_id,
            terminal_id=terminal_id,
            what="release",
            exit_code=run.exit_code,
            signal=run.signal,
            by="shield",
        )
        return ReleaseTerminalResponse()

    # -- questions and extensions --------------------------------------------------------

    async def elicitation(self, session_id: str, params: dict[str, Any]) -> Any:
        self.proxy._session(session_id)
        self.proxy.audit.write("turn", session=session_id, what="question", by="agent")
        # The SDK's agent-side connection routes no elicitation; its connection does.
        return await self.proxy.client._conn.send_request("elicitation/create", params)

    async def ext_method(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self.proxy.client.ext_method(method, params)

    async def ext_notification(self, method: str, params: dict[str, Any]) -> None:
        await self.proxy.client.ext_notification(method, params)


@asynccontextmanager
async def proxy_running(proxy: ShieldProxy) -> AsyncIterator[ShieldProxy]:
    try:
        yield proxy
    finally:
        await proxy.stop_agent()


async def serve_stdio(proxy: ShieldProxy) -> None:
    """Run the proxy as an ACP agent on this process's stdio until the client goes away."""
    async with proxy_running(proxy):
        await run_agent(proxy)


def stderr_passthrough(line: str) -> None:
    sys.stderr.write(line)
    sys.stderr.flush()


__all__ = [
    "REFUSED",
    "SHIELD_OPTIONS",
    "ProxyRefused",
    "SessionState",
    "ShieldProxy",
    "action_of_tool_call",
    "lend_mcp_servers",
    "proxy_running",
    "serve_stdio",
    "stderr_passthrough",
]
