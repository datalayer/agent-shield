# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The neutral events of the package: SHIELD §4.1's left column, typed.

These are the package's own, small on purpose: agent-runtimes maps them onto
its ``ProtocolEvent``s, the landing onto its rows. Nothing here imports the
runtime.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str


class TextDelta(_Event):
    """``agent_message_chunk``: the answer, streamed."""

    event: Literal["text"] = "text"
    text: str


class ThoughtDelta(_Event):
    """``agent_thought_chunk``: reasoning, kept in the record, folded on the page."""

    event: Literal["thought"] = "thought"
    text: str


class UserText(_Event):
    """``user_message_chunk``: what the person said, replayed by ``session/load``."""

    event: Literal["user_text"] = "user_text"
    text: str


class Diff(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display: Literal["diff"] = "diff"
    path: str
    old_text: str | None = None
    new_text: str


class Terminal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display: Literal["terminal"] = "terminal"
    terminal_id: str


class Text(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display: Literal["text"] = "text"
    text: str


Display = Diff | Terminal | Text


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    line: int | None = None


class ToolCallSaid(_Event):
    """``tool_call``: a tool row titled by the harness, its kind as its icon."""

    event: Literal["tool_call"] = "tool_call"
    tool_call_id: str
    title: str
    kind: str
    status: str
    input: Any = None
    locations: list[Location] = Field(default_factory=list)
    displays: list[Display] = Field(default_factory=list)
    awaiting: bool = Field(default=False, description="``pending``: the row waits.")


class ToolCallUpdated(_Event):
    """``tool_call_update``: the row's status and its displays (a diff, a terminal)."""

    event: Literal["tool_call_update"] = "tool_call_update"
    tool_call_id: str
    title: str | None = None
    kind: str | None = None
    status: str | None = None
    input: Any = None
    output: Any = None
    locations: list[Location] = Field(default_factory=list)
    displays: list[Display] = Field(default_factory=list)


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str
    priority: str
    status: str


class PlanUpdated(_Event):
    """``plan``: the plan card, steps ticked, replaced as it progresses."""

    event: Literal["plan"] = "plan"
    steps: list[PlanStep]


class Command(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str


class CommandsUpdated(_Event):
    """``available_commands_update``: slash commands for the composer."""

    event: Literal["commands"] = "commands"
    commands: list[Command]


class ModeChanged(_Event):
    """``current_mode_update``: the mode in the header."""

    event: Literal["mode"] = "mode"
    mode_id: str


class SessionInfo(_Event):
    """``session_info_update``: a title, a timestamp."""

    event: Literal["session_info"] = "session_info"
    info: dict[str, Any]


class PermissionAsked(_Event):
    """``session/request_permission``: the row awaits an approval (§4.5)."""

    event: Literal["permission"] = "permission"
    tool_call_id: str
    title: str | None
    kind: str | None
    options: list[dict[str, str]]


class Question(_Event):
    """``elicitation/create``: a question the person answers."""

    event: Literal["question"] = "question"
    message: str
    schema_: dict[str, Any] | None = Field(default=None, alias="schema")


class ShieldAction(_Event):
    """An ``fs/*`` or ``terminal/*`` the Shield answered: visible, decided, recorded."""

    event: Literal["shield_action"] = "shield_action"
    kind: Literal["fs_read", "fs_write", "terminal"]
    title: str
    path: str | None = None
    command: str | None = None
    verdict: str
    sentence: str


class TurnEnded(_Event):
    """``session/prompt``'s answer: why the turn stopped."""

    event: Literal["turn_ended"] = "turn_ended"
    stop_reason: str


Event = (
    TextDelta
    | ThoughtDelta
    | UserText
    | ToolCallSaid
    | ToolCallUpdated
    | PlanUpdated
    | CommandsUpdated
    | ModeChanged
    | SessionInfo
    | PermissionAsked
    | Question
    | ShieldAction
    | TurnEnded
)

__all__ = [
    "Command",
    "CommandsUpdated",
    "Diff",
    "Display",
    "Event",
    "Location",
    "ModeChanged",
    "PermissionAsked",
    "PlanStep",
    "PlanUpdated",
    "Question",
    "SessionInfo",
    "ShieldAction",
    "Terminal",
    "Text",
    "TextDelta",
    "ThoughtDelta",
    "ToolCallSaid",
    "ToolCallUpdated",
    "TurnEnded",
    "UserText",
]
