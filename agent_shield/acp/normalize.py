# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""``session/update`` → one neutral event; a malformed update ends the turn with a sentence."""

from __future__ import annotations

from typing import Any

from acp.schema import SessionNotification
from pydantic import ValidationError

from .events import (
    Command,
    CommandsUpdated,
    Diff,
    Display,
    Event,
    Location,
    ModeChanged,
    PlanStep,
    PlanUpdated,
    SessionInfo,
    Terminal,
    Text,
    TextDelta,
    ThoughtDelta,
    ToolCallSaid,
    ToolCallUpdated,
    UserText,
)


class MalformedUpdate(ValueError):
    """An update the protocol does not describe: no silent drop, the turn ends with this."""


def _text_of(content: Any, what: str) -> str:
    block_type = getattr(content, "type", None)
    if block_type == "text":
        return content.text
    if block_type in ("image", "audio"):
        return f"[{block_type}]"
    if block_type == "resource_link":
        return f"[{content.name}]({content.uri})"
    if block_type == "resource":
        resource = content.resource
        return getattr(resource, "text", None) or f"[resource {resource.uri}]"
    raise MalformedUpdate(f"{what} carries a content block of type {block_type!r}, which ACP does not name")


def _displays(content: list[Any] | None) -> list[Display]:
    displays: list[Display] = []
    for item in content or []:
        kind = getattr(item, "type", None)
        if kind == "diff":
            displays.append(Diff(path=item.path, old_text=item.old_text, new_text=item.new_text))
        elif kind == "terminal":
            displays.append(Terminal(terminal_id=item.terminal_id))
        elif kind == "content":
            displays.append(Text(text=_text_of(item.content, "a tool call's content")))
        else:
            raise MalformedUpdate(f"a tool call carries content of type {kind!r}, which ACP does not name")
    return displays


def _locations(locations: list[Any] | None) -> list[Location]:
    return [Location(path=item.path, line=item.line) for item in locations or []]


def normalize(session_id: str, update: Any) -> Event:
    """One ``session/update``'s ``update`` (an SDK model, or its wire dict) as an event."""
    if isinstance(update, dict):
        try:
            update = SessionNotification.model_validate({"sessionId": session_id, "update": update}).update
        except ValidationError as exc:
            first = exc.errors()[0]
            raise MalformedUpdate(f"session/update is not one ACP describes: {first['msg']}") from None
    kind = getattr(update, "session_update", None)
    if kind == "agent_message_chunk":
        return TextDelta(session_id=session_id, text=_text_of(update.content, "agent_message_chunk"))
    if kind == "agent_thought_chunk":
        return ThoughtDelta(session_id=session_id, text=_text_of(update.content, "agent_thought_chunk"))
    if kind == "user_message_chunk":
        return UserText(session_id=session_id, text=_text_of(update.content, "user_message_chunk"))
    if kind == "tool_call":
        if update.kind is None:
            raise MalformedUpdate(
                f"tool_call {update.tool_call_id!r} ({update.title}) names no kind, so it cannot be classed"
            )
        status = update.status or "pending"
        return ToolCallSaid(
            session_id=session_id,
            tool_call_id=update.tool_call_id,
            title=update.title,
            kind=update.kind,
            status=status,
            input=update.raw_input,
            locations=_locations(update.locations),
            displays=_displays(update.content),
            awaiting=status == "pending",
        )
    if kind == "tool_call_update":
        return ToolCallUpdated(
            session_id=session_id,
            tool_call_id=update.tool_call_id,
            title=update.title,
            kind=update.kind,
            status=update.status,
            input=update.raw_input,
            output=update.raw_output,
            locations=_locations(update.locations),
            displays=_displays(update.content),
        )
    if kind == "plan":
        return PlanUpdated(
            session_id=session_id,
            steps=[PlanStep(content=e.content, priority=e.priority, status=e.status) for e in update.entries],
        )
    if kind == "available_commands_update":
        return CommandsUpdated(
            session_id=session_id,
            commands=[Command(name=c.name, description=c.description) for c in update.available_commands],
        )
    if kind == "current_mode_update":
        return ModeChanged(session_id=session_id, mode_id=update.current_mode_id)
    if kind == "session_info_update":
        return SessionInfo(session_id=session_id, info=update.model_dump(by_alias=True, exclude_none=True))
    raise MalformedUpdate(f"session/update of kind {kind!r} is not one ACP describes")


__all__ = ["MalformedUpdate", "normalize"]
