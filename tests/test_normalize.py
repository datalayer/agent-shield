# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""``session/update`` → neutral events (SHIELD §4.1); a malformed update is a sentence."""

from __future__ import annotations

import pytest
from acp import (
    plan_entry,
    start_tool_call,
    text_block,
    tool_diff_content,
    tool_terminal_ref,
    update_agent_message_text,
    update_agent_thought_text,
    update_plan,
    update_tool_call,
    update_user_message_text,
)
from acp.helpers import update_available_commands, update_current_mode
from acp.schema import AvailableCommand, ImageContentBlock, ToolCallLocation

from agent_shield.acp import MalformedUpdate, normalize
from agent_shield.acp.events import (
    CommandsUpdated,
    Diff,
    ModeChanged,
    PlanUpdated,
    Terminal,
    Text,
    TextDelta,
    ThoughtDelta,
    ToolCallSaid,
    ToolCallUpdated,
    UserText,
)


def test_text_thought_and_user_chunks():
    assert normalize("s", update_agent_message_text("hi")) == TextDelta(session_id="s", text="hi")
    assert normalize("s", update_agent_thought_text("hm")) == ThoughtDelta(session_id="s", text="hm")
    assert normalize("s", update_user_message_text("yo")) == UserText(session_id="s", text="yo")


def test_an_image_chunk_is_said_not_dropped():
    update = update_agent_message_text("x")
    update.content = ImageContentBlock(type="image", data="AAAA", mime_type="image/png")
    assert normalize("s", update).text == "[image]"


def test_a_tool_call_carries_kind_status_input_locations_and_awaits_while_pending():
    update = start_tool_call(
        "c1", "Edit README.md", kind="edit", status="pending",
        locations=[ToolCallLocation(path="README.md", line=3)], raw_input={"path": "README.md"},
        content=[tool_diff_content("README.md", "new", "old")],
    )
    event = normalize("s", update)
    assert event == ToolCallSaid(
        session_id="s", tool_call_id="c1", title="Edit README.md", kind="edit", status="pending",
        input={"path": "README.md"}, locations=[{"path": "README.md", "line": 3}],
        displays=[Diff(path="README.md", old_text="old", new_text="new")], awaiting=True,
    )


def test_a_tool_call_with_no_status_is_pending():
    event = normalize("s", start_tool_call("c1", "Read", kind="read"))
    assert event.status == "pending" and event.awaiting


def test_a_tool_call_naming_no_kind_ends_the_turn_in_a_sentence():
    with pytest.raises(MalformedUpdate, match="tool_call 'c1' \\(Mystery\\) names no kind"):
        normalize("s", start_tool_call("c1", "Mystery"))


def test_a_tool_call_update_carries_the_displays():
    update = update_tool_call(
        "c1", status="completed", content=[tool_terminal_ref("t1"), tool_diff_content("a", "n")], raw_output={"ok": 1}
    )
    event = normalize("s", update)
    assert event == ToolCallUpdated(
        session_id="s", tool_call_id="c1", status="completed", output={"ok": 1},
        displays=[Terminal(terminal_id="t1"), Diff(path="a", new_text="n")],
    )


def test_text_content_of_a_tool_call_is_a_text_display():
    from acp import tool_content

    event = normalize("s", update_tool_call("c1", content=[tool_content(text_block("out"))]))
    assert event.displays == [Text(text="out")]


def test_plan_commands_and_mode():
    plan = normalize("s", update_plan([plan_entry("a", priority="high", status="in_progress")]))
    assert plan == PlanUpdated(session_id="s", steps=[{"content": "a", "priority": "high", "status": "in_progress"}])
    commands = normalize("s", update_available_commands([AvailableCommand(name="plan", description="Plan it")]))
    assert commands == CommandsUpdated(session_id="s", commands=[{"name": "plan", "description": "Plan it"}])
    assert normalize("s", update_current_mode("plan")) == ModeChanged(session_id="s", mode_id="plan")


def test_a_wire_dict_is_normalized_too():
    event = normalize("s", {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "hi"}})
    assert event == TextDelta(session_id="s", text="hi")


def test_a_wire_dict_acp_does_not_describe_is_a_sentence():
    with pytest.raises(MalformedUpdate, match="session/update is not one ACP describes"):
        normalize("s", {"sessionUpdate": "telepathy", "content": {"type": "text", "text": "hi"}})


def test_an_unknown_model_kind_is_a_sentence():
    class Odd:
        session_update = "odd_update"

    with pytest.raises(MalformedUpdate, match="kind 'odd_update' is not one ACP describes"):
        normalize("s", Odd())
