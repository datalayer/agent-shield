# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Shield over OTEL (SH-51): rows as events and counts, the trace handed on."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_shield import tracing
from agent_shield.audit import EVENTS, AuditLog

TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

otel_sdk = pytest.importorskip("opentelemetry.sdk", reason="the OTEL SDK is optional; without it the Shield only decides")


@pytest.fixture
def recording(monkeypatch: pytest.MonkeyPatch):
    """Spans and points collected without touching the process-wide providers, which refuse a second set."""
    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    monkeypatch.setattr(otel_trace, "get_tracer_provider", lambda: provider)
    monkeypatch.setattr(otel_metrics, "get_meter_provider", lambda: meter_provider)
    tracing.reset_instruments()
    yield exporter, reader
    tracing.reset_instruments()
    tracing._labels.clear()


def points_of(reader) -> dict[str, list[dict]]:
    return {
        metric.name: [dict(point.attributes) for point in metric.data.data_points]
        for resource in reader.get_metrics_data().resource_metrics
        for scope in resource.scope_metrics
        for metric in scope.metrics
    }


def test_the_audit_writes_a_row_as_an_event_and_counts_it(recording, tmp_path: Path):
    exporter, reader = recording
    log = AuditLog(tmp_path / "audit.jsonl", environment={})
    tracing.set_labels(harness="claude-code", deployment="dep-1")
    with tracing.turn_span("s1"):
        log.write("permission", session="s1", kind="execute", **{"class": "execute"}, title="Run `rm -rf x`",
                  command="rm -rf x", decision="deny", chosen="reject_once", by="policy", sentence="leave it to me", rule="r")
        log.write("limit", session="s1", limit="terminals", decision="deny", by="shield", sentence="2 terminals at once reached")
        log.write("plan", session="s1", steps=2, by="agent")
    (span,) = exporter.get_finished_spans()
    assert span.attributes["harness"] == "claude-code" and span.attributes["shield.session"] == "s1"
    assert [event.name for event in span.events] == ["shield.permission", "shield.limit", "shield.plan"]
    assert span.events[0].attributes["command"] == "rm -rf x" and "sentence" not in span.events[0].attributes
    points = points_of(reader)
    assert points["shield.decisions"] == [{"decision": "deny", "class": "execute", "kind": "execute", "harness": "claude-code", "deployment": "dep-1"},
                                          {"decision": "deny", "harness": "claude-code", "deployment": "dep-1"}]
    assert points["shield.limits"] == [{"limit": "terminals", "harness": "claude-code", "deployment": "dep-1"}]
    assert len(points["shield.actions"]) == 3


def test_plan_is_an_audit_event():
    assert "plan" in EVENTS


def test_the_prompts_meta_carries_the_trace_the_face_arrived_on(recording):
    with tracing.continued(TRACEPARENT):
        with tracing.turn_span("s1"):
            meta = tracing.with_traceparent({"other": 1})
            headers = tracing.trace_headers()
    assert meta["other"] == 1
    assert meta["traceparent"].startswith("00-0af7651916cd43dd8448eb211c80319c-")
    assert headers["traceparent"] == meta["traceparent"]
    assert tracing.traceparent_of(meta) == meta["traceparent"]


def test_a_callers_own_meta_traceparent_wins(recording):
    with tracing.turn_span("s1"):
        assert tracing.with_traceparent({"traceparent": "00-aa-bb-01"}) == {"traceparent": "00-aa-bb-01"}


def test_no_trace_no_header_never_an_invented_one(recording):
    assert tracing.with_traceparent(None) is None
    assert tracing.trace_headers() == {}
    assert tracing.traceparent_of(None) is None


def test_continued_does_not_replace_a_trace_already_current(recording):
    exporter, _ = recording
    with tracing.turn_span("outer"):
        with tracing.continued(TRACEPARENT):
            with tracing.turn_span("inner"):
                pass
    inner, outer = exporter.get_finished_spans()
    assert inner.context.trace_id == outer.context.trace_id
    assert format(inner.context.trace_id, "032x") != "0af7651916cd43dd8448eb211c80319c"


def test_the_catalogue_names_what_a_count_carries():
    assert set(tracing.CATALOGUE) == {"shield.actions", "shield.decisions", "shield.refusals", "shield.limits"}
    for labels in tracing.CATALOGUE.values():
        assert {"harness", "deployment", "usage_account_uid"} <= set(labels)


async def test_each_proxied_prompt_is_a_turn_span(recording, tmp_path: Path):
    """A Shield in front of an agent sends each prompt as a `shield.turn` span, with how it stopped."""
    import sys

    pytest.importorskip("aiohttp", reason="`serve` needs the serve extra")
    pytest.importorskip("websockets", reason="the WebSocket channel needs the websocket extra")
    from acp import text_block

    from agent_shield.acp import WebSocketACPChannel
    from agent_shield.acp.proxy import ShieldProxy
    from agent_shield.acp.server import ACP_PATH, ShieldServer
    from agent_shield.policy import LoadedPolicy, default_policy

    exporter, _ = recording
    fake = str(Path(__file__).parent / "fixtures" / "fake_agent.py")
    audit = AuditLog(tmp_path / "audit.jsonl", environment={})

    def make() -> ShieldProxy:
        return ShieldProxy(
            [sys.executable, fake],
            policies=[LoadedPolicy(policy=default_policy(), origin="the default")],
            audit=audit,
            workspace=tmp_path,
        )

    class Client:
        async def session_update(self, session_id, update, **kw):
            return None

    served = ShieldServer({"": make}, audit=audit, idle_seconds=5.0)
    await served.start("127.0.0.1", 0)
    try:
        async with WebSocketACPChannel.connect(Client(), f"ws://127.0.0.1:{served.port}{ACP_PATH}") as channel:
            await channel.initialize()
            session = await channel.new_session(tmp_path)
            await channel.prompt(session.session_id, [text_block("hello")])
    finally:
        await served.stop()
    turns = [span for span in exporter.get_finished_spans() if span.name == "shield.turn"]
    assert len(turns) == 1
    assert turns[0].attributes["shield.stop_reason"] == "end_turn"
    assert {event.name for event in turns[0].events} >= {"shield.turn"}


def _token(claims: dict) -> str:
    import base64
    import json

    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{body}.sig"


def test_the_exported_telemetry_names_its_account():
    """The ingest files telemetry by the resource's account; without it nothing can be read back."""
    assert tracing.subject_of_token(_token({"user": {"uid": "u1"}})) == "u1"
    assert tracing.subject_of_token(_token({"sub": {"uid": "u2"}})) == "u2"
    assert tracing.subject_of_token(_token({"sub": "agent-3"})) == "agent-3"
    assert tracing.subject_of_token("not-a-jwt") == ""
    resource = tracing.export_resource(
        _token({"sub": "agent-3"}), service_name="agent-shield", usage_account_uid="org-1", **{"shield.agent": "a"}
    )
    assert resource == {
        "service.name": "agent-shield",
        "datalayer.user_uid": "agent-3",
        "datalayer.usage_account_uid": "org-1",
        "shield.agent": "a",
    }
    assert "datalayer.usage_account_uid" not in tracing.export_resource("x", service_name="agent-shield")
