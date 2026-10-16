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
