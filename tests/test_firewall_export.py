# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The firewall's rows to OTEL, one span each (Agent Firewall N3-03)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_shield.audit import AuditLog
from agent_shield.cli import app
from agent_shield.firewall import ConnectionRecorder
from agent_shield.firewall.export import SPAN_NAMES, export_row, row_attributes, runtime_uid
from agent_shield.firewall.nflog import Connection

pytest.importorskip("opentelemetry.sdk", reason="the OTEL SDK is optional; without it the rows stay on stdout")

runner = CliRunner()


@pytest.fixture
def spans(monkeypatch: pytest.MonkeyPatch):
    """Spans collected without touching the process-wide provider, which refuses a second set."""
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(otel_trace, "get_tracer_provider", lambda: provider)
    return exporter


class FakeKernel:
    def __call__(self, argv, stdin=""):
        return 0, ""


def test_a_connection_row_is_a_span_with_the_decision_and_the_destination(spans, tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.jsonl", environment={})
    recorder = ConnectionRecorder(audit, host_of=lambda a: "api.tavily.com" if a == "198.51.100.7" else None)
    allowed = recorder.record(Connection("allow", "spec:*", "tcp", "10.244.1.5", "198.51.100.7", 40000, 443))
    refused = recorder.record(Connection("refuse", "default", "tcp", "10.244.1.5", "10.0.0.9", 40001, 5432))
    assert export_row(allowed, runtime="01runtime") and export_row(refused, runtime="01runtime")
    first, second = spans.get_finished_spans()
    assert first.name == SPAN_NAMES["connection"] == "shield.firewall.connection"
    assert dict(first.attributes) == {
        "shield.event": "connection",
        "datalayer.runtime_uid": "01runtime",
        "shield.decision": "allow",
        "shield.rule": "spec:*",
        "shield.destination": "198.51.100.7:443",
        "shield.host": "api.tavily.com",
        "shield.port": 443,
        "shield.protocol": "tcp",
        "shield.source": "10.244.1.5",
    }
    assert second.attributes["shield.decision"] == "refuse"
    assert second.attributes["shield.destination"] == "10.0.0.9:5432"
    assert "shield.host" not in second.attributes
    # Each is a root of its own: a connection belongs to no request.
    assert first.parent is None and first.context.trace_id != second.context.trace_id


def test_a_firewall_row_is_an_apply_span():
    attributes = row_attributes(
        {
            "event": "firewall",
            "reason": "configure",
            "revision": "42",
            "egress": ["*"],
            "base": ["gateway"],
            "rules": 9,
        }
    )
    assert attributes == {
        "shield.event": "firewall",
        "shield.reason": "configure",
        "shield.revision": "42",
        "shield.egress": ["*"],
        "shield.base": ["gateway"],
        "shield.rules": 9,
    }


def test_other_rows_are_not_exported(spans):
    assert export_row({"event": "permission", "decision": "allow"}) is False
    assert spans.get_finished_spans() == ()
    with pytest.raises(ValueError, match="not a firewall row"):
        row_attributes({"event": "permission"})


def test_the_runtime_uid_is_the_sidecars_environment():
    assert runtime_uid({"AGENT_SHIELD_RUNTIME_UID": "a", "DATALAYER_RUNTIME_ID": "b"}) == "a"
    assert runtime_uid({"DATALAYER_RUNTIME_ID": "b"}) == "b"
    assert runtime_uid({}) is None


def test_watch_exports_its_rows_as_spans(spans, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agent_shield.firewall.controller.run_command", FakeKernel())
    monkeypatch.setenv("AGENT_SHIELD_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("DATALAYER_RUNTIME_ID", "01runtime")
    rules = tmp_path / "spec.json"
    rules.write_text(json.dumps({"revision": "7", "shield": {"egress": ["*"]}}))
    state = tmp_path / "state"
    args = ["firewall", "watch", "--rules", str(rules), "--state", str(state), "--once", "--no-audit-file"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    applied = [span for span in spans.get_finished_spans() if span.name == "shield.firewall.apply"]
    assert [span.attributes.get("shield.reason") for span in applied] == ["start", "start"]
    assert applied[-1].attributes["shield.revision"] == "7"
    assert applied[-1].attributes["datalayer.runtime_uid"] == "01runtime"


def test_watch_without_export_writes_no_span(spans, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agent_shield.firewall.controller.run_command", FakeKernel())
    monkeypatch.setenv("AGENT_SHIELD_HOME", str(tmp_path / "home"))
    args = ["firewall", "watch", "--rules", str(tmp_path / "none.json"), "--state", str(tmp_path / "s"), "--once"]
    result = runner.invoke(app, [*args, "--no-export", "--no-audit-file"])
    assert result.exit_code == 0, result.output
    assert spans.get_finished_spans() == ()
