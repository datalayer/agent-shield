# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Shield over OTEL: one trace across the chain, counts under the account (SHIELD §6.8, SH-51).

The ACP session is a trace, each prompt a span (:func:`turn_span`), and every
audit row a span event and a count (:func:`observe`) in the audit's safe
vocabulary — the event, the kind and class, the decision and who decided,
never a path's content or a credential. The trace context arrives with the
face — A2A's and AG-UI's ``traceparent`` — and is handed on: to the harness
in the prompt's ``_meta.traceparent`` (:func:`with_traceparent`, the key ACP
reserves for it), to a lent MCP server as HTTP headers (:func:`trace_headers`).

OpenTelemetry is optional: without it every function here does nothing and
returns what it was given, so a standalone Shield without the SDK keeps
deciding. With the API alone (no SDK configured) the global provider is a
no-op and so is this. **No span, no header, and never an invented one**: a
fabricated ``traceparent`` is an orphan that looks real and joins to nothing.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)

#: The tracer and meter name.
INSTRUMENTATION = "agent_shield"

#: The key ACP reserves in ``_meta`` for the W3C trace context.
META_TRACEPARENT = "traceparent"
META_TRACESTATE = "tracestate"

#: What is counted, and the labels each count carries (held equal by the OTEL
#: service's dashboards catalogue, `datalayer_otel.dashboards.SHIELD_CATALOGUE`).
CATALOGUE: dict[str, tuple[str, ...]] = {
    "shield.actions": ("event", "kind", "class", "decision", "by", "harness", "deployment", "usage_account_uid"),
    "shield.decisions": ("decision", "decided_by", "class", "kind", "harness", "deployment", "usage_account_uid"),
    "shield.refusals": ("event", "decided_by", "harness", "deployment", "usage_account_uid"),
    "shield.limits": ("limit", "harness", "deployment", "usage_account_uid"),
}

#: The row's fields that go on a span event: the safe vocabulary, nothing else.
EVENT_FIELDS = (
    "event",
    "session",
    "what",
    "kind",
    "class",
    "title",
    "path",
    "command",
    "url",
    "status",
    "decision",
    "decided_by",
    "by",
    "rule",
    "scope",
    "chosen",
    "tool_call_id",
    "terminal_id",
    "exit_code",
    "stop_reason",
    "limit",
    "steps",
    "server",
)

_counters: dict[str, Any] | None = None
#: Labels every count carries, set by the host (the harness, the deployment, the account).
_labels: dict[str, str] = {}


def set_labels(**labels: str) -> None:
    """The labels every count and span carries from now on: ``harness``, ``deployment``, ``usage_account_uid``."""
    _labels.update({key: str(value) for key, value in labels.items() if value})


def labels() -> dict[str, str]:
    return dict(_labels)


def _otel() -> tuple[Any, Any] | None:
    try:
        from opentelemetry import metrics, trace
    except Exception:  # noqa: BLE001 - telemetry is optional
        return None
    return trace, metrics


def _instruments() -> dict[str, Any]:
    global _counters
    if _counters is not None:
        return _counters
    found = _otel()
    if found is None:
        _counters = {}
        return _counters
    meter = found[1].get_meter_provider().get_meter(INSTRUMENTATION)
    _counters = {
        name: meter.create_counter(name=name, description=f"Shield {name.split('.', 1)[1]}", unit="1")
        for name in CATALOGUE
    }
    return _counters


def reset_instruments() -> None:
    """Forget the counters, so a test's meter provider makes new ones."""
    global _counters
    _counters = None


def _attributes(row: Mapping[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    attributes = {name: row[name] for name in names if row.get(name) is not None and name not in _labels}
    attributes.update({name: value for name, value in _labels.items() if name in names})
    return {key: (value if isinstance(value, (str, int, float, bool)) else str(value)) for key, value in attributes.items()}


def observe(row: Mapping[str, Any]) -> None:
    """One audit row as a span event on the current span and as counts.

    Called by the audit after redaction, so what reaches the trace is what
    reaches the log and nothing more.
    """
    found = _otel()
    if found is None:
        return
    event = str(row.get("event") or "")
    try:
        span = found[0].get_current_span()
        if span is not None and span.is_recording():
            span.add_event(f"shield.{event}", attributes=_attributes(row, EVENT_FIELDS))
        counters = _instruments()
        if not counters:
            return
        counters["shield.actions"].add(1, _attributes(row, CATALOGUE["shield.actions"]))
        decision = row.get("decision")
        if decision in ("allow", "ask", "deny"):
            counters["shield.decisions"].add(1, _attributes(row, CATALOGUE["shield.decisions"]))
        if decision == "deny" or event == "refusal":
            counters["shield.refusals"].add(
                1, _attributes({**row, "event": event, "decided_by": row.get("decided_by") or row.get("by")}, CATALOGUE["shield.refusals"])
            )
        if event == "limit":
            counters["shield.limits"].add(1, _attributes(row, CATALOGUE["shield.limits"]))
    except Exception as error:  # noqa: BLE001 - the story about the work is worth less than the work
        logger.debug("The Shield's telemetry could not take a row: %s", error)


@contextmanager
def turn_span(session_id: str, **attributes: Any) -> Iterator[Any]:
    """One prompt as a span, a child of whatever is current (the face's request), or nothing without OTEL."""
    found = _otel()
    if found is None:
        yield None
        return
    carried = {"shield.session": session_id, **_labels, **{k: v for k, v in attributes.items() if v is not None}}
    tracer = found[0].get_tracer_provider().get_tracer(INSTRUMENTATION)
    with tracer.start_as_current_span("shield.turn", attributes=carried) as span:
        yield span


def trace_headers() -> dict[str, str]:
    """The current trace context as W3C headers, or nothing when there is none."""
    try:
        from opentelemetry.propagate import inject
    except Exception:  # noqa: BLE001
        return {}
    carrier: dict[str, str] = {}
    try:
        inject(carrier)
    except Exception as error:  # noqa: BLE001
        logger.debug("The trace context could not be injected: %s", error)
        return {}
    return carrier


def with_traceparent(meta: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    """``meta`` with the current ``traceparent`` (and ``tracestate``) added when there is one and ``meta`` names none.

    What the harness is handed in the prompt's ``_meta``: the key ACP
    reserves, so a harness that honours it continues the trace into its own
    tool calls. ``None`` when there is nothing to carry and nothing given.
    """
    carried = dict(meta or {})
    if META_TRACEPARENT in carried:
        return carried
    headers = trace_headers()
    if headers.get(META_TRACEPARENT):
        carried[META_TRACEPARENT] = headers[META_TRACEPARENT]
        if headers.get(META_TRACESTATE):
            carried[META_TRACESTATE] = headers[META_TRACESTATE]
    return carried or None


def traceparent_of(meta: Mapping[str, Any] | None) -> str | None:
    """The ``traceparent`` a ``_meta`` carries, when it carries one."""
    value = (meta or {}).get(META_TRACEPARENT)
    return str(value) if value else None


@contextmanager
def continued(traceparent: str | None, tracestate: str | None = None) -> Iterator[None]:
    """Continue the trace a caller handed in (its ``_meta.traceparent``), when this process is not already on one."""
    found = _otel()
    if found is None or not traceparent:
        yield
        return
    try:
        from opentelemetry import context as otel_context
        from opentelemetry.propagate import extract
    except Exception:  # noqa: BLE001
        yield
        return
    current = found[0].get_current_span()
    if current is not None and current.get_span_context().is_valid:
        yield
        return
    carrier = {META_TRACEPARENT: traceparent}
    if tracestate:
        carrier[META_TRACESTATE] = tracestate
    token = otel_context.attach(extract(carrier))
    try:
        yield
    finally:
        otel_context.detach(token)


__all__ = [
    "CATALOGUE",
    "EVENT_FIELDS",
    "INSTRUMENTATION",
    "META_TRACEPARENT",
    "continued",
    "labels",
    "observe",
    "reset_instruments",
    "set_labels",
    "trace_headers",
    "traceparent_of",
    "turn_span",
    "with_traceparent",
]
