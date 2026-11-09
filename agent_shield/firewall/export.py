# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The firewall's rows to OTEL: one span per ``connection`` and ``firewall`` row (Agent Firewall N3-03).

``firewall watch`` writes every row to its audit (stdout, and a file unless
``--no-audit-file``); the audit's counts reach OTEL through
:func:`agent_shield.tracing.observe`, but a count carries no destination. So
each ``connection`` row (a connection the firewall allowed or refused) and each
``firewall`` row (an apply of the rules) is also one span of its own,
``shield.firewall.connection`` or ``shield.firewall.apply``, started and ended
at once, with the row's fields as attributes. The span leaves the process only
once :func:`agent_shield.tracing.configure_export` has set the tracer provider;
without it, or without OpenTelemetry, :func:`export_row` does nothing.

The attributes (the contract the platform's views query):

- every span: ``shield.event`` (``connection`` or ``firewall``),
  ``datalayer.runtime_uid`` (from ``$AGENT_SHIELD_RUNTIME_UID``, else
  ``$DATALAYER_RUNTIME_ID``, when set);
- ``shield.firewall.connection``: ``shield.decision`` (``allow`` or
  ``refuse``), ``shield.rule``, ``shield.destination`` (``address:port``),
  ``shield.host`` (the spec host the address was resolved from, when known),
  ``shield.port``, ``shield.protocol`` (``tcp``, ``udp``, ``icmp``),
  ``shield.source``, ``shield.repeated`` (connections folded into this row);
- ``shield.firewall.apply``: ``shield.reason`` (``start``, ``configure``,
  ``refresh``, ``apply``), ``shield.revision``, ``shield.egress`` and
  ``shield.ingress`` (the entries applied), ``shield.base`` (the base layer's
  allowances by name), ``shield.rules`` (how many rules were compiled),
  ``shield.unresolved`` (hosts that resolved to nothing).

A refused connection is ``deny`` in the audit (the Shield's vocabulary, counted
with the refusals) and ``refuse`` on the span (the firewall's, as its log
prefix says it).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger(__name__)

#: The rows that become spans, and the span each becomes.
SPAN_NAMES: dict[str, str] = {"connection": "shield.firewall.connection", "firewall": "shield.firewall.apply"}
#: Where the runtime's uid is read from, first found wins.
RUNTIME_UID_ENV: tuple[str, ...] = ("AGENT_SHIELD_RUNTIME_UID", "DATALAYER_RUNTIME_ID")
#: The tracer's name.
INSTRUMENTATION = "agent_shield.firewall"

#: A row's field → the span's attribute.
_CONNECTION_FIELDS = {
    "rule": "shield.rule",
    "destination": "shield.destination",
    "host": "shield.host",
    "port": "shield.port",
    "protocol": "shield.protocol",
    "source": "shield.source",
    "repeated": "shield.repeated",
}
_FIREWALL_FIELDS = {
    "reason": "shield.reason",
    "revision": "shield.revision",
    "egress": "shield.egress",
    "ingress": "shield.ingress",
    "base": "shield.base",
    "rules": "shield.rules",
    "unresolved": "shield.unresolved",
}


def runtime_uid(environment: Mapping[str, str] | None = None) -> str | None:
    """The runtime's uid the sidecar was given, or ``None``."""
    env = os.environ if environment is None else environment
    for name in RUNTIME_UID_ENV:
        value = (env.get(name) or "").strip()
        if value:
            return value
    return None


def _value(value: Any) -> Any:
    if isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return str(value)


def row_attributes(row: Mapping[str, Any], *, runtime: str | None = None) -> dict[str, Any]:
    """A ``connection`` or ``firewall`` row as the span's attributes; :data:`SPAN_NAMES` says which rows."""
    event = str(row.get("event") or "")
    if event not in SPAN_NAMES:
        raise ValueError(f"{event!r} is not a firewall row; one of {', '.join(SPAN_NAMES)}")
    attributes: dict[str, Any] = {"shield.event": event}
    if runtime:
        attributes["datalayer.runtime_uid"] = runtime
    if event == "connection":
        attributes["shield.decision"] = "allow" if row.get("decision") == "allow" else "refuse"
        fields = _CONNECTION_FIELDS
    else:
        fields = _FIREWALL_FIELDS
    for name, attribute in fields.items():
        if row.get(name) is not None:
            attributes[attribute] = _value(row[name])
    return attributes


def export_row(row: Mapping[str, Any], *, runtime: str | None = None) -> bool:
    """One firewall row as one span; ``False`` when the row is not one or OpenTelemetry is not there.

    The span is a root of its own (a connection belongs to no request the
    sidecar serves), started and ended at once. Never raises: the firewall's
    telemetry never stops the firewall.
    """
    if str(row.get("event") or "") not in SPAN_NAMES:
        return False
    try:
        from opentelemetry import context, trace
    except ImportError:
        return False
    try:
        tracer = trace.get_tracer_provider().get_tracer(INSTRUMENTATION)
        span = tracer.start_span(
            SPAN_NAMES[str(row["event"])],
            context=context.Context(),
            kind=trace.SpanKind.INTERNAL,
            attributes=row_attributes(row, runtime=runtime),
        )
        span.end()
    except Exception as error:
        logger.debug("The firewall's row could not be exported: %s", error)
        return False
    return True


__all__ = ["INSTRUMENTATION", "RUNTIME_UID_ENV", "SPAN_NAMES", "export_row", "row_attributes", "runtime_uid"]
