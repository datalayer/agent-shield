# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""``agent-shield firewall``: check, compile, apply, watch.

``check`` validates an agent spec's ``policy.shield`` (or a bare rules file);
``compile`` prints the ``iptables-restore`` script for a base and rules;
``apply`` applies them once; ``watch`` is the sidecar's daemon: it applies the
base (and the rules file when one is there), writes the ready file a startup
probe waits on, applies the rules file again whenever it changes, resolves the
spec's hosts again every ``--refresh`` seconds, and records every connection
the rules logged. ``apply`` and ``watch`` need ``NET_ADMIN`` in the network
namespace they change.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import typer
import yaml
from pydantic import ValidationError

from agent_shield.audit import AuditLog
from agent_shield.firewall.compile import BaseLayer, compile_rules
from agent_shield.firewall.controller import ConnectionRecorder, Controller, FirewallRefused
from agent_shield.firewall.model import FirewallError, FirewallRules, firewall_json_schema, rules_of_spec

firewall_app = typer.Typer(
    name="firewall",
    help="The firewall: an agent's policy.shield enforced in its network namespace, every connection recorded.",
    no_args_is_help=True,
)


def _refuse(text: str, code: int = 2) -> None:
    typer.echo(f"agent-shield: {text}", err=True)
    raise typer.Exit(code)


def _load(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        _refuse(f"{path} could not be read: {error}")


def parse_rules(path: Path) -> FirewallRules:
    """Rules from an agent spec (its ``policy.shield``), a ``{shield: …}`` mapping, or bare rules.

    Raises :class:`FirewallError` with the sentence that says why not.
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as error:
        raise FirewallError(f"{path} could not be read: {error}") from None
    if not isinstance(data, dict):
        raise FirewallError(f"{path}: rules are a mapping")
    try:
        if "policy" in data:
            return rules_of_spec(data)
        if "shield" in data:
            return FirewallRules.model_validate(data["shield"] or {})
        return FirewallRules.model_validate(data)
    except ValidationError as error:
        message = str(error.errors()[0]["msg"]).removeprefix("Value error, ")
        raise FirewallError(f"{path}: {message}") from None


def load_rules(path: Path | None) -> FirewallRules:
    """:func:`parse_rules` for a command: a refusal is said and ends it."""
    if path is None:
        return FirewallRules()
    try:
        return parse_rules(path)
    except FirewallError as error:
        _refuse(str(error))
    raise AssertionError("unreachable")


#: The base layer's JSON, when no ``--base`` file is given: how a pod's container is handed it.
BASE_ENV = "AGENT_SHIELD_FIREWALL_BASE"


def load_revision(path: Path) -> str | None:
    """The ``revision`` a rules file names (``{"revision": …, "shield": {…}}``), echoed once applied."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if isinstance(data, dict) and data.get("revision") is not None:
        return str(data["revision"])
    return None


def load_base(path: Path | None) -> BaseLayer:
    if path is None:
        said = os.environ.get(BASE_ENV, "").strip()
        if not said:
            return BaseLayer()
        try:
            return BaseLayer.from_json(json.loads(said))
        except (KeyError, TypeError, ValueError) as error:
            _refuse(f"{BASE_ENV} is not a base layer: {error}")
    try:
        return BaseLayer.from_json(_load(path) or {})
    except (KeyError, TypeError, ValueError) as error:
        _refuse(f"{path} is not a base layer: {error}")
    raise AssertionError("unreachable")


@firewall_app.command("check")
def check(path: Path = typer.Argument(..., help="An agent spec, or a rules file.")) -> None:
    """Validate the rules; say what they allow."""
    rules = load_rules(path)
    egress = (
        "the platform's endpoints and any public address"
        if rules.open_egress
        else ("the platform's endpoints" + (f" and {', '.join(rules.egress)}" if rules.egress else " only"))
    )
    typer.echo(f"egress: {egress}")
    typer.echo(f"ingress: {', '.join(rules.ingress) or 'platform'}")


@firewall_app.command("schema")
def schema() -> None:
    """The JSON Schema of policy.shield."""
    typer.echo(json.dumps(firewall_json_schema(), indent=2))


@firewall_app.command("compile")
def compile_command(
    rules: Path | None = typer.Option(None, "--rules", help="An agent spec or a rules file."),
    base: Path | None = typer.Option(None, "--base", help="The base layer's JSON."),
    ingress: bool = typer.Option(False, "--ingress", help="Enforce ingress too."),
) -> None:
    """Print the iptables-restore script; spec hosts are resolved here."""
    loaded = load_rules(rules)
    controller = Controller(load_base(base), enforce_ingress=ingress)
    resolved = {
        entry.value: controller.resolver(entry.value) for entry in loaded.egress_entries() if entry.kind == "host"
    }
    compiled = compile_rules(controller.base, loaded, resolved=resolved, enforce_ingress=ingress)
    typer.echo(compiled.script, nl=False)
    for host in compiled.unresolved:
        typer.echo(f"agent-shield: {host} resolves to nothing; it is refused", err=True)


@firewall_app.command("apply")
def apply_command(
    rules: Path | None = typer.Option(None, "--rules"),
    base: Path | None = typer.Option(None, "--base"),
    ingress: bool = typer.Option(False, "--ingress"),
    state: Path | None = typer.Option(None, "--state", help="Where applied.json is written."),
) -> None:
    """Apply base and rules once (needs NET_ADMIN)."""
    controller = Controller(load_base(base), audit=AuditLog(), enforce_ingress=ingress, state_dir=state)
    try:
        applied = controller.apply(load_rules(rules))
    except FirewallRefused as error:
        _refuse(str(error), code=1)
    typer.echo(
        f"applied: {applied.compiled.rules} rules, unresolved: {', '.join(applied.compiled.unresolved) or 'none'}"
    )


class EchoingAuditLog(AuditLog):
    """The audit, each row also written to stdout as one JSON line: a container's log carries it."""

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        row = super().write(event, **fields)
        typer.echo(json.dumps(row, separators=(",", ":"), ensure_ascii=False))
        return row


def _listen(recorder: ConnectionRecorder) -> None:
    from agent_shield.firewall.nflog import Listener

    listener = Listener()
    for connection in listener.connections():
        recorder.record(connection)


def _digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


@firewall_app.command("watch")
def watch(
    rules: Path = typer.Option(..., "--rules", help="The rules file applied whenever its content changes."),
    base: Path | None = typer.Option(None, "--base", help=f"The base layer's JSON; ${BASE_ENV} when not given."),
    state: Path = typer.Option(Path("/run/agent-shield/state"), "--state", help="applied.json and the ready file."),
    ingress: bool = typer.Option(False, "--ingress"),
    refresh: float = typer.Option(60.0, "--refresh", help="Seconds between resolving the spec's hosts again."),
    record: bool = typer.Option(True, "--record/--no-record", help="Record every logged connection."),
    echo: bool = typer.Option(True, "--echo/--no-echo", help="Write each audit row to stdout as well."),
    audit_file: bool = typer.Option(
        True, "--audit-file/--no-audit-file", help="Keep the rows in the audit file; off, stdout and the trace only."
    ),
    once: bool = typer.Option(False, "--once", hidden=True, help="Apply, mark ready and return (tests)."),
) -> None:
    """The sidecar's daemon: apply, keep current, record (needs NET_ADMIN)."""
    audit = EchoingAuditLog(persist=audit_file) if echo else AuditLog(persist=audit_file)
    controller = Controller(load_base(base), audit=audit, enforce_ingress=ingress, state_dir=state)
    seen = _digest(rules)

    def apply_file(reason: str) -> None:
        revision = None
        try:
            revision = load_revision(rules)
            controller.apply(parse_rules(rules), reason=reason, revision=revision)
        except (FirewallRefused, FirewallError) as error:
            # The previous rules stand; the refusal is said, never opened around.
            said = str(error) or "the rules are not valid"
            typer.echo(f"agent-shield: the rules were not applied: {said}", err=True)
            state.mkdir(parents=True, exist_ok=True)
            (state / "refused.json").write_text(
                json.dumps({"at": time.time(), "revision": revision, "error": said}), encoding="utf-8"
            )

    try:
        controller.apply(None, reason="start")
    except FirewallRefused as error:
        _refuse(str(error), code=1)
    if seen is not None:
        apply_file("start")
    (state / "ready").write_text("base applied\n", encoding="utf-8")
    if once:
        return
    if record:
        recorder = ConnectionRecorder(audit, host_of=controller.host_of)
        threading.Thread(target=_listen, args=(recorder,), name="shield-nflog", daemon=True).start()
    last_refresh = time.monotonic()
    while True:
        time.sleep(0.5)
        digest = _digest(rules)
        if digest is not None and digest != seen:
            seen = digest
            apply_file("configure")
        elif time.monotonic() - last_refresh >= refresh:
            last_refresh = time.monotonic()
            try:
                controller.refresh()
            except FirewallRefused as error:
                typer.echo(f"agent-shield: the refreshed rules were not applied: {error}", err=True)


__all__ = ["BASE_ENV", "EchoingAuditLog", "firewall_app", "load_base", "load_revision", "load_rules", "parse_rules"]
