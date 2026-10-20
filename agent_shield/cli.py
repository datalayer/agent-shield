# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The ``agent-shield`` command.

    agent-shield setup [--harness claude-code] [--local|--register]
    agent-shield run [--workspace DIR] [--policy FILE] -- claude-agent-acp
    agent-shield log [--last 20] [--json]
    agent-shield policy show | schema | init
    agent-shield harnesses
    agent-shield upgrade [--check]
    agent-shield uninstall [--yes]
    agent-shield serve [--host 127.0.0.1] [--port 8788] [--token-env NAME] [--harness ID]... [--bridge] -- <command>
    agent-shield connect ws://host:port/acp [--token-env NAME]

Everything the proxy writes to its stdout is the protocol; what it says to a
person goes to stderr. Nothing secret is printed: credentials are reported
by name, never by value.
"""

from __future__ import annotations

import asyncio
import getpass
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Optional

import typer

from agent_shield.__version__ import __version__
from agent_shield.audit import AuditLog
from agent_shield.config import (
    AUDIT_FILE,
    POLICY_FILE,
    Config,
    find_policy_file,
    harness_bin,
    harness_prefix,
    home,
)
from agent_shield.policy import (
    LoadedPolicy,
    PolicyRefused,
    default_policy,
    dump_policy,
    load_policies,
    policy_json_schema_text,
)
from agent_shield.register import Harness, RegisterRefused, catalogue, credential_refusal, harness_of_command
from agent_shield.register import harness as harness_of
from agent_shield.registration import (
    DEFAULT_IAM_URL,
    KEY_ENV,
    Registration,
    RegistrationRefused,
    cannot_have,
    pap_sentence,
)
from agent_shield.registration import register as register_shield
from agent_shield.tracing import configure_export, flush_export, refresh_export_token

#: Where `serve` listens by default.
DEFAULT_PORT = 8788
#: How long an HTTP connection of `serve` may sit idle (the server's default).
DEFAULT_IDLE_SECONDS = 300.0

app = typer.Typer(
    name="agent-shield",
    help="Agent Shield: a runtime firewall for every agent. Run any ACP agent behind it.",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)
policy_app = typer.Typer(
    name="policy", help="The policy in force: show it, its schema, write the default.", no_args_is_help=True
)
app.add_typer(policy_app)


def say(text: str) -> None:
    typer.echo(text, err=True)


def refuse(text: str, code: int = 2) -> None:
    say(f"agent-shield: {text}")
    raise typer.Exit(code)


# -- run -----------------------------------------------------------------------------------


def _harness_for_command(executable: str, config: Config) -> Harness | None:
    name = Path(executable).name
    for harness_id, installed in config.harnesses.items():
        if Path(installed.get("bin", "")).name == name:
            try:
                return harness_of(harness_id)
            except RegisterRefused:
                return None
    return harness_of_command(executable)


def _resolve_command(command: list[str], config: Config) -> tuple[list[str], Harness | None]:
    """The command as given, or the register's installed adapter when its name is a harness's."""
    entry = _harness_for_command(command[0], config)
    if entry is None or os.path.isabs(command[0]):
        return command, entry
    refusal = credential_refusal(entry)
    if refusal:
        refuse(refusal)
    installed = config.installed(entry.id)
    if installed and Path(installed["bin"]).is_file():
        return [installed["bin"], *entry.launch_args, *command[1:]], entry
    if shutil.which(command[0]) is None:
        refuse(f"{command[0]!r} is not on PATH and not installed by `agent-shield setup --harness {entry.id}`")
    return command, entry


def _agent_environment(entry: Harness | None, extra: list[str]) -> dict[str, str]:
    names = list(entry.secrets) if entry else []
    names.extend(extra)
    environment: dict[str, str] = {}
    missing: list[str] = []
    for name in names:
        value = os.environ.get(name)
        if value is None:
            missing.append(name)
        else:
            environment[name] = value
    if entry and missing:
        say(f"agent-shield: {', '.join(missing)} not in the environment; {entry.name} may ask to sign in or refuse")
    return environment


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    ctx: typer.Context,
    workspace: Optional[Path] = typer.Option(
        None, "--workspace", "-w", help="The directory the Shield guards; default: each session's cwd."
    ),
    policy: Optional[Path] = typer.Option(
        None,
        "--policy",
        "-p",
        help="The policy file; default: ./agent-shield.yaml, else ~/.agent-shield/agent-shield.yaml.",
    ),
    audit: Optional[Path] = typer.Option(None, "--audit", help="The audit file; default: ~/.agent-shield/audit.jsonl."),
    env: list[str] = typer.Option(
        [], "--env", help="An environment variable name to pass to the agent, besides its declared secrets."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Pass the agent's stderr through and log at DEBUG."),
    pap: list[str] = typer.Option(
        [],
        "--pap",
        help="A company (its domain) to lend the gateway's PAP toolset at; registered Shields only (repeatable).",
    ),
) -> None:
    """Run an ACP agent behind the Shield: `agent-shield run -- claude-agent-acp`."""
    from agent_shield.acp.proxy import ProxyRefused, ShieldProxy, serve_stdio, stderr_passthrough

    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if verbose else logging.WARNING)
    command = list(ctx.args)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        refuse("no agent command: `agent-shield run -- <command>`")
    config = Config.load()
    base = (workspace or Path.cwd()).resolve()
    policy_path = policy or find_policy_file(base)
    if policy_path is None:
        refuse(f"no {POLICY_FILE} in {base} and none in {home()}: `agent-shield setup` writes the default one")
    try:
        loaded = load_policies(policy_path)
    except PolicyRefused as exc:
        refuse(str(exc))
    command, entry = _resolve_command(command, config)
    own_servers = _pap_lending(pap, [item.policy for item in loaded])
    say(
        f"agent-shield {__version__}: {' '.join(command)} behind the Shield; policy {policy_path}; audit {audit or home() / AUDIT_FILE}"
        + (f"; PAP lent at {', '.join(pap)}" if pap else "")
    )
    try:
        proxy = ShieldProxy(
            command,
            policies=loaded,
            audit=AuditLog(audit),
            workspace=workspace,
            agent_env=_agent_environment(entry, env),
            agent_stderr=stderr_passthrough if verbose else None,
            subject=_local_subject(),
            companies=[company.strip().lower() for company in pap],
            own_servers=own_servers,
        )
    except (ProxyRefused, ValueError) as exc:
        refuse(str(exc))
    asyncio.run(serve_stdio(proxy))


def _pap_lending(companies: list[str], policies: list) -> Callable[[], Sequence[Any]] | None:
    """What lends the gateway's PAP toolsets (SH-73), or ``None``; refused before the agent starts.

    Local-only, PAP is refused in :func:`pap_sentence`'s words; registered, each
    company's server must be named on the strictest policy's ``mcp.allow`` —
    a flag never lends what the policy does not.
    """
    if not companies:
        return None
    from types import SimpleNamespace

    from agent_shield.acp.proxy import lend_mcp_servers
    from agent_shield.registration import (
        RegistrationRefused,
        pap_sentence,
        pap_server_name,
        pap_servers,
    )

    registration = _registration_or_none()
    if registration is None:
        refuse(pap_sentence(False))
    try:
        names = [pap_server_name(company) for company in companies]
    except RegistrationRefused as exc:
        refuse(str(exc))
    _, cut = lend_mcp_servers([SimpleNamespace(name=name) for name in names], policies)
    if cut:
        refuse(
            f"PAP at {', '.join(cut)} is not on the policy's mcp.allow list: the policy names it, "
            "or the Shield does not lend it"
        )
    return lambda: pap_servers(registration, companies)


# -- setup -----------------------------------------------------------------------------------


def _node_version() -> tuple[int, ...] | None:
    node = shutil.which("node")
    if node is None:
        return None
    out = subprocess.run([node, "--version"], capture_output=True, text=True, check=False).stdout.strip()
    try:
        return tuple(int(part) for part in out.lstrip("v").split("."))
    except ValueError:
        return None


def _node_ok(required: str | None, found: tuple[int, ...] | None) -> bool:
    if required is None:
        return True
    if found is None:
        return False
    floor = tuple(int(part) for part in required.lstrip(">=").split("."))
    return found >= floor


def install_adapter(entry: Harness, base: Path | None = None) -> Path:
    """``npm install --prefix ~/.agent-shield/harnesses/<id>@<version> <package>@<version>``, in the foreground.

    The executable is the one the package's ``bin`` names (read from its
    ``package.json`` once installed), never a global ``npx``.
    """
    package = entry.npm_package
    if package is None:
        raise RuntimeError(f"{entry.name} is not an npm adapter; install {entry.adapter} {entry.version} yourself")
    prefix = harness_prefix(entry.id, entry.version, base)
    prefix.mkdir(parents=True, exist_ok=True)
    spec = f"{package}@{entry.version}"
    result = subprocess.run(
        ["npm", "install", "--prefix", str(prefix), spec, "--no-audit", "--no-fund", "--loglevel=error"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"npm install of {spec} failed: {result.stderr.strip()[-400:]}")
    manifest = prefix / "node_modules" / package / "package.json"
    bins = json.loads(manifest.read_text(encoding="utf-8")).get("bin") or {}
    names = [bins] if isinstance(bins, str) else list(bins)
    executable = harness_bin(prefix, entry.command if entry.command in names or not names else names[0])
    if not executable.is_file():
        raise RuntimeError(f"{spec} installed but {executable} is not there")
    return executable


@app.command()
def setup(
    harness: str = typer.Option(
        "claude-code", "--harness", help="The harness to set up (see `agent-shield harnesses`)."
    ),
    register: bool = typer.Option(
        False,
        "--register/--local",
        help=f"Register with Datalayer through a service-agent key read from ${KEY_ENV} (SH-47), or stay local.",
    ),
    org: Optional[str] = typer.Option(
        None, "--org", help="With --register: the organization the service agent belongs to."
    ),
    agent: Optional[str] = typer.Option(None, "--agent", help="With --register: the service agent's uid."),
    iam_url: str = typer.Option(DEFAULT_IAM_URL, "--iam-url", help="With --register: IAM."),
    otel_url: str = typer.Option(
        "", "--otel-url", help="With --register: where the telemetry goes; default: IAM's host."
    ),
    key_env: str = typer.Option(
        KEY_ENV, "--key-env", help="With --register: the environment variable holding the key."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask."),
) -> None:
    """The first five minutes: find node, the vendor CLIs and credentials; install the pinned adapter; write the policy."""
    started = time.monotonic()
    try:
        entry = harness_of(harness)
    except RegisterRefused as exc:
        refuse(str(exc))
    base = home()
    config = Config.load(base)
    say(
        f"Agent Shield {__version__} setup for {entry.name} ({entry.adapter} {entry.version}; register checked by agentspecs)"
    )
    node = _node_version()
    node_requirement = entry.node_requirement
    say(
        f"  node: {'v' + '.'.join(map(str, node)) if node else 'not found'}"
        + (f" (needs {node_requirement})" if node_requirement else "")
    )
    if entry.npm_package and not _node_ok(node_requirement, node):
        refuse(f"{entry.name}'s adapter needs Node {node_requirement}; install it (nodejs.org) and run setup again")
    for cli in ("claude", "codex", "gemini", "goose", "opencode", "openhands"):
        found = shutil.which(cli)
        if found:
            say(f"  vendor CLI on PATH: {cli} ({found})")
    missing = [name for name in entry.secrets if not os.environ.get(name)]
    present = [name for name in entry.secrets if os.environ.get(name)]
    if present:
        say(f"  credentials present: {', '.join(present)} (by name; values are never shown)")
    if missing:
        say(
            f"  credentials missing: {', '.join(missing)} — export before `agent-shield run`; the Shield stores no secret"
        )
    refusal = credential_refusal(entry)
    if refusal:
        refuse(refusal)
    say(
        f"  terms: served to third parties: {entry.entry.served_to_third_parties.value}; {entry.entry.credential}; {entry.entry.licence}"
    )
    if entry.entry.tier_restrictions:
        say(f"  tiers: {entry.entry.tier_restrictions}")
    if register:
        try:
            registration = register_shield(
                org_uid=org or "",
                agent_uid=agent or "",
                key=os.environ.get(key_env, ""),
                iam_url=iam_url,
                otel_url=otel_url,
                base=base,
            )
        except RegistrationRefused as exc:
            refuse(str(exc))
        config.data["registered"] = True
        config.data.pop("wants_registration", None)
        say(
            f"  registered with Datalayer: organization {registration.org_uid}, service agent {registration.agent_uid}, "
            f"IAM {registration.iam_url}; the key and the token kept in {registration.path} (0600), never shown"
        )
        say(f"  {cannot_have()}")
    else:
        config.data["registered"] = bool(Registration.load(base))
    if entry.npm_package:
        installed = config.installed(entry.id)
        if installed and installed.get("version") == entry.version and Path(installed["bin"]).is_file():
            say(f"  adapter already installed: {installed['bin']}")
            executable = Path(installed["bin"])
        else:
            if not yes and not typer.confirm(
                f"  install {entry.npm_package}@{entry.version} into {harness_prefix(entry.id, entry.version, base)}?",
                default=True,
                err=True,
            ):
                refuse("setup stopped before installing the adapter", 1)
            say("  installing the adapter (npm install --prefix …)")
            try:
                executable = install_adapter(entry, base)
            except RuntimeError as exc:
                refuse(str(exc))
            say(f"  installed: {executable}")
        config.harnesses[entry.id] = {"version": entry.version, "bin": str(executable), "package": entry.npm_package}
    else:
        found = shutil.which(entry.command)
        say(
            f"  {entry.name} is its own program: {found or 'not on PATH — install ' + entry.adapter + ' ' + entry.version + ' yourself'}"
        )
        config.harnesses[entry.id] = {"version": entry.version, "bin": found or entry.command, "package": entry.adapter}
    config.data["default_harness"] = entry.id
    config.save()
    say(f"  config: {config.path}")
    say(f"  {pap_sentence(bool(config.data.get('registered')))}")
    project_policy = Path.cwd() / POLICY_FILE
    if project_policy.is_file():
        say(f"  policy kept: {project_policy}")
    else:
        project_policy.write_text(dump_policy(default_policy()), encoding="utf-8")
        say(f"  policy written (the default): {project_policy}")
    command = f"agent-shield run -- {entry.command}"
    say(f"  run: {command}")
    say(
        f'  Zed: settings.json → "agent_servers": {{"{entry.name} behind the Shield": {{"command": "agent-shield", "args": ["run", "--", "{entry.command}"]}}}}'
    )
    say(f"  done in {time.monotonic() - started:.1f} s")


# -- log, policy, harnesses --------------------------------------------------------------------


@app.command()
def log(
    last: int = typer.Option(20, "--last", "-n", help="How many rows."),
    as_json: bool = typer.Option(False, "--json", help="Rows as JSON lines."),
    audit: Optional[Path] = typer.Option(None, "--audit", help="The audit file."),
) -> None:
    """The audit: the last rows, one line each."""
    rows = AuditLog(audit).rows(last=last)
    if not rows:
        say(f"no audit rows yet in {AuditLog(audit).path}")
        return
    for row in rows:
        if as_json:
            typer.echo(json.dumps(row, ensure_ascii=False))
            continue
        decision = row.get("decision")
        head = f"{row['ts']}  {row['event']:<11}"
        tail = row.get("sentence") or row.get("what") or row.get("title") or ""
        if decision and not row.get("sentence"):
            tail = f"{decision}: {tail}"
        if row.get("by"):
            tail += f"  [{row['by']}]"
        typer.echo(f"{head} {tail}")


def _loaded_policies(policy: Optional[Path], workspace: Path) -> list[LoadedPolicy]:
    path = policy or find_policy_file(workspace)
    if path is None:
        refuse(f"no {POLICY_FILE} in {workspace} and none in {home()}: `agent-shield setup` writes the default one")
    try:
        return load_policies(path)
    except PolicyRefused as exc:
        refuse(str(exc))
    return []  # pragma: no cover


@policy_app.command("show")
def policy_show(
    policy: Optional[Path] = typer.Option(None, "--policy", "-p"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Every line of the policy in force, and where it came from."""
    for item in _loaded_policies(policy, (workspace or Path.cwd()).resolve()):
        doc = item.policy
        typer.echo(
            f"{doc.scope} policy (version {doc.version}) — from {item.origin}"
            + (f", expires {doc.expires.isoformat()}" if doc.expires else "")
        )
        for n, rule in enumerate(doc.rules, 1):
            what = ", ".join(rule.classes) if rule.classes else "every class"
            where = {"inside": " inside the workspace", "outside": " outside the workspace", "any": ""}[rule.where]
            extra = []
            if rule.kinds:
                extra.append("kinds " + ", ".join(rule.kinds))
            if rule.paths:
                extra.append("paths " + ", ".join(rule.paths))
            if rule.commands:
                extra.append("commands " + "; ".join(rule.commands))
            line = f"  {n:>2}. {rule.name}: {what}{where} → {rule.decision}"
            if extra:
                line += f"  ({'; '.join(extra)})"
            if rule.reason:
                line += f"  — {rule.reason}"
            typer.echo(line)
        for name in ("tool_calls", "terminals_open", "bytes_written"):
            threshold = getattr(doc.limits, name)
            if threshold:
                typer.echo(f"  limit {name}: soft {threshold.soft}, hard {threshold.hard}")
        typer.echo(f"  fetch allow-list: {', '.join(doc.network.fetch) or 'none (every fetch refused)'}")
        typer.echo(f"  mcp lent: {', '.join(doc.mcp.allow) or 'none'}")
        typer.echo("  nothing a rule names falls to: ask me first")
    try:
        registration = Registration.load()
    except RegistrationRefused as exc:
        refuse(str(exc))
    if registration is None:
        typer.echo(
            "registration: local-only (the policy above is a file's; `agent-shield setup --register` takes IAM's)"
        )
    else:
        described = registration.describe()
        typer.echo(
            f"registration: organization {described['org_uid']}, service agent {described['agent_uid']}, IAM {described['iam_url']}, "
            f"telemetry to {described['otel_url']}, token {described['token']}"
            + (f" until {described['token_expires']}" if described["token_expires"] else "")
        )
        typer.echo(f"  {cannot_have()}")
    typer.echo(pap_sentence(registration is not None))


@policy_app.command("schema")
def policy_schema() -> None:
    """The policy document's JSON Schema."""
    typer.echo(policy_json_schema_text(), nl=False)


@policy_app.command("init")
def policy_init(path: Path = typer.Argument(Path(POLICY_FILE)), force: bool = typer.Option(False, "--force")) -> None:
    """Write the default policy."""
    if path.exists() and not force:
        refuse(f"{path} exists; --force overwrites it")
    path.write_text(dump_policy(default_policy()), encoding="utf-8")
    say(f"written {path}")


@app.command()
def harnesses() -> None:
    """The register: every harness with its terms."""
    from agentspecs.harnesses import load_register

    checked = yaml_checked_on()
    for entry in catalogue().values():
        typer.echo(
            f"{entry.id:<12} {entry.name:<12} {entry.adapter}@{entry.version}  `{entry.command} {' '.join(entry.launch_args)}`".rstrip()
        )
        typer.echo(
            f"             served to third parties: {entry.entry.served_to_third_parties.value}; {entry.entry.credential}; {entry.entry.licence}"
        )
        if entry.entry.tier_restrictions:
            typer.echo(f"             tiers: {entry.entry.tier_restrictions}")
        typer.echo(
            f"             licence read at {entry.entry.licence_source}; terms at {entry.entry.terms_source}; register checked on {checked}"
        )
    typer.echo(f"({len(load_register())} register entries, from agentspecs)")


def yaml_checked_on() -> str:
    import yaml
    from agentspecs.harnesses import REGISTER_PATH

    return str((yaml.safe_load(REGISTER_PATH.read_text()) or {}).get("checked_on", "?"))


# -- upgrade, uninstall, serve, version ----------------------------------------------------------


def _latest_on_pypi() -> str | None:
    try:
        with urllib.request.urlopen("https://pypi.org/pypi/datalayer-agent-shield/json", timeout=10) as response:
            return json.load(response)["info"]["version"]
    except Exception:
        return None


@app.command()
def upgrade(
    check: bool = typer.Option(False, "--check", help="Only say what a newer Shield or adapter would be."),
) -> None:
    """Move the adapters to the register's pinned versions; say whether a newer Shield exists."""
    config = Config.load()
    latest = _latest_on_pypi()
    if latest is None:
        say(f"Shield {__version__}; PyPI not reachable")
    elif latest != __version__:
        say(f"Shield {__version__}; {latest} is on PyPI: pip install -U datalayer-agent-shield")
    else:
        say(f"Shield {__version__} is the latest on PyPI")
    register = catalogue()
    for harness_id, installed in config.harnesses.items():
        entry = register.get(harness_id)
        if entry is None:
            say(f"  {harness_id}: no longer in the register")
            continue
        if installed.get("version") == entry.version:
            say(f"  {harness_id}: {entry.version} is the pinned version")
            continue
        say(f"  {harness_id}: installed {installed.get('version')}, pinned {entry.version}")
        if check or not entry.npm_package:
            continue
        try:
            executable = install_adapter(entry)
        except RuntimeError as exc:
            refuse(str(exc))
        config.harnesses[harness_id] = {"version": entry.version, "bin": str(executable), "package": entry.npm_package}
        config.save()
        say(f"  {harness_id}: moved to {entry.version} ({executable})")


@app.command()
def uninstall(yes: bool = typer.Option(False, "--yes", "-y", help="Do it; without it, preview.")) -> None:
    """Preview what would go (the adapters, the config); the audit and the policies stay."""
    base = home()
    going = [p for p in (base / "harnesses",).__iter__() if p.exists()] + [
        p for p in (base / "config.yaml",) if p.exists()
    ]
    staying = [p for p in (base / AUDIT_FILE, base / POLICY_FILE) if p.exists()]
    if not going:
        say(f"nothing of the Shield's is installed under {base}")
        return
    say("would remove:" if not yes else "removing:")
    for path in going:
        say(f"  {path}")
    if staying:
        say("kept: " + ", ".join(str(p) for p in staying))
    if not yes:
        say("run again with --yes to do it; `pip uninstall datalayer-agent-shield` removes the command")
        return
    for path in going:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    say("done; `pip uninstall datalayer-agent-shield` removes the command")


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def serve(
    ctx: typer.Context,
    host: str = typer.Option("127.0.0.1", "--host", help="Where to listen; beyond the loopback a token is needed."),
    port: int = typer.Option(DEFAULT_PORT, "--port", help="The port; 0 picks a free one and says it."),
    token_env: Optional[str] = typer.Option(
        None,
        "--token-env",
        help="The environment variable holding the bearer token clients present (header or first message).",
    ),
    harness: list[str] = typer.Option(
        [], "--harness", help="A harness of the register to serve at /acp/<id> (repeatable), instead of one command."
    ),
    bridge: bool = typer.Option(
        False, "--bridge", help="No Shield: relay each connection to a harness it spawns (the sidecar, SH-40)."
    ),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="The directory the Shield guards."),
    policy: Optional[Path] = typer.Option(None, "--policy", "-p", help="The policy file (local-only)."),
    audit: Optional[Path] = typer.Option(None, "--audit", help="The audit file; default: ~/.agent-shield/audit.jsonl."),
    env: list[str] = typer.Option([], "--env", help="An environment variable name to pass to the agents."),
    idle: float = typer.Option(DEFAULT_IDLE_SECONDS, "--idle", help="Seconds an HTTP connection may sit idle."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log at DEBUG; pass the agents' stderr through."),
) -> None:
    """The proxy as a server over WebSocket and ACP Streamable HTTP, one harness per connection (SH-52, SH-56)."""
    from agent_shield.acp.proxy import ProxyRefused, ShieldProxy, stderr_passthrough
    from agent_shield.acp.server import ServeRefused, ShieldBackend, ShieldServer

    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if verbose else logging.INFO)
    command = list(ctx.args)
    if command and command[0] == "--":
        command = command[1:]
    if bool(command) == bool(harness):
        refuse("serve one command after `--`, or one or more `--harness <id>` of the register; not both, not neither")
    token = None
    if token_env:
        token = os.environ.get(token_env, "")
        if not token:
            refuse(
                f"${token_env} is empty: the token is read from the environment, never from an argument or the address"
            )
    config = Config.load()
    base = (workspace or Path.cwd()).resolve()
    commands: dict[str, tuple[list[str], Harness | None]] = {}
    if command:
        commands[""] = _resolve_command(command, config)
    for harness_id in harness:
        try:
            entry = harness_of(harness_id)
        except RegisterRefused as exc:
            refuse(str(exc))
        commands[entry.id] = _resolve_command([entry.command], config)
    environments = {name: _agent_environment(entry, env) for name, (_, entry) in commands.items()}
    audit_log = AuditLog(audit)
    registration = None if bridge else _registration_or_none()
    loaded: list[LoadedPolicy] = []
    managed = None
    if bridge:
        say(
            "agent-shield serve --bridge: no Shield here; every connection relayed verbatim to its harness (the runtime's Shield decides)"
        )
    elif registration is not None:
        managed = _managed_policies(registration)
        try:
            loaded = _managed_loaded(managed, registration)
        except Exception as exc:
            refuse(str(exc))
        if not configure_export(
            registration.telemetry_url,
            registration.token,
            service_name="agent-shield",
            usage_account_uid=registration.org_uid,
            **{"shield.agent": registration.agent_uid},
        ):
            refuse(
                "registered, the Shield exports its telemetry; install `datalayer-agent-shield[otel]` for the OTEL SDK and the OTLP exporter"
            )
        say(
            f"agent-shield {__version__}: policies from IAM at {registration.iam_url} ({len(loaded)} documents), telemetry to {registration.telemetry_url}; {cannot_have()}"
        )
    else:
        policy_path = policy or find_policy_file(base)
        if policy_path is None:
            refuse(f"no {POLICY_FILE} in {base} and none in {home()}: `agent-shield setup` writes the default one")
        try:
            loaded = load_policies(policy_path)
        except PolicyRefused as exc:
            refuse(str(exc))
        say(f"agent-shield {__version__}: policy {policy_path} (local-only); audit {audit or home() / AUDIT_FILE}")

    def factory_of(name: str):
        resolved, _entry = commands[name]

        def make() -> ShieldProxy:
            return ShieldProxy(
                resolved,
                policies=loaded,
                audit=audit_log,
                workspace=workspace,
                agent_env=environments[name],
                agent_stderr=stderr_passthrough if verbose else None,
                authorizer=_iam_authorizer(registration) if registration is not None else None,
                subject=_registered_subject(registration) if registration is not None else _local_subject(),
            )

        return make

    agents: dict = {name: (resolved if bridge else factory_of(name)) for name, (resolved, _) in commands.items()}
    bridge_env = environments.get("") or (environments[next(iter(environments))] if len(environments) == 1 else {})
    try:
        server = ShieldServer(
            agents,
            audit=audit_log,
            token=token,
            bridge_cwd=str(base) if bridge else None,
            bridge_env=bridge_env,
            idle_seconds=idle,
        )
    except (ServeRefused, ProxyRefused) as exc:
        refuse(str(exc))

    async def main() -> None:
        try:
            await server.start(host, port)
        except ServeRefused as exc:
            refuse(str(exc))
        paths = ", ".join(f"/acp/{name}" if name else "/acp" for name in sorted(agents))
        say(
            f"agent-shield serve: listening on {server.host}:{server.port} ({paths}; WebSocket and Streamable HTTP; "
            f"{'bearer token required' if token else 'no token: loopback only'})"
        )
        watcher = None
        if managed is not None and registration is not None:

            async def changed(policies) -> None:
                fresh = [LoadedPolicy(policy=item, origin=f"IAM {registration.iam_url}") for item in policies]
                loaded[:] = fresh
                for served in list(server.connections.values()):
                    if isinstance(served.backend, ShieldBackend):
                        served.backend.proxy.replace_policies(fresh)

            async def unavailable(sentence: str) -> None:
                for served in list(server.connections.values()):
                    if isinstance(served.backend, ShieldBackend):
                        served.backend.proxy.refuse_all(sentence)

            watcher = asyncio.create_task(_watch_managed(managed, registration, changed, unavailable))
        try:
            await asyncio.Event().wait()
        finally:
            if watcher is not None:
                watcher.cancel()
            await server.stop()
            flush_export()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        say("agent-shield serve: stopped")


def _local_subject():
    """Who acts behind a local-only Shield: the account running it."""
    from agent_shield.policy import Subject

    try:
        who = getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name in some containers
        who = "local"
    return Subject(type="account", id=who or "local")


def _registered_subject(registration: Registration):
    """Who acts behind a registered Shield: the service agent it is registered as."""
    from agent_shield.policy import Subject

    return Subject(type="agent", id=registration.agent_uid)


def _iam_authorizer(registration: Registration):
    """OpenFGA through IAM (SH-75): the registered Shield's authorizer, the token kept fresh."""
    from agent_shield.saas import IamAuthorizer

    return IamAuthorizer(registration.iam_url, registration.fresh_token)


def _registration_or_none() -> Registration | None:
    try:
        return Registration.load()
    except RegistrationRefused as exc:
        refuse(str(exc))
    return None  # pragma: no cover


def _managed_policies(registration: Registration):
    from agent_shield.saas import IamPolicySource, ManagedPolicies

    token = registration.fresh_token()
    return ManagedPolicies(IamPolicySource(registration.iam_url, token, registration.agent_uid))


def _managed_loaded(managed, registration: Registration) -> list[LoadedPolicy]:
    from agent_shield.saas import IamPolicySource

    if not registration.token_fresh():
        managed.source = IamPolicySource(registration.iam_url, registration.fresh_token(), registration.agent_uid)
        refresh_export_token(registration.token)
    pulled = managed.pull()
    if not pulled:
        raise RegistrationRefused(
            f"IAM at {registration.iam_url} serves no Shield document for service agent {registration.agent_uid}: "
            "its organization has written none, or IAM does not answer a service agent's organization yet; "
            "with no document nothing is decided, so the Shield does not start"
        )
    return [LoadedPolicy(policy=item, origin=f"IAM {registration.iam_url}") for item in pulled]


async def _watch_managed(managed, registration: Registration, changed, unavailable) -> None:
    """Poll IAM as the saas module does, the token exchanged again before it expires."""
    from agent_shield.saas import IamPolicySource, PolicyUnavailable, fingerprint

    before = fingerprint(managed.kept.policies) if managed.kept is not None else None
    refused_said = False
    while True:
        await asyncio.sleep(managed.poll_seconds)
        if not registration.token_fresh():
            try:
                managed.source = IamPolicySource(
                    registration.iam_url, registration.fresh_token(), registration.agent_uid
                )
                refresh_export_token(registration.token)
            except RegistrationRefused as exc:
                if not refused_said:
                    await unavailable(
                        f"The Shield cannot exchange its key at IAM ({exc}); nothing is decided until it can"
                    )
                refused_said = True
                continue
        try:
            policies = await asyncio.to_thread(managed.pull)
        except PolicyUnavailable as exc:
            if not refused_said:
                await unavailable(str(exc))
            refused_said = True
            continue
        now = fingerprint(policies)
        if now != before or refused_said:
            before = now
            refused_said = False
            await changed(policies)


@app.command()
def connect(
    url: str = typer.Argument(..., help="The Shield served elsewhere: ws://host:port/acp (or /acp/<harness>)."),
    token_env: Optional[str] = typer.Option(
        None, "--token-env", help="The environment variable holding the bearer token."
    ),
) -> None:
    """A remote Shield as a local stdio agent, for clients that only start commands (SH-56)."""
    from agent_shield.acp.remote import RemoteRefused, mirror_stdio

    token = None
    if token_env:
        token = os.environ.get(token_env, "")
        if not token:
            refuse(
                f"${token_env} is empty: the token is read from the environment, never from an argument or the address"
            )
    try:
        status = asyncio.run(mirror_stdio(url, token=token))
    except RemoteRefused as exc:
        refuse(str(exc))
    except OSError as exc:
        refuse(f"{url} could not be reached ({exc})")
    raise typer.Exit(status)


@app.command()
def version() -> None:
    """The Shield's version."""
    typer.echo(__version__)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
