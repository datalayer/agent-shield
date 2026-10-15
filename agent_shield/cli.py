# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The ``agent-shield`` command (SHIELD §5.2, §5.3).

    agent-shield setup [--harness claude-code] [--local|--register]
    agent-shield run [--workspace DIR] [--policy FILE] -- claude-agent-acp
    agent-shield log [--last 20] [--json]
    agent-shield policy show | schema | init
    agent-shield harnesses
    agent-shield upgrade [--check]
    agent-shield uninstall [--yes]
    agent-shield serve          # not built (SH-52): says so

Everything the proxy writes to its stdout is the protocol; what it says to a
person goes to stderr. Nothing secret is printed: credentials are reported
by name, never by value.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

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
    say(
        f"agent-shield {__version__}: {' '.join(command)} behind the Shield; policy {policy_path}; audit {audit or home() / AUDIT_FILE}"
    )
    try:
        proxy = ShieldProxy(
            command,
            policies=loaded,
            audit=AuditLog(audit),
            workspace=workspace,
            agent_env=_agent_environment(entry, env),
            agent_stderr=stderr_passthrough if verbose else None,
        )
    except ProxyRefused as exc:
        refuse(str(exc))
    asyncio.run(serve_stdio(proxy))


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
        False, "--register/--local", help="Register with Datalayer (not built: SH-47) or stay local."
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
    config.data["registered"] = False
    if register:
        say("  registration with Datalayer is not built (SH-47): staying local; the wish is recorded in config.yaml")
        config.data["wants_registration"] = True
    config.save()
    say(f"  config: {config.path}")
    project_policy = Path.cwd() / POLICY_FILE
    if project_policy.is_file():
        say(f"  policy kept: {project_policy}")
    else:
        project_policy.write_text(dump_policy(default_policy()), encoding="utf-8")
        say(f"  policy written (the default of decision 5): {project_policy}")
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


@policy_app.command("schema")
def policy_schema() -> None:
    """The policy document's JSON Schema."""
    typer.echo(policy_json_schema_text(), nl=False)


@policy_app.command("init")
def policy_init(path: Path = typer.Argument(Path(POLICY_FILE)), force: bool = typer.Option(False, "--force")) -> None:
    """Write the default policy of decision 5."""
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


@app.command()
def serve() -> None:
    """The proxy as a WebSocket server: not built (SH-52)."""
    refuse("serve is not built (SHIELD SH-52); `agent-shield run -- <command>` is the stdio proxy")


@app.command()
def version() -> None:
    """The Shield's version."""
    typer.echo(__version__)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
