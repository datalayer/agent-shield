# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The harness register, read from agentspecs (SHIELD §3.3, SH-04).

The catalogue of harnesses and the register — every harness with its
adapter, the version pinned, its licence and where that was read, the
agent's terms, the credential it takes, whether serving it to third parties
is permitted and its tier restrictions — live in agentspecs
(``agentspecs/harnesses/*.yaml`` and ``harnesses/register.yaml``, 0.0.100).
agentspecs' loader refuses a harness without an entry; this module reads
both and adds the Shield's part: **refusing, at ``setup`` and ``run``, a
credential the register forbids** — Claude Code or Codex with a
subscription login where only an API key serves, Gemini CLI with a Google
login on the individuals tier — in a sentence.

The Shield never runs an adapter through ``npx``: a spec whose command is
``npx -y <package>@<version>`` is installed once into the Shield's own prefix
(``~/.agent-shield/harnesses/<id>@<version>``) and run from there.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from agentspecs.harnesses import (
    CUSTOM_HARNESS,
    HarnessError,
    HarnessSpec,
    RegisterEntry,
    ThirdPartyServing,
    load_harnesses,
    load_register,
)

#: The executable an npm adapter installs, where it is not the package's own last name.
EXECUTABLES: dict[str, str] = {"@google/gemini-cli": "gemini", "opencode-ai": "opencode"}


class RegisterRefused(ValueError):
    """A harness the Shield will not set up or run, said in a sentence."""


@dataclass(frozen=True)
class Harness:
    """A catalogue harness with its register entry, as the Shield uses it."""

    spec: HarnessSpec
    entry: RegisterEntry

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def version(self) -> str:
        return self.entry.version

    @property
    def adapter(self) -> str:
        return self.entry.adapter

    @property
    def install_dir_name(self) -> str:
        return f"{self.id}@{self.version}"

    @property
    def npm_package(self) -> str | None:
        """The npm package the spec launches through ``npx``, which the Shield installs instead."""
        acp = self.spec.acp
        if acp is None or acp.command != "npx":
            return None
        for arg in acp.args:
            if arg.startswith("-"):
                continue
            name, _, version = arg.rpartition("@")
            if name and version == self.version:
                return name
            return arg
        return None

    @property
    def launch_args(self) -> list[str]:
        """The arguments after the package, when launched from the prefix."""
        acp = self.spec.acp
        if acp is None:
            return []
        if self.npm_package is None:
            return list(acp.args)
        args = [arg for arg in acp.args if arg != "-y"]
        return args[1:]

    @property
    def command(self) -> str:
        acp = self.spec.acp
        if acp is None:
            raise RegisterRefused(f"{self.id} has no launch command; an organization's own spec names it")
        if self.npm_package is not None:
            return EXECUTABLES.get(self.npm_package, self.npm_package.rpartition("/")[2])
        return acp.command

    @property
    def secrets(self) -> list[str]:
        return list(self.spec.requires.secrets)

    @property
    def node_requirement(self) -> str | None:
        words = self.entry.binaries
        if "Node 22" in words:
            return ">=22"
        if "Node 20" in words:
            return ">=20"
        return None


def catalogue() -> dict[str, Harness]:
    """Every launchable harness of the catalogue with its register entry."""
    specs = load_harnesses()
    register = load_register()
    found: dict[str, Harness] = {}
    for harness_id, spec in specs.items():
        if harness_id == CUSTOM_HARNESS or spec.acp is None:
            continue
        entry = register.get(harness_id)
        if entry is None:  # pragma: no cover - agentspecs refuses this first
            raise RegisterRefused(f"{harness_id} has no entry in the register")
        found[harness_id] = Harness(spec=spec, entry=entry)
    return found


def harness(harness_id: str) -> Harness:
    try:
        found = catalogue()
    except HarnessError as exc:
        raise RegisterRefused(str(exc)) from None
    if harness_id == CUSTOM_HARNESS:
        raise RegisterRefused("'custom' is an organization's own spec, not one the Shield sets up from the catalogue")
    try:
        return found[harness_id]
    except KeyError:
        raise RegisterRefused(
            f"{harness_id!r} is not in the register; the harnesses are {', '.join(sorted(found))}"
        ) from None


def harness_of_command(executable: str) -> Harness | None:
    """The harness whose adapter or command an executable's name is, if any."""
    name = Path(executable).name
    for entry in catalogue().values():
        try:
            if name == entry.command:
                return entry
        except RegisterRefused:
            continue
    return None


#: Where a vendor's subscription login is kept, per harness: a credential the register refuses.
SUBSCRIPTION_LOGINS: dict[str, tuple[str, str]] = {
    "claude-code": ("~/.claude/.credentials.json", "a Claude Code login (Pro or Max)"),
    "codex": ("~/.codex/auth.json", "a ChatGPT login"),
    "gemini-cli": ("~/.gemini/oauth_creds.json", "a Google login"),
}


def credential_refusal(
    entry: Harness, environment: dict[str, str] | None = None, home: Path | None = None
) -> str | None:
    """The sentence that refuses the credentials at hand, or ``None`` when an API key serves.

    The register says ``api_key_only`` for the harnesses whose vendors refuse
    subscription credentials for third parties (SHIELD §3.3): with the key
    absent and a subscription login present, the Shield refuses rather than
    letting the adapter use the login; Gemini's login is only served on a
    Code Assist Standard or Enterprise tier, which the Shield cannot see, so
    its login is refused too and the key asked for.
    """
    env = os.environ if environment is None else environment
    keys_present = [name for name in entry.secrets if env.get(name)]
    if keys_present:
        return None
    login = SUBSCRIPTION_LOGINS.get(entry.id)
    if login is None:
        return None
    path, words = login
    where = Path(path.replace("~", str(home or Path.home())))
    if not where.exists():
        return None
    if entry.entry.served_to_third_parties is ThirdPartyServing.API_KEY_ONLY:
        tiers = f" ({entry.entry.tier_restrictions})" if entry.entry.tier_restrictions else ""
        return (
            f"{entry.name}: {words} is at {where}, and the register serves {entry.name} with an API key only"
            f"{tiers}; export {' or '.join(entry.secrets)} and the Shield runs it"
        )
    return None


__all__ = [
    "EXECUTABLES",
    "SUBSCRIPTION_LOGINS",
    "Harness",
    "RegisterRefused",
    "catalogue",
    "credential_refusal",
    "harness",
    "harness_of_command",
]
