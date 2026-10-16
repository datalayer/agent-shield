# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Registration with Datalayer, for a Shield that runs outside its runtimes (SH-47, SH-73).

A standalone Shield registers with a **service-agent key** of an
organization — made by its administrator with
``datalayer mcp service-agents create`` — which is not a bearer token: it is
exchanged at IAM's token endpoint (``POST /api/iam/v1/oauth/token``,
``grant_type=client_credentials``) for an access token that lasts an hour.
``agent-shield setup --register`` does the first exchange, to prove the key,
and keeps the key and the token in ``credentials.yaml`` of the Shield's home,
mode ``0600``; ``serve`` reads them, pulls its policies from IAM with the
token (:mod:`agent_shield.saas`), exports its telemetry with it
(:mod:`agent_shield.tracing`), and exchanges the key again before the token
expires. The key is read from the environment, never from an argument, and
neither it nor the token is ever printed.

What a registered standalone Shield **cannot** have is said in one sentence
(:func:`cannot_have`): the operator's network boundary and the companion's
mounts are a Datalayer runtime's, and nothing here pretends to them. PAP
 is said unavailable while local-only (:func:`pap_sentence`); once
registered, ``run --pap <company>`` lends the gateway's ``pap`` toolset at
that company (:func:`pap_servers`), reached with the registered Shield's own
token, exchanged again as it nears its end — the gateway's custody and
identity, never a company's key here.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from agent_shield.config import home

CREDENTIALS_FILE = "credentials.yaml"
#: The environment variable the key is read from, by default.
KEY_ENV = "AGENT_SHIELD_SERVICE_KEY"
#: IAM's token endpoint, under its API prefix.
TOKEN_PATH = "/api/iam/v1/oauth/token"  # noqa: S105 - a path, not a secret
#: The default IAM, and where the telemetry goes when nothing else is said.
DEFAULT_IAM_URL = "https://prod1.datalayer.run"
#: Datalayer's MCP gateway, where a registered Shield's PAP toolsets are lent from.
DEFAULT_GATEWAY_URL = "https://mcp.datalayer.run/mcp"
#: The environment variable naming another gateway.
GATEWAY_ENV = "DATALAYER_MCP_SERVER_URL"
#: A token this close to its end is exchanged again before use.
RENEW_MARGIN = timedelta(seconds=120)

#: What a standalone Shield cannot have, said once and everywhere it matters.
CANNOT_HAVE = (
    "Standalone, the Shield has IAM's policies and Datalayer's observability, and cannot have the "
    "operator's network boundary (the pod's egress table) nor the companion's mounts: those are a "
    "Datalayer runtime's, and here the host's own firewall and filesystem stand in their place."
)


class RegistrationRefused(RuntimeError):
    """What stops a registration, said in a sentence; never the key."""


def cannot_have() -> str:
    return CANNOT_HAVE


def pap_sentence(registered: bool) -> str:
    """PAP through the Shield (SH-73): once registered, said unavailable while local-only."""
    if registered:
        return (
            "PAP: available — `run --pap <company>` lends the gateway's pap toolset at that company, reached "
            "with this Shield's registered token; the policy's mcp.allow names it (pap_<company>)."
        )
    return (
        "PAP: unavailable while local-only — a personal agent reaches a company through Datalayer's gateway and "
        "custody; `agent-shield setup --register` offers it."
    )


@dataclass
class Registration:
    """``credentials.yaml``: where the Shield is registered and with what."""

    path: Path
    iam_url: str = DEFAULT_IAM_URL
    org_uid: str = ""
    agent_uid: str = ""
    key: str = field(default="", repr=False)
    token: str = field(default="", repr=False)
    token_expires: datetime | None = None
    otel_url: str = ""
    registered_on: str = ""

    # -- the file --------------------------------------------------------------------

    @classmethod
    def load(cls, base: Path | None = None) -> Registration | None:
        """The registration kept, or ``None`` when the Shield is local-only."""
        path = (base or home()) / CREDENTIALS_FILE
        if not path.is_file():
            return None
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise RegistrationRefused(f"{path} is mode {mode:o}; the credentials file is 0600 or it is not read")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise RegistrationRefused(f"{path}: the credentials are a mapping")
        expires = data.get("token_expires")
        return cls(
            path=path,
            iam_url=str(data.get("iam_url") or DEFAULT_IAM_URL),
            org_uid=str(data.get("org_uid") or ""),
            agent_uid=str(data.get("agent_uid") or ""),
            key=str(data.get("key") or ""),
            token=str(data.get("token") or ""),
            token_expires=datetime.fromisoformat(expires) if isinstance(expires, str) and expires else None,
            otel_url=str(data.get("otel_url") or ""),
            registered_on=str(data.get("registered_on") or ""),
        )

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "iam_url": self.iam_url,
            "org_uid": self.org_uid,
            "agent_uid": self.agent_uid,
            "key": self.key,
            "token": self.token,
            "token_expires": self.token_expires.isoformat() if self.token_expires else None,
            "otel_url": self.otel_url,
            "registered_on": self.registered_on,
        }
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(yaml.safe_dump(data, sort_keys=False))
        os.chmod(self.path, 0o600)

    def forget(self) -> None:
        if self.path.exists():
            self.path.unlink()

    # -- the token ---------------------------------------------------------------------

    @property
    def token_url(self) -> str:
        return self.iam_url.rstrip("/") + TOKEN_PATH

    @property
    def telemetry_url(self) -> str:
        return (self.otel_url or self.iam_url).rstrip("/")

    def token_fresh(self, now: datetime | None = None) -> bool:
        if not self.token or self.token_expires is None:
            return False
        return (now or datetime.now(timezone.utc)) + RENEW_MARGIN < self.token_expires

    def exchange(self, *, timeout: float = 15.0, now: datetime | None = None) -> str:
        """The key for a token at IAM (``client_credentials``); kept with its expiry; the token."""
        if not self.agent_uid or not self.key:
            raise RegistrationRefused("a service agent's uid and its key are needed to register")
        if not self.iam_url.startswith(("https://", "http://")):
            raise RegistrationRefused(f"IAM's URL is http(s), not {self.iam_url!r}")
        body = urllib.parse.urlencode(
            {"grant_type": "client_credentials", "client_id": self.agent_uid, "client_secret": self.key}
        ).encode("ascii")
        request = urllib.request.Request(  # noqa: S310 - the scheme is checked above
            self.token_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as answer:  # noqa: S310 - http(s) only
                data = json.loads(answer.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = ""
            try:
                payload = json.loads(error.read().decode("utf-8"))
                detail = str(payload.get("error_description") or payload.get("error") or "")
            except Exception:
                detail = ""
            raise RegistrationRefused(
                f"IAM at {self.iam_url} answered {error.code} to the key exchange"
                + (f" ({detail})" if detail else "")
                + ": check the agent's uid, and that the key is not rotated or revoked"
            ) from None
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            reason = getattr(error, "reason", None) or error
            raise RegistrationRefused(f"IAM at {self.iam_url} could not be reached ({reason})") from None
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise RegistrationRefused(f"IAM at {self.iam_url} answered no access_token to the key exchange")
        lifetime = data.get("expires_in")
        seconds = int(lifetime) if isinstance(lifetime, (int, float, str)) and str(lifetime).isdigit() else 3600
        self.token = token
        self.token_expires = (now or datetime.now(timezone.utc)) + timedelta(seconds=seconds)
        return token

    def fresh_token(self, *, now: datetime | None = None) -> str:
        """The token, exchanged again when it is about to expire, and the file kept in step."""
        if not self.token_fresh(now):
            self.exchange(now=now)
            self.save()
        return self.token

    def describe(self) -> dict[str, Any]:
        """What ``policy show`` and ``setup`` say about it: never the key, never the token."""
        return {
            "iam_url": self.iam_url,
            "org_uid": self.org_uid,
            "agent_uid": self.agent_uid,
            "token": "held" if self.token else "none",
            "token_expires": self.token_expires.isoformat() if self.token_expires else None,
            "otel_url": self.telemetry_url,
            "registered_on": self.registered_on,
            "cannot_have": CANNOT_HAVE,
        }


def pap_server_name(company: str) -> str:
    """A company's server as the runtime names it: ``pap_`` and its domain in plain characters."""
    name = re.sub(r"[^a-z0-9]+", "_", f"pap_{company.strip().lower()}").strip("_")
    if name == "pap":
        raise RegistrationRefused("a company is named by its domain, e.g. `--pap manzanita.examples.datalayer.run`")
    return name


def pap_servers(
    registration: Registration | None,
    companies: list[str] | tuple[str, ...],
    *,
    gateway_url: str = "",
    now: datetime | None = None,
) -> list[Any]:
    """The gateway's ``pap`` toolset at each company, lent with the registered Shield's token.

    Made at each session, so a token near its end is exchanged first. Refused
    in :func:`pap_sentence`'s words while local-only.
    """
    if not companies:
        return []
    if registration is None:
        raise RegistrationRefused(pap_sentence(False))
    from acp.schema import HttpHeader, HttpMcpServer

    gateway = (gateway_url or os.environ.get(GATEWAY_ENV) or DEFAULT_GATEWAY_URL).rstrip("/")
    if not gateway.startswith(("https://", "http://")):
        raise RegistrationRefused(f"the gateway {gateway!r} is not an http(s) address")
    token = registration.fresh_token(now=now)
    return [
        HttpMcpServer(
            type="http",
            name=pap_server_name(company),
            url=f"{gateway}?only=pap&pap-company={urllib.parse.quote(company.strip().lower(), safe='')}",
            headers=[HttpHeader(name="Authorization", value=f"Bearer {token}")],
        )
        for company in companies
    ]


def register(
    *,
    org_uid: str,
    agent_uid: str,
    key: str,
    iam_url: str = DEFAULT_IAM_URL,
    otel_url: str = "",
    base: Path | None = None,
    now: datetime | None = None,
) -> Registration:
    """Exchange the key once, to prove it, and keep the registration (``0600``)."""
    if not org_uid.strip():
        raise RegistrationRefused("the organization's uid is needed (`--org`)")
    if not agent_uid.strip():
        raise RegistrationRefused("the service agent's uid is needed (`--agent`)")
    if not key.strip():
        raise RegistrationRefused(f"the service agent's key is read from the environment (${KEY_ENV}), and it is empty")
    registration = Registration(
        path=(base or home()) / CREDENTIALS_FILE,
        iam_url=iam_url.rstrip("/"),
        org_uid=org_uid.strip(),
        agent_uid=agent_uid.strip(),
        key=key.strip(),
        otel_url=otel_url.rstrip("/"),
        registered_on=(now or datetime.now(timezone.utc)).isoformat(),
    )
    registration.exchange(now=now)
    registration.save()
    return registration


__all__ = [
    "CANNOT_HAVE",
    "CREDENTIALS_FILE",
    "DEFAULT_GATEWAY_URL",
    "DEFAULT_IAM_URL",
    "GATEWAY_ENV",
    "KEY_ENV",
    "RENEW_MARGIN",
    "TOKEN_PATH",
    "Registration",
    "RegistrationRefused",
    "cannot_have",
    "pap_sentence",
    "pap_server_name",
    "pap_servers",
    "register",
]
