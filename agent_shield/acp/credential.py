# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Authority across the chain: the execution credential a caller hands the Shield (SHIELD §2.4, SH-33).

A caller that delegates work — an orchestrator, a person's runtime, Datalayer's
control plane — hands the execution's own token in ``_meta.datalayer.credential``
(ORCHESTRATOR O1-17), the key Datalayer's delegations already use beside the
model budget. The Shield is where it stops:

- **never to the agent.** The ``_meta`` the agent is handed keeps only that one
  was sent (``withheld``), at ``session/new`` and at every ``session/prompt``;
- **the lent MCP is scoped by it.** Handed at ``session/new``, it becomes the
  ``Authorization`` of every HTTP MCP server the session is lent, whatever the
  client wrote there — so the gateway, which reads the credential's manifest,
  decides every call the agent *and every sub-agent it spawns* make through
  those servers: a sub-agent reaches MCP through the servers its parent was
  lent, and they carry no other authority. A stdio server cannot be lent the
  credential without putting it in the agent's arguments or environment, so a
  session given both is refused in a sentence;
- **one session, one authority.** A prompt carrying a credential the session's
  servers were not lent with is refused in a sentence: its tools would act with
  another authority than the turn's. A new session is opened with it.

The credential itself is never written anywhere — not in the audit, not in a
sentence: a row says only that one was lent.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

#: The key of Datalayer's own ``_meta`` (and of an A2A message's ``metadata``).
DATALAYER_META = "datalayer"
#: Where the execution's token travels under it (ORCHESTRATOR O1-17).
CREDENTIAL_FIELD = "credential"
#: What is left in its place: that one was sent, never what it was.
WITHHELD = "withheld"


def take_credential(meta: Mapping[str, Any] | None) -> tuple[dict[str, Any] | None, str | None]:
    """The ``_meta`` to hand on, with the credential withheld, and the credential when one was sent.

    The caller's mapping is not changed: what is handed on is a copy.
    """
    if not meta:
        return None, None
    handed = dict(meta)
    ours = handed.get(DATALAYER_META)
    if not isinstance(ours, Mapping):
        return handed, None
    credential = ours.get(CREDENTIAL_FIELD)
    if not isinstance(credential, str) or not credential or credential == WITHHELD:
        return handed, None
    handed[DATALAYER_META] = {**ours, CREDENTIAL_FIELD: WITHHELD}
    return handed, credential


def fingerprint(credential: str) -> str:
    """Which credential, to compare two: a digest, never kept beside the token."""
    return hashlib.sha256(credential.encode()).hexdigest()


class CredentialRefused(ValueError):
    """A credential the Shield cannot lend as asked, said in a sentence."""


def lent_with(servers: list[Any], credential: str) -> list[Any]:
    """The lent servers, each HTTP one's ``Authorization`` the credential; a stdio one refused."""
    from acp.schema import HttpHeader

    lent: list[Any] = []
    for server in servers:
        name = getattr(server, "name", None) or "?"
        headers = getattr(server, "headers", None)
        if getattr(server, "type", None) not in ("http", "sse") or headers is None:
            raise CredentialRefused(
                f"MCP server {name!r} is a stdio server, and the execution's credential cannot be lent "
                "to one without putting it in the agent's arguments or environment: lend it over HTTP, "
                "or open the session without a credential."
            )
        kept = [header for header in headers if header.name.lower() != "authorization"]
        lent.append(
            server.model_copy(
                update={"headers": [HttpHeader(name="Authorization", value=f"Bearer {credential}"), *kept]}
            )
        )
    return lent


__all__ = [
    "CREDENTIAL_FIELD",
    "DATALAYER_META",
    "WITHHELD",
    "CredentialRefused",
    "fingerprint",
    "lent_with",
    "take_credential",
]
