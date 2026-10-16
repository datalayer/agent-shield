# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Registration with Datalayer through a service-agent key (SHIELD SH-47, SH-73): exchanged, kept 0600, never shown."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qs

import pytest
from typer.testing import CliRunner

from agent_shield.cli import app
from agent_shield.config import Config
from agent_shield.registration import (
    CANNOT_HAVE,
    CREDENTIALS_FILE,
    KEY_ENV,
    Registration,
    RegistrationRefused,
    cannot_have,
    pap_sentence,
    register,
)

runner = CliRunner()
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
KEY = "svc-key-never-printed-0123456789"
TOKEN_ONE = "eyJtoken.one.signature"  # noqa: S105
TOKEN_TWO = "eyJtoken.two.signature"  # noqa: S105


class FakeIam(BaseHTTPRequestHandler):
    """IAM's token endpoint: client_credentials for one agent and one key, a token an hour long."""

    exchanges: ClassVar[list[dict]] = []
    tokens: ClassVar[list[str]] = [TOKEN_ONE, TOKEN_TWO]

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        FakeIam.exchanges.append({**form, "path": self.path})
        if self.path != "/api/iam/v1/oauth/token" or form.get("grant_type") != "client_credentials":
            self.send_response(400)
            self.end_headers()
            return
        if form.get("client_id") != "agent-1" or form.get("client_secret") != KEY:
            body = json.dumps(
                {"error": "invalid_client", "error_description": "Unknown service agent or key."}
            ).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        token = FakeIam.tokens[min(len(FakeIam.exchanges) - 1, len(FakeIam.tokens) - 1)]
        body = json.dumps({"access_token": token, "token_type": "Bearer", "expires_in": 3600}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


@pytest.fixture
def iam():
    FakeIam.exchanges = []
    server = HTTPServer(("127.0.0.1", 0), FakeIam)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def shield_home(tmp_path: Path, monkeypatch) -> Path:
    base = tmp_path / "home"
    monkeypatch.setenv("AGENT_SHIELD_HOME", str(base))
    monkeypatch.chdir(tmp_path)
    return base


def test_register_exchanges_the_key_once_and_keeps_the_file_0600(iam: str, shield_home: Path):
    registration = register(org_uid="org-1", agent_uid="agent-1", key=KEY, iam_url=iam, base=shield_home, now=NOW)
    assert registration.token == TOKEN_ONE and registration.token_expires == NOW + timedelta(seconds=3600)
    path = shield_home / CREDENTIALS_FILE
    assert path.stat().st_mode & 0o777 == 0o600
    assert FakeIam.exchanges == [
        {
            "grant_type": "client_credentials",
            "client_id": "agent-1",
            "client_secret": KEY,
            "path": "/api/iam/v1/oauth/token",
        }
    ]
    kept = Registration.load(shield_home)
    assert kept is not None and kept.key == KEY and kept.token == TOKEN_ONE and kept.org_uid == "org-1"
    described = kept.describe()
    assert KEY not in json.dumps(described) and TOKEN_ONE not in json.dumps(described)
    assert described["cannot_have"] == CANNOT_HAVE and described["token"] == "held"  # noqa: S105 - a word, not a token
    assert kept.telemetry_url == iam


def test_a_token_about_to_expire_is_exchanged_again(iam: str, shield_home: Path):
    registration = register(org_uid="org-1", agent_uid="agent-1", key=KEY, iam_url=iam, base=shield_home, now=NOW)
    assert registration.fresh_token(now=NOW + timedelta(minutes=10)) == TOKEN_ONE
    assert registration.fresh_token(now=NOW + timedelta(minutes=59)) == TOKEN_TWO
    assert Registration.load(shield_home).token == TOKEN_TWO  # type: ignore[union-attr]
    assert len(FakeIam.exchanges) == 2


def test_a_wrong_key_is_refused_in_a_sentence_without_the_key(iam: str, shield_home: Path):
    with pytest.raises(RegistrationRefused) as refused:
        register(org_uid="org-1", agent_uid="agent-1", key="wrong-key-value", iam_url=iam, base=shield_home)
    assert "answered 401" in str(refused.value) and "Unknown service agent" in str(refused.value)
    assert "wrong-key-value" not in str(refused.value)
    assert not (shield_home / CREDENTIALS_FILE).exists()
    with pytest.raises(RegistrationRefused, match="could not be reached"):
        register(org_uid="org-1", agent_uid="agent-1", key=KEY, iam_url="http://127.0.0.1:1", base=shield_home)
    with pytest.raises(RegistrationRefused, match="read from the environment"):
        register(org_uid="org-1", agent_uid="agent-1", key="", iam_url=iam, base=shield_home)


def test_a_loose_credentials_file_is_not_read(iam: str, shield_home: Path):
    register(org_uid="org-1", agent_uid="agent-1", key=KEY, iam_url=iam, base=shield_home)
    path = shield_home / CREDENTIALS_FILE
    os.chmod(path, 0o644)
    with pytest.raises(RegistrationRefused, match="0600"):
        Registration.load(shield_home)
    assert Registration.load(shield_home / "elsewhere") is None


def test_the_sentences():
    assert "cannot have the operator's network boundary" in cannot_have()
    assert "unavailable while local-only" in pap_sentence(False) and "setup --register" in pap_sentence(False)
    assert "`run --pap <company>`" in pap_sentence(True) and "registered token" in pap_sentence(True)


def test_setup_register_reads_the_key_from_the_environment_and_policy_show_says_so(
    iam: str, shield_home: Path, tmp_path: Path, monkeypatch
):
    monkeypatch.setenv(KEY_ENV, KEY)
    monkeypatch.setattr("agent_shield.cli._node_version", lambda: (22, 23, 2))
    monkeypatch.setattr("agent_shield.cli.install_adapter", lambda entry, base=None: _fake_adapter(entry, base))
    result = runner.invoke(
        app, ["setup", "--yes", "--register", "--org", "org-1", "--agent", "agent-1", "--iam-url", iam]
    )
    assert result.exit_code == 0, result.output
    assert "registered with Datalayer: organization org-1, service agent agent-1" in result.output
    assert KEY not in result.output and TOKEN_ONE not in result.output
    assert "cannot have the operator's network boundary" in result.output
    assert "PAP: available" in result.output
    assert Config.load(shield_home).data["registered"] is True
    shown = runner.invoke(app, ["policy", "show"])
    assert shown.exit_code == 0, shown.output
    assert "registration: organization org-1, service agent agent-1" in shown.output
    assert "token held until" in shown.output and KEY not in shown.output and TOKEN_ONE not in shown.output
    assert "PAP: available" in shown.output
    # The key named by another variable, and a missing one, each said.
    monkeypatch.delenv(KEY_ENV)
    refused = runner.invoke(
        app, ["setup", "--yes", "--register", "--org", "org-1", "--agent", "agent-1", "--iam-url", iam]
    )
    assert refused.exit_code == 2 and f"${KEY_ENV}" in refused.output


def _fake_adapter(entry, base):
    from agent_shield.config import harness_prefix

    executable = harness_prefix(entry.id, entry.version, base) / "node_modules" / ".bin" / entry.command
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_text("#!/bin/sh\n")
    return executable


def test_serve_refuses_to_start_registered_with_no_document_from_iam(iam: str, shield_home: Path):
    from agent_shield.cli import _managed_loaded
    from agent_shield.saas import ManagedPolicies, ServedPolicies

    registration = register(org_uid="org-1", agent_uid="agent-1", key=KEY, iam_url=iam, base=shield_home)

    class Empty:
        where = "IAM at " + iam

        def fetch(self):
            return ServedPolicies(policies=[], expires=NOW + timedelta(minutes=10))

    with pytest.raises(RegistrationRefused, match="serves no Shield document for service agent agent-1"):
        _managed_loaded(ManagedPolicies(Empty()), registration)
