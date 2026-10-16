# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A second decision point through the port (SH-78): Open Policy Agent.

The port is not OpenFGA-shaped: the same ``EvaluationRequest`` goes to OPA as
its ``input``, a Rego package answers ``decision`` and ``context``, and
``decide`` honours it with the same rules. Proved against a real OPA when
Docker is here (``AGENT_SHIELD_OPA_IMAGE``, ``openpolicyagent/opa:1.9.0``);
the adapter's wrapping is held by the fake either way.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request

import pytest

from agent_shield.policy import (
    ActionName,
    Action,
    AuthorizerConfig,
    AuthorizerUnreachable,
    Context,
    EvaluationRequest,
    OpaAuthorizer,
    Policy,
    Resource,
    Rule,
    Subject,
    decide,
    hook_for,
)

REGO = """
package authzen.evaluation

import rego.v1

default decision := false

# An account may read and write inside its own folder; a deployment may call the
# tools it was handed; nobody buys.
decision if {
    input.subject.type == "account"
    startswith(input.resource.id, concat("/", ["home", input.subject.id]))
    input.action.name in {"read", "write", "execute"}
}

decision if {
    input.subject.type == "deployment"
    input.action.name == "can_call"
    input.resource.id in data.handed[input.subject.id]
}

context := {"model_version": "rego:1", "reason_user": reason}

reason := "OPA allows it" if decision
reason := "OPA holds no rule letting it" if not decision
"""


def request(subject=("account", "alice"), action="write", resource=("workspace", "home/alice/p")):
    return EvaluationRequest(
        subject=Subject(type=subject[0], id=subject[1]),
        action=ActionName(name=action),
        resource=Resource(type=resource[0], id=resource[1]),
    )


def test_the_adapter_wraps_the_request_as_input_and_unwraps_the_result(monkeypatch):
    import importlib

    port = importlib.import_module("agent_shield.policy.authorize")
    sent = {}

    def fake(url, body, headers, timeout, who):
        sent["url"], sent["body"] = url, body
        return {"result": {"decision": True, "context": {"model_version": "rego:1"}}}

    monkeypatch.setattr(port, "_post_json", fake)
    opa = OpaAuthorizer("http://opa:8181", package="authzen.evaluation")
    answer = opa.evaluate(request())
    assert answer.decision is True and answer.model_version == "rego:1"
    assert sent["url"] == "http://opa:8181/v1/data/authzen/evaluation"
    assert sent["body"] == {"input": request().model_dump()}
    monkeypatch.setattr(port, "_post_json", lambda *a, **k: {"result": {}})
    with pytest.raises(AuthorizerUnreachable, match="no boolean 'decision' in its result"):
        opa.evaluate(request())
    assert AuthorizerConfig(opa={"url": "http://opa:8181"}).kind == "opa"
    assert isinstance(AuthorizerConfig(opa={"url": "http://opa:8181"}).build(), OpaAuthorizer)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def opa_url():
    docker = shutil.which("docker")
    if docker is None or os.environ.get("AGENT_SHIELD_NO_DOCKER"):
        pytest.skip("no docker here: the OPA container drill needs one")
    image = os.environ.get("AGENT_SHIELD_OPA_IMAGE", "openpolicyagent/opa:1.9.0")
    port = _free_port()
    started = subprocess.run(
        [docker, "run", "-d", "--rm", "-p", f"127.0.0.1:{port}:8181", image, "run", "--server", "--addr", "0.0.0.0:8181"],
        capture_output=True, text=True, timeout=180,
    )
    if started.returncode != 0:
        pytest.skip(f"OPA could not be started: {started.stderr.strip()[:200]}")
    container = started.stdout.strip()
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"{url}/health", timeout=1) as answer:  # noqa: S310
                    if answer.status == 200:
                        break
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        else:
            pytest.skip("OPA did not become healthy")
        policy = urllib.request.Request(f"{url}/v1/policies/authzen", data=REGO.encode(), method="PUT", headers={"Content-Type": "text/plain"})
        with urllib.request.urlopen(policy, timeout=5) as answer:  # noqa: S310
            assert answer.status == 200
        handed = urllib.request.Request(
            f"{url}/v1/data/handed", data=json.dumps({"d-1": ["tool:read_notebook"]}).encode(), method="PUT", headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(handed, timeout=5) as answer:  # noqa: S310
            assert answer.status in (200, 204)
        yield url
    finally:
        subprocess.run([docker, "stop", container], capture_output=True, text=True, timeout=60)


def test_a_real_opa_decides_through_the_same_port(opa_url):
    opa = OpaAuthorizer(opa_url)
    allowed = opa.evaluate(request())
    assert allowed.decision is True and allowed.reason == "OPA allows it" and allowed.model_version == "rego:1"
    denied = opa.evaluate(request(resource=("workspace", "home/bob/p")))
    assert denied.decision is False and denied.reason == "OPA holds no rule letting it"
    assert opa.evaluate(request(("deployment", "d-1"), "can_call", ("tool", "tool:read_notebook"))).decision is True
    assert opa.evaluate(request(("deployment", "d-1"), "can_call", ("tool", "tool:launch_sandbox"))).decision is False
    # And decide honours it as any authorizer: a Rule's do it needs its allow, its deny wins.
    policy = Policy(scope="session", authorize=["write", "buy"], rules=[Rule(name="write freely", decision="allow", classes=["write"]), Rule(name="buy freely", decision="allow", classes=["buy"])])
    ctx = Context(workspace="/home/alice/p", subject=Subject(type="account", id="alice"), authorize=hook_for(opa))
    inside = decide(Action(kind="edit", title="edit", path="a.py", inside=True, **{"class": "write"}), ctx, [policy])
    assert inside.verdict == "allow" and inside.authorizer == "opa" and inside.model_version == "rego:1"
    buy = decide(Action(kind="other", title="pap_confirm", resource="connection:acme.example", **{"class": "buy"}), ctx, [policy])
    assert buy.verdict == "deny" and buy.decided_by == "authorizer" and "OPA holds no rule letting it" in buy.sentence
    # Stopped, OPA is a deny in a sentence naming it — the port's rule, whoever the decision point is.
    down = OpaAuthorizer("http://127.0.0.1:9", timeout=0.5)
    ctx_down = Context(workspace="/home/alice/p", subject=Subject(type="account", id="alice"), authorize=hook_for(down))
    refused = decide(Action(kind="edit", title="edit", path="b.py", inside=True, **{"class": "write"}), ctx_down, [policy])
    assert refused.verdict == "deny" and "the authorizer opa" in refused.sentence and "could not be reached" in refused.sentence
