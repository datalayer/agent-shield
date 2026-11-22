# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The firewall: rules, compiler, controller, the kernel's log read back, the command."""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from agent_shield.audit import AuditLog
from agent_shield.cli import app
from agent_shield.firewall import (
    BaseAllowance,
    BaseLayer,
    ConnectionRecorder,
    Controller,
    FirewallError,
    FirewallRefused,
    FirewallRules,
    compile_rules,
    firewall_json_schema,
    is_public_address,
    parse_entry,
    rules_of_spec,
)
from agent_shield.firewall.compile import prefix
from agent_shield.firewall.nflog import (
    NFULA_PAYLOAD,
    NFULA_PREFIX,
    Connection,
    _attribute,
    config_message,
    decode_message,
    messages,
)

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()

BASE = BaseLayer(
    dns=("10.96.0.10",),
    allow=(BaseAllowance("gateway", "mcp.datalayer.run", ("203.0.113.5",), (443,)),),
    platform_sources=("10.244.0.0/16",),
)


# -- rules ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,kind,value,port",
    [
        ("*", "any", "*", None),
        ("*:443", "any", "*", 443),
        ("*:80", "any", "*", 80),
        ("api.tavily.com", "host", "api.tavily.com", None),
        ("registry.npmjs.org:443", "host", "registry.npmjs.org", 443),
        ("8.8.8.8", "network", "8.8.8.8/32", None),
        ("1.1.1.0/24:53", "network", "1.1.1.0/24", 53),
    ],
)
def test_an_egress_entry_is_parsed(text, kind, value, port):
    entry = parse_entry(text, "egress")
    assert (entry.kind, entry.value, entry.port) == (kind, value, port)


@pytest.mark.parametrize(
    "text,said",
    [
        ("*.example.com", "addresses, not names"),
        ("10.0.0.0/8", "private or reserved"),
        ("169.254.169.254", "private or reserved"),
        ("192.168.1.1:22", "private or reserved"),
        ("localhost", "fully qualified"),
        ("example.com:70000", "between 1 and 65535"),
        ("*:70000", "between 1 and 65535"),
        ("*:", "addresses, not names"),
        ("*:443:80", "addresses, not names"),
        ("platform", "ingress source"),
        ("1.2.3.4/33", "IPv4"),
        ("", "names nothing"),
    ],
)
def test_an_egress_entry_is_refused_with_its_reason(text, said):
    with pytest.raises(FirewallError, match=said):
        parse_entry(text, "egress")


def test_ingress_takes_platform_and_private_sources_not_hosts():
    assert parse_entry("platform", "ingress").kind == "platform"
    assert parse_entry("10.42.0.0/16:8765", "ingress").port == 8765
    with pytest.raises(FirewallError, match="not a host name"):
        parse_entry("example.com", "ingress")


def test_star_stands_alone_and_an_entry_once():
    assert FirewallRules(egress=["*"]).open_egress
    with pytest.raises(ValidationError, match="stands alone"):
        FirewallRules(egress=["*", "example.com"])
    with pytest.raises(ValidationError, match="named twice"):
        FirewallRules(egress=["example.com", "example.com"])
    with pytest.raises(ValidationError):
        FirewallRules.model_validate({"egress": [], "fetch": []})


def test_star_on_a_port_is_any_public_address_on_that_port_beside_other_entries():
    rules = FirewallRules(egress=["*:80", "*:443", "smtp.example.com:587"])
    assert not rules.open_egress
    assert rules.open_egress_ports == [80, 443]
    assert parse_entry("*:8765", "ingress").port == 8765
    with pytest.raises(ValidationError, match="stands alone"):
        FirewallRules(egress=["*", "*:443"])
    with pytest.raises(ValidationError, match="named twice"):
        FirewallRules(egress=["*:443", "*:443"])


def test_empty_ingress_means_platform():
    assert [e.kind for e in FirewallRules().ingress_entries()] == ["platform"]


def test_rules_of_a_spec_are_its_policy_shield():
    assert rules_of_spec({"policy": {"shield": {"egress": ["*"]}}}).egress == ["*"]
    assert rules_of_spec({"id": "x"}).egress == []


def test_the_published_schema_is_the_models():
    published = json.loads((ROOT / "schema" / "firewall.schema.json").read_text())
    assert published == firewall_json_schema()


# -- compiler ------------------------------------------------------------------------------


def test_base_alone_allows_dns_and_the_platform_and_refuses_the_rest():
    script = compile_rules(BASE).script
    lines = script.splitlines()
    assert lines[0] == "*filter" and lines[-1] == "COMMIT"
    assert "-A SHIELD-EGRESS -d 10.96.0.10/32 -p udp --dport 53 -j ACCEPT" in lines
    assert "-A SHIELD-EGRESS -d 203.0.113.5/32 -p tcp --dport 443 -j ACCEPT" in lines
    # The metadata address is refused before anything is allowed.
    assert lines.index("-A SHIELD-EGRESS -d 169.254.169.254/32 -j SHIELD-REFUSE") < lines.index(
        "-A SHIELD-EGRESS -d 203.0.113.5/32 -p tcp --dport 443 -j ACCEPT"
    )
    assert lines[-2] == "-A SHIELD-EGRESS -j SHIELD-REFUSE"
    assert "SHIELD-INGRESS" not in script


def test_every_allow_and_refuse_is_logged_on_a_new_connection():
    script = compile_rules(
        BASE, FirewallRules(egress=["api.tavily.com"]), resolved={"api.tavily.com": ["198.51.100.7"]}
    ).script
    assert '--nflog-group 7 --nflog-prefix "shield allow base:gateway"' in script
    assert '--nflog-prefix "shield allow spec:api.tavily.com"' in script
    assert '--nflog-prefix "shield refuse default"' in script
    assert "-A SHIELD-EGRESS -d 198.51.100.7/32 -p tcp -j ACCEPT" in script


def test_star_refuses_the_non_public_ranges_first_then_accepts_tcp():
    lines = compile_rules(BASE, FirewallRules(egress=["*"])).script.splitlines()
    accept = lines.index("-A SHIELD-EGRESS -p tcp -j ACCEPT")
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"):
        assert lines.index(f"-A SHIELD-EGRESS -d {network} -j SHIELD-REFUSE") < accept
    # The base's own private addresses (DNS) are allowed before the ranges are refused.
    assert lines.index("-A SHIELD-EGRESS -d 10.96.0.10/32 -p udp --dport 53 -j ACCEPT") < accept


def test_star_on_ports_refuses_the_non_public_ranges_on_those_ports_then_accepts_them_only():
    lines = compile_rules(
        BASE,
        FirewallRules(egress=["*:80", "*:443", "smtp.example.com:587"]),
        resolved={"smtp.example.com": ["198.51.100.9"]},
    ).script.splitlines()
    for port in (80, 443):
        accept = lines.index(f"-A SHIELD-EGRESS -p tcp --dport {port} -j ACCEPT")
        for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"):
            assert lines.index(f"-A SHIELD-EGRESS -d {network} -p tcp --dport {port} -j SHIELD-REFUSE") < accept
        assert f'--nflog-prefix "shield allow spec:*:{port}"' in "\n".join(lines)
    # No rule accepts every TCP port, and the ranges are not refused on every protocol.
    assert "-A SHIELD-EGRESS -p tcp -j ACCEPT" not in lines
    assert "-A SHIELD-EGRESS -d 10.0.0.0/8 -j SHIELD-REFUSE" not in lines
    # Another entry on another port still holds, and the rest is refused.
    assert "-A SHIELD-EGRESS -d 198.51.100.9/32 -p tcp --dport 587 -j ACCEPT" in lines
    assert lines[-2] == "-A SHIELD-EGRESS -j SHIELD-REFUSE"


def test_an_unresolved_host_is_refused_and_said():
    compiled = compile_rules(BASE, FirewallRules(egress=["gone.example.com:443"]), resolved={})
    assert compiled.unresolved == ["gone.example.com"]
    assert "gone.example.com" not in compiled.script.replace('"', "")


def test_a_spec_hosts_non_public_answers_are_dropped_and_said():
    """DNS rebinding: a public name that later resolves into a private range gets no rule there."""
    compiled = compile_rules(
        BASE,
        FirewallRules(egress=["mixed.example.com:443", "rebound.example.com:443", "api.tavily.com"]),
        resolved={
            "mixed.example.com": ["198.51.100.7", "10.0.0.5", "169.254.169.254"],
            "rebound.example.com": ["127.0.0.1", "100.64.1.1", "192.168.1.1", "172.16.0.9", "fd00::1"],
            "api.tavily.com": ["198.51.100.8"],
        },
    )
    lines = compiled.script.splitlines()
    assert "-A SHIELD-EGRESS -d 198.51.100.7/32 -p tcp --dport 443 -j ACCEPT" in lines
    assert "-A SHIELD-EGRESS -d 198.51.100.8/32 -p tcp -j ACCEPT" in lines
    for address in ("10.0.0.5", "127.0.0.1", "100.64.1.1", "192.168.1.1", "172.16.0.9"):
        assert not [line for line in lines if f"-d {address}/32" in line and "ACCEPT" in line]
    # The metadata address stays refused by the base, never accepted for a host.
    assert not [line for line in lines if "169.254.169.254/32" in line and "ACCEPT" in line]
    assert compiled.non_public == {
        "mixed.example.com": ["10.0.0.5", "169.254.169.254"],
        "rebound.example.com": ["100.64.1.1", "127.0.0.1", "172.16.0.9", "192.168.1.1", "fd00::1"],
    }
    assert compiled.non_public_only == ["rebound.example.com"]
    assert compiled.unresolved == []
    assert '--nflog-prefix "shield allow spec:rebound.example.com:443"' not in compiled.script
    assert compiled.hosts.get("10.0.0.5") is None


def test_the_cluster_ranges_are_never_a_spec_hosts_and_star_refuses_them():
    base = BaseLayer(dns=("10.96.0.10",), cluster_ranges=("198.18.0.0/15", "203.0.113.0/24"))
    compiled = compile_rules(
        base, FirewallRules(egress=["svc.example.com:443"]), resolved={"svc.example.com": ["203.0.113.9"]}
    )
    assert compiled.non_public_only == ["svc.example.com"]
    lines = compile_rules(base, FirewallRules(egress=["*"])).script.splitlines()
    accept = lines.index("-A SHIELD-EGRESS -p tcp -j ACCEPT")
    assert lines.index("-A SHIELD-EGRESS -d 203.0.113.0/24 -j SHIELD-REFUSE") < accept
    assert BaseLayer.from_json(base.to_json()) == base


def test_cluster_ranges_as_a_string_is_refused():
    with pytest.raises(ValueError, match="cluster_ranges is a list of IPv4 networks"):
        BaseLayer.from_json({"cluster_ranges": "203.0.113.0/24"})


@pytest.mark.parametrize("bad", ["203.0.113.0/typo", "not-a-network", "203.0.113.300/24", ""])
def test_a_malformed_cluster_range_is_refused(bad):
    with pytest.raises(ValueError, match="is not an IPv4 network"):
        BaseLayer.from_json({"cluster_ranges": ["10.42.0.0/16", bad]})


def test_an_ipv6_cluster_range_is_refused_with_a_sentence():
    with pytest.raises(ValueError, match="IPv6 network; the firewall's rules are IPv4 only"):
        BaseLayer.from_json({"cluster_ranges": ["fd00:10:42::/56"]})


def test_a_cluster_range_that_is_not_a_string_is_refused():
    with pytest.raises(ValueError, match="as strings"):
        BaseLayer.from_json({"cluster_ranges": [167772160]})


def test_valid_cluster_ranges_are_normalized():
    base = BaseLayer.from_json({"cluster_ranges": ["203.0.113.9/24", " 10.42.0.0/16 ", "198.51.100.7"]})
    assert base.cluster_ranges == ("203.0.113.0/24", "10.42.0.0/16", "198.51.100.7/32")
    assert BaseLayer.from_json({}).cluster_ranges == ()
    assert BaseLayer.from_json({"cluster_ranges": None}).cluster_ranges == ()
    compiled = compile_rules(
        base, FirewallRules(egress=["svc.example.com:443"]), resolved={"svc.example.com": ["203.0.113.9"]}
    )
    assert compiled.non_public_only == ["svc.example.com"]


def test_load_base_refuses_a_bad_cluster_range(tmp_path, monkeypatch, capsys):
    import typer

    from agent_shield.firewall.cli import BASE_ENV, load_base

    path = tmp_path / "base.json"
    path.write_text(json.dumps({"dns": ["10.96.0.10"], "cluster_ranges": ["203.0.113.0/typo"]}))
    with pytest.raises(typer.Exit) as raised:
        load_base(path)
    assert raised.value.exit_code == 2
    assert "is not a base layer: cluster_ranges: '203.0.113.0/typo' is not an IPv4 network" in capsys.readouterr().err
    monkeypatch.setenv(BASE_ENV, json.dumps({"cluster_ranges": "203.0.113.0/24"}))
    with pytest.raises(typer.Exit):
        load_base(None)
    assert f"{BASE_ENV} is not a base layer: cluster_ranges is a list" in capsys.readouterr().err


def test_the_base_layers_private_endpoints_are_never_filtered():
    """The platform's own endpoints (a cluster database, a broker) are the base's, and private by design."""
    base = BaseLayer(
        dns=("10.96.0.10",),
        allow=(
            BaseAllowance("memories", "memories-postgres.datalayer.svc", ("10.43.12.7",), (5432,)),
            BaseAllowance("pulsar", "pulsar.datalayer.svc", ("10.43.20.1",), (6650,)),
        ),
    )
    compiled = compile_rules(base, FirewallRules(egress=["*:80", "*:443"]))
    lines = compiled.script.splitlines()
    assert "-A SHIELD-EGRESS -d 10.43.12.7/32 -p tcp --dport 5432 -j ACCEPT" in lines
    assert "-A SHIELD-EGRESS -d 10.43.20.1/32 -p tcp --dport 6650 -j ACCEPT" in lines
    assert compiled.non_public == {} and compiled.non_public_only == []


@pytest.mark.parametrize(
    "address,public",
    [
        ("93.184.215.14", True),
        ("140.82.121.4", True),
        ("10.1.2.3", False),
        ("172.31.255.255", False),
        ("192.168.0.1", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),
        ("100.64.0.1", False),
        ("0.0.0.0", False),
        ("224.0.0.1", False),
        ("fd12:3456::1", False),
        ("fe80::1", False),
        ("2606:4700::1111", False),
        ("not-an-address", False),
    ],
)
def test_is_public_address(address, public):
    assert is_public_address(address) is public


def test_is_public_address_takes_the_cluster_ranges():
    assert is_public_address("203.0.113.9") is True
    assert is_public_address("203.0.113.9", ("203.0.113.0/24",)) is False


def test_the_controller_says_dropped_answers_in_its_log_its_row_and_its_state(tmp_path, caplog):
    audit = AuditLog(tmp_path / "audit.jsonl")
    answers = {"rebound.example.com": ["10.0.0.5"], "mixed.example.com": ["198.51.100.7", "192.168.0.4"]}
    controller = Controller(
        BASE, audit=audit, runner=FakeKernel(), resolver=lambda host: answers[host], state_dir=tmp_path / "state"
    )
    with caplog.at_level("WARNING", logger="agent_shield.firewall.controller"):
        controller.apply(FirewallRules(egress=["rebound.example.com:443", "mixed.example.com:443"]))
    said = caplog.text
    assert "rebound.example.com resolves only to non-public addresses; it gets no rule" in said
    assert "mixed.example.com resolved to 192.168.0.4, not a public address; dropped" in said
    row = audit.rows()[-1]
    assert row["non_public_only"] == ["rebound.example.com"]
    assert row["non_public"]["mixed.example.com"] == ["192.168.0.4"]
    state = json.loads((tmp_path / "state" / "applied.json").read_text())
    assert state["non_public_only"] == ["rebound.example.com"]
    from agent_shield.firewall.export import row_attributes

    assert row_attributes(row)["shield.non_public_only"] == ["rebound.example.com"]
    # A later answer that turns private is dropped at the refresh as well.
    answers["mixed.example.com"] = ["10.9.9.9"]
    assert controller.refresh() is True
    assert controller.applied.compiled.non_public_only == ["rebound.example.com", "mixed.example.com"]


def test_compile_says_a_host_that_resolves_only_to_private_addresses(tmp_path, monkeypatch):
    from agent_shield.firewall import controller as controller_module

    monkeypatch.setattr(
        controller_module.socket,
        "getaddrinfo",
        lambda host, *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))],
    )
    base = tmp_path / "base.json"
    base.write_text(json.dumps(BASE.to_json()))
    rules = tmp_path / "rules.yaml"
    rules.write_text("egress: ['rebound.example.com:443']\n")
    result = runner.invoke(app, ["firewall", "compile", "--base", str(base), "--rules", str(rules)])
    assert result.exit_code == 0, result.output
    assert "rebound.example.com resolves only to non-public addresses; it gets no rule" in result.output
    assert "10.0.0.5/32" not in result.output.split("agent-shield:")[0]


def test_the_address_map_names_base_and_spec_hosts():
    compiled = compile_rules(
        BASE, FirewallRules(egress=["api.tavily.com"]), resolved={"api.tavily.com": ["198.51.100.7"]}
    )
    assert compiled.hosts == {"203.0.113.5": ["mcp.datalayer.run"], "198.51.100.7": ["api.tavily.com"]}


def test_ingress_compiles_platform_sources_and_ports_when_enforced():
    rules = FirewallRules(ingress=["platform", "10.42.0.0/16:8765"])
    script = compile_rules(BASE, rules, enforce_ingress=True).script
    assert "-A SHIELD-INGRESS -s 10.244.0.0/16 -j ACCEPT" in script
    assert "-A SHIELD-INGRESS -s 10.42.0.0/16 -p tcp --dport 8765 -j ACCEPT" in script
    assert script.splitlines()[-2] == "-A SHIELD-INGRESS -j SHIELD-REFUSE"


def test_a_prefix_is_short_and_safe():
    said = prefix("allow", 'spec:"bad" rule; rm -rf /' + "x" * 80)
    assert len(said) <= 63 and '"' not in said and ";" not in said


def test_the_base_layer_round_trips_and_always_refuses_metadata():
    layer = BaseLayer.from_json(
        {"dns": ["10.96.0.10"], "allow": [{"name": "g", "host": "h", "addresses": ["1.2.3.4"], "ports": [443]}]}
    )
    assert "169.254.169.254/32" in layer.refuse
    assert BaseLayer.from_json(layer.to_json()) == layer
    with pytest.raises(ValueError, match="no extra"):
        BaseLayer.from_json({"extra": []})


# -- controller ----------------------------------------------------------------------------


class FakeKernel:
    def __init__(self, refuse_restore: bool = False):
        self.calls: list[tuple[list[str], str]] = []
        self.hooked: set[str] = set()
        self.refuse_restore = refuse_restore

    def __call__(self, argv, stdin):
        argv = list(argv)
        self.calls.append((argv, stdin))
        if argv[0] == "iptables-restore":
            return (1, "iptables-restore: line 3 failed") if self.refuse_restore else (0, "")
        if argv[1] == "-C":
            return (0, "") if argv[2] in self.hooked else (1, "no rule")
        if argv[1] == "-I":
            self.hooked.add(argv[2])
            return 0, ""
        return 1, "unexpected"


def test_apply_restores_atomically_hooks_once_and_records(tmp_path):
    kernel = FakeKernel()
    audit = AuditLog(tmp_path / "audit.jsonl")
    controller = Controller(
        BASE, audit=audit, runner=kernel, resolver=lambda host: ["198.51.100.7"], state_dir=tmp_path / "state"
    )
    controller.apply(FirewallRules(egress=["api.tavily.com"]))
    controller.apply(FirewallRules(egress=["*"]), reason="configure")
    restores = [c for c in kernel.calls if c[0][0] == "iptables-restore"]
    assert [c[0] for c in restores] == [["iptables-restore", "--noflush"]] * 2
    assert sum(1 for c in kernel.calls if c[0][1:2] == ["-I"]) == 1
    rows = audit.rows()
    assert [r["event"] for r in rows] == ["firewall", "firewall"]
    assert rows[0]["egress"] == ["api.tavily.com"] and rows[1]["reason"] == "configure"
    state = json.loads((tmp_path / "state" / "applied.json").read_text())
    assert state["egress"] == ["*"]


def test_a_refused_restore_keeps_the_previous_rules(tmp_path):
    controller = Controller(BASE, runner=FakeKernel(refuse_restore=True))
    with pytest.raises(FirewallRefused, match="line 3 failed"):
        controller.apply(FirewallRules(egress=["*"]))
    assert controller.applied is None


def test_ingress_is_hooked_only_when_enforced():
    kernel = FakeKernel()
    Controller(BASE, runner=kernel, enforce_ingress=True).apply()
    assert kernel.hooked == {"OUTPUT", "INPUT"}


def test_refresh_reapplies_only_when_an_answer_changed():
    answers = {"api.tavily.com": ["198.51.100.7"]}
    kernel = FakeKernel()
    controller = Controller(BASE, runner=kernel, resolver=lambda host: answers[host])
    controller.apply(FirewallRules(egress=["api.tavily.com"]))
    assert controller.refresh() is False
    answers["api.tavily.com"] = ["198.51.100.8"]
    assert controller.refresh() is True
    assert "198.51.100.8/32" in [c for c in kernel.calls if c[0][0] == "iptables-restore"][-1][1]
    assert controller.host_of("198.51.100.8") == "api.tavily.com"


def test_connections_are_recorded_and_repeats_folded(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    now = [0.0]
    recorder = ConnectionRecorder(
        audit, host_of=lambda a: "api.tavily.com" if a == "198.51.100.7" else None, clock=lambda: now[0]
    )
    allowed = Connection("allow", "spec:*", "tcp", "10.244.1.5", "198.51.100.7", 40000, 443)
    refused = Connection("refuse", "default", "tcp", "10.244.1.5", "10.0.0.9", 40001, 5432)
    assert recorder.record(allowed)["decision"] == "allow"
    assert recorder.record(allowed) is None
    assert recorder.record(allowed) is None
    row = recorder.record(refused)
    assert row["decision"] == "deny" and row["destination"] == "10.0.0.9:5432" and row["by"] == "shield"
    now[0] = 61.0
    again = recorder.record(allowed)
    assert again["repeated"] == 2 and again["host"] == "api.tavily.com"
    assert [r["event"] for r in audit.rows()] == ["connection"] * 3


# -- the kernel's log ----------------------------------------------------------------------


def _packet_message(prefix_text: str, payload: bytes) -> bytes:
    body = struct.pack("=BBH", socket.AF_INET, 0, socket.htons(7))
    body += _attribute(NFULA_PREFIX, prefix_text.encode() + b"\0")
    body += _attribute(NFULA_PAYLOAD, payload)
    return struct.pack("=IHHII", 16 + len(body), 0x400, 0, 0, 0) + body


def _ipv4_tcp(source: str, destination: str, sport: int, dport: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, socket.inet_aton(source), socket.inet_aton(destination)
    )
    return header + struct.pack("!HH", sport, dport) + b"\0" * 16


def test_a_logged_packet_decodes_into_a_connection():
    message = _packet_message("shield refuse default", _ipv4_tcp("10.244.1.5", "104.16.0.1", 40000, 443))
    connection = decode_message(message)
    assert connection == Connection("refuse", "default", "tcp", "10.244.1.5", "104.16.0.1", 40000, 443)
    assert connection.target == "104.16.0.1:443"


def test_another_prefix_or_a_non_ipv4_packet_is_not_the_shields():
    assert decode_message(_packet_message("other thing", _ipv4_tcp("1.1.1.1", "2.2.2.2", 1, 2))) is None
    assert decode_message(_packet_message("shield allow x", b"\x60" + b"\0" * 39)) is None


def test_one_datagram_carries_several_messages():
    one = _packet_message("shield allow base:gateway", _ipv4_tcp("10.0.0.1", "203.0.113.5", 1, 443))
    two = _packet_message("shield refuse default", _ipv4_tcp("10.0.0.1", "8.8.8.8", 2, 80))
    decoded = [decode_message(m) for m in messages(one + two)]
    assert [c.decision for c in decoded] == ["allow", "refuse"]


def test_a_config_message_is_a_ulog_config_request():
    message = config_message(1, family=socket.AF_UNSPEC, group=7, seq=3)
    length, kind, flags, seq, _pid = struct.unpack_from("=IHHII", message)
    assert (length, kind, flags & 1, seq) == (len(message), 0x401, 1, 3)
    assert struct.unpack_from("!H", message, 18)[0] == 7


# -- the command ---------------------------------------------------------------------------


def test_check_reads_an_agent_specs_policy_shield(tmp_path):
    spec = tmp_path / "agent.yaml"
    spec.write_text("id: crawler\npolicy:\n  shield:\n    egress: ['*']\n")
    result = runner.invoke(app, ["firewall", "check", str(spec)])
    assert result.exit_code == 0, result.output
    assert "any public address" in result.output


def test_check_says_the_ports_of_star_on_a_port(tmp_path):
    spec = tmp_path / "agent.yaml"
    spec.write_text("id: marketer\npolicy:\n  shield:\n    egress: ['*:80', '*:443']\n")
    result = runner.invoke(app, ["firewall", "check", str(spec)])
    assert result.exit_code == 0, result.output
    assert "any public address on ports 80, 443" in result.output


def test_check_refuses_a_wildcard_host_with_the_reason(tmp_path):
    spec = tmp_path / "agent.yaml"
    spec.write_text("policy:\n  shield:\n    egress: ['*.example.com']\n")
    result = runner.invoke(app, ["firewall", "check", str(spec)])
    assert result.exit_code == 2
    assert "addresses, not names" in result.output


def test_compile_prints_the_script(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(json.dumps(BASE.to_json()))
    rules = tmp_path / "rules.yaml"
    rules.write_text("egress: ['8.8.8.8:53']\n")
    result = runner.invoke(app, ["firewall", "compile", "--base", str(base), "--rules", str(rules)])
    assert result.exit_code == 0, result.output
    assert "-A SHIELD-EGRESS -d 8.8.8.8/32 -p tcp --dport 53 -j ACCEPT" in result.output


# -- revisions and the sidecar's daemon ----------------------------------------------------


def test_the_revision_a_rules_file_names_is_echoed_in_applied_json(tmp_path):
    controller = Controller(BASE, runner=FakeKernel(), state_dir=tmp_path)
    controller.apply(FirewallRules(egress=["*"]), revision="r-7")
    assert json.loads((tmp_path / "applied.json").read_text())["revision"] == "r-7"
    controller.applied.resolved = {"stale": []}
    controller.refresh()
    assert json.loads((tmp_path / "applied.json").read_text())["revision"] == "r-7"


def test_watch_takes_its_base_from_the_environment_applies_the_file_and_marks_ready(tmp_path, monkeypatch):
    kernel = FakeKernel()
    monkeypatch.setattr("agent_shield.firewall.controller.run_command", kernel)
    monkeypatch.setenv("AGENT_SHIELD_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("AGENT_SHIELD_FIREWALL_BASE", json.dumps(BASE.to_json()))
    rules = tmp_path / "rules" / "spec.json"
    rules.parent.mkdir()
    rules.write_text(json.dumps({"revision": "42", "shield": {"egress": ["*"]}}))
    state = tmp_path / "state"
    result = runner.invoke(app, ["firewall", "watch", "--rules", str(rules), "--state", str(state), "--once"])
    assert result.exit_code == 0, result.output
    assert (state / "ready").is_file()
    applied = json.loads((state / "applied.json").read_text())
    assert applied["revision"] == "42" and applied["egress"] == ["*"]
    restores = [stdin for argv, stdin in kernel.calls if argv[0] == "iptables-restore"]
    assert "203.0.113.5/32" in restores[-1] and "-A SHIELD-EGRESS -p tcp -j ACCEPT" in restores[-1]
    # Each row is echoed on stdout, a JSON line the container's log carries.
    echoed = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    assert [row["event"] for row in echoed] == ["firewall", "firewall"] and echoed[-1]["revision"] == "42"


def test_watch_says_a_refused_rules_file_with_its_revision_and_keeps_the_base(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_shield.firewall.controller.run_command", FakeKernel())
    monkeypatch.setenv("AGENT_SHIELD_HOME", str(tmp_path / "home"))
    rules = tmp_path / "spec.json"
    rules.write_text(json.dumps({"revision": "43", "shield": {"egress": ["10.0.0.0/8"]}}))
    state = tmp_path / "state"
    result = runner.invoke(app, ["firewall", "watch", "--rules", str(rules), "--state", str(state), "--once"])
    assert result.exit_code == 0, result.output
    refused = json.loads((state / "refused.json").read_text())
    assert refused["revision"] == "43" and "private or reserved" in refused["error"]
    assert json.loads((state / "applied.json").read_text())["egress"] == []


def test_watch_without_the_audit_file_keeps_rows_on_stdout_only(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_shield.firewall.controller.run_command", FakeKernel())
    monkeypatch.setenv("AGENT_SHIELD_HOME", str(tmp_path / "home"))
    state = tmp_path / "state"
    args = [
        "firewall",
        "watch",
        "--rules",
        str(tmp_path / "none.json"),
        "--state",
        str(state),
        "--once",
        "--no-audit-file",
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert '"event":"firewall"' in result.stdout
    assert not (tmp_path / "home" / "audit.jsonl").exists()
