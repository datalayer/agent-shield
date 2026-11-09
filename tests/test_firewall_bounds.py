# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""An agent's firewall rules held to its organization's ceiling (Agent Firewall N3-01)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_shield.firewall import FirewallCeiling, FirewallRules, bounded, bounded_by, organization_ceilings
from agent_shield.policy import Policy, parse_policy, policy_json_schema


def egress(rules: FirewallRules) -> list[str]:
    return list(rules.egress)


def test_no_ceiling_leaves_the_rules_as_they_are():
    rules = FirewallRules(egress=["*"], ingress=["10.42.0.0/16:8765"])
    assert bounded(rules, None) == rules
    assert bounded(rules, FirewallCeiling()) == rules
    assert bounded_by(rules, []) == rules


def test_a_star_ceiling_allows_anything_public():
    rules = {"egress": ["api.tavily.com", "198.51.100.0/24:443", "pypi.org:443"]}
    assert egress(bounded(rules, {"egress": ["*"]})) == rules["egress"]
    assert egress(bounded({"egress": ["*"]}, {"egress": ["*"]})) == ["*"]


def test_the_rules_star_is_the_ceiling_itself():
    held = bounded({"egress": ["*"]}, {"egress": ["github.com", "203.0.113.0/24:443"]})
    assert egress(held) == ["github.com", "203.0.113.0/24:443"]


@pytest.mark.parametrize(
    "asked,ceiling,held",
    [
        # Exact hosts match exactly.
        (["api.tavily.com"], ["api.tavily.com"], ["api.tavily.com"]),
        (["api.tavily.com"], ["mcp.tavily.com"], []),
        # host:port needs the host and the port.
        (["api.tavily.com:443"], ["api.tavily.com:443"], ["api.tavily.com:443"]),
        (["api.tavily.com:443"], ["api.tavily.com:80"], []),
        (["api.tavily.com:443"], ["api.tavily.com"], ["api.tavily.com:443"]),
        # Every port asked, one allowed: the one.
        (["api.tavily.com"], ["api.tavily.com:443"], ["api.tavily.com:443"]),
        # An address or CIDR must be covered by a ceiling CIDR.
        (["198.51.100.7"], ["198.51.100.0/24"], ["198.51.100.7"]),
        (["198.51.100.0/25:443"], ["198.51.100.0/24"], ["198.51.100.0/25:443"]),
        (["198.51.100.7"], ["203.0.113.0/24"], []),
        # A wider CIDR asked, a narrower allowed: the narrower part.
        (["198.51.0.0/16"], ["198.51.100.0/24:443"], ["198.51.100.0/24:443"]),
        (["198.51.0.0/16"], ["198.51.100.9"], ["198.51.100.9"]),
        # A host is never matched against a CIDR, nor an address against a host.
        (["api.tavily.com"], ["198.51.100.0/24"], []),
        (["198.51.100.7"], ["api.tavily.com"], []),
        # The strictest wins: an empty ceiling grants nothing beyond the base.
        (["api.tavily.com", "pypi.org"], [], []),
        (["api.tavily.com", "pypi.org", "github.com"], ["github.com", "pypi.org"], ["pypi.org", "github.com"]),
    ],
)
def test_an_egress_entry_holds_only_as_far_as_the_ceiling_allows(asked, ceiling, held):
    assert egress(bounded({"egress": asked}, {"egress": ceiling})) == held


def test_ingress_keeps_platform_and_is_bounded_like_egress():
    rules = {"egress": ["*"], "ingress": ["platform", "10.42.0.0/16:8765", "10.50.0.0/16"]}
    held = bounded(rules, {"ingress": ["10.42.0.0/16"]})
    assert held.ingress == ["platform", "10.42.0.0/16:8765"]
    assert held.egress == ["*"]
    assert bounded(rules, {"ingress": []}).ingress == ["platform"]
    assert bounded({"ingress": ["*"]}, {"ingress": ["10.42.0.0/16"]}).ingress == ["10.42.0.0/16"]
    assert bounded(rules, {"ingress": ["*"]}).ingress == rules["ingress"]
    # No ingress asked is 'platform', and stays so.
    assert bounded({"egress": []}, {"ingress": ["10.42.0.0/16"]}).ingress == []


def test_every_ceiling_in_turn_the_strictest_wins():
    held = bounded_by({"egress": ["*"]}, [{"egress": ["github.com", "pypi.org"]}, {"egress": ["pypi.org"]}])
    assert egress(held) == ["pypi.org"]


def test_a_ceiling_takes_the_rules_grammar():
    with pytest.raises(ValidationError, match="private or reserved"):
        FirewallCeiling(egress=["10.0.0.0/8"])
    with pytest.raises(ValidationError, match="wildcard host"):
        FirewallCeiling(egress=["*.example.com"])
    with pytest.raises(ValidationError, match="stands alone"):
        FirewallCeiling(egress=["*", "github.com"])


def test_the_organization_document_carries_the_ceiling_and_no_other_scope_does():
    document = parse_policy({"scope": "organization", "firewall": {"egress": ["github.com"]}}, "org")
    assert document.firewall == FirewallCeiling(egress=["github.com"])
    with pytest.raises(Exception, match="the organization's"):
        parse_policy({"scope": "team", "firewall": {"egress": ["*"]}}, "team")
    team = Policy(scope="team")
    assert organization_ceilings([document, team, Policy(scope="organization")]) == [document.firewall]
    schema = policy_json_schema()
    assert "firewall" in schema["properties"]
    assert "FirewallCeiling" in schema["$defs"]
