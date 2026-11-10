# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""An organization's document compiled for AgentCore Policy (AC-44) and its Gateway rate limits (AC-45)."""

from __future__ import annotations

import pytest

from agent_shield.policy import PolicyRefused, parse_policy
from agent_shield.policy.agentcore import (
    RATE_LIMIT_ID,
    AgentCoreRefused,
    compile_for_agentcore,
    gateway_rate_limit,
    split_statements,
)
from agent_shield.policy.dogwood import cedar_problem, parse_set

GATEWAY = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/payments-gw-abcde12345"
OTHER = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/other-0123456789"
GATEWAY_UID = f'AgentCore::Gateway::"{GATEWAY}"'

APPROVAL = """
// a payment needs an approval of the same payment first
@id("approval before a payment")
permit (principal, action == Datalayer::Action::"payments___pay", resource)
when { context.input.amount < 1000 }
when temporal {
    formerly within 24h Datalayer::Action::"approvals___approve"::response{ input.paymentId: context.input.paymentId }
};
"""


def _org(**document) -> object:
    return parse_policy({"scope": "organization", **document}, "test")


def _compile(document: dict, gateways: list[str] | None = None, tools: list[str] | None = None):
    return compile_for_agentcore(_org(**document), gateways or [GATEWAY], tools=tools)


def test_a_dogwood_set_is_said_in_agentcore_names() -> None:
    compiled = _compile({"dogwood": {"policies": APPROVAL}})
    (statement,) = compiled.statements
    assert statement.name == "dl_approval_before_a_payment_abcde12345"
    assert statement.temporal
    assert statement.gateway == GATEWAY
    text = statement.statement
    assert text.startswith('permit (principal, action == AgentCore::Action::"payments___pay", resource == ')
    assert GATEWAY_UID in text
    assert "Datalayer::" not in text
    assert "@id" not in text and "//" not in text
    assert 'AgentCore::Action::"approvals___approve"::response{ eventResource: resource, input.paymentId:' in text
    assert statement.definition == {"policy": {"statement": text}}
    assert compiled.mode == "enforce"
    parse_set(text)


def test_each_temporal_predicate_carries_the_event_resource() -> None:
    policies = """
    permit (principal, action == Datalayer::Action::"a___b", resource)
    when temporal {
        formerly within 1h Datalayer::Action::"a___c"::request
        && formerly within 1h Datalayer::Action::"a___d"::response{}
        && !(formerly within 1h Datalayer::Action::"a___e"::error{ eventResource: resource })
    };
    """
    (statement,) = _compile({"dogwood": {"policies": policies}}).statements
    text = statement.statement
    assert '"a___c"::request { eventResource: resource }' in text
    assert '"a___d"::response{ eventResource: resource }' in text
    assert text.count("eventResource") == 3
    parse_set(text)


def test_an_event_resource_other_than_the_gateway_is_refused() -> None:
    policies = """
    permit (principal, action == Datalayer::Action::"a___b", resource)
    when temporal { formerly within 1h Datalayer::Action::"a___c"::request{ eventResource: Datalayer::Runtime::"x" } };
    """
    with pytest.raises(AgentCoreRefused, match="eventResource other than resource"):
        _compile({"dogwood": {"policies": policies}})


def test_a_plain_statement_is_cedar_and_names_the_gateway_and_the_oauth_user() -> None:
    policies = (
        'permit (principal is Datalayer::User, action == Datalayer::Action::"payments___list", '
        'resource == Datalayer::Runtime::"local");'
    )
    (statement,) = _compile({"dogwood": {"policies": policies}}).statements
    assert not statement.temporal
    assert statement.statement == (
        f'permit (principal is AgentCore::OAuthUser, action == AgentCore::Action::"payments___list", '
        f"resource == {GATEWAY_UID});"
    )
    assert list(statement.definition) == ["cedar"]


def test_what_the_shield_alone_sees_is_refused_every_part_in_one_sentence() -> None:
    policies = """
    @id("by class")
    permit (principal, action, resource) when { context.class == "read" && principal.org_uid == "o" };

    @id("an agent")
    permit (principal == Datalayer::Agent::"a", action, resource);

    @id("mixed")
    permit (principal, action in [Datalayer::Action::"a___b", Datalayer::Action::"shield___fs_read"], resource);
    """
    with pytest.raises(AgentCoreRefused) as refused:
        _compile(
            {
                "dogwood": {"policies": policies},
                "rules": [
                    {"name": "send asks", "decision": "ask", "classes": ["send"]},
                    {"name": "inside", "decision": "allow", "where": "inside"},
                ],
            }
        )
    said = str(refused.value)
    assert "the rules 'send asks', 'inside' are conditioned" in said
    assert "dogwood policy 'by class' names context.class, principal.org_uid" in said
    assert "Datalayer::Agent" in said
    assert "the Shield's own action" in said


def test_a_policy_of_the_shields_own_actions_alone_stays_the_shields() -> None:
    policies = (
        APPROVAL + '\n@id("files")\npermit (principal, action == Datalayer::Action::"shield___fs_read", resource);'
    )
    compiled = _compile({"dogwood": {"policies": policies}})
    assert [s.name for s in compiled.statements] == ["dl_approval_before_a_payment_abcde12345"]
    assert any("'files' decides only the Shield's own actions" in note for note in compiled.notes)


@pytest.mark.parametrize(
    ("decision", "expected"),
    [("allow", "permit (principal, action, resource == "), ("deny", "forbid (principal, action, resource == ")],
)
def test_an_unconditioned_first_rule_decides_every_call(decision: str, expected: str) -> None:
    rules = [{"name": "first", "decision": decision}, {"name": "never", "decision": "allow"}]
    if decision == "deny":
        compiled = _compile({"rules": rules, "dogwood": {"policies": APPROVAL}})
        statement = compiled.statements[-1]
    else:
        compiled = _compile({"rules": rules})
        (statement,) = compiled.statements
    assert statement.statement.startswith(expected)
    assert statement.name == "dl_first_abcde12345"
    assert any("'never' never decide" in note for note in compiled.notes)


def test_a_first_rule_that_allows_lets_the_dogwood_set_decide() -> None:
    compiled = _compile({"rules": [{"name": "all", "decision": "allow"}], "dogwood": {"policies": APPROVAL}})
    assert [s.name for s in compiled.statements] == ["dl_approval_before_a_payment_abcde12345"]
    assert any("lets the dogwood set decide" in note for note in compiled.notes)


def test_a_rule_that_asks_cannot_be_said_at_a_gateway() -> None:
    with pytest.raises(AgentCoreRefused, match="asks a person first"):
        _compile({"rules": [{"name": "ask", "decision": "ask"}]})


def test_a_document_that_permits_nothing_is_refused() -> None:
    with pytest.raises(AgentCoreRefused, match="nothing in the document permits a call"):
        _compile({"limits": {"tool_calls": {"soft": 1, "hard": 2}}}, tools=["a___b"])


def test_the_tool_calls_limit_is_a_count_per_tool_named() -> None:
    document = {"rules": [{"name": "all", "decision": "allow"}], "limits": {"tool_calls": {"soft": 3, "hard": 5}}}
    with pytest.raises(AgentCoreRefused, match="name the Gateway tools"):
        _compile(document)
    with pytest.raises(AgentCoreRefused, match="not Gateway tools"):
        _compile(document, tools=["pay"])
    compiled = _compile(document, tools=["payments___pay", "payments___refund"])
    forbids = [s for s in compiled.statements if s.temporal]
    assert [s.name for s in forbids] == ["dl_calls_payments_pay_abcde12345", "dl_calls_payments_refund_abcde12345"]
    assert "n > 5" in forbids[0].statement
    assert '"payments___pay"::request{ eventResource: resource }' in forbids[0].statement
    assert any("soft threshold (3)" in note for note in compiled.notes)


def test_the_model_and_workspace_limits_stay_the_shields() -> None:
    compiled = _compile(
        {
            "rules": [{"name": "all", "decision": "allow"}],
            "limits": {"spend": {"soft": 1, "hard": 2}, "model_tokens": {"soft": 1, "hard": 2}},
        }
    )
    assert len(compiled.statements) == 1
    assert sum("stays the Shield's" in note for note in compiled.notes) == 2


def test_each_gateway_has_its_own_policies_and_the_engine_quota_holds_over_all() -> None:
    compiled = _compile({"dogwood": {"policies": APPROVAL}}, gateways=[GATEWAY, OTHER])
    assert [s.name for s in compiled.statements] == [
        "dl_approval_before_a_payment_abcde12345",
        "dl_approval_before_a_payment_0123456789",
    ]
    assert OTHER in compiled.statements[1].statement
    many = "\n".join(
        f'@id("p{i}")\npermit (principal, action == Datalayer::Action::"a___b{i}", resource)\n'
        f'when temporal {{ formerly within 1h Datalayer::Action::"a___c"::request }};'
        for i in range(11)
    )
    assert len(_compile({"dogwood": {"policies": many}}).statements) == 11
    with pytest.raises(AgentCoreRefused, match="22 temporal policies"):
        _compile({"dogwood": {"policies": many}}, gateways=[GATEWAY, OTHER])


def test_only_an_organizations_document_and_real_gateways() -> None:
    team = parse_policy({"scope": "team", "rules": [{"name": "all", "decision": "allow"}]}, "t")
    with pytest.raises(AgentCoreRefused, match="a team policy is not pushed"):
        compile_for_agentcore(team, [GATEWAY])
    with pytest.raises(AgentCoreRefused, match="registers none"):
        compile_for_agentcore(_org(rules=[{"name": "all", "decision": "allow"}]), [])
    with pytest.raises(AgentCoreRefused, match="not an AgentCore Gateway ARN"):
        compile_for_agentcore(_org(rules=[{"name": "all", "decision": "allow"}]), ["arn:aws:x"])


def test_the_log_only_mode_is_carried() -> None:
    assert _compile({"dogwood": {"policies": APPROVAL, "mode": "log_only"}}).mode == "log_only"


def test_statements_split_with_their_annotations() -> None:
    texts = split_statements(APPROVAL + '\npermit (principal, action, resource) when { context.input.x == ";" };')
    assert len(texts) == 2
    assert texts[0].startswith('@id("approval before a payment")')
    assert texts[1].endswith('== ";" };')


def test_every_compiled_statement_is_cedar_once_lowered() -> None:
    pytest.importorskip("cedarpy")
    compiled = _compile(
        {"dogwood": {"policies": APPROVAL}, "limits": {"tool_calls": {"soft": 5, "hard": 5}}}, tools=["payments___pay"]
    )
    for statement in compiled.statements:
        assert cedar_problem(parse_set(statement.statement).lowered) is None


def test_the_statements_fit_create_policy() -> None:
    botocore = pytest.importorskip("botocore.session")
    from botocore.validate import validate_parameters

    model = botocore.get_session().get_service_model("bedrock-agentcore-control")
    shape = model.operation_model("CreatePolicy").input_shape
    for statement in _compile({"dogwood": {"policies": APPROVAL}}).statements:
        validate_parameters(
            {
                "policyEngineId": "datalayer_org-abcdefghij",
                "name": statement.name,
                "definition": statement.definition,
                "description": statement.description,
                "enforcementMode": "LOG_ONLY",
            },
            shape,
        )


# -- rate limits (AC-45) ------------------------------------------------------------------------


def test_rate_limits_are_an_organizations_and_name_a_rate() -> None:
    policy = _org(rate_limits={"requests": {"rate": 100, "per": "minute"}, "tokens": {"rate": 5000, "per": "second"}})
    assert policy.rate_limits is not None and policy.rate_limits.requests.rate == 100
    with pytest.raises(PolicyRefused, match="cannot carry 'rate_limits'"):
        parse_policy({"scope": "team", "rate_limits": {"requests": {"rate": 1, "per": "second"}}}, "t")
    with pytest.raises(PolicyRefused, match="an empty section limits nothing"):
        parse_policy({"scope": "organization", "rate_limits": {}}, "o")
    with pytest.raises(PolicyRefused):
        parse_policy({"scope": "organization", "rate_limits": {"requests": {"rate": 1, "per": "hour"}}}, "o")
    with pytest.raises(PolicyRefused):
        parse_policy({"scope": "organization", "rate_limits": {"requests": {"rate": 0, "per": "second"}}}, "o")


@pytest.mark.parametrize(
    ("authorizer", "dimension"), [("CUSTOM_JWT", "$.context.jwt.sub"), ("AWS_IAM", "$.context.iam.principal")]
)
def test_rate_limits_are_one_gateway_entry_per_user(authorizer: str, dimension: str) -> None:
    policy = _org(
        rate_limits={
            "requests": {"rate": 100, "per": "minute"},
            "tokens": {"rate": 5000, "per": "second"},
            "connections": {"rate": 3, "per": "second"},
        }
    )
    entry = gateway_rate_limit(policy.rate_limits, authorizer)
    assert entry == {
        "rateLimitId": RATE_LIMIT_ID,
        "description": "Datalayer: the organization's rate limits, per user",
        "dimensionKeys": [dimension],
        "entries": [
            {
                "dimensions": {dimension: "*"},
                "requests": [{"rate": 100.0, "period": "minute"}],
                "tokens": [{"rate": 5000.0, "period": "second"}],
                "connections": [{"rate": 3.0, "period": "second"}],
            }
        ],
    }
    botocore = pytest.importorskip("botocore.session")
    from botocore.validate import validate_parameters

    shape = (
        botocore.get_session()
        .get_service_model("bedrock-agentcore-control")
        .operation_model("BatchPutGatewayRateLimits")
        .input_shape
    )
    validate_parameters({"gatewayIdentifier": "payments-gw-abcde12345", "rateLimits": [entry]}, shape)


def test_a_gateway_that_names_no_person_takes_no_rate_limit_per_user() -> None:
    policy = _org(rate_limits={"requests": {"rate": 1, "per": "second"}})
    with pytest.raises(AgentCoreRefused, match="names no person to count"):
        gateway_rate_limit(policy.rate_limits, "NONE")
