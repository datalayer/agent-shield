# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The model budget and the spend limit, soft then hard (SH-32, SH-54)."""

from __future__ import annotations

from agent_shield.policy import (
    MODEL_KIND,
    Action,
    Context,
    Limits,
    LimitState,
    Policy,
    Rule,
    Threshold,
    class_of,
    decide,
    decide_budget,
)

BUDGET = Policy(
    scope="organization", limits=Limits(model_tokens=Threshold(soft=100, hard=200), spend=Threshold(soft=10, hard=20))
)


def test_a_model_request_within_every_limit_is_done_and_the_rules_are_not_consulted():
    policies = [BUDGET, Policy(scope="session", rules=[Rule(name="nothing", decision="deny")])]
    decision = decide_budget(Context(workspace="/w"), policies, tokens=50, cost=5)
    assert decision.verdict == "allow" and decision.decided_by == "default" and decision.counted


def test_the_soft_threshold_asks_once_and_the_hard_one_refuses_with_what_would_let_it_go_on():
    state = LimitState()
    ctx = Context(workspace="/w", state=state)
    first = decide_budget(ctx, [BUDGET], tokens=90)
    assert first.verdict == "allow"
    state.spent(tokens=90, cost=9)
    second = decide_budget(ctx, [BUDGET], tokens=90)
    assert second.verdict == "ask" and second.rule == "model_tokens" and second.scope == "organization"
    assert second.sentence == (
        "a model request: ask me first — the session's model tokens spent would reach 180, past the soft limit of 100 "
        "in the organization policy; the hard limit is 200"
    )
    state.soft_asked.add(("organization", "model_tokens"))
    state.spent(tokens=90, cost=9)
    third = decide_budget(ctx, [BUDGET], tokens=90)
    assert third.verdict == "deny" and third.rule == "model_tokens"
    assert third.sentence == (
        "a model request: refused — the session's model tokens spent would reach 270, over the hard limit of 200 "
        "in the organization policy; a cheaper model, a wider budget, or a person's word would let it go on"
    )


def test_the_spend_limit_is_the_deployments_in_credits_and_is_checked_after_the_token_budget():
    state = LimitState(spend=15)
    state.soft_asked.add(("organization", "spend"))
    ctx = Context(workspace="/w", state=state)
    decision = decide_budget(ctx, [BUDGET], tokens=1, cost=6)
    assert decision.verdict == "deny" and decision.rule == "spend"
    assert "credits spent would reach 21, over the hard limit of 20" in decision.sentence
    assert decision.sentence.endswith("a wider spend limit or a person's word would let it go on")


def test_the_strictest_scopes_budget_is_read_first_and_the_appspecs_can_only_be_tighter():
    team = Policy(scope="team", limits=Limits(spend=Threshold(soft=2, hard=4)))
    ctx = Context(workspace="/w", state=LimitState(spend=3))
    decision = decide_budget(ctx, [BUDGET, team], cost=2)
    assert decision.verdict == "deny" and decision.scope == "team"


def test_model_requests_count_no_tool_call_and_tool_calls_touch_no_model_limit():
    state = LimitState()
    ctx = Context(workspace="/w", state=state)
    policies = [
        Policy(
            scope="session", limits=Limits(tool_calls=Threshold(soft=1, hard=1), model_tokens=Threshold(soft=1, hard=1))
        )
    ]
    model = Action(kind=MODEL_KIND, title="m", tokens=5)
    state.count(model, decide_budget(ctx, policies, tokens=0))
    assert state.tool_calls == 0 and state.model_tokens == 5
    read = Action(kind="read", title="r", path="a", inside=True, **{"class": class_of("read")})
    decision = decide(read, ctx, policies)
    assert (
        decision.verdict == "ask" and decision.decided_by == "default"
    )  # no rule names it; the model limit did not refuse it
    state.count(read, decision)
    assert state.tool_calls == 1 and state.model_tokens == 5


def test_with_no_model_limit_anywhere_a_model_request_is_always_done():
    assert (
        decide_budget(Context(workspace="/w"), [Policy(scope="session")], tokens=10**9, cost=10**9).verdict == "allow"
    )
