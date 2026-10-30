"""Pre-work hard stops, atomic shared ledgers, and actual repair accounting."""

import asyncio

import pytest

from adaptive_test_support import granted_view

from reef_panda_arena.adaptive.budgets import AdaptiveLimits, BudgetExceeded, BudgetLedger
from reef_panda_arena.adaptive.fixtures import AdaptiveFixtureRegistry
from reef_panda_arena.adaptive.proposer import OllamaProposer, ReplayProposer
from reef_panda_arena.application.budgets import ModelBudget
from reef_panda_arena.application.decisions import DecisionBudget, DecisionLimitExceeded
from reef_panda_arena.model.ollama import ModelUnavailable
from reef_panda_arena.model.protocol import ModelConfig, ModelMessage, ModelRequest, ModelResult
from reef_panda_arena.scenarios.loader import ScenarioLoader


CONFIG = ModelConfig(model_name="local-test-double", temperature=0.0,
                     max_response_tokens=128, timeout_seconds=1.0)
REQUEST = ModelRequest(messages=(ModelMessage(role="user", content="local fixture"),),
                       config=CONFIG)


def test_decision_caps_validate_and_reservations_are_atomic():
    for kwargs in ({"max_turns": 13}, {"max_model_calls": 25}, {"max_turns": True}):
        with pytest.raises(ValueError):
            DecisionBudget(**kwargs)
    budget = DecisionBudget(max_turns=3, max_model_calls=1)
    budget.reserve_model()
    with pytest.raises(DecisionLimitExceeded, match="max_total_model_calls"):
        budget.reserve_model()
    budget.reserve_script()
    budget.reserve_script()
    before = budget.snapshot()
    with pytest.raises(DecisionLimitExceeded, match="max_decision_turns"):
        budget.reserve_script()
    assert budget.snapshot() == before
    assert before["decision_turns"] == 3
    assert before["scripted_turns"] == 2
    assert before["total_model_calls"] == 1


@pytest.mark.parametrize("initial_script", [False, True])
def test_parallel_model_budget_stops_before_thirteenth_decision(initial_script):
    class Caller:
        calls = 0
        async def complete(self, request):
            self.calls += 1
            await asyncio.sleep(0)
            return ModelResult(content="", proposed_calls=(), model_name="local-test-double")

    async def verify():
        caller = Caller()
        decisions = DecisionBudget()
        if initial_script:
            decisions.reserve_script()
        budget = ModelBudget(caller, decisions=decisions)
        results = await asyncio.gather(*(budget.complete(REQUEST) for _ in range(15)),
                                       return_exceptions=True)
        expected_calls = 11 if initial_script else 12
        assert caller.calls == budget.calls == expected_calls
        failures = [result for result in results if isinstance(result, DecisionLimitExceeded)]
        assert len(failures) == 15 - expected_calls
        assert {error.counter for error in failures} == {
            "max_decision_turns" if initial_script else "max_total_model_calls"
        }
        assert decisions.decision_turns == 12
        assert decisions.total_model_calls == expected_calls
    asyncio.run(verify())


@pytest.mark.parametrize("first_error", ["invalid_json", "unavailable"])
def test_adaptive_model_repair_and_unavailable_retry_are_decisions(first_error):
    async def verify():
        case = AdaptiveFixtureRegistry().load("C22", 31, b"1" * 32)
        scenario = ScenarioLoader().load("C22")
        source_view = await granted_view(case)
        valid = await ReplayProposer().propose("decision-test", 1, scenario, source_view, ())
        class Caller:
            calls = 0
            async def complete(self, request):
                self.calls += 1
                if self.calls == 1:
                    if first_error == "unavailable":
                        raise ModelUnavailable("Synthetic unavailable model")
                    content = "invalid-json"
                else:
                    content = valid.proposal.model_dump_json()
                return ModelResult(content=content, proposed_calls=(),
                                   model_name="local-test-double")
        ledger = BudgetLedger(AdaptiveLimits())
        await ledger.charge_decision()
        caller = Caller()
        proposer = OllamaProposer(caller, ledger, CONFIG, ledger.limits, "none")
        outcome = await proposer.propose("decision-test", 1, scenario, source_view, (), "blind")
        assert outcome.proposal is not None
        assert caller.calls == ledger.counts["total_model_calls"] == 2
        assert ledger.snapshot()["decision_turns"] == 3
        assert ledger.snapshot()["scripted_turns"] == 1
        assert ledger.snapshot()["total_model_calls"] == 2
    asyncio.run(verify())


def test_adaptive_turn_budget_prevents_actual_repair_request():
    class Caller:
        calls = 0
        async def complete(self, request):
            self.calls += 1
            return ModelResult(content="invalid-json", proposed_calls=(),
                               model_name="local-test-double")

    async def verify():
        limits = AdaptiveLimits(max_decision_turns=2)
        ledger = BudgetLedger(limits)
        await ledger.charge_decision()
        caller = Caller()
        proposer = OllamaProposer(caller, ledger, CONFIG, limits, "none")
        case = AdaptiveFixtureRegistry().load("C22", 31, b"1" * 32)
        source_view = await granted_view(case)
        with pytest.raises(BudgetExceeded, match="max_decision_turns"):
            await proposer.propose("decision-test", 1, ScenarioLoader().load("C22"),
                                   source_view, (), "blind")
        assert caller.calls == ledger.snapshot()["total_model_calls"] == 1
        assert ledger.snapshot()["decision_turns"] == 2
    asyncio.run(verify())


def test_failed_model_request_is_charged_and_local_limit_is_typed():
    class Caller:
        calls = 0
        async def complete(self, request):
            self.calls += 1
            raise TimeoutError("Synthetic model timeout")

    async def verify():
        caller = Caller()
        budget = ModelBudget(caller, max_calls=1)
        with pytest.raises(TimeoutError):
            await budget.complete(REQUEST)
        assert caller.calls == budget.calls == budget.decisions.decision_turns == 1
        with pytest.raises(DecisionLimitExceeded, match="max_total_model_calls"):
            await budget.complete(REQUEST)
        assert caller.calls == budget.calls == 1
        assert budget.decisions.snapshot()["max_total_model_calls"] == 1
    asyncio.run(verify())
