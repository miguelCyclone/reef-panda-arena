"""Actual graph privacy and decision accounting with local fake model calls."""

import asyncio
import json
from contextlib import contextmanager

import pytest
from langchain_core.runnables.config import var_child_runnable_config
from langchain_core.tracers.context import tracing_v2_callback_var
from langchain_core.tracers.langchain import LangChainTracer
from langsmith import Client, tracing_context
from langsmith.run_helpers import get_tracing_context

from reef_panda_arena.adaptive.budgets import AdaptiveLimits, BudgetLedger
from reef_panda_arena.adaptive.fixtures import AdaptiveFixtureRegistry
from reef_panda_arena.adaptive.proposer import OllamaProposer, ReplayProposer
from reef_panda_arena.adaptive.research_loop import AdaptiveResearchLoop
from reef_panda_arena.application.budgets import ModelBudget
from reef_panda_arena.application.decisions import DecisionBudget
from reef_panda_arena.application.unified_attack import ATTACK_ROUTES, UnifiedAttack
from reef_panda_arena.application.unified_workflow import UnifiedWorkflow
from reef_panda_arena.gateway.budget import UnifiedBudgetExceeded
from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.graph.nodes import LiveNodes
from reef_panda_arena.graph.roster import AgentRoster, LEGACY_RUNTIME_ROLES
from reef_panda_arena.graph.topology import build_live_graph
from reef_panda_arena.model.protocol import ModelConfig, ModelResult
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.telemetry.privacy import invoke_graph_privately
from reef_panda_arena.tools.adaptive import (
    ADAPTIVE_TOOL_DESTINATIONS, ADAPTIVE_TOOL_INPUTS, AdaptiveToolAdapter,
    adaptive_role_tools,
)
from reef_panda_arena.tools.registry import MockToolRegistry
from reef_panda_arena.tools.unified import (
    UNIFIED_DESTINATIONS, UNIFIED_ROLE_TOOLS, UNIFIED_TOOL_INPUTS, UnifiedToolAdapter,
)


class MemoryStore:
    def __init__(self):
        self.events = []
        self.receipts = []

    async def append(self, event, receipt=None):
        self.events.append(event)
        if receipt is not None:
            self.receipts.append(receipt)
        return event


class FakeLiveModel:
    def __init__(self):
        self.calls = 0

    async def complete(self, request):
        self.calls += 1
        tool = request.tool_names[0]
        if tool == "customer.profile":
            arguments = {"customer_id": "CUS-008"}
        elif tool == "customer.notify":
            prompt = request.messages[-1].content
            text = prompt.split("exactly: ", 1)[1]
            arguments = {"shipment_id": "SHP-1042", "customer_id": "CUS-008", "text": text}
        else:
            arguments = {"shipment_id": "SHP-1042"}
        return ModelResult(content="", proposed_calls=(
            ProposedCall(tool_name=tool, arguments=arguments),
        ), model_name="local-test-double")


@pytest.fixture
def exports(monkeypatch):
    """Spy on real SDK export entrypoints; never allow a transport request."""
    captured = []
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "true")
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    monkeypatch.setenv("LANGSMITH_API_KEY", "synthetic-test-only")

    def record(self, *args, **kwargs):
        captured.append((args, kwargs))

    def deny_network(self, *args, **kwargs):
        raise AssertionError("Tracing test attempted a transport request")

    for name in ("create_run", "update_run", "batch_ingest_runs", "multipart_ingest"):
        monkeypatch.setattr(Client, name, record)
    monkeypatch.setattr(Client, "request_with_retries", deny_network)
    return captured


@contextmanager
def inherited_exporter():
    client = Client(api_url="http://127.0.0.1:1", api_key="synthetic-test-only",
                    auto_batch_tracing=False, info={})
    tracer = LangChainTracer(client=client)
    tracer.run_inline = True
    config = {"callbacks": [tracer], "tags": ["outside-private-run"]}
    tracer_token = tracing_v2_callback_var.set(tracer)
    config_token = var_child_runnable_config.set(config)
    try:
        with tracing_context(enabled=True, client=client):
            before = get_tracing_context().copy()
            yield tracer
            assert get_tracing_context() == before
            assert tracing_v2_callback_var.get() is tracer
            assert var_child_runnable_config.get() is config
    finally:
        var_child_runnable_config.reset(config_token)
        tracing_v2_callback_var.reset(tracer_token)
        client.close()


def make_live():
    fixture = ScenarioLoader().shipping_fixture()
    store = MemoryStore()
    gateway = PolicyGateway(
        store, MockToolRegistry(fixture, b"SYNTH123"), "none", secret=b"SYNTH123",
        run_id="privacy-live", runtime_roles=LEGACY_RUNTIME_ROLES,
        max_calls=16, max_events=48, max_payload_bytes=4096,
        allowed_attack_tool="customer.notify",
    )
    model = FakeLiveModel()
    budget = ModelBudget(model)
    nodes = LiveNodes(
        "privacy-live", gateway, budget,
        ModelConfig(model_name="local-test-double", temperature=0.0,
                    max_response_tokens=128, timeout_seconds=1.0), True,
    )
    factory = lambda: build_live_graph(nodes.operations_worker, nodes.customer_worker,
                                      nodes.response_writer)
    initial = {"shipment_id": "SHP-1042", "customer_id": "CUS-008"}
    return factory, initial, store, model, budget


def test_real_live_graph_positive_export_control_and_private_execution(exports):
    async def verify():
        with inherited_exporter() as tracer:
            factory, initial, store, model, budget = make_live()
            output = await factory().ainvoke(initial, config={"callbacks": [tracer]})
            assert output["writer_accepted"] and store.events
            assert exports, "The unprotected real graph must exercise SDK export spies"
            exports.clear()
            factory, initial, store, model, budget = make_live()
            output = await invoke_graph_privately(
                factory, initial, config={"callbacks": [tracer], "recursion_limit": 8},
            )
            assert output["writer_accepted"] and len(store.receipts) == 2
            assert model.calls == budget.calls == budget.decisions.decision_turns == 5
            assert budget.decisions.scripted_turns == 0
            assert exports == []
    asyncio.run(verify())


@pytest.mark.parametrize("proposal_mode", ["replay", "model"])
def test_real_adaptive_graph_is_private_and_counts_decisions(exports, proposal_mode):
    async def verify():
        fixture = ScenarioLoader().shipping_fixture()
        case = AdaptiveFixtureRegistry().load("C22", 31, b"1" * 32)
        scenario = ScenarioLoader().load("C22")
        store = MemoryStore()
        gateway = PolicyGateway(
            store, AdaptiveToolAdapter(fixture, case.marker, "C22", case.source_tool,
                                       case.source_record), "none", secret=case.marker,
            run_id="privacy-adaptive", runtime_roles=LEGACY_RUNTIME_ROLES,
            tool_inputs=ADAPTIVE_TOOL_INPUTS, tool_destinations=ADAPTIVE_TOOL_DESTINATIONS,
            role_tools=adaptive_role_tools(), research_run_id="privacy-adaptive",
            max_calls=32, max_events=100, max_payload_bytes=2048,
            allowed_attack_tool="customer.notify",
        )
        limits = AdaptiveLimits()
        ledger = BudgetLedger(limits)

        async def invoke(actor, call, *, operation_id, derived_from=None, **kwargs):
            return await gateway.invoke(TrustedContext(
                "privacy-adaptive", actor, actor, operation_id=operation_id,
                derived_from=derived_from or {},
            ), call)

        proposer = ReplayProposer()
        if proposal_mode == "model":
            class FakeAdaptiveModel:
                async def complete(self, request):
                    context = json.loads(request.messages[1].content)
                    if context.get("task_version") == "adaptive-task-v2":
                        from adaptive_test_support import model_task_answer
                        return ModelResult(content=model_task_answer(context).model_dump_json(),
                                           proposed_calls=(), model_name="local-test-double")
                    proposed = await ReplayProposer().propose(
                        context["run_id"], context["round_index"], scenario, loop.source_view, (),
                    )
                    return ModelResult(content=proposed.proposal.model_dump_json(),
                                       proposed_calls=(), model_name="local-test-double")
            proposer = OllamaProposer(
                FakeAdaptiveModel(), ledger,
                ModelConfig(model_name="local-test-double", temperature=0.0,
                            max_response_tokens=128, timeout_seconds=1.0), limits, "none",
            )
        loop = AdaptiveResearchLoop(
            run_id="privacy-adaptive", scenario=scenario, case=case, limits=limits,
            ledger=ledger, gateway=gateway, invoke=invoke, arm="A2",
            proposer=proposer, frozen_spec=None,
        )
        await ledger.charge_decision()  # The controller's one benign task script.
        source = await invoke("customer_worker", ProposedCall(
            tool_name=case.source_tool, arguments={"case_id": "C22"},
        ), operation_id="source")
        assert source.allowed
        loop.bind_source(source)
        with inherited_exporter():
            await loop.prepare_work(fixture)
            await loop.run(2)
        assert loop.valid_candidates == 2 and store.events and store.receipts, [
            event.reason_code for event in store.events
        ]
        assert ledger.snapshot()["decision_turns"] == 4
        assert ledger.snapshot()["scripted_turns"] == (4 if proposal_mode == "replay" else 1)
        assert ledger.snapshot()["total_model_calls"] == (0 if proposal_mode == "replay" else 3)
        assert ledger.snapshot()["task_model_calls"] == (0 if proposal_mode == "replay" else 1)
        assert exports == []
    asyncio.run(verify())


def make_unified(decisions=None):
    fixture = ScenarioLoader().shipping_fixture()
    registry = ArtifactRegistry("privacy-unified")
    roster = AgentRoster()
    store = MemoryStore()
    gateway = PolicyGateway(
        store, UnifiedToolAdapter(fixture, b"SYNTH123"), "transitive",
        secret=b"", max_calls=40, max_events=48, max_payload_bytes=4096,
        tool_inputs=UNIFIED_TOOL_INPUTS, tool_destinations=UNIFIED_DESTINATIONS,
        role_tools=UNIFIED_ROLE_TOOLS, artifact_registry=registry,
        run_id=registry.run_id, runtime_roles=roster.runtime_roles,
    )
    workflow = UnifiedWorkflow(gateway, registry, fixture, roster, ATTACK_ROUTES,
                               decisions=decisions)
    return workflow, store


def test_real_unified_graph_is_private_and_attack_script_counts_two_slots(exports):
    async def verify():
        decisions = DecisionBudget()
        workflow, store = make_unified(decisions)
        attack = UnifiedAttack(ScenarioLoader().load("C29"), workflow)
        with inherited_exporter():
            result = await workflow.run(attack_prepare=attack.prepare, attack_finish=attack.finish)
            assert result.notice_accepted and result.graph_steps == 12
            assert attack.result is not None and attack.result.attempted
            assert workflow.gateway.calls > 24
        assert decisions.decision_turns == decisions.scripted_turns == 12
        assert decisions.total_model_calls == 0
        assert len(store.receipts) >= 1 and exports == []
    asyncio.run(verify())


def test_private_graph_restores_context_on_cancellation(exports):
    async def noop(state):
        return {}

    async def verify():
        outer = asyncio.current_task()
        async def cancel(state):
            outer.cancel()
            await asyncio.Future()
        with inherited_exporter() as tracer:
            with pytest.raises(asyncio.CancelledError):
                await invoke_graph_privately(
                    lambda: build_live_graph(cancel, noop, noop), {},
                    config={"callbacks": [tracer]},
                )
        assert exports == []
    asyncio.run(verify())


def test_unified_turn_limit_stops_before_next_role_activation():
    async def verify():
        decisions = DecisionBudget(max_turns=3)
        workflow, store = make_unified(decisions)
        with pytest.raises(UnifiedBudgetExceeded, match="max_decision_turns"):
            await workflow.run()
        assert workflow.source_read
        assert workflow.released_category is None
        assert decisions.decision_turns == decisions.scripted_turns == 3
        assert decisions.total_model_calls == 0
        assert store.events and not store.receipts
    asyncio.run(verify())
