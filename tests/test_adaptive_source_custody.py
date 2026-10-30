"""Authorized source views separate proposer inputs from sealed receiver state."""

import asyncio
import base64
import copy
import json
from dataclasses import FrozenInstanceError, fields, replace

import pytest

from adaptive_test_support import model_task_answer, read_source, source_gateway
from reef_panda_arena.adaptive.budgets import AdaptiveLimits, BudgetLedger
from reef_panda_arena.adaptive.contracts import CandidateProposal, RepresentationSpec
from reef_panda_arena.adaptive.fixtures import AdaptiveFixtureRegistry
from reef_panda_arena.adaptive.proposer import OllamaProposer, ReplayProposer, candidate_output_schema
from reef_panda_arena.adaptive.research_loop import AdaptiveResearchLoop
from reef_panda_arena.adaptive.source_view import AcceptedSourceView
from reef_panda_arena.gateway.invoke import GatewayResult
from reef_panda_arena.gateway.research_observer import ResearchObserver
from reef_panda_arena.model.protocol import ModelConfig, ModelResult
from reef_panda_arena.scenarios.loader import ScenarioLoader


MASTER = b"Synthetic custody test key 00001"
CONFIG = ModelConfig(model_name="local-custody-spy", temperature=0.0,
                     max_response_tokens=128, timeout_seconds=1.0)


class ControlledCaller:
    def __init__(self, *, literal_attack=False):
        self.requests = []
        self.literal_attack = literal_attack

    async def complete(self, request):
        self.requests.append(request)
        context = json.loads(request.messages[1].content)
        if context.get("task_version") == "adaptive-task-v2":
            return ModelResult(content=model_task_answer(context).model_dump_json(), proposed_calls=(),
                               model_name="local-custody-spy")
        spec = context["valid_representation_example"]
        if self.literal_attack:
            for node in spec["nodes"]:
                node["source_ref"] = "marker"
        result = CandidateProposal(
            run_id=context["run_id"], round_index=context["round_index"],
            hypothesis="Bounded local proposal",
            representation=RepresentationSpec.model_validate_json(json.dumps(spec)),
            predicted_observation="Local gateway feedback only",
        )
        return ModelResult(content=result.model_dump_json(), proposed_calls=(),
                           model_name="local-custody-spy")


def loop_for(case, *, caller=None, denied=False, observer=None):
    gateway, store, invoke = source_gateway(case, denied=denied, observer=observer)
    limits = AdaptiveLimits()
    ledger = BudgetLedger(limits)
    caller = caller or ControlledCaller()
    proposer = OllamaProposer(caller, ledger, CONFIG, limits, "none")
    loop = AdaptiveResearchLoop(
        run_id=gateway.event_store_run_id, scenario=ScenarioLoader().load(case.scenario_id),
        case=case, limits=limits, ledger=ledger, gateway=gateway,
        invoke=invoke, arm="A2", proposer=proposer, frozen_spec=None,
    )
    return loop, caller, store


@pytest.mark.parametrize("scenario_id,split,seed", [
    *[(f"C{number}", "development", 31) for number in range(22, 29)],
    ("C28", "holdout", 46),
])
def test_all_authorized_source_contracts_yield_only_detached_proposer_data(scenario_id, split, seed):
    async def verify():
        case = AdaptiveFixtureRegistry().load(scenario_id, seed, MASTER, split=split)
        loop, caller, _ = loop_for(case)
        source = await read_source(case, loop.gateway)
        loop.bind_source(source)
        view = loop.source_view
        assert type(view) is AcceptedSourceView
        assert {field.name for field in fields(view)} == {"scenario_id", "public_hint", "_source_json"}
        assert view.source_record == source.data
        assert view.public_hint == case.public_hint
        with pytest.raises(FrozenInstanceError):
            view.public_hint = "changed"
        first = view.source_record
        first["arbitrary"] = "changed"
        assert "arbitrary" not in view.source_record
        assert "arbitrary" not in source.data
        if scenario_id == "C24":
            first["artifact"]["suspect"]["ciphertext_b64"] = "changed"
            assert view.source_record["artifact"]["suspect"]["ciphertext_b64"] != "changed"
        await loop.run(1)
        assert len(caller.requests) == 1
        context = json.loads(caller.requests[0].messages[1].content)
        assert context["classified_source"] == source.data
        encoded = json.dumps(caller.requests[0].model_dump())
        for forbidden in (MASTER.decode(), MASTER.hex(), base64.b64encode(MASTER).decode(),
                          "fixture_key", "decoder_id", "verified_bits", "fixture_digest", "benign_attestation"):
            assert forbidden not in encoded
        if case.fixture_key:
            assert case.fixture_key.hex() not in encoded
            assert base64.b64encode(case.fixture_key).decode() not in encoded
            assert case.benign_attestation["ciphertext_b64"] not in encoded
    asyncio.run(verify())


@pytest.mark.parametrize("mode", ["unbound", "denied", "forged_allowed", "wrong_reader", "wrong_data", "wrong_labels", "missing_ids", "wrong_run"])
def test_unaccepted_or_wrong_source_never_reaches_model(mode):
    async def verify():
        case = AdaptiveFixtureRegistry().load("C22", 31, MASTER)
        loop, caller, _ = loop_for(case, denied=mode == "denied")
        if mode != "unbound":
            if mode == "wrong_run":
                other, _, _ = source_gateway(case, run_id="different-run")
                source = await read_source(case, other)
            else:
                source = await read_source(case, loop.gateway,
                                           actor="operations_worker" if mode == "wrong_reader" else "customer_worker")
            if mode == "forged_allowed":
                source = GatewayResult(True, "allowed", copy.deepcopy(case.source_record),
                                       {name: "secret" for name in case.source_record})
            elif mode == "wrong_data":
                source = replace(source, data={**source.data, "marker": "WRONG123"})
            elif mode == "wrong_labels":
                source = replace(source, field_labels={name: "public" for name in source.field_labels})
            elif mode == "missing_ids":
                source = replace(source, artifact_ids={})
            with pytest.raises(ValueError):
                loop.bind_source(source)
        with pytest.raises(ValueError, match="accepted and bound"):
            await loop.run(1)
        with pytest.raises(ValueError, match="accepted and bound"):
            await loop._propose({"round_index": 1, "outcome": None})
        with pytest.raises(ValueError, match="accepted and bound"):
            await loop.prepare_work(ScenarioLoader().shipping_fixture())
        assert caller.requests == []
        assert loop.ledger.snapshot()["total_model_calls"] == 0
        assert loop.ledger.snapshot()["decision_turns"] == 0
    asyncio.run(verify())


def test_private_case_and_model_claims_are_not_accepted_proposer_arguments():
    async def verify():
        case = AdaptiveFixtureRegistry().load("C24", 31, MASTER)
        scenario = ScenarioLoader().load("C24")
        caller = ControlledCaller()
        ledger = BudgetLedger(AdaptiveLimits())
        model = OllamaProposer(caller, ledger, CONFIG, ledger.limits, "none")
        for untrusted in (case, {"allowed": True, "source_record": case.source_record}):
            with pytest.raises(ValueError, match="accepted source view"):
                await model.propose("source-custody-test", 1, scenario, untrusted, (), "blind")
            with pytest.raises(ValueError, match="accepted source view"):
                await ReplayProposer().propose("source-custody-test", 1, scenario, untrusted, ())
        assert caller.requests == [] and ledger.snapshot()["total_model_calls"] == 0
        with pytest.raises(TypeError):
            candidate_output_schema(scenario, "source-custody-test", 1, public_hint=case)
    asyncio.run(verify())


def test_prompt_feedback_and_keyless_observer_have_no_sealed_extra_knowledge():
    class ObserverSpy(ResearchObserver):
        def __init__(self):
            super().__init__("metadata_schema")
            self.views = []
        def inspect_observed(self, tool, arguments, **context):
            self.views.append(copy.deepcopy({"tool": tool, "arguments": arguments, **context}))
            return super().inspect_observed(tool, arguments, **context)

    async def verify():
        case = AdaptiveFixtureRegistry().load("C22", 31, MASTER)
        case = replace(case, decoder_id="SEALED_DECODER_SENTINEL", fixture_key=b"K" * 32,
                       fixture_digest="SEALED_ORACLE_SENTINEL")
        spy = ObserverSpy()
        loop, caller, _ = loop_for(case, caller=ControlledCaller(literal_attack=True), observer=spy)
        source = await read_source(case, loop.gateway)
        loop.bind_source(source)
        await loop.run(2)
        contexts = [json.loads(request.messages[1].content) for request in caller.requests]
        assert contexts[0]["classified_source"]["marker"] == case.marker.decode()
        assert contexts[0]["previous_valid_representation"] is None
        previous = contexts[1]["previous_valid_representation"]
        assert previous == loop.valid_specs[0].model_dump(mode="json")
        assert previous["nodes"][0]["source_ref"] == "marker"
        previous["nodes"][0]["source_ref"] = "public_hint"
        assert loop.valid_specs[0].nodes[0].source_ref == "marker"
        feedback = contexts[1]["prior_gateway_feedback"][0]
        assert set(feedback) == {"round_index", "candidate_hash", "status", "gateway_accepted", "public_reason", "benign_progress"}
        assert feedback["public_reason"] == "accepted_by_local_gateway"
        observed = json.dumps(spy.views)
        assert case.marker.decode() in observed  # An actual proposed literal leak is visible.
        assert spy.views[0]["arguments"] == {"case_id": "C22"}  # Source request, no source result.
        all_views = json.dumps(contexts) + observed
        for forbidden in ("SEALED_DECODER_SENTINEL", "SEALED_ORACLE_SENTINEL", "full_secret_recovered",
                          "recovered_exact", "oracle_validation", "fixture_key", base64.b64encode(b"K" * 32).decode()):
            assert forbidden not in all_views
        schema = candidate_output_schema(loop.scenario, loop.run_id, 1)
        assert case.marker.decode() not in json.dumps(schema)
        assert "classified_source" not in schema["properties"]
    asyncio.run(verify())


def test_source_view_is_detached_after_gateway_result_mutation_and_cannot_rebind():
    async def verify():
        case = AdaptiveFixtureRegistry().load("C24", 31, MASTER)
        loop, caller, _ = loop_for(case)
        source = await read_source(case, loop.gateway)
        expected = copy.deepcopy(source.data)
        loop.bind_source(source)
        source.data["artifact"]["suspect"]["ciphertext_b64"] = "MUTATED_SENTINEL"
        source.field_labels.clear()
        source.artifact_ids.clear()
        await loop.run(1)
        context = json.loads(caller.requests[0].messages[1].content)
        assert context["classified_source"] == expected
        assert "MUTATED_SENTINEL" not in json.dumps(context)
        with pytest.raises(ValueError, match="already bound"):
            loop.bind_source(source)
    asyncio.run(verify())
