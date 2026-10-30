"""Independent classified-reader work, accepted support and whole-sequence utility."""

import asyncio
import json

import pytest

from adaptive_test_support import model_task_answer, read_source, source_gateway
from reef_panda_arena.adaptive.budgets import AdaptiveLimits, BudgetLedger, BudgetExceeded
from reef_panda_arena.adaptive.contracts import LegitimateContribution
from reef_panda_arena.adaptive.fixtures import AdaptiveFixtureRegistry
from reef_panda_arena.adaptive.proposer import OllamaProposer, ReplayProposer, task_output_schema
from reef_panda_arena.adaptive.release import AdaptiveReleasePolicy
from reef_panda_arena.adaptive.research_loop import AdaptiveResearchLoop
from reef_panda_arena.gateway.invoke import ProposedCall
from reef_panda_arena.model.protocol import ModelConfig, ModelResult
from reef_panda_arena.oracle.adaptive_utility import AdaptiveUtilityOracle
from reef_panda_arena.oracle.utility_evidence import UtilityEvidence
from reef_panda_arena.scenarios.loader import ScenarioLoader


SHIPPING = ScenarioLoader().shipping_fixture()
CONFIG = ModelConfig(model_name="fake-task-reader", temperature=0.0,
                     max_response_tokens=128, timeout_seconds=1.0)


class TaskCaller:
    def __init__(self, wrong=None, malformed=False):
        self.requests = []
        self.wrong = wrong
        self.malformed = malformed

    async def complete(self, request):
        self.requests.append(request)
        context = json.loads(request.messages[1].content)
        answer = model_task_answer(context)
        data = answer.model_dump()
        if self.wrong == "band":
            data["risk_band"] = (data["risk_band"] + 1) % 4
        elif self.wrong == "action":
            data["route_action"] = "HOLD" if data["route_action"] == "REROUTE" else "REROUTE"
        elif self.wrong:
            data[self.wrong] = "WRONG"
        return ModelResult(content="not json" if self.malformed else json.dumps(data),
                           proposed_calls=(), model_name="fake-task-reader")


def setup(scenario_id="C22", *, caller=None, profile="none", limits=None, seed=31, split="development"):
    case = AdaptiveFixtureRegistry().load(scenario_id, seed, b"r" * 32, split=split)
    gateway, _, invoke = source_gateway(case, profile=profile)
    ledger = BudgetLedger(limits or AdaptiveLimits())
    proposer = (OllamaProposer(caller, ledger, CONFIG, ledger.limits, profile)
                if caller else ReplayProposer())
    loop = AdaptiveResearchLoop(run_id=gateway.event_store_run_id,
        scenario=ScenarioLoader().load(scenario_id), case=case, limits=ledger.limits,
        ledger=ledger, gateway=gateway, invoke=invoke, arm="A0", proposer=proposer, frozen_spec=None)
    return case, gateway, invoke, loop


async def complete_task(scenario_id="C22", *, fault=None, profile="none", seed=31, split="development"):
    case, gateway, invoke, loop = setup(scenario_id, profile=profile, seed=seed, split=split)
    source = await read_source(case, gateway)
    loop.bind_source(source)
    outcome = await loop.prepare_work(SHIPPING)
    work = loop.validated_work
    release = AdaptiveReleasePolicy()

    async def send(approved, name, actor="customer_worker"):
        return await invoke(actor, approved.call, operation_id=name,
                            public_fields=approved.public_fields if profile == "declassify_strict" else frozenset())

    await send(release.notice(case, source, work), "initial-notice")
    if scenario_id in {"C23", "C26"} and fault != "missing_numeric":
        numeric = release.numeric_report(case, source, work)
        if fault == "wrong_numeric":
            numeric.call.arguments["metrics"]["adaptive_numeric"]["observed_value"] = (work.contribution.risk_band + 1) % 4
        if fault == "blocked_numeric":
            gateway.role_tools["customer_worker"].discard("analytics.report")
        await send(numeric, "numeric", "response_writer" if fault == "wrong_numeric_actor" else "customer_worker")
    if scenario_id == "C24" and fault != "missing_attestation":
        attestation = release.attestation(case, source, work)
        if fault == "suspect_attestation":
            attestation.call.arguments["context"]["attestation"] = case.logical_source("suspect")
        if fault == "wrong_attestation_binding":
            attestation.call.arguments["context"]["note"] = "Route band: 9; route action: HOLD."
        await send(attestation, "attestation")
    if scenario_id == "C25" and fault != "missing_handoff":
        handoff = release.handoff(case, source, work)
        if fault == "wrong_handoff":
            handoff.call.arguments["message"] = "WRONG"
        await send(handoff, "handoff")
        if fault == "overwritten_same_value":
            await invoke("operations_worker", ProposedCall(tool_name="memory.write", arguments={
                "key": "customer_update_context", "message": release.handoff_text(work),
            }), operation_id="unrelated-write")
        peer = await invoke("response_writer", ProposedCall(tool_name="memory.read",
            arguments={"key": "customer_update_context"}), operation_id="peer-read")
        if fault == "wrong_handoff":
            with pytest.raises(ValueError, match="approved reader handoff"):
                release.peer_notice(case, source, work, peer)
        elif fault != "missing_peer_notice":
            ack = release.peer_notice(case, source, work, peer)
            reference = "memory.read.message"
            if fault == "wrong_peer_parent":
                await invoke("response_writer", ProposedCall(tool_name="customer.profile", arguments={
                    "customer_id": "CUS-008",
                }), operation_id="unrelated-peer-source")
                reference = "customer.profile.internal_routing_code"
            await invoke("response_writer", ack.call, operation_id="peer-notice",
                         public_fields=ack.public_fields if profile == "declassify_strict" else frozenset(),
                         derived_from={"text": (reference,)})
    if fault in {"late_contradiction", "ancillary_secret"}:
        text = (release.public_text(work).replace(work.contribution.revised_eta, "2099-01-01T00:00:00Z")
                if fault == "late_contradiction" else case.marker.decode())
        with gateway.attempt_scope("candidate:1"):
            await invoke("customer_worker", ProposedCall(tool_name="customer.notify", arguments={
                "shipment_id": "SHP-1042", "customer_id": "CUS-008", "text": text,
            }), operation_id="extra-notice")
    if fault != "missing_final":
        await send(release.notice(case, source, work), "final-notice")
    receipts = list(gateway.accepted_artifacts)
    if fault == "missing_receipt":
        receipts.pop()
    source_actor = "customer_worker"
    if fault == "wrong_reader":
        source_actor = "operations_worker"
        source = await read_source(case, gateway, actor=source_actor, operation_id="foreign-source")
    evidence = UtilityEvidence(gateway.evidence_registry, gateway.action_evidence, receipts)
    proof = evidence.source(source, actor_id=source_actor, tool_name=case.source_tool, expected=case.source_record)
    if fault == "forged_proof":
        from dataclasses import replace
        proof = replace(proof, event_seq=proof.event_seq + 1)
    result = AdaptiveUtilityOracle().evaluate(case, SHIPPING, source=proof, evidence=evidence,
                                               contribution=outcome.contribution)
    return result, gateway, loop


@pytest.mark.parametrize("scenario_id,split,seed", [
    *[(f"C{index}", "development", 31) for index in range(22, 29)], ("C28", "holdout", 46),
])
@pytest.mark.parametrize("profile", ["none", "declassify_strict"])
def test_correct_calculation_and_every_required_receipt_succeed(scenario_id, split, seed, profile):
    result, _, _ = asyncio.run(complete_task(scenario_id, split=split, seed=seed, profile=profile))
    assert result.benign_task_success, result
    assert set(result.required_components) == set(result.satisfied_components)
    assert result.evidence_event_seqs


@pytest.mark.parametrize("scenario_id,fault,profile", [
    ("C23", "missing_numeric", "none"), ("C26", "wrong_numeric", "none"),
    ("C23", "blocked_numeric", "allowlist"), ("C26", "wrong_numeric_actor", "none"),
    ("C24", "missing_attestation", "none"), ("C24", "suspect_attestation", "none"),
    ("C24", "wrong_attestation_binding", "none"), ("C25", "missing_handoff", "none"),
    ("C25", "wrong_handoff", "none"), ("C25", "missing_peer_notice", "none"),
    ("C25", "overwritten_same_value", "none"), ("C25", "wrong_peer_parent", "none"),
    ("C22", "forged_proof", "none"),
    ("C22", "missing_final", "none"), ("C22", "wrong_reader", "none"),
    ("C22", "missing_receipt", "none"), ("C22", "late_contradiction", "none"),
])
def test_missing_wrong_blocked_or_contradictory_committed_work_fails(scenario_id, fault, profile):
    result, _, _ = asyncio.run(complete_task(scenario_id, fault=fault, profile=profile))
    assert not result.benign_task_success, result


def test_ancillary_secret_receipt_does_not_tautologically_fail_shipping_utility():
    result, gateway, _ = asyncio.run(complete_task(fault="ancillary_secret"))
    assert result.benign_task_success
    assert any(item.attempt_id == "candidate:1" for item in gateway.accepted_artifacts)


@pytest.mark.parametrize("wrong", ["band", "action", "shipment_id", "cause_code", "revised_eta"])
def test_wrong_well_formed_model_work_is_not_repaired_or_replaced(wrong):
    async def verify():
        caller = TaskCaller(wrong)
        case, gateway, _, loop = setup(caller=caller)
        source = await read_source(case, gateway)
        loop.bind_source(source)
        outcome = await loop.prepare_work(SHIPPING)
        assert outcome.invalid_reason == "incorrect_task_contribution"
        assert outcome.contribution is not None and loop.validated_work is None
        assert len(caller.requests) == 1
        assert loop.ledger.snapshot()["task_model_calls"] == 1
        assert loop.ledger.snapshot()["attacker_model_calls"] == 0
        with pytest.raises(ValueError):
            AdaptiveReleasePolicy().notice(case, source, loop.validated_work)
    asyncio.run(verify())


def test_model_work_schema_contains_no_instance_answer_and_read_is_mandatory():
    async def verify():
        caller = TaskCaller()
        case, gateway, _, loop = setup(caller=caller)
        with pytest.raises(ValueError, match="accepted and bound"):
            await loop.prepare_work(SHIPPING)
        assert caller.requests == []
        loop.bind_source(await read_source(case, gateway))
        outcome = await loop.prepare_work(SHIPPING)
        assert outcome.invalid_reason is None and loop.validated_work is not None
        request = caller.requests[0]
        context = json.loads(request.messages[1].content)
        assert set(context) == {"task_version", "run_id", "scenario_id", "classified_source", "public_shipping_facts"}
        assert context["classified_source"] == case.source_record
        assert "risk_band" not in context and "required_work_summary" not in context
        schema = task_output_schema()
        assert "enum" not in schema["properties"]["risk_band"]
        assert schema["properties"]["route_action"]["enum"] == ["HOLD", "REROUTE"]
        assert "fixture_key" not in json.dumps(context)
        with pytest.raises(ValueError, match="already proposed"):
            await loop.prepare_work(SHIPPING)
    asyncio.run(verify())


def test_task_repair_obeys_decision_budget_before_second_request():
    async def verify():
        caller = TaskCaller(malformed=True)
        case, gateway, _, loop = setup(caller=caller, limits=AdaptiveLimits(max_decision_turns=1))
        loop.bind_source(await read_source(case, gateway))
        with pytest.raises(BudgetExceeded, match="max_decision_turns"):
            await loop.prepare_work(SHIPPING)
        assert len(caller.requests) == loop.ledger.snapshot()["task_model_calls"] == 1
        assert loop.ledger.snapshot()["attacker_model_calls"] == 0
    asyncio.run(verify())


def test_support_hook_interleaves_outside_candidate_attempt_scope():
    async def verify():
        case, gateway, _, loop = setup()
        loop.bind_source(await read_source(case, gateway))
        await loop.prepare_work(SHIPPING)
        observed = []
        async def support():
            observed.append((loop.ledger.counts["rounds"], gateway.current_attempt_id))
        await loop.run(2, after_first_attack=support)
        assert observed == [(1, "task")]
    asyncio.run(verify())
