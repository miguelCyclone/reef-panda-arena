"""Finite scenario contracts, exact decoders, and the small replay matrix."""

import asyncio
import json
import os

import pytest
import yaml
from pydantic import ValidationError

from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.gateway.invoke import SinkArtifact
from reef_panda_arena.oracle.decoders import reconstruct_candidates
from reef_panda_arena.scenarios.loader import ScenarioDefinition, ScenarioLoader
from reef_panda_arena.scenarios.scripts import attack_actions
from reef_panda_arena.tools.outbound import encode_sink_payload
from reef_panda_arena.tools.registry import TOOL_INPUTS


def test_all_scenario_contracts_and_reject_unknown_decoder() -> None:
    loader = ScenarioLoader()
    assert loader.list_ids() == tuple(f"C{index:02}" for index in range(44))
    for scenario_id in loader.list_ids():
        assert loader.load(scenario_id).id == scenario_id
    raw = yaml.safe_load((loader.root / "scenarios" / "C03.yaml").read_text())
    raw["attack_contract"]["decoder_id"] = "python_eval"
    with pytest.raises(ValidationError):
        ScenarioDefinition.model_validate(raw)
    raw["attack_contract"]["decoder_id"] = "polynomial_coefficients_v1"
    raw["unexpected_code"] = "print(1)"
    with pytest.raises(ValidationError):
        ScenarioDefinition.model_validate(raw)


@pytest.mark.parametrize("scenario_id", ["C01", "C03", "C07", "C08"])
def test_core_decoder_requires_complete_exact_artifacts(scenario_id: str) -> None:
    scenario = ScenarioLoader().load(scenario_id)
    secret = b"AB" if scenario_id == "C08" else b"ABCDEFGH"
    actions = attack_actions(scenario, secret, 9, "SHP-1042", "CUS-008")
    artifacts = []
    for index, action in enumerate(actions, 1):
        call = action.proposed_call({})
        dto = TOOL_INPUTS[call.tool_name].model_validate(call.arguments)
        payload = encode_sink_payload(call.tool_name, dto)
        artifacts.append(SinkArtifact(index, payload, call.tool_name))
    assert secret in reconstruct_candidates(scenario, artifacts, 9)
    if scenario_id in {"C07", "C08"}:
        assert secret not in reconstruct_candidates(scenario, artifacts[:-1], 9)
    elif scenario_id == "C03":
        corrupt = json.loads(artifacts[0].payload)
        corrupt["metrics"]["poly_coefficients"][0]["denominator"] = 0
        bad = SinkArtifact(1, json.dumps(corrupt).encode(), "analytics.report")
        assert reconstruct_candidates(scenario, [bad], 9) == []
    else:
        bad = SinkArtifact(1, b"%%%", "customer.notify")
        assert reconstruct_candidates(scenario, [bad], 9) == []


def test_all_replay_scenarios_compare_baseline_and_taint() -> None:
    if os.getenv("ARENA_TEST_MYSQL") != "1":
        pytest.skip("Set ARENA_TEST_MYSQL=1 to test the local MySQL matrix")

    async def verify() -> None:
        for scenario_id in tuple(f"C{index:02}" for index in range(10)):
            baseline = await run_replay(scenario_id, "none", 23)
            defended = await run_replay(scenario_id, "taint", 23)
            assert baseline.secret_escaped and baseline.benign_task_success
            assert not defended.secret_escaped and defended.benign_task_success
            assert not baseline.invalid_attempt and not defended.invalid_attempt
            assert defended.blocked_attempts >= 1

    asyncio.run(verify())
