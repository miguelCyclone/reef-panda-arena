"""Matched reports preserve real configuration, coverage and trial assignments."""

import asyncio
from copy import deepcopy
from pathlib import Path

import pytest

from reef_panda_arena.application.benign_cost import measure_benign_cost
from reef_panda_arena.application.benign_cost_aggregate import summarize_costs
from reef_panda_arena.application.comparison_contract import declare_comparison
from reef_panda_arena.application.decisions import DecisionBudget
from reef_panda_arena.application.knowledge import knowledge_metadata
from reef_panda_arena.gateway.observer import ContentObserver
from reef_panda_arena.oracle.sensitive import SENSITIVE_ORACLE_VERSION
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
from reef_panda_arena.scenarios.sensitive_scripts import attack_actions
from test_benign_cost import contract
from test_utility_integrity import task


async def trial(identifier, *, attack=False, status="completed", key=b"T" * 32,
                seed=31, turns=12, observer=True, disable_after_declaration=False):
    registry = SensitiveFixtureRegistry()
    case = registry.load("C13", seed, key)
    work = await task("C13", profile="taint", case_override=case)
    work.gateway.observer = ContentObserver() if observer else None
    scenario = ScenarioLoader().load("C13")
    work.gateway.comparison_contract = declare_comparison(
        work.gateway, scenario, work.shipping, key=key, decisions=DecisionBudget(max_turns=turns),
        seconds=min(scenario.limits.timeout_seconds, 900), schedule="sensitive-interleaved-v3",
        attack_enabled=attack, extra_limits=scenario.limits.model_dump(mode="json"),
    )
    if disable_after_declaration:
        work.gateway.observer = None
    for call in work.calls:
        await work.send(call, approved=False)
    if attack:
        with work.gateway.attempt_scope("attack:1"):
            for action in attack_actions(case, case.source_record):
                await work.send(action.call, approved=False)
    return {
        "run_id": identifier, "scenario_id": "C13", "scenario_revision": scenario.revision,
        "seed": seed, "status": status, "mode": "replay", "attack_enabled": attack,
        "defense_profile": "taint", "prompt_version": "sensitive-replay-v3",
        "utility_version": "sensitive-utility-v3", "utility_scope": "same_reader_scripted",
        "task_mechanism": "scripted_computation", "task_actor": scenario.rogue_slot,
        "oracle_version": SENSITIVE_ORACLE_VERSION,
        **knowledge_metadata("C13", "key_derived_unknown", registry.template_digest,
                             defense_profile="taint", observer_profile="content" if observer else None),
        "benign_cost": measure_benign_cost(work.gateway, contract(work), status=status),
    }


@pytest.fixture
def pair():
    async def actual():
        return [await trial("control"), await trial("attack", attack=True)]
    return asyncio.run(actual())


def test_real_same_seed_pair_and_distinct_action_vs_run_denominators(pair):
    result = summarize_costs(pair)
    assert len(result["pairs"]) == 1 and len(result["groups"]) == 2
    assert result["unmatched_metadata_trials"] == result["unpaired_or_ambiguous_trials"] == 0
    for group in result["groups"]:
        total = group["required_task"]
        assert total["eligible_actions"] == total["policy_decisions"] == total["policy_false_blocks"] == 2
        assert total["observer_inspections"] == 2 and total["observer_false_alerts"] == 1
        assert total["observer_false_alert_rate"] == 0.5
        assert total["observer_false_alert_run_rate"] == total["policy_false_block_run_rate"] == 1
        assert total["policy_eligible_runs"] == total["observer_eligible_runs"] == 1
        assert group["shape_matched"][0]["observer_false_alert_rate"] == 1
    assert result["pairs"][0]["control_run_id"] == "control"
    assert result["pairs"][0]["attack_run_id"] == "attack"


def test_multiple_seeds_are_inventoried_and_partial_runs_keep_no_run_denominator(pair):
    extra = asyncio.run(trial("control32", seed=32, status="timed_out"))
    result = summarize_costs([*pair, extra])
    controls = next(group for group in result["groups"] if not group["conditions"]["attack_enabled"])
    assert controls["seeds"] == [31, 32] and controls["completed_runs"] == 1
    assert controls["required_task"]["policy_false_blocks"] == 4
    assert controls["required_task"]["policy_false_block_runs"] == 1
    assert controls["required_task"]["policy_measurement"] == "partial"
    assert len(result["pairs"]) == 1 and result["unpaired_or_ambiguous_trials"] == 1


@pytest.mark.parametrize("field,value", [
    ("source_revision", "1" * 64), ("configuration_digest", "2" * 64),
    ("budget_digest", "3" * 64), ("fixture_cohort", "4" * 64),
    ("observer_profile", "metadata_schema"), ("max_gateway_actions", 39),
    ("observer_history", "prior_inspected_proposals_in_run"),
])
def test_mismatched_runtime_conditions_never_form_a_pair(pair, field, value):
    pair[1]["benign_cost"]["comparison"][field] = value
    result = summarize_costs(pair)
    assert result["pairs"] == []
    assert result["unpaired_or_ambiguous_trials"] == 2


def test_actual_budget_and_key_changes_have_distinct_declarations(pair):
    changed = asyncio.run(trial("changed", attack=True, key=b"U" * 32, turns=10))
    original, alternate = pair[0]["benign_cost"]["comparison"], changed["benign_cost"]["comparison"]
    assert original["source_revision"] == alternate["source_revision"]
    assert original["configuration_digest"] == alternate["configuration_digest"]
    assert original["fixture_cohort"] != alternate["fixture_cohort"]
    assert original["budget_digest"] != alternate["budget_digest"]
    assert summarize_costs([pair[0], changed])["pairs"] == []
    assert b"T" * 32 not in str(original).encode() and b"U" * 32 not in str(alternate).encode()


def test_missing_historical_model_or_assignment_evidence_remains_unmatched(pair):
    historical = deepcopy(pair[0]); historical["run_id"] = "historical"
    historical["benign_cost"]["comparison"] = None
    live = deepcopy(pair[1]); live["run_id"] = "live"; live["mode"] = "live_adaptive"
    missing = deepcopy(pair[0]); missing["run_id"] = "missing"; missing.pop("utility_version")
    inconsistent = deepcopy(pair[0]); inconsistent["run_id"] = "wrong-assignment"
    inconsistent["attack_enabled"] = True
    result = summarize_costs([historical, live, missing, inconsistent])
    assert result["unmatched_metadata_trials"] == 4
    assert result["groups"] == result["pairs"] == []


def test_public_probe_cannot_substitute_for_task_only_counterpart(pair):
    pair[0]["benign_cost"]["comparison"]["control_context"] = "public_transport_probe"
    result = summarize_costs(pair)
    assert result["pairs"] == []
    assert len(result["groups"]) == 2  # Its actual required task cost remains measurable.


def test_missing_inspection_is_not_zero_false_alert_rate():
    row = asyncio.run(trial("unobserved", observer=False))
    summary = summarize_costs([row])["groups"][0]["required_task"]
    assert summary["observer_inspections"] == summary["observer_eligible_runs"] == 0
    assert summary["observer_false_alert_rate"] is summary["observer_false_alert_run_rate"] is None
    assert summary["observer_measurement"] == "not_measured"
    assert summary["policy_false_block_rate"] == 1


def test_duplicate_and_ambiguous_trials_cannot_inflate_pairs(pair):
    with pytest.raises(ValueError, match="Duplicate"):
        summarize_costs([*pair, pair[0]])
    other = deepcopy(pair[0]); other["run_id"] = "other-control"
    result = summarize_costs([*pair, other])
    assert result["pairs"] == [] and result["unpaired_or_ambiguous_trials"] == 3
    with pytest.raises(ValueError, match="finite trial bound"):
        summarize_costs([{}] * 10001)


def test_printed_report_shows_shapes_actual_denominators_and_unknowns(pair, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "tools"))
    from benchmark_reporting import cost_report_lines
    output = "\n".join(cost_report_lines(pair))
    assert "unique same-seed task-only/attack pairs: 1" in output
    assert "numeric_array" in output and "1/2" in output and "2/2" in output
    assert "not_measured" not in output
    assert "missing comparison evidence: 1" in "\n".join(cost_report_lines([{}]))


def test_distinct_attack_arms_can_share_one_explicit_control_without_double_counting(pair):
    pair[0]["arm"], pair[1]["arm"] = "A0", "A1"
    other = deepcopy(pair[1]); other["run_id"] = "attack-a3"; other["arm"] = "A3"
    result = summarize_costs([*pair, other])
    assert len(result["pairs"]) == 2 and result["unpaired_or_ambiguous_trials"] == 0
    assert all(item["control_reused"] and item["control_pair_count"] == 2 for item in result["pairs"])
    controls = [group for group in result["groups"] if not group["conditions"]["attack_enabled"]]
    assert len(controls) == 1 and controls[0]["required_task"]["eligible_runs"] == 1
    assert {item["attack_arm"] for item in result["pairs"]} == {"A1", "A3"}


def test_positive_control_cost_remains_visible_without_duplicate_primary_pair(pair):
    probe = deepcopy(pair[1]); probe["run_id"] = "positive"; probe["arm"] = "P0"
    probe["benign_cost"]["comparison"]["control_context"] = "positive_control"
    result = summarize_costs([*pair, probe])
    assert len(result["pairs"]) == 1 and len(result["groups"]) == 3
    assert result["unmatched_metadata_trials"] == result["unpaired_or_ambiguous_trials"] == 0


def test_saved_cost_study_preserves_conditions_ids_and_does_not_overwrite(pair, monkeypatch, tmp_path):
    import json
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "tools"))
    from benchmark_reporting import save_cost_records
    output = tmp_path / "study.json"
    assert save_cost_records(pair, family="sensitive", output=output) == output
    saved = json.loads(output.read_text())
    assert saved["rows"] == pair
    assert saved["cost_summary"]["pairs"][0]["control_run_id"] == "control"
    with pytest.raises(FileExistsError):
        save_cost_records(pair, family="sensitive", output=output)
    assert json.loads(output.read_text()) == saved


def test_configured_observer_cannot_claim_matching_after_actual_inspection_is_disabled():
    row = asyncio.run(trial("disabled-after-declaration", disable_after_declaration=True))
    assert row["benign_cost"]["comparison"] is None
    assert row["benign_cost"]["policy_false_blocks"] == 2
    assert row["benign_cost"]["observer_false_alert_rate"] is None
    result = summarize_costs([row])
    assert result["unmatched_metadata_trials"] == 1 and result["groups"] == []
