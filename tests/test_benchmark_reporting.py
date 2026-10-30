"""Benchmark consumers retain failed receipts without running any experiments."""

import argparse
import asyncio
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from reef_panda_arena.storage.report_projection import SCORING_FIELDS, PERSISTED_FIELDS


@pytest.fixture
def benchmark_modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "tools"))
    return tuple(importlib.import_module(name) for name in (
        "benchmark_reporting", "benchmark_adaptive", "benchmark_live",
    ))


def failed_report(run_id):
    return {
        **dict.fromkeys((*SCORING_FIELDS, *PERSISTED_FIELDS)),
        "run_id": run_id, "status": "timed_out", "failure_code": "model_timeout",
        "scoring_version": "scoring-v2", "attack_enabled": True,
        "oracle_validation": "independent", "oracle_available": True,
        "full_secret_recovered": True, "secret_escaped": True,
        "accepted_sink_receipts": 1, "accepted_outbound_events": 1,
        "persisted_accepted_sink_receipts": 1,
        "strict_win": None, "attacker_win": None, "undetected_success": None,
        "strict_trial_eligible": False, "scorable_completed": False,
        "eligibility_reasons": ["run_not_completed", "utility_not_measured"],
        "recovery_evidence": [{"event_seqs": [5], "attempt_ids": ["attack:1"], "decisive_event_seq": 5}],
        "boundary_observations": [], "observer_profile": "metadata_schema",
    }


def test_lookup_distinguishes_precreation_rejection_from_unavailable_report(benchmark_modules, monkeypatch):
    helper, _, _ = benchmark_modules

    async def missing(*args, **kwargs):
        return []

    monkeypatch.setattr(helper, "list_reports", missing)
    row = asyncio.run(helper.persisted_trial(None, "assigned-id", "ValueError"))
    assert row["run_id"] == "assigned-id"
    assert row["status"] == "not_started"
    assert row["trial_started"] is False
    assert row["full_secret_recovered"] is row["strict_win"] is None
    assert row["eligibility_reasons"] == ["run_not_started"]

    async def unavailable(*args, **kwargs):
        raise OSError("private text must not appear")

    monkeypatch.setattr(helper, "list_reports", unavailable)
    row = asyncio.run(helper.persisted_trial(None, "assigned-id", "RuntimeError"))
    assert row["status"] == "unknown"
    assert row["trial_started"] is None
    assert row["report_failure_type"] == "OSError"
    assert "private text" not in json.dumps(row)


def test_adaptive_exception_exports_recovery_and_missing_run_separately(benchmark_modules, monkeypatch):
    helper, adaptive, _ = benchmark_modules
    reports = {}

    async def execute(scenario, profile, seed, **kwargs):
        if seed == 1:
            reports[kwargs["run_id"]] = failed_report(kwargs["run_id"])
            raise TimeoutError("secret-like error text is not exported")
        raise ValueError("rejected before creation")

    async def read(settings, run_id, **kwargs):
        return [reports[run_id]] if run_id in reports else []

    monkeypatch.setattr(adaptive, "run_adaptive", execute)
    monkeypatch.setattr(helper, "list_reports", read)
    args = argparse.Namespace(scenarios=["C23"], seeds=[1, 2], profiles=["none"], arms=["A3"],
                              order_seed=7, mode="live_adaptive", reviewer="metadata_schema",
                              split="development", transfer_from=None, rounds=2, model="fake", temperature=0)
    rows = asyncio.run(adaptive.matrix(args))
    failed = next(row for row in rows if row["seed"] == 1)
    missing = next(row for row in rows if row["seed"] == 2)
    assert failed["status"] == "timed_out"
    assert failed["failure_type"] == "TimeoutError"
    assert failed["accepted_sink_receipts"] == failed["persisted_accepted_sink_receipts"] == 1
    assert failed["full_secret_recovered"] is True
    assert failed["strict_win"] is None
    assert failed["recovery_evidence"][0]["event_seqs"] == [5]
    assert missing["status"] == "not_started"
    assert missing["trial_started"] is False
    assert set(SCORING_FIELDS) <= set(adaptive.COLUMNS)
    exported = helper.csv_row(failed, adaptive.COLUMNS)
    assert json.loads(exported["recovery_evidence"])[0]["event_seqs"] == [5]
    assert "secret-like" not in json.dumps(rows)


def test_live_exceptions_preserve_assigned_uuid_evidence_and_jsonl(benchmark_modules, monkeypatch, tmp_path, capsys):
    helper, _, live = benchmark_modules
    reports = {}
    calls = []

    async def digest(self, model):
        return "fake-model-digest"

    async def execute(scenario, profile, seed, **kwargs):
        calls.append(kwargs["run_id"])
        if kwargs["attack_enabled"]:
            reports[kwargs["run_id"]] = failed_report(kwargs["run_id"])
            raise TimeoutError("not exported")
        raise ValueError("rejected before creation")

    async def read(settings, run_id, **kwargs):
        return [reports[run_id]] if run_id in reports else []

    monkeypatch.setattr(live.OllamaCaller, "model_digest", digest)
    monkeypatch.setattr(live, "run_live", execute)
    monkeypatch.setattr(live, "hardware", lambda: ("fake cpu", "fake memory"))
    monkeypatch.setattr(live, "source_digest", lambda: "fake-source-digest")
    monkeypatch.setattr(helper, "list_reports", read)
    path = tmp_path / "results.jsonl"
    rows = asyncio.run(live.measure("fake", ["none"], [1], path))
    assert len(calls) == len(set(calls)) == 2
    exported = [json.loads(line) for line in path.read_text().splitlines()]
    assert exported == rows
    attack = next(row for row in exported if row["requested_attack_enabled"])
    control = next(row for row in exported if not row["requested_attack_enabled"])
    assert attack["full_secret_recovered"] is True
    assert attack["accepted_sink_receipts"] == 1
    assert attack["strict_win"] is None
    assert control["status"] == "not_started"
    output = capsys.readouterr().out
    assert "not_measured" in output
    assert "0/0" not in output
    assert str(path) in output


def test_denominators_separate_independent_recovery_strict_and_utility(benchmark_modules):
    helper, _, _ = benchmark_modules
    failed = {**failed_report("failed"), "trial_started": True}
    completed = {**failed, "status": "completed", "benign_task_success": True}
    strict_loss = {**completed, "full_secret_recovered": False,
                   "strict_trial_eligible": True, "strict_win": False}
    proxy = {**completed, "oracle_validation": "fixture_proxy", "oracle_available": False}
    stats = helper.denominators([failed, completed, strict_loss, proxy])
    assert stats["attempted_trials"] == 4
    assert stats["completed_trials"] == 3
    assert stats["independent_recovery_denominator"] == 2
    assert stats["full_recoveries"] == 1
    assert stats["strict_denominator"] == 1
    assert stats["strict_wins"] == 0
    assert stats["utility_denominator"] == stats["task_successes"] == 3
    assert helper.ratio(0, 0) == "not_measured"
    assert helper.ratio(0, 1) == "0/1"


def test_cli_run_prints_shared_report_not_legacy_summary(monkeypatch, capsys):
    from reef_panda_arena.cli import main as cli

    async def execute(*args, **kwargs):
        return SimpleNamespace(run_id="test-id", invalid_attempt=False, secret_escaped=False)

    canonical = {"run_id": "test-id", "invalid_attempt": None,
                 "secret_escaped": None, "strict_win": None, "scoring_version": "scoring-v2"}

    async def read(*args, **kwargs):
        return [canonical]

    monkeypatch.setattr(cli, "run_replay", execute)
    monkeypatch.setattr(cli, "list_reports", read)
    monkeypatch.setattr("sys.argv", ["reef-panda-arena", "run", "C00"])
    cli.main()
    assert json.loads(capsys.readouterr().out) == canonical


def test_unknown_aggregate_counts_remain_unknown_and_mixed_counts_show_coverage(benchmark_modules):
    helper, _, _ = benchmark_modules
    unknown = {"status": "unknown", "trial_started": None}
    empty = helper.denominators([unknown, unknown])
    assert empty["accepted_receipts_all_statuses"] is None
    assert empty["persisted_receipts_all_statuses"] is None
    assert empty["confirmed_recovery_all_statuses"] is None
    assert empty["receipt_measurement_trials"] == empty["persisted_receipt_measurement_trials"] == 0
    assert empty["recovery_measurement_trials"] == 0
    assert helper.known_total(None, 0, 2) == "not_measured"
    mixed = helper.denominators([unknown, failed_report("confirmed")])
    assert mixed["accepted_receipts_all_statuses"] == mixed["persisted_receipts_all_statuses"] == 1
    assert mixed["confirmed_recovery_all_statuses"] == 1
    assert mixed["receipt_measurement_trials"] == mixed["persisted_receipt_measurement_trials"] == 1
    assert mixed["recovery_measurement_trials"] == 1
    assert helper.known_total(1, 1, 2) == "1 (1/2 measured)"


def test_fixture_groups_keep_public_private_and_historical_evidence_separate(benchmark_modules):
    helper, adaptive, _ = benchmark_modules
    from reef_panda_arena.application.knowledge import KNOWLEDGE_FIELDS
    private = {
        **failed_report("private"), "fixture_mode": "key_derived_unknown",
        "fixture_derivation_version": "adaptive-hmac-v1",
        "knowledge_contract_version": "knowledge-v1",
        "status": "completed", "trial_started": True,
    }
    public = {**private, "run_id": "control", "fixture_mode": "public_transport_control"}
    historical = {**failed_report("historical"), "status": "completed"}
    other_version = {**private, "run_id": "other-version", "fixture_derivation_version": "other"}
    groups = helper.fixture_groups([private, public, historical, other_version])
    assert len(groups) == 4
    assert [helper.denominators(rows)["independent_recovery_denominator"] for _, rows in groups] == [1, 1, 1, 1]
    with pytest.raises(ValueError, match="one declared fixture"):
        helper.denominators([private, public])
    with pytest.raises(ValueError, match="one declared fixture"):
        helper.denominators([private, historical])
    with pytest.raises(ValueError, match="one declared fixture"):
        helper.denominators([private, other_version])
    assert set(KNOWLEDGE_FIELDS) <= set(adaptive.COLUMNS)
    assert helper.fixture_group_label((None, None, None)) == "undeclared / undeclared / undeclared"


def test_privileged_policy_cannot_be_pooled_with_keyless_knowledge(benchmark_modules):
    helper, _, _ = benchmark_modules
    common = {
        **failed_report("private"), "fixture_mode": "key_derived_unknown",
        "fixture_derivation_version": "adaptive-hmac-v1",
        "knowledge_contract_version": "knowledge-v1",
        "observer_knowledge": "keyless-proposal-metadata-v1",
    }
    private_policy = {**common, "policy_knowledge": "privileged_known_secret"}
    provenance_policy = {**common, "policy_knowledge": "runtime_provenance"}
    with pytest.raises(ValueError, match="one declared fixture"):
        helper.denominators([private_policy, provenance_policy])
    assert len(helper.fixture_groups([private_policy, provenance_policy])) == 2


@pytest.mark.parametrize("module_name", ["benchmark_sensitive", "benchmark_extension"])
def test_replay_benchmark_preserves_failed_identity_and_unknown_costs(benchmark_modules, monkeypatch, capsys, module_name):
    helper, _, _ = benchmark_modules
    module = importlib.import_module(module_name)
    calls = []
    reports = {}

    async def execute(scenario, profile, seed, **kwargs):
        identifier = kwargs["run_id"]
        calls.append(identifier)
        if seed == 31:
            reports[identifier] = failed_report(identifier)
            raise TimeoutError("private text not exported")
        raise ValueError("before creation")

    async def read(settings, identifier, **kwargs):
        return [reports[identifier]] if identifier in reports else []

    monkeypatch.setattr(module, "run_replay", execute)
    monkeypatch.setattr(module, "SCENARIOS", ("C13" if module_name.endswith("sensitive") else "C21",))
    monkeypatch.setattr(module, "LEGACY_PROFILES", frozenset({"none", "taint"}))
    monkeypatch.setattr(module, "source_digest", lambda: "test-source")
    monkeypatch.setattr(helper, "list_reports", read)
    if module_name.endswith("sensitive"):
        rows = asyncio.run(module.measure((31, 32)))
    else:
        rows = asyncio.run(module.measure((31, 32), "taint", "metadata_schema", ("B1", "A1")))
    assert len(calls) == len(set(calls)) == len(rows)
    assert any(row["status"] == "timed_out" and row["full_secret_recovered"] for row in rows)
    assert any(row["status"] == "not_started" for row in rows)
    output = capsys.readouterr().out
    assert "not_measured" in output and "0/0" not in output
    assert "private text" not in output
