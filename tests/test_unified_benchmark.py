"""Benchmark failures remain evidence, never successful defense trials."""

import asyncio
import importlib
import json
from pathlib import Path

import pytest

from test_benchmark_reporting import failed_report


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'tools'))
    return importlib.import_module('benchmark_reporting'), importlib.import_module('benchmark_unified')


def test_unified_runner_failure_keeps_uuid_and_persisted_recovery(modules, monkeypatch):
    helper, benchmark = modules
    stored = {}
    async def execute(*args, **kwargs):
        stored[kwargs['run_id']] = failed_report(kwargs['run_id'])
        raise TimeoutError('private failure detail must not be exported')
    async def reports(settings, run_id, **kwargs):
        return [stored[run_id]]
    monkeypatch.setattr(benchmark, 'run_unified_replay', execute)
    monkeypatch.setattr(helper, 'list_reports', reports)
    row = asyncio.run(benchmark.one_run('C31', 'transitive', 31, True, None))
    assert row['run_id'] in stored
    assert row['trial_started'] is True
    assert row['status'] == 'timed_out' and row['failure_type'] == 'TimeoutError'
    assert row['full_secret_recovered'] is True and row['strict_win'] is None
    assert row['requested_attack_enabled'] is True
    assert 'private failure detail' not in json.dumps(row)


def test_small_failed_matrix_has_actual_denominators_and_nonoverwriting_evidence(modules, monkeypatch, tmp_path):
    _, benchmark = modules
    monkeypatch.setattr(benchmark, 'ORDERED_PROFILES', ('transitive',))
    monkeypatch.setattr(benchmark, 'source_identity', lambda: {
        'source_tree_sha256': 'a' * 64, 'base_commit': 'b' * 40, 'dirty_worktree': True, 'files': {},
    })
    async def one(scenario, profile, seed, attack, settings):
        row = failed_report('attack' if attack else 'control')
        row.update(trial_started=True, report_available=True, requested_scenario_id=scenario,
            requested_defense_profile=profile, requested_seed=seed, requested_attack_enabled=attack)
        if not attack:
            row.update(status='completed', full_secret_recovered=False, benign_task_success=False)
        return row
    monkeypatch.setattr(benchmark, 'one_run', one)
    output = tmp_path / 'new-study'
    result = asyncio.run(benchmark.measure(('C31',), (31,), output=output))
    group = result['rows'][0]
    assert group['attack']['attempted_trials'] == 1
    assert group['attack']['completed_trials'] == 0
    assert group['attack']['independent_recovery_denominator'] == 0
    assert group['attack']['strict_denominator'] == 0
    assert group['attack']['confirmed_recovery_all_statuses'] == 1
    assert group['control']['utility_denominator'] == 1
    assert group['control']['task_successes'] == 0
    text = benchmark.render_markdown(result)
    assert 'Trials: 2 requested; 2 confirmed started; 1 completed.' in text
    assert 'not_measured' in text and '0/1' in text
    assert '/45' not in text and '540' not in text and 'not_implemented' not in text
    lines = (output / 'TRIALS.jsonl').read_text().splitlines()
    assert [json.loads(line)['run_id'] for line in lines] == ['control', 'attack']
    with pytest.raises(FileExistsError):
        asyncio.run(benchmark.measure(('C31',), (31,), output=output))
    assert (output / 'TRIALS.jsonl').read_text().splitlines() == lines
