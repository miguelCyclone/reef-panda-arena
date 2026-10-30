"""Predeclared finite matrix, failure evidence and source-bound exported trials."""

import asyncio
import csv
import importlib
from pathlib import Path

import pytest

from reef_panda_arena.settings import ArenaSettings
from test_benchmark_reporting import failed_report


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'tools'))
    return tuple(importlib.import_module(name) for name in (
        'benchmark_post_audit', 'benchmark_matrix_evidence', 'benchmark_reporting'))


def test_final_plan_preserves_all_ids_matched_pairs_and_capabilities(modules):
    driver, _, _ = modules
    plan = driver.make_plan(tuple(f'C{i:02}' for i in range(44)), (31, 32, 33), ArenaSettings())
    assert len(plan['trials']) == 1584
    assert len({t['run_id'] for t in plan['trials']}) == 1584
    pairs = {}
    for trial in plan['trials']:
        pairs.setdefault(trial['pair_id'], []).append(trial)
    assert len(pairs) == 792
    for pair in pairs.values():
        assert [t['attack'] for t in pair] == [False, True]
        assert len({(t['scenario_id'], t['profile'], t['seed']) for t in pair}) == 1
    for scenarios, seeds in ((('C00', 'C00'), (31,)), (('C13',), (999,)), (('C44',), (31,))):
        with pytest.raises(ValueError):
            driver.make_plan(scenarios, seeds, ArenaSettings())


def test_timed_out_trial_keeps_assigned_identity_and_exported_partial_evidence(modules, monkeypatch, tmp_path):
    driver, evidence, helper = modules
    plan = driver.make_plan(('C32',), (31,), ArenaSettings())
    trial = next(t for t in plan['trials'] if t['attack'])
    reports = {}
    async def held(*args, **kwargs):
        reports[kwargs['run_id']] = failed_report(kwargs['run_id'])
        await asyncio.Future()
    async def read(settings, run_id, **kwargs):
        return [reports[run_id]]
    monkeypatch.setattr(driver, 'run_unified_replay', held)
    monkeypatch.setattr(helper, 'list_reports', read)
    row = asyncio.run(driver.execute_trial(trial, plan, None, timeout_seconds=0.01))
    assert row['status'] == 'timed_out' and row['failure_type'] == 'TimeoutError'
    assert row['run_id'] == trial['run_id'] and row['full_secret_recovered'] is True
    assert row['source_tree_sha256'] == plan['source']['source_tree_sha256']
    assert row['scenario_manifest_sha256'] == plan['source']['files']['scenarios/C32.yaml']
    stats = evidence.groups_for([row])[0]['attack']
    assert stats['independent_recovery_denominator'] == stats['strict_denominator'] == 0
    assert stats['confirmed_recovery_all_statuses'] == 1
    path = tmp_path / 'matrix.csv'
    evidence.write_matrix(path, [row])
    with path.open() as stream:
        exported, = list(csv.DictReader(stream))
    assert exported['strict_win'] == '' and exported['full_secret_recovered'] == 'True'
    assert exported['oracle_validation'] == 'independent'
    assert asyncio.run(driver.verify_persistence([row], None))['verified_rows'] == 1
    with pytest.raises(FileExistsError):
        evidence.write_matrix(path, [row])
    reports[trial['run_id']]['full_secret_recovered'] = False
    with pytest.raises(RuntimeError, match='projection differs'):
        asyncio.run(driver.verify_persistence([row], None))
