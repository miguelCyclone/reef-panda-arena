"""Fresh, predeclared C00-C43 replay study with immutable source and per-run evidence."""

import argparse
import asyncio
import json
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4, uuid5

from benchmark_matrix_evidence import groups_for, render_matrix, write_matrix
from benchmark_provenance import ROOT, hardware_info, runtime_versions, source_identity
from benchmark_reporting import persisted_trial
from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.application.unified import run_unified_replay
from reef_panda_arena.gateway.policies import LEGACY_PROFILES, UNIFIED_PROFILES
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.settings import ArenaSettings

MAX_STUDY_SECONDS = 7200
MAX_TRIALS = 10000
TERMINAL = {'completed', 'failed', 'timed_out', 'cancelled', 'budget_exhausted', 'not_started', 'unknown'}


def make_plan(scenarios, seeds, settings):
    loader = ScenarioLoader()
    if (not scenarios or len(set(scenarios)) != len(scenarios) or not seeds
            or len(set(seeds)) != len(seeds) or any(type(s) is not int or not 0 <= s < 2**64 for s in seeds)):
        raise ValueError('Choose distinct scenarios and unsigned seeds')
    study_id = str(uuid4())
    trials = []
    for sid in scenarios:
        loader.load(sid)
        index = int(sid[1:])
        if 10 <= index <= 14:
            from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
            allowed = SensitiveFixtureRegistry().seeds
        elif 15 <= index <= 21:
            from reef_panda_arena.scenarios.extension_fixtures import ExtensionFixtureRegistry
            allowed = ExtensionFixtureRegistry().seeds
        elif 22 <= index <= 28:
            from reef_panda_arena.adaptive.fixtures import AdaptiveFixtureRegistry
            allowed = AdaptiveFixtureRegistry().development_seeds
        else:
            allowed = seeds
        if any(seed not in allowed for seed in seeds):
            raise ValueError(f'Seed not available for {sid}')
        for profile in sorted(UNIFIED_PROFILES if index >= 29 else LEGACY_PROFILES):
            for seed in seeds:
                pair = str(uuid5(UUID(study_id), f'{sid}:{profile}:{seed}'))
                for attack in (False, True):
                    trials.append({'run_id': str(uuid4()), 'pair_id': pair, 'scenario_id': sid,
                        'profile': profile, 'seed': seed, 'attack': attack, 'observer': 'metadata_schema'})
    if len(trials) > MAX_TRIALS:
        raise ValueError('Study exceeds finite trial cap')
    return {'version': 'post-audit-replay-v1', 'study_id': study_id,
        'created_at': datetime.now(timezone.utc).isoformat(), 'source': source_identity(),
        'hardware': hardware_info(), 'dependencies': runtime_versions(),
        'fixture_mode': settings.fixture_mode, 'audit_mode': settings.audit_mode,
        'execution_category': 'scripted_replay', 'model_name': None, 'model_digest': None,
        'scenarios': list(scenarios), 'seeds': list(seeds), 'max_study_seconds': MAX_STUDY_SECONDS,
        'trials': trials}


def check_source(plan):
    if source_identity()['source_tree_sha256'] != plan['source']['source_tree_sha256']:
        raise RuntimeError('Public source changed after plan; do not pool these trials')


def freeze_source(plan, output):
    with tarfile.open(output / 'source.tar.gz', 'w:gz') as archive:
        for name in plan['source']['files']:
            archive.add(ROOT / name, arcname=name, recursive=False)
    import hashlib
    with tarfile.open(output / 'source.tar.gz', 'r:gz') as archive:
        actual = {member.name: hashlib.sha256(archive.extractfile(member).read()).hexdigest()
                  for member in archive.getmembers()}
    if actual != plan['source']['files']:
        raise RuntimeError('Source archive does not match predeclared plan')


async def execute_trial(trial, plan, settings, *, timeout_seconds=900):
    failure = None
    started = time.monotonic()
    runner = run_unified_replay if int(trial['scenario_id'][1:]) >= 29 else run_replay
    try:
        async with asyncio.timeout(timeout_seconds):
            await runner(trial['scenario_id'], trial['profile'], trial['seed'], settings=settings,
                attack_enabled=trial['attack'], run_id=trial['run_id'], observer_profile=trial['observer'])
    except Exception as error:
        failure = type(error).__name__
    row = await persisted_trial(settings, trial['run_id'], failure)
    return {**row, 'study_id': plan['study_id'], 'pair_id': trial['pair_id'],
        'execution_category': 'scripted_replay', 'source_tree_sha256': plan['source']['source_tree_sha256'],
        'source_base_commit': plan['source']['base_commit'], 'source_worktree_dirty': plan['source']['dirty_worktree'],
        'implementation_sha256': plan['source']['implementation_sha256'],
        'scenario_manifest_sha256': plan['source']['files'][f"scenarios/{trial['scenario_id']}.yaml"],
        'requested_scenario_id': trial['scenario_id'], 'requested_defense_profile': trial['profile'],
        'requested_seed': trial['seed'], 'requested_attack_enabled': trial['attack'],
        'requested_observer_profile': trial['observer'],
        'trial_elapsed_ms': round((time.monotonic() - started) * 1000)}


async def verify_persistence(rows, settings):
    for row in rows:
        persisted = await persisted_trial(settings, row['run_id'], row['failure_type'])
        if any(row.get(key) != value for key, value in persisted.items()):
            raise RuntimeError(f"Persisted projection differs for {row['run_id']}")
        if row['status'] not in TERMINAL:
            raise RuntimeError(f"Nonterminal run requires investigation: {row['run_id']}")
        comparison = (row.get('benign_cost') or {}).get('comparison') or {}
        if comparison and comparison['source_revision'] != row['implementation_sha256']:
            raise RuntimeError('Runtime implementation does not match study manifest')
    return {'version': 'post-audit-readback-v1', 'verified_rows': len(rows),
            'verified_at': datetime.now(timezone.utc).isoformat(),
            'all_rows_terminal': True, 'public_report_fields_equal': True}


async def study(scenarios, seeds, output):
    settings = ArenaSettings().model_copy(update={'fixture_mode': 'key_derived_unknown', 'audit_mode': True})
    output = Path(output)
    if output.exists():
        raise FileExistsError('Use a new study directory; existing evidence is never overwritten')
    plan = make_plan(scenarios, seeds, settings)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'PLAN.json').write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
    freeze_source(plan, output)
    rows = []
    beginning = time.monotonic()
    for index, trial in enumerate(plan['trials'], 1):
        if time.monotonic() - beginning > plan['max_study_seconds']:
            raise RuntimeError('Study wall-time limit; completed trials retained, unstarted plan entries remain visible')
        check_source(plan)
        row = await execute_trial(trial, plan, settings,
            timeout_seconds=min(900, plan['max_study_seconds'] - (time.monotonic() - beginning)))
        rows.append(row)
        with (output / 'TRIALS.jsonl').open('a') as stream:
            stream.write(json.dumps(row, sort_keys=True) + '\n')
        if index % (12 * len(seeds)) == 0:
            print(f"Recorded {trial['scenario_id']}: {index}/{len(plan['trials'])} trials", flush=True)
    check_source(plan)
    verification = await verify_persistence(rows, settings)
    (output / 'PERSISTENCE_VERIFIED.json').write_text(json.dumps(verification, indent=2) + '\n')
    write_matrix(output / 'POST_FIX_MATRIX.csv', rows)
    (output / 'GROUPS.json').write_text(json.dumps(groups_for(rows), indent=2, sort_keys=True) + '\n')
    (output / 'README.md').write_text(render_matrix(plan, rows))
    print(f"Verified {len(rows)} persisted trials; study {plan['study_id']}", flush=True)
    return plan, rows


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--start', type=int, default=0)
    parser.add_argument('--end', type=int, default=43)
    parser.add_argument('--seeds', type=int, nargs='+', default=[31, 32, 33])
    parser.add_argument('--output', type=Path, required=True, help='New ignored directory, normally under .build/measurements')
    args = parser.parse_args()
    if not 0 <= args.start <= args.end <= 43:
        parser.error('Range must be within C00-C43')
    await study(tuple(f'C{i:02}' for i in range(args.start, args.end + 1)), tuple(args.seeds), args.output)


if __name__ == '__main__':
    asyncio.run(main())
