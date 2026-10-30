"""Bounded C29-C43 matched replay; failed starts and null measurements stay visible."""

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from reef_panda_arena.application.unified import run_unified_replay
from reef_panda_arena.application.benign_cost_aggregate import summarize_costs
from reef_panda_arena.settings import ArenaSettings
from benchmark_provenance import ROOT, hardware_info, runtime_versions, source_identity
from benchmark_reporting import (
    cost_report_lines, denominators, fixture_groups, fixture_group_label,
    ratio, recorded_replay,
)

ORDERED_PROFILES = ('allowlist_only', 'content_only', 'actor_local',
                    'transitive', 'scoped_release', 'strict_no_release')


async def one_run(scenario, profile, seed, attack, settings):
    row = await recorded_replay(run_unified_replay, scenario, profile, seed,
                                settings, attack_enabled=attack)
    return {**row, 'requested_scenario_id': scenario, 'requested_defense_profile': profile,
            'requested_seed': seed, 'requested_attack_enabled': attack}


def grouped_results(trials):
    conditions = {}
    for row in trials:
        key = (row['requested_scenario_id'], row['requested_defense_profile'])
        conditions.setdefault(key, []).append(row)
    groups = []
    for (scenario, profile), rows in conditions.items():
        for knowledge, group in fixture_groups(rows):
            attacks = [row for row in group if row['requested_attack_enabled']]
            controls = [row for row in group if not row['requested_attack_enabled']]
            groups.append({'scenario': scenario, 'profile': profile,
                'knowledge_group': fixture_group_label(knowledge),
                'attack': denominators(attacks), 'control': denominators(controls),
                'run_ids': [row['run_id'] for row in group]})
    return groups


async def measure(scenarios, seeds, *, output=None):
    if (not scenarios or not seeds or len(set(scenarios)) != len(scenarios)
            or len(set(seeds)) != len(seeds) or any(s not in {f'C{i}' for i in range(29, 44)} for s in scenarios)
            or any(type(seed) is not int or not 0 <= seed < 2**64 for seed in seeds)
            or len(scenarios) * len(ORDERED_PROFILES) * len(seeds) * 2 > 10000):
        raise ValueError('Invalid or excessive replay matrix')
    settings = ArenaSettings()
    source = source_identity()
    plan = {'version': 'unified-benchmark-v2', 'source': source, 'hardware': hardware_info(),
        'dependencies': runtime_versions(), 'created_at': datetime.now(timezone.utc).isoformat(),
        'fixture_mode': settings.fixture_mode, 'scenarios': scenarios, 'seeds': seeds,
        'profiles': ORDERED_PROFILES, 'model_name': None, 'model_digest': None,
        'execution_category': 'scripted_replay', 'conditions': 'Local MySQL and mock sinks; sequential pairs; no LLM'}
    if output is not None:
        output = Path(output)
        output.mkdir(parents=True, exist_ok=False)
        (output / 'PLAN.json').write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
    trials = []
    for scenario in scenarios:
        for profile in ORDERED_PROFILES:
            for seed in seeds:
                for attack in (False, True):
                    if source_identity()['source_tree_sha256'] != source['source_tree_sha256']:
                        raise RuntimeError('Source changed after predeclared plan; retained trials must not be pooled')
                    row = await one_run(scenario, profile, seed, attack, settings)
                    trials.append(row)
                    if output is not None:
                        with (output / 'TRIALS.jsonl').open('a') as stream:
                            stream.write(json.dumps(row, sort_keys=True) + '\n')
        print(f'Recorded {scenario}: {len(seeds)} matched seeds x {len(ORDERED_PROFILES)} profiles', flush=True)
    if source_identity()['source_tree_sha256'] != source['source_tree_sha256']:
        raise RuntimeError('Source changed during benchmark')
    return {**plan, 'rows': grouped_results(trials), 'trial_reports': trials,
            'benign_cost_summary': summarize_costs(trials),
            'benign_cost_markdown': cost_report_lines(trials)}


def render_markdown(data):
    trials = data['trial_reports']
    completed = sum(row['status'] == 'completed' for row in trials)
    started = sum(row['trial_started'] is True for row in trials)
    lines = ['# Unified replay measurements', '',
        'Local scripted replay only; these defenses and reviewers are local implementations, not vendor evaluations.', '',
        f"- Source tree: `{data['source']['source_tree_sha256']}`; base commit: `{data['source']['base_commit']}`; dirty: `{data['source']['dirty_worktree']}`",
        f"- Fixture mode: `{data['fixture_mode']}`; seeds: {', '.join(map(str, data['seeds']))}",
        f'- Trials: {len(trials)} requested; {started} confirmed started; {completed} completed.',
        '- Failed and unavailable trials remain in the per-run JSONL. Confirmed recovery during failure remains evidence, but does not enter completed-trial efficacy.',
        '- Zero eligible denominator is not measured. Knowledge groups remain separate; task-only controls are distinct from attack receipts.',
        '- Per-run reports contain scenario/oracle/scoring versions, prompt, observer/knowledge scope, duration and eligibility reasons. Source files and runtime dependencies are in PLAN.json.', '',
        '| Case | Profile | Knowledge | Attack completed / requested | Independent full recovery | Strict win | Attack utility | Control utility | Confirmed recovery, all statuses |',
        '|---|---|---|---:|---:|---:|---:|---:|---:|']
    for row in data['rows']:
        attack, control = row['attack'], row['control']
        lines.append(f"| {row['scenario']} | {row['profile']} | {row['knowledge_group']} | "
            f"{attack['completed_trials']}/{attack['attempted_trials']} | "
            f"{ratio(attack['full_recoveries'], attack['independent_recovery_denominator'])} | "
            f"{ratio(attack['strict_wins'], attack['strict_denominator'])} | "
            f"{ratio(attack['task_successes'], attack['utility_denominator'])} | "
            f"{ratio(control['task_successes'], control['utility_denominator'])} | "
            f"{ratio(attack['confirmed_recovery_all_statuses'], attack['recovery_measurement_trials'])} |")
    lines += ['', 'C34 rejects an unauthorized read; C37 has no attack outbound; C40 is a partial prefix. Distinct case IDs can share a replay algorithm. See docs/EXECUTED_MECHANISMS.md.', '',
        'Independent live execution exists but is not tested by this replay matrix. Deliberate lineage faults are not injected here. Historical matrices are separate.', '', *data['benign_cost_markdown']]
    return '\n'.join(lines) + '\n'


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--start', type=int, default=29)
    parser.add_argument('--end', type=int, default=43)
    parser.add_argument('--seeds', type=int, nargs='+', default=[31, 32, 33])
    parser.add_argument('--output', type=Path, help='New directory; existing evidence is never overwritten')
    args = parser.parse_args()
    if not 29 <= args.start <= args.end <= 43:
        parser.error('Range must be within C29-C43')
    output = args.output or ROOT / '.build/measurements' / f'unified-v2-{uuid4().hex}'
    data = await measure(tuple(f'C{i}' for i in range(args.start, args.end + 1)), tuple(args.seeds), output=output)
    (output / 'RESULTS.json').write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    (output / 'README.md').write_text(render_markdown(data))
    print(f"Saved {len(data['trial_reports'])} trials to {output}", flush=True)


if __name__ == '__main__':
    asyncio.run(main())
