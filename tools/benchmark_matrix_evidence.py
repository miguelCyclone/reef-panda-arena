"""Redacted per-trial exports and condition-specific denominators for replay studies."""

import csv
import json
from collections import Counter

from benchmark_reporting import csv_row, denominators, fixture_groups, fixture_group_label, ratio
from reef_panda_arena.storage.reports import REPORT_COLUMNS

PROVENANCE_FIELDS = (
    'study_id', 'pair_id', 'execution_category', 'source_tree_sha256', 'source_base_commit',
    'source_worktree_dirty', 'implementation_sha256', 'scenario_manifest_sha256',
    'requested_scenario_id', 'requested_defense_profile', 'requested_seed',
    'requested_attack_enabled', 'requested_observer_profile', 'trial_elapsed_ms',
    'trial_started', 'report_available', 'report_failure_type', 'failure_type',
)
COLUMNS = tuple(dict.fromkeys((*PROVENANCE_FIELDS, *REPORT_COLUMNS)))
CONDITIONS = ('requested_scenario_id', 'requested_defense_profile', 'scenario_revision',
              'oracle_version', 'scoring_version', 'observer_profile', 'observer_scope',
              'utility_version', 'utility_scope')


def groups_for(rows):
    conditions = {}
    for row in rows:
        key = tuple(row.get(field) for field in CONDITIONS)
        conditions.setdefault(key, []).append(row)
    result = []
    for condition, values in conditions.items():
        for knowledge, group in fixture_groups(values):
            attack = [row for row in group if row['requested_attack_enabled']]
            control = [row for row in group if not row['requested_attack_enabled']]
            information = [row['information'] for row in attack if row.get('information') is not None]
            result.append({
                **dict(zip(CONDITIONS, condition)), 'knowledge_group': fixture_group_label(knowledge),
                'attack': denominators(attack), 'control': denominators(control),
                'information_measured_attacks': len(information),
                'partial_recovery_attacks': sum(item['recovery_state'] == 'partial' for item in information),
                'run_ids': [row['run_id'] for row in group],
            })
    return result


def write_matrix(path, rows):
    with path.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(csv_row(row, COLUMNS) for row in rows)


def render_matrix(plan, rows):
    counts = Counter(row['status'] for row in rows)
    lines = ['# Post-audit matched replay results', '',
        'Finite local scripted replay; no model calls, external destinations or vendor defender evaluation.', '',
        f"- Study: `{plan['study_id']}`; execution category: `scripted_replay`",
        f"- Executed source: `{plan['source']['source_tree_sha256']}`; base commit: `{plan['source']['base_commit']}`; dirty worktree: `{plan['source']['dirty_worktree']}`",
        f"- Implementation digest: `{plan['source']['implementation_sha256']}`",
        f"- Seeds: {', '.join(map(str, plan['seeds']))}; fixture mode: `{plan['fixture_mode']}`",
        f"- Planned: {len(plan['trials'])}; exported: {len(rows)}; statuses: `{json.dumps(dict(sorted(counts.items())), sort_keys=True)}`",
        '- Every attacked run is paired by scenario, policy and seed with a task-only control. Group rows separate oracle, scoring, utility, observer and participant-knowledge conditions.',
        '- Denominators are eligible measured completed trials, not all attempts. Zero coverage is `not_measured`; failed runs retain confirmed recovery and receipts separately.',
        '- Partial information is independently verified accepted content; a prefix is not full recovery, and representation capacity is not source entropy.', '',
        '| Case | Policy | Knowledge | Completed attacks / attempts | Full recovery / measured | Strict win / eligible | Attack utility / measured | Control utility / measured | Partial / information measured |',
        '|---|---|---|---:|---:|---:|---:|---:|---:|']
    for group in groups_for(rows):
        a, c = group['attack'], group['control']
        lines.append(f"| {group['requested_scenario_id']} | {group['requested_defense_profile']} | {group['knowledge_group']} | "
            f"{a['completed_trials']}/{a['attempted_trials']} | "
            f"{ratio(a['full_recoveries'], a['independent_recovery_denominator'])} | "
            f"{ratio(a['strict_wins'], a['strict_denominator'])} | "
            f"{ratio(a['task_successes'], a['utility_denominator'])} | "
            f"{ratio(c['task_successes'], c['utility_denominator'])} | "
            f"{ratio(group['partial_recovery_attacks'], group['information_measured_attacks'])} |")
    return '\n'.join(lines) + '\n'
