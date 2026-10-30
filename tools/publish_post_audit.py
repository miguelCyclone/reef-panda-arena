"""Publish a verified local study's sanitized evidence; preserve executed source identity."""

import argparse
import asyncio
import gzip
import hashlib
import json
import shutil
import tarfile
import tempfile
from collections import Counter
from pathlib import Path

from benchmark_matrix_evidence import groups_for, write_matrix
from benchmark_post_audit import verify_persistence
from benchmark_reporting import cost_report_lines
from reef_panda_arena.application.benign_cost_aggregate import summarize_costs
from reef_panda_arena.settings import ArenaSettings


def sha(data):
    return hashlib.sha256(data).hexdigest()


def packed(path, data):
    with path.open('xb') as stream:
        with gzip.GzipFile(filename='', fileobj=stream, mode='wb', mtime=0) as archive:
            archive.write(data)


async def publish(study, output):
    study, output = Path(study), Path(output)
    if output.exists():
        raise FileExistsError('Use a new publication directory; preserved evidence is never overwritten')
    plan = json.loads((study / 'PLAN.json').read_text())
    raw = (study / 'TRIALS.jsonl').read_bytes()
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) != len(plan['trials']) or [r['run_id'] for r in rows] != [t['run_id'] for t in plan['trials']]:
        raise ValueError('Every planned trial must be exported once in declared order')
    for row, trial in zip(rows, plan['trials']):
        if (row['source_tree_sha256'] != plan['source']['source_tree_sha256']
                or row['pair_id'] != trial['pair_id']
                or row['requested_scenario_id'] != trial['scenario_id']
                or row['requested_defense_profile'] != trial['profile']
                or row['requested_seed'] != trial['seed']
                or row['requested_attack_enabled'] != trial['attack']):
            raise ValueError('Trial configuration differs from plan')
    with tarfile.open(study / 'source.tar.gz', 'r:gz') as archive:
        files = {member.name: sha(archive.extractfile(member).read()) for member in archive.getmembers()}
    if files != plan['source']['files'] or sha(json.dumps(files, sort_keys=True).encode()) != plan['source']['source_tree_sha256']:
        raise ValueError('Executed source archive does not match declared digest')
    verification = await verify_persistence(rows, ArenaSettings())
    csv_bytes = (study / 'POST_FIX_MATRIX.csv').read_bytes()
    with tempfile.TemporaryDirectory(prefix='reef-matrix-verify-') as temporary:
        expected = Path(temporary) / 'matrix.csv'
        write_matrix(expected, rows)
        if expected.read_bytes() != csv_bytes:
            raise ValueError('CSV is not the declared projection of JSONL trials')
    groups = groups_for(rows)
    if groups != json.loads((study / 'GROUPS.json').read_text()):
        raise ValueError('Stored aggregates differ from per-trial denominators')
    costs = summarize_costs(rows)
    verification.update(trials_sha256=sha(raw), matrix_sha256=sha(csv_bytes),
                        source_tree_sha256=plan['source']['source_tree_sha256'])
    output.mkdir(parents=True, exist_ok=False)
    packed(output / 'trials.jsonl.gz', raw)
    packed(output / 'matrix.csv.gz', csv_bytes)
    packed(output / 'benign-cost.json.gz', (json.dumps(costs, sort_keys=True) + '\n').encode())
    (output / 'groups.json').write_text(json.dumps(groups, indent=2, sort_keys=True) + '\n')
    (output / 'plan.json').write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
    (output / 'verification.json').write_text(json.dumps(verification, indent=2, sort_keys=True) + '\n')
    shutil.copyfile(study / 'source.tar.gz', output / 'executed-source.tar.gz')
    (output / 'costs.md').write_text('\n'.join(cost_report_lines(rows)) + '\n')
    manifest = {
        'version': 'post-audit-publication-v1', 'study_id': plan['study_id'],
        'executed_source_tree_sha256': plan['source']['source_tree_sha256'],
        'publisher_sha256': sha(Path(__file__).read_bytes()),
        'statuses': dict(Counter(row['status'] for row in rows)),
        'files': {path.name: sha(path.read_bytes()) for path in sorted(output.iterdir())},
        'scope': 'Sanitized reports and source archive; no local key, .env, raw prompt or accepted payload capture',
    }
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(f"Published {len(rows)} verified local reports to {output}; no new arena runs", flush=True)
    return manifest


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--study', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    await publish(args.study, args.output)


if __name__ == '__main__':
    asyncio.run(main())
