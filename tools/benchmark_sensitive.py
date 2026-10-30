"""Matched finite C10-C14 replay benchmark; prints only aggregate safe metrics."""

import argparse
import asyncio
import hashlib
import platform
from pathlib import Path

from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.gateway.policies import LEGACY_PROFILES
from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
from reef_panda_arena.settings import ArenaSettings
from benchmark_reporting import save_cost_records, cost_report_lines, denominators, recorded_replay, ratio, fixture_groups, fixture_group_label

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("C10", "C11", "C12", "C13", "C14")


def source_digest() -> str:
    digest = hashlib.sha256()
    paths = [*sorted((ROOT / "src").rglob("*.py")),
             *sorted((ROOT / "scenarios").glob("*.yaml")),
             ROOT / "scenarios/catalog.csv", ROOT / "fixtures/shipping_task.json",
             ROOT / "fixtures/sensitive_cases.json", ROOT / "migration/schema.sql"]
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


async def measure(seeds: tuple[int, ...]) -> list[dict]:
    if len(SCENARIOS) * len(LEGACY_PROFILES) * len(seeds) * 2 > 10000:
        raise ValueError("Replay matrix exceeds the finite trial bound")
    settings = ArenaSettings()
    registry = SensitiveFixtureRegistry()
    if any(seed not in registry.seeds for seed in seeds):
        raise ValueError("Every seed must belong to the finite sensitive fixture registry")
    print("# C10-C14 matched replay benchmark", flush=True)
    print(f"Python {platform.python_version()}; source digest {source_digest()}; no model", flush=True)
    print(f"Seeds: {', '.join(map(str, seeds))}; each row has {len(seeds)} attacked and {len(seeds)} controls", flush=True)
    print(f"Fixture mode: {settings.fixture_mode}; public controls do not measure unknown-secret efficacy", flush=True)
    rows = []
    print("| Case | Policy | Full recovery / measured attacks | Attack utility / measured | Control utility / measured |", flush=True)
    print("|---|---|---:|---:|---:|", flush=True)
    for scenario in SCENARIOS:
        for profile in sorted(LEGACY_PROFILES):
            paired = []
            for seed in seeds:
                for attack in (False, True):
                    row = await recorded_replay(run_replay, scenario, profile, seed, settings,
                                                attack_enabled=attack)
                    row["requested_attack_enabled"] = attack
                    paired.append(row)
            rows.extend(paired)
            for key, group in fixture_groups(paired):
                attacks = denominators([row for row in group if row["requested_attack_enabled"]])
                controls = denominators([row for row in group if not row["requested_attack_enabled"]])
                print(f"Fixture group: {fixture_group_label(key)}", flush=True)
                print(f"| {scenario} | {profile} | {ratio(attacks['full_recoveries'], attacks['independent_recovery_denominator'])} | "
                      f"{ratio(attacks['task_successes'], attacks['utility_denominator'])} | "
                      f"{ratio(controls['task_successes'], controls['utility_denominator'])} |", flush=True)
    print("\n".join(cost_report_lines(rows)), flush=True)
    print("Fixed synthetic replay only. Failed and unmeasured outcomes are excluded from completed-trial rates.", flush=True)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", default=list(range(31, 51)))
    args = parser.parse_args()
    if len(set(args.seeds)) != len(args.seeds) or not args.seeds:
        parser.error("Supply a nonempty, unique finite seed set")
    rows = asyncio.run(measure(tuple(args.seeds)))
    print(f"Saved per-run costs and matching evidence to {save_cost_records(rows, family='sensitive')}")


if __name__ == "__main__":
    main()
