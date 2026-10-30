"""Finite matched C15-C21 replay matrix; aggregate safe outcomes only."""

import argparse
import asyncio
import hashlib
import platform
from pathlib import Path

from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.gateway.policies import LEGACY_PROFILES
from reef_panda_arena.gateway.research_observer import VALID_REVIEWERS
from reef_panda_arena.scenarios.extension_fixtures import ExtensionFixtureRegistry
from reef_panda_arena.settings import ArenaSettings
from benchmark_reporting import save_cost_records, cost_report_lines, denominators, recorded_replay, ratio, fixture_groups, fixture_group_label

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = tuple(f"C{index}" for index in range(15, 22))
ARMS = ("B0", "B1", "A0", "A1", "H0", "P0")


def source_digest() -> str:
    digest = hashlib.sha256()
    paths = [*sorted((ROOT / "src").rglob("*.py")),
             *sorted((ROOT / "scenarios").glob("*.yaml")),
             *sorted((ROOT / "fixtures").glob("*.json")),
             ROOT / "scenarios/catalog.csv", ROOT / "migration/schema.sql"]
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


async def measure(seeds: tuple[int, ...], defense: str, reviewer: str,
                  arms: tuple[str, ...] = ARMS) -> list[dict]:
    if defense not in LEGACY_PROFILES - {"none"} or reviewer not in VALID_REVIEWERS:
        raise ValueError("Choose one enforced defense and one reviewer view")
    if any(seed not in ExtensionFixtureRegistry().seeds for seed in seeds):
        raise ValueError("Every seed must belong to the finite extension fixture set")
    if len(SCENARIOS) * len(arms) * len(seeds) > 10000:
        raise ValueError("Replay matrix exceeds the finite trial bound")
    settings = ArenaSettings()
    print(f"# C15-C21 finite arm matrix; Python {platform.python_version()}; source digest {source_digest()}", flush=True)
    print(f"Defense {defense}; reviewer {reviewer}; seeds {','.join(map(str, seeds))}; n={len(seeds)} per arm; local mock sinks; no model", flush=True)
    print(f"Fixture mode: {settings.fixture_mode}; public controls do not measure unknown-secret efficacy", flush=True)
    rows = []
    print("| Case | Arm | Full recovery / measured | Utility / measured | Strict wins / eligible |", flush=True)
    print("|---|---|---:|---:|---:|", flush=True)
    for scenario in SCENARIOS:
        for arm in arms:
            profile = "none" if arm in {"B0", "A0"} else defense
            group = [await recorded_replay(run_replay, scenario, profile, seed, settings,
                                           arm=arm, observer_profile=reviewer) for seed in seeds]
            rows.extend(group)
            for key, partition in fixture_groups(group):
                stats = denominators(partition)
                print(f"Fixture group: {fixture_group_label(key)}", flush=True)
                print(f"| {scenario} | {arm} | {ratio(stats['full_recoveries'], stats['independent_recovery_denominator'])} | "
                      f"{ratio(stats['task_successes'], stats['utility_denominator'])} | "
                      f"{ratio(stats['strict_wins'], stats['strict_denominator'])} |", flush=True)
    print("\n".join(cost_report_lines(rows)), flush=True)
    print("Public-only H0 probes are not a substitute for classified-reader work. Partial component scores are not entropy.", flush=True)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", default=[31, 32, 33])
    parser.add_argument("--defense", choices=sorted(LEGACY_PROFILES - {"none"}), default="declassify_strict")
    parser.add_argument("--reviewer", choices=sorted(VALID_REVIEWERS), default="metadata_schema")
    parser.add_argument("--arms", nargs="+", choices=ARMS, default=list(ARMS))
    args = parser.parse_args()
    if not args.seeds or len(set(args.seeds)) != len(args.seeds):
        parser.error("Supply a nonempty unique seed set")
    if len(set(args.arms)) != len(args.arms):
        parser.error("Supply unique arms")
    rows = asyncio.run(measure(tuple(args.seeds), args.defense, args.reviewer, tuple(args.arms)))
    print(f"Saved per-run costs and matching evidence to {save_cost_records(rows, family='extension')}")


if __name__ == "__main__":
    main()
