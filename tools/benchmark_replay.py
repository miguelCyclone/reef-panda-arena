"""Measure a small matched replay matrix; stdout is safe Markdown."""

import argparse
import asyncio
import hashlib
import platform
from pathlib import Path
from statistics import median
from time import monotonic

from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.gateway.policies import VALID_PROFILES
from reef_panda_arena.scenarios.loader import ScenarioLoader


ROOT = Path(__file__).resolve().parents[1]


def source_digest() -> str:
    paths = [
        *sorted((ROOT / "src").rglob("*.py")),
        *sorted((ROOT / "scenarios").glob("*.yaml")),
        ROOT / "scenarios" / "catalog.csv",
        ROOT / "fixtures" / "shipping_task.json",
        ROOT / "migration" / "schema.sql",
    ]
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def hardware() -> tuple[str, str]:
    cpu = platform.processor() or "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    memory = "unknown"
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory = f"{int(line.split()[1]) / 1024**2:.1f} GiB"
                break
    return cpu, memory


def ratio(count: int, total: int) -> str:
    return f"{count}/{total}"


async def measure(seeds: tuple[int, ...]) -> None:
    cpu, memory = hardware()
    print("# Local replay measurements")
    print()
    print(f"- Runtime: Python {platform.python_version()}, MySQL 8.4, no LLM")
    print(f"- Hardware: {cpu}; RAM {memory}; OS {platform.system()} {platform.release()}")
    print(f"- Source digest: `{source_digest()}`; scenario revision `0.1.0`")
    print(f"- Seeds: {', '.join(map(str, seeds))}; one attacked and one benign control per seed/profile/scenario")
    print("- Conditions: local mock tools and sink, deterministic replay, fresh run IDs, temperature not applicable")
    print()
    print("| Scenario | Profile | Attacked N | ASR | Utility under attack | Benign utility | Invalid attempts | Blocks | p50 ms |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for scenario_id in ScenarioLoader().list_ids():
        for profile in sorted(VALID_PROFILES):
            escaped = utility = benign = invalid = blocks = 0
            durations = []
            for seed in seeds:
                start = monotonic()
                attacked = await run_replay(scenario_id, profile, seed, attack_enabled=True)
                durations.append(round((monotonic() - start) * 1000))
                control = await run_replay(scenario_id, profile, seed, attack_enabled=False)
                escaped += attacked.secret_escaped
                utility += attacked.benign_task_success
                benign += control.benign_task_success
                invalid += attacked.invalid_attempt
                blocks += attacked.blocked_attempts
            print(
                f"| {scenario_id} | {profile} | {len(seeds)} | {ratio(escaped, len(seeds))} "
                f"| {ratio(utility, len(seeds))} | {ratio(benign, len(seeds))} "
                f"| {invalid} | {blocks} | {median(durations):.0f} |"
            )
    print()
    print("These results measure fixed synthetic replay scripts and selected application boundaries. They do not establish security against arbitrary encodings, unmodeled tool paths, host compromise, or real-world workloads. Content filtering and taint tracking are deliberately limited baselines; live-model behavior must be reported separately.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", default=[31, 32, 33])
    args = parser.parse_args()
    if len(set(args.seeds)) != len(args.seeds) or any(not 0 <= seed < 2**64 for seed in args.seeds):
        parser.error("seeds must be distinct unsigned 64-bit integers")
    asyncio.run(measure(tuple(args.seeds)))


if __name__ == "__main__":
    main()
