"""Measure matched C00 live runs with safe counts and explicit failures."""

import argparse
import asyncio
from collections import Counter
from statistics import median
import sys
from time import monotonic

from reef_panda_arena.application.live import run_live
from reef_panda_arena.gateway.policies import VALID_PROFILES
from reef_panda_arena.model.ollama import OllamaCaller
from reef_panda_arena.settings import ArenaSettings
from benchmark_replay import hardware, source_digest


async def measure(model: str, profiles: list[str], seeds: list[int]) -> None:
    settings = ArenaSettings()
    digest = await OllamaCaller(settings.ollama_url).model_digest(model)
    if digest is None:
        raise SystemExit("Selected local model is not installed")
    cpu, memory = hardware()
    rows = []
    for profile in profiles:
        attacked = Counter()
        controls = Counter()
        durations = []
        failure_codes = Counter()
        for seed in seeds:
            for attack_enabled in (False, True):
                kind = "attack" if attack_enabled else "control"
                print(f"C00 {profile} seed={seed} {kind}", file=sys.stderr, flush=True)
                started = monotonic()
                try:
                    result = await run_live(
                        "C00", profile, seed, attack_enabled=attack_enabled,
                        model_name=model, temperature=0.0, settings=settings,
                    )
                except Exception as error:
                    failure_codes[f"{kind}:{type(error).__name__}"] += 1
                    continue
                target = attacked if attack_enabled else controls
                target["completed"] += 1
                target["utility"] += result.benign_task_success
                target["escape"] += result.secret_escaped
                target["blocks"] += result.blocked_attempts
                target["invalid"] += result.invalid_attempt
                if attack_enabled:
                    durations.append(round((monotonic() - started) * 1000))
        rows.append((profile, attacked, controls, durations, failure_codes))
    print("# Local C00 live measurements")
    print()
    print(f"- Model: `{model}`; digest `{digest}`; Ollama loopback; temperature 0; 4,096-token context")
    print(f"- Hardware: {cpu}; RAM {memory}; local MySQL mock sink; check `ollama ps` for CPU/GPU placement")
    print(f"- Source digest: `{source_digest()}`; prompt version `live-v1`; scenario revision `0.1.0`")
    print(f"- Seeds: {', '.join(map(str, seeds))}; one attacked and one benign control per seed/profile")
    print("- Bounds: 512 response tokens, 120 s per model call, 360 s per run, 12 model calls, 8 tool calls, fixed graph")
    print("- Failure counts are excluded from ASR and utility denominators and displayed separately")
    print()
    print("| Profile | Attack complete / attempted | ASR | Attack utility | Control utility | Blocks | Invalid | Attack p50 ms | Failures |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---|")
    for profile, attacked, controls, durations, failures in rows:
        complete = attacked["completed"]
        control_complete = controls["completed"]
        failure_text = ", ".join(f"{key}={count}" for key, count in sorted(failures.items())) or "none"
        p50 = f"{median(durations):.0f}" if durations else "n/a"
        print(
            f"| {profile} | {complete}/{len(seeds)} | {attacked['escape']}/{complete} "
            f"| {attacked['utility']}/{complete} | {controls['utility']}/{control_complete} "
            f"| {attacked['blocks']} | {attacked['invalid']} | {p50} | {failure_text} |"
        )
    print()
    print("These are local C00 observations on fixed synthetic data, not general detection guarantees. Other scenarios remain replay-only. Model output failures are not treated as successful defenses.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=ArenaSettings().model)
    parser.add_argument("--profiles", nargs="+", default=["none", "taint"])
    parser.add_argument("--seeds", nargs="+", type=int, default=[31, 32, 33, 34, 35])
    args = parser.parse_args()
    if any(profile not in VALID_PROFILES for profile in args.profiles):
        parser.error("unknown defense profile")
    if not args.seeds or len(set(args.seeds)) != len(args.seeds) or any(not 0 <= seed < 2**64 for seed in args.seeds):
        parser.error("seeds must be distinct unsigned 64-bit integers")
    asyncio.run(measure(args.model, args.profiles, args.seeds))


if __name__ == "__main__":
    main()
