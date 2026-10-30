"""Measure matched C00 live trials with persisted evidence and explicit denominators."""

import argparse
import asyncio
from collections import Counter
import json
from pathlib import Path
from statistics import median
import sys
from time import monotonic
from uuid import uuid4

from reef_panda_arena.application.live import run_live
from reef_panda_arena.gateway.policies import LEGACY_PROFILES
from reef_panda_arena.model.ollama import OllamaCaller
from reef_panda_arena.settings import ArenaSettings
from benchmark_replay import hardware, source_digest
from benchmark_reporting import denominators, fixture_groups, fixture_group_label, known_total, persisted_trial, ratio


async def measure(model: str, profiles: list[str], seeds: list[int],
                  output: Path | None = None) -> list[dict]:
    settings = ArenaSettings()
    digest = await OllamaCaller(settings.ollama_url).model_digest(model)
    if digest is None:
        raise SystemExit("Selected local model is not installed")
    cpu, memory = hardware()
    code_digest = source_digest()
    rows = []
    output = output or Path(f".build/measurements/live-{uuid4().hex}.jsonl")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        for profile in profiles:
            for seed in seeds:
                for attack_enabled in (False, True):
                    kind = "attack" if attack_enabled else "control"
                    trial_run_id = str(uuid4())
                    print(f"C00 {profile} seed={seed} {kind} run_id={trial_run_id}",
                          file=sys.stderr, flush=True)
                    started = monotonic()
                    failure_type = None
                    try:
                        await run_live(
                            "C00", profile, seed, attack_enabled=attack_enabled,
                            model_name=model, temperature=0.0, settings=settings,
                            run_id=trial_run_id,
                        )
                    except Exception as error:
                        failure_type = type(error).__name__
                    elapsed_ms = round((monotonic() - started) * 1000)
                    report = await persisted_trial(settings, trial_run_id, failure_type)
                    row = {
                        "scenario_id": "C00", "seed": seed, "defense_profile": profile,
                        "mode": "live", "requested_attack_enabled": attack_enabled,
                        "requested_fixture_mode": settings.fixture_mode,
                        "requested_model": model, "requested_model_digest": digest,
                        "benchmark_source_digest": code_digest,
                        "trial_elapsed_ms": elapsed_ms, **report,
                    }
                    if row["status"] != "completed" and row.get("failure_type") is None:
                        row["failure_type"] = row.get("failure_code") or "run_not_completed"
                    rows.append(row)
                    stream.write(json.dumps(row, sort_keys=True) + "\n")
                    stream.flush()
    print("# Local C00 live measurements")
    print()
    print(f"- Model: `{model}`; digest `{digest}`; Ollama loopback; temperature 0; 4,096-token context")
    print(f"- Hardware: {cpu}; RAM {memory}; local MySQL mock sink; check `ollama ps` for CPU/GPU placement")
    print(f"- Source digest: `{code_digest}`; prompt/scenario/oracle versions are recorded per persisted trial")
    print(f"- Seeds: {', '.join(map(str, seeds))}; one attacked and one benign control per seed/profile")
    print("- Bounds: 512 response tokens, 120 s per model call, 360 s per run, 12 model calls, 8 tool calls, fixed graph")
    print(f"- Per-trial sanitized evidence, UUIDs and failure reasons: `{output}` (JSON Lines)")
    print("- Full-recovery denominator: completed attacks with an independent measured oracle. Strict denominator: strict_trial_eligible attacks. Utility denominator: completed trials with measured utility.")
    print("- All planned trials remain in the file. Failed-run confirmed recoveries and receipts remain visible separately; not_started means no persisted run for its assigned UUID. A zero denominator is not_measured.")
    print()
    print("| Profile / fixture group | Attack complete / trials | Independent full recovery | Strict win | Attack utility | Control utility | Known confirmed recovery (coverage) | Known accepted receipts (coverage) | Attack completed p50 ms | Incomplete trials |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    for profile in profiles:
        selected = [row for row in rows if row["defense_profile"] == profile]
        for key, selected in fixture_groups(selected):
            attacks = [row for row in selected if row["requested_attack_enabled"]]
            controls = [row for row in selected if not row["requested_attack_enabled"]]
            attacked = denominators(attacks)
            benign = denominators(controls)
            durations = [row["trial_elapsed_ms"] for row in attacks if row["status"] == "completed"]
            failures = Counter(
                ("attack" if row["requested_attack_enabled"] else "control") + ":" + row["status"]
                + ":" + (row.get("failure_type") or "unknown")
                for row in selected if row["status"] != "completed"
            )
            failure_text = ", ".join(f"{key}={count}" for key, count in sorted(failures.items())) or "none"
            p50 = f"{median(durations):.0f}" if durations else "not_measured"
            print(
                f"| {profile} / {fixture_group_label(key)} | {attacked['completed_trials']}/{attacked['attempted_trials']} "
                f"| {ratio(attacked['full_recoveries'], attacked['independent_recovery_denominator'])} "
                f"| {ratio(attacked['strict_wins'], attacked['strict_denominator'])} "
                f"| {ratio(attacked['task_successes'], attacked['utility_denominator'])} "
                f"| {ratio(benign['task_successes'], benign['utility_denominator'])} "
                f"| {known_total(attacked['confirmed_recovery_all_statuses'], attacked['recovery_measurement_trials'], attacked['attempted_trials'])} "
                f"| {known_total(attacked['accepted_receipts_all_statuses'], attacked['receipt_measurement_trials'], attacked['attempted_trials'])} "
                f"| {p50} | {failure_text} |"
            )
    print()
    print("These are local C00 observations on fixed synthetic data. Observer coverage and strict eligibility are explicit per run; model failures do not establish successful defense.")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=ArenaSettings().model)
    parser.add_argument("--profiles", nargs="+", default=["none", "taint"])
    parser.add_argument("--seeds", nargs="+", type=int, default=[31, 32, 33, 34, 35])
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    if any(profile not in LEGACY_PROFILES for profile in args.profiles):
        parser.error("unknown defense profile")
    if not args.seeds or len(set(args.seeds)) != len(args.seeds) or any(not 0 <= seed < 2**64 for seed in args.seeds):
        parser.error("seeds must be distinct unsigned 64-bit integers")
    asyncio.run(measure(args.model, args.profiles, args.seeds, args.output))


if __name__ == "__main__":
    main()
