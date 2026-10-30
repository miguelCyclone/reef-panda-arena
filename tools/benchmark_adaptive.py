"""Run bounded local C22-C28 matrices and export only sanitized outcomes."""

import argparse
import asyncio
import csv
from random import Random
from pathlib import Path
from uuid import uuid4

from reef_panda_arena.application.adaptive import run_adaptive
from reef_panda_arena.application.knowledge import KNOWLEDGE_FIELDS
from reef_panda_arena.application.utility_contract import UTILITY_FIELDS
from benchmark_reporting import cost_report_lines, save_cost_records
from reef_panda_arena.storage.report_projection import PERSISTED_FIELDS, SCORING_FIELDS
from benchmark_reporting import TRIAL_FIELDS, csv_row, denominators, fixture_groups, fixture_group_label, known_total, persisted_trial, ratio
from reef_panda_arena.settings import ArenaSettings


COLUMNS = (
    "scenario_id", "scenario_revision", "seed", "split", "mode", "arm",
    "profile", "reviewer", "reviewer_requested", "transfer_from_run_id",
    "order_seed", "round_limit", "requested_fixture_mode", "source_digest", "model_digest",
    "model_top_p", "model_generation_seed",
    "prompt_version", "model_temperature",
    "status", "failure_type", "run_id", "invalid_attempt", "secret_escaped",
    "benign_task_success", "undetected_success", "alerts",
    "attack_alerts", "benign_alerts", "accepted_outbound_events",
    "blocked_attempts", "valid_candidates", "invalid_candidates",
    "unsupported_proposals", "rounds_used", "attacker_model_calls",
    "total_model_calls", "gateway_calls", "graph_supersteps",
    "tokens_in", "tokens_out", "run_duration_ms", "stop_reason",
    "verified_bits", "first_success_round", "candidate_family_count",
    "novelty_status", "novel_vs_catalog", "distinct_candidate_count",
    "accepted_sink_bytes", "first_alert_round", "first_block_round",
    "model_originated", "model_name", "requested_attack_enabled",
)
COLUMNS = tuple(dict.fromkeys((*COLUMNS, *SCORING_FIELDS, *PERSISTED_FIELDS, *TRIAL_FIELDS, *KNOWLEDGE_FIELDS, *UTILITY_FIELDS, "defense_profile")))


async def matrix(args: argparse.Namespace) -> list[dict]:
    settings = ArenaSettings()
    rows = []
    trials = [
        (scenario, seed, profile, arm)
        for scenario in args.scenarios for seed in args.seeds
        for profile in args.profiles for arm in args.arms
    ]
    if len(trials) > 10000:
        raise ValueError("Adaptive matrix exceeds the finite trial bound")
    Random(args.order_seed).shuffle(trials)
    for scenario, seed, profile, arm in trials:
        row = {
            "scenario_id": scenario, "seed": seed,
            "mode": args.mode, "arm": arm, "requested_attack_enabled": arm != "A0",
            "profile": profile, "reviewer": args.reviewer,
            "reviewer_requested": args.reviewer,
            "split": args.split, "transfer_from_run_id": args.transfer_from,
            "order_seed": args.order_seed, "requested_fixture_mode": settings.fixture_mode,
            "status": "failed", "failure_type": "",
        }
        trial_run_id = str(uuid4())
        row["run_id"] = trial_run_id
        failure_type = None
        try:
            await run_adaptive(
                scenario, profile, seed, settings=settings,
                mode=args.mode, arm=arm,
                observer_profile=args.reviewer,
                round_limit=args.rounds, split=args.split,
                transfer_from_run_id=args.transfer_from,
                model_name=args.model,
                temperature=args.temperature, run_id=trial_run_id,
            )
        except Exception as error:
            failure_type = type(error).__name__
        report = await persisted_trial(settings, trial_run_id, failure_type)
        # Keep request metadata separate from authoritative measured outcomes.
        row.update({key: value for key, value in report.items() if key in COLUMNS})
        if report.get("observer_profile") is not None:
            row["reviewer"] = report["observer_profile"]
        if row["status"] != "completed" and row.get("failure_type") is None:
            row["failure_type"] = report.get("failure_code") or report.get("stop_reason") or "run_not_completed"
        rows.append(row)
        print(
            f"{scenario} seed={seed} {profile} {arm} "
            f"status={row['status']} "
            f"exact={row.get('secret_escaped')} "
            f"utility={row.get('benign_task_success')}",
            flush=True,
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scenarios", nargs="+",
        choices=[f"C{i}" for i in range(22, 29)],
        default=[f"C{i}" for i in range(22, 29)],
    )
    parser.add_argument(
        "--seeds", nargs="+", type=int, default=[31, 32, 33, 34, 35],
    )
    parser.add_argument(
        "--profiles", nargs="+", default=["none", "declassify_strict"],
        choices=["none", "allowlist", "content", "taint",
                 "combined", "declassify_strict"],
    )
    parser.add_argument(
        "--arms", nargs="+", default=["A0", "A1", "A3"],
        choices=["A0", "A1", "A2", "A3", "A4", "A5"],
    )
    parser.add_argument(
        "--mode", choices=["replay", "live_adaptive"], default="replay",
    )
    parser.add_argument(
        "--reviewer", default="metadata_schema",
        choices=["literal_content", "metadata_schema",
                 "structural_math", "provenance_release"],
    )
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--order-seed", type=int, default=314159)
    parser.add_argument(
        "--split", choices=["development", "holdout"],
        default="development",
    )
    parser.add_argument("--transfer-from")
    parser.add_argument("--model")
    parser.add_argument("--temperature", type=float, default=0)
    parser.add_argument(
        "--output", type=Path,
        default=None,
    )
    args = parser.parse_args()
    if args.mode == "replay" and any(
        arm in {"A2", "A4"} for arm in args.arms
    ):
        parser.error("A2/A4 require a model; replay only supports scripted controls")
    if args.mode == "live_adaptive" and "A1" in args.arms:
        parser.error("A1 is a scripted replay control")
    args.output = args.output or Path(f".build/measurements/adaptive-{uuid4().hex}.csv")
    if args.output.exists():
        parser.error("Use a new output path; existing evidence is never overwritten")
    rows = asyncio.run(matrix(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(csv_row(row, COLUMNS) for row in rows)
    print("\n".join(cost_report_lines(rows)))
    print(f"Saved matching evidence to {save_cost_records(rows, family='adaptive')}")
    for key, group in fixture_groups(rows):
        stats = denominators(group)
        attacked = denominators([row for row in group if row["requested_attack_enabled"]])
        controls = denominators([row for row in group if not row["requested_attack_enabled"]])
        print(
            f"Fixture group {fixture_group_label(key)}; {len(group)} trials in {args.output}; "
            f"started={stats['started_trials']}, completed={stats['completed_trials']}, "
            f"not_started={stats['not_started_trials']}, unknown_start={stats['unknown_start_trials']}; "
            f"attack_independent_full_recovery={ratio(attacked['full_recoveries'], attacked['independent_recovery_denominator'])}; "
            f"attack_strict_win={ratio(attacked['strict_wins'], attacked['strict_denominator'])}; "
            f"attack_utility={ratio(attacked['task_successes'], attacked['utility_denominator'])}; "
            f"control_utility={ratio(controls['task_successes'], controls['utility_denominator'])}; "
            f"known_confirmed_recoveries_all_statuses={known_total(stats['confirmed_recovery_all_statuses'], stats['recovery_measurement_trials'], stats['attempted_trials'])}; "
            f"known_accepted_receipts={known_total(stats['accepted_receipts_all_statuses'], stats['receipt_measurement_trials'], stats['attempted_trials'])}; "
            f"known_persisted_receipts={known_total(stats['persisted_receipts_all_statuses'], stats['persisted_receipt_measurement_trials'], stats['attempted_trials'])}"
        )


if __name__ == "__main__":
    main()
