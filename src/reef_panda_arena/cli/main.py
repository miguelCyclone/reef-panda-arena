"""CLI for database checks, local runs, catalog and sanitized reports."""

import argparse
import asyncio
import csv
import json
import sys

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.gateway.policies import VALID_PROFILES
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.scenarios.unified_contract import UnifiedScenarioDefinition
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.doctor import check_database
from reef_panda_arena.storage.reports import REPORT_COLUMNS, get_unified_report, iter_reports, list_reports


async def _export_csv(settings: ArenaSettings, run_id: str | None) -> None:
    writer = csv.DictWriter(sys.stdout, fieldnames=REPORT_COLUMNS)
    writer.writeheader()
    async for row in iter_reports(settings, run_id):
        writer.writerow({
            name: json.dumps(value, sort_keys=True, separators=(",", ":"))
            if isinstance(value, (dict, list)) else value
            for name, value in row.items()
        })


def main() -> None:
    parser = argparse.ArgumentParser(prog="reef-panda-arena")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check the local MySQL schema")
    scenarios = commands.add_parser("scenarios", help="Inspect implemented scenarios")
    scenarios.add_argument("action", choices=["list"])
    run = commands.add_parser("run", help="Run a bounded local scenario")
    run.add_argument("scenario_id")
    run.add_argument("--mode", choices=["replay", "live", "live_adaptive", "live_multiagent"], default="replay")
    run.add_argument("--defense", choices=sorted(VALID_PROFILES))
    run.add_argument("--seed", type=int, default=1)
    run.add_argument("--model")
    run.add_argument("--temperature", type=float, default=0.0)
    run.add_argument("--top-p", type=float)
    run.add_argument("--generation-seed", type=int)
    run.add_argument("--no-attack", action="store_true")
    run.add_argument("--arm", choices=["B0", "B1", "A0", "A1", "A2", "A3", "A4", "A5", "H0", "P0"])
    run.add_argument("--rounds", type=int, default=8)
    run.add_argument("--split", choices=["development", "holdout"], default="development")
    run.add_argument("--transfer-from")
    run.add_argument("--observer", choices=["literal_content", "metadata_schema", "structural_math", "provenance_release"], default="metadata_schema")
    booking = commands.add_parser("booking", help="Run the core synthetic medical booking experiment")
    booking.add_argument("--mode", choices=["live", "replay"], default="live")
    booking.add_argument("--arm", choices=["A0", "A1", "A2", "A3", "A4"], default="A0")
    booking.add_argument("--policy", choices=["schema", "content", "actor_taint", "restricted_release", "transitive"], default="schema")
    booking.add_argument("--seed", type=int, default=31)
    booking.add_argument("--variant", type=int, choices=[0, 1], default=0)
    booking.add_argument("--model", default="qwen2.5:3b-instruct-q4_K_M")
    booking.add_argument("--temperature", type=float, default=0.0)
    booking.add_argument("--generation-seed", type=int, default=31)
    booking.add_argument("--report", metavar="RUN_UUID", help="Read an existing sanitized booking report")
    serve = commands.add_parser("serve", help="Serve the local HTTP API on loopback")
    serve.add_argument("--port", type=int, default=8000)
    report = commands.add_parser("report", help="Read sanitized persisted scores")
    report.add_argument("run_id", nargs="?")
    report.add_argument("--csv", action="store_true")
    report.add_argument("--unified", action="store_true")
    report.add_argument("--lineage", action="store_true", help="Reconstruct redacted lineage from persisted events")
    args = parser.parse_args()

    try:
        if args.command == "doctor":
            version, tables = asyncio.run(check_database(ArenaSettings()))
            print(f"Database ready: schema {version}, {len(tables)} tables")
        elif args.command == "booking":
            from reef_panda_arena.application.booking import run_booking
            from reef_panda_arena.application.booking_contract import BookingConfig
            from reef_panda_arena.storage.booking import booking_report
            if args.report:
                result = asyncio.run(booking_report(ArenaSettings(), args.report))
                if result is None:
                    raise ValueError("Unknown booking run")
            else:
                config = BookingConfig(mode=args.mode, arm=args.arm, policy=args.policy,
                    seed=args.seed, variant=args.variant, model=args.model,
                    temperature=args.temperature, generation_seed=args.generation_seed)
                result = asyncio.run(run_booking(config))
            print(json.dumps(result, indent=2))
        elif args.command == "scenarios":
            loader = ScenarioLoader()
            for scenario_id in loader.list_ids():
                scenario = loader.load(scenario_id)
                decoder = (
                    "unified_exact" if isinstance(scenario, UnifiedScenarioDefinition)
                    else scenario.attack_contract.decoder_id
                )
                print(f"{scenario.id}\t{scenario.level}\t{scenario.title}\t{decoder}")
        elif args.command == "run":
            scenario = ScenarioLoader().load(args.scenario_id)
            if args.mode not in scenario.mode_support:
                raise ValueError("Mode is unavailable for this scenario")
            unified = args.scenario_id in {f"C{i}" for i in range(29, 44)}
            defense = args.defense or ("transitive" if unified else "none")
            if args.mode == "live_multiagent" and not unified:
                raise ValueError("Independent multiagent mode requires C29-C43")
            if (args.top_p is not None or args.generation_seed is not None) and args.mode != "live_multiagent":
                raise ValueError("Explicit sampling options require independent multiagent mode")
            if unified:
                if (args.mode not in {"replay", "live_multiagent"} or args.arm is not None
                        or args.rounds != 8 or args.split != "development" or args.transfer_from is not None):
                    raise ValueError("Unified cases require replay or live_multiagent without adaptive options")
                from reef_panda_arena.application.unified import run_unified_live, run_unified_replay

                runner = run_unified_live if args.mode == "live_multiagent" else run_unified_replay
                options = {"model_name": args.model, "temperature": args.temperature,
                           "top_p": args.top_p, "generation_seed": args.generation_seed} if args.mode == "live_multiagent" else {}
                summary = asyncio.run(runner(
                    args.scenario_id, defense, args.seed,
                    attack_enabled=not args.no_attack,
                    observer_profile=args.observer, **options,
                ))
            elif args.scenario_id in {f"C{i}" for i in range(22, 29)}:
                from reef_panda_arena.application.adaptive import run_adaptive

                summary = asyncio.run(run_adaptive(
                    args.scenario_id, defense, args.seed,
                    mode=args.mode,
                    arm=args.arm or (
                        "A0" if args.no_attack else
                        "A3" if args.mode == "live_adaptive" else "A1"
                    ),
                    observer_profile=args.observer,
                    round_limit=args.rounds,
                    split=args.split,
                    transfer_from_run_id=args.transfer_from,
                    model_name=args.model,
                    temperature=args.temperature,
                ))
            elif args.mode == "live_adaptive":
                raise ValueError("Adaptive live mode requires C22-C28")
            elif args.mode == "live":
                if args.arm is not None or args.observer != "metadata_schema":
                    raise ValueError("Extension arm and reviewer apply to replay only")
                from reef_panda_arena.application.live import run_live

                summary = asyncio.run(run_live(
                    args.scenario_id, defense, args.seed,
                    attack_enabled=not args.no_attack,
                    model_name=args.model,
                    temperature=args.temperature,
                ))
            else:
                summary = asyncio.run(
                    run_replay(
                        args.scenario_id, defense, args.seed,
                        attack_enabled=not args.no_attack,
                        arm=args.arm, observer_profile=args.observer,
                    )
                )
            reports = asyncio.run(list_reports(ArenaSettings(), summary.run_id, limit=1))
            if not reports:
                raise RuntimeError("Persisted run report is unavailable")
            print(json.dumps(reports[0], sort_keys=True))
        elif args.command == "serve":
            if not 1 <= args.port <= 65535:
                parser.error("port must be within 1..65535")
            import uvicorn
            from reef_panda_arena.api.app import create_app
            uvicorn.run(create_app(), host="127.0.0.1", port=args.port, workers=1)
        elif args.command == "report":
            if args.lineage:
                if args.run_id is None or args.csv or args.unified:
                    parser.error("--lineage requires one run_id and no --csv or --unified")
                from reef_panda_arena.storage.lineage import load_run_lineage
                graph = asyncio.run(load_run_lineage(ArenaSettings(), args.run_id))
                if graph is None:
                    parser.exit(1, "Run not found.\n")
                print(json.dumps(graph, sort_keys=True))
                return
            if args.unified:
                if args.run_id is None or args.csv:
                    parser.error("--unified requires one run_id and no --csv")
                row = asyncio.run(get_unified_report(ArenaSettings(), args.run_id))
                if row is None:
                    parser.exit(1, "Unified run report not found.\n")
                print(json.dumps(row, sort_keys=True))
                return
            if args.run_id is None and not args.csv:
                parser.error("report requires a run_id or --csv")
            if args.csv:
                asyncio.run(_export_csv(ArenaSettings(), args.run_id))
            else:
                rows = asyncio.run(list_reports(ArenaSettings(), args.run_id))
                if rows:
                    print(json.dumps(rows[0], sort_keys=True))
                else:
                    parser.exit(1, "Run report not found.\n")
    except (ValidationError, ValueError, RuntimeError, SQLAlchemyError, OSError,
            TimeoutError) as error:
        parser.exit(1, f"Command failed ({type(error).__name__}).\n")


if __name__ == "__main__":
    main()
