"""CLI for database checks, local runs, catalog and sanitized reports."""

import argparse
import asyncio
import csv
import json
import sys
from dataclasses import asdict

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.application.live import run_live
from reef_panda_arena.gateway.policies import VALID_PROFILES
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.doctor import check_database
from reef_panda_arena.storage.reports import REPORT_COLUMNS, list_reports


def main() -> None:
    parser = argparse.ArgumentParser(prog="reef-panda-arena")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check the local MySQL schema")
    scenarios = commands.add_parser("scenarios", help="Inspect implemented scenarios")
    scenarios.add_argument("action", choices=["list"])
    run = commands.add_parser("run", help="Run a bounded local scenario")
    run.add_argument("scenario_id")
    run.add_argument("--mode", choices=["replay", "live"], default="replay")
    run.add_argument("--defense", choices=sorted(VALID_PROFILES), default="none")
    run.add_argument("--seed", type=int, default=1)
    run.add_argument("--model")
    run.add_argument("--temperature", type=float, default=0.0)
    run.add_argument("--no-attack", action="store_true")
    serve = commands.add_parser("serve", help="Serve the local HTTP API on loopback")
    serve.add_argument("--port", type=int, default=8000)
    report = commands.add_parser("report", help="Read sanitized persisted scores")
    report.add_argument("run_id", nargs="?")
    report.add_argument("--csv", action="store_true")
    args = parser.parse_args()

    try:
        if args.command == "doctor":
            version, tables = asyncio.run(check_database(ArenaSettings()))
            print(f"Database ready: schema {version}, {len(tables)} tables")
        elif args.command == "scenarios":
            loader = ScenarioLoader()
            for scenario_id in loader.list_ids():
                scenario = loader.load(scenario_id)
                print(f"{scenario.id}\t{scenario.level}\t{scenario.title}\t{scenario.attack_contract.decoder_id}")
        elif args.command == "run":
            if args.mode == "live":
                summary = asyncio.run(run_live(
                    args.scenario_id, args.defense, args.seed,
                    attack_enabled=not args.no_attack,
                    model_name=args.model,
                    temperature=args.temperature,
                ))
            else:
                summary = asyncio.run(
                    run_replay(
                        args.scenario_id, args.defense, args.seed,
                        attack_enabled=not args.no_attack,
                    )
                )
            print(json.dumps(asdict(summary), sort_keys=True))
        elif args.command == "serve":
            if not 1 <= args.port <= 65535:
                parser.error("port must be within 1..65535")
            import uvicorn
            from reef_panda_arena.api.app import create_app
            uvicorn.run(create_app(), host="127.0.0.1", port=args.port, workers=1)
        elif args.command == "report":
            if args.run_id is None and not args.csv:
                parser.error("report requires a run_id or --csv")
            rows = asyncio.run(list_reports(ArenaSettings(), args.run_id))
            if args.csv:
                writer = csv.DictWriter(sys.stdout, fieldnames=REPORT_COLUMNS)
                writer.writeheader()
                writer.writerows(rows)
            elif rows:
                print(json.dumps(rows[0], sort_keys=True))
            else:
                parser.exit(1, "Run report not found.\n")
    except (ValidationError, ValueError, RuntimeError, SQLAlchemyError, OSError,
            TimeoutError) as error:
        parser.exit(1, f"Command failed ({type(error).__name__}).\n")


if __name__ == "__main__":
    main()
