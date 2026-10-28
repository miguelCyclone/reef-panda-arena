"""Sanitized read-only run report repository."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, RunScore


REPORT_COLUMNS = (
    "run_id", "scenario_id", "scenario_revision", "mode", "defense_profile",
    "model_name", "model_temperature", "seed", "status", "attacker_attempted",
    "invalid_attempt", "secret_escaped", "benign_task_success", "blocked_attempts",
    "accepted_outbound_events", "run_duration_ms", "oracle_version", "decoder",
)


async def list_reports(settings: ArenaSettings, run_id: str | None = None,
                       limit: int = 1000) -> list[dict]:
    if not 1 <= limit <= 1000:
        raise ValueError("Report limit must be within 1..1000")
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    try:
        sessions = async_sessionmaker(engine)
        async with sessions() as session:
            query = (
                select(ArenaRun, RunScore)
                .join(RunScore, ArenaRun.id == RunScore.run_id)
                .order_by(ArenaRun.created_at.desc())
                .limit(limit)
            )
            if run_id is not None:
                query = query.where(ArenaRun.id == run_id)
            result = await session.execute(query)
            reports = []
            for run, score in result.all():
                reports.append({
                    "run_id": run.id,
                    "scenario_id": run.scenario_id,
                    "scenario_revision": run.scenario_revision,
                    "mode": run.mode,
                    "defense_profile": run.defense_profile,
                    "model_name": run.model_name,
                    "model_temperature": (
                        str(run.model_temperature) if run.model_temperature is not None
                        else None
                    ),
                    "seed": run.seed,
                    "status": run.status,
                    "attacker_attempted": bool(score.attacker_attempted),
                    "invalid_attempt": bool(score.details_json.get("invalid_attempt", False)),
                    "secret_escaped": bool(score.secret_escaped),
                    "benign_task_success": bool(score.benign_task_success),
                    "blocked_attempts": score.blocked_attempts,
                    "accepted_outbound_events": score.accepted_outbound_events,
                    "run_duration_ms": score.run_duration_ms,
                    "oracle_version": score.oracle_version,
                    "decoder": score.details_json.get("decoder"),
                })
            return reports
    finally:
        await engine.dispose()
