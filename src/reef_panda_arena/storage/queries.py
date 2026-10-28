"""Sanitized status and finite event-history repository queries."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, RunEvent, RunScore
from reef_panda_arena.telemetry.events import safe_event


def _run_status(run: ArenaRun, score: RunScore | None) -> dict:
    return {
        "run_id": run.id,
        "scenario_id": run.scenario_id,
        "mode": run.mode,
        "defense_profile": run.defense_profile,
        "status": run.status,
        "model_name": run.model_name,
        "failure_code": run.failure_code,
        "secret_escaped": bool(score.secret_escaped) if score else None,
        "benign_task_success": bool(score.benign_task_success) if score else None,
        "accepted_outbound_events": score.accepted_outbound_events if score else None,
    }


async def get_run_status(settings: ArenaSettings, run_id: str) -> dict | None:
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    try:
        sessions = async_sessionmaker(engine)
        async with sessions() as session:
            row = await session.execute(
                select(ArenaRun, RunScore)
                .outerjoin(RunScore, ArenaRun.id == RunScore.run_id)
                .where(ArenaRun.id == run_id)
            )
            pair = row.first()
            return _run_status(*pair) if pair is not None else None
    finally:
        await engine.dispose()


async def list_recent_runs(settings: ArenaSettings, limit: int = 20) -> list[dict]:
    if not 1 <= limit <= 50:
        raise ValueError("Recent-run limit must be within 1..50")
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    try:
        sessions = async_sessionmaker(engine)
        async with sessions() as session:
            rows = await session.execute(
                select(ArenaRun, RunScore)
                .outerjoin(RunScore, ArenaRun.id == RunScore.run_id)
                .order_by(ArenaRun.created_at.desc(), ArenaRun.id.desc())
                .limit(limit)
            )
            return [_run_status(run, score) for run, score in rows.all()]
    finally:
        await engine.dispose()


async def list_run_events(settings: ArenaSettings, run_id: str,
                          cursor: int = 0, limit: int = 100) -> list[dict]:
    if not 0 <= cursor < 2**32 or not 1 <= limit <= 100:
        raise ValueError("Invalid event page")
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    try:
        sessions = async_sessionmaker(engine)
        async with sessions() as session:
            result = await session.execute(
                select(RunEvent)
                .where(RunEvent.run_id == run_id, RunEvent.event_seq >= cursor)
                .order_by(RunEvent.event_seq)
                .limit(limit)
            )
            return [safe_event(event) for event in result.scalars()]
    finally:
        await engine.dispose()
