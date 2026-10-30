"""Sanitized status and finite event-history repository queries."""

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, RunEvent, RunScore, SinkReceipt
from reef_panda_arena.storage.report_projection import project_report
from reef_panda_arena.storage.reports import load_report_evidence
from reef_panda_arena.telemetry.events import safe_event


def _run_status(run: ArenaRun, score: RunScore | None, evidence: dict | None = None) -> dict:
    """Status and report routes deliberately share nullable score semantics."""
    return project_report(run, score, evidence)


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
            if pair is None:
                return None
            evidence = await load_report_evidence(session, [run_id])
            return _run_status(*pair, evidence[run_id])
    finally:
        await engine.dispose()


async def list_recent_runs(settings: ArenaSettings, limit: int = 20, *,
                           scenario_ids: tuple[str, ...] | None = None) -> list[dict]:
    if not 1 <= limit <= 50:
        raise ValueError("Recent-run limit must be within 1..50")
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    try:
        sessions = async_sessionmaker(engine)
        async with sessions() as session:
            query = select(ArenaRun, RunScore).outerjoin(RunScore, ArenaRun.id == RunScore.run_id)
            if scenario_ids is not None:
                query = query.where(ArenaRun.scenario_id.in_(scenario_ids))
            rows = await session.execute(
                query.order_by(ArenaRun.created_at.desc(), ArenaRun.id.desc()).limit(limit)
            )
            pairs = rows.all()
            evidence = await load_report_evidence(session, [run.id for run, _ in pairs])
            return [_run_status(run, score, evidence[run.id]) for run, score in pairs]
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
                select(RunEvent, SinkReceipt.accepted)
                .outerjoin(SinkReceipt, and_(
                    SinkReceipt.run_id == RunEvent.run_id,
                    SinkReceipt.event_seq == RunEvent.event_seq,
                ))
                .where(RunEvent.run_id == run_id, RunEvent.event_seq >= cursor)
                .order_by(RunEvent.event_seq)
                .limit(limit)
            )
            return [safe_event(event, accepted_sink_receipt=accepted is True)
                    for event, accepted in result]
    finally:
        await engine.dispose()
