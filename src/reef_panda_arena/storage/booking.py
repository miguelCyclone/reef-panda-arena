"""Read the persisted core experiment and independently count accepted receipts."""

from uuid import UUID
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from reef_panda_arena.storage.models import ArenaRun, SinkReceipt


async def booking_report(settings, run_id):
    run_id=str(UUID(run_id))
    engine=create_async_engine(settings.sqlalchemy_url,pool_pre_ping=True)
    try:
        async with async_sessionmaker(engine)() as session:
            run=await session.get(ArenaRun,run_id)
            if run is None or run.scenario_id!='booking-core':return None
            report=dict((run.stage_snapshot_json or {}).get('booking',{}))
            count=await session.scalar(select(func.count()).select_from(SinkReceipt).where(
                SinkReceipt.run_id==run_id,SinkReceipt.accepted.is_(True)))
            report['persisted_accepted_outbound_count']=count
            report['receipt_count_consistent']=count==report.get('accepted_outbound_count',0)
            return report
    finally:
        await engine.dispose()


async def recent_bookings(settings, limit=20):
    if type(limit) is not int or not 1<=limit<=50:
        raise ValueError("Invalid booking history limit")
    engine=create_async_engine(settings.sqlalchemy_url,pool_pre_ping=True)
    try:
        async with async_sessionmaker(engine)() as session:
            result=await session.scalars(select(ArenaRun).where(ArenaRun.scenario_id=='booking-core')
                .order_by(ArenaRun.created_at.desc()).limit(limit))
            return [dict((run.stage_snapshot_json or {})['booking']) for run in result]
    finally:
        await engine.dispose()


async def booking_receipt_fingerprints(settings, run_id):
    """Private comparison helper; public reports expose equality, not small-domain hashes."""
    run_id=str(UUID(run_id))
    engine=create_async_engine(settings.sqlalchemy_url,pool_pre_ping=True)
    try:
        async with async_sessionmaker(engine)() as session:
            result=await session.scalars(select(SinkReceipt.payload_sha256).where(
                SinkReceipt.run_id==run_id,SinkReceipt.accepted.is_(True)).order_by(SinkReceipt.event_seq))
            return tuple(result)
    finally:
        await engine.dispose()
