"""One cross-family audit experiment, held by a dedicated local MySQL session."""

import asyncio
import logging
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from reef_panda_arena.settings import ArenaSettings


AUDIT_LOCK = "reef_panda_audit_run_v1"
_FAMILIES = frozenset({"core", "live", "sensitive", "extension", "adaptive", "unified"})
_FAMILY_LOCKS = {
    "adaptive": "reef_panda_adaptive_run_v1",
    "unified": "reef_panda_unified_run_v1",
}
_CLEANUP_SECONDS = 5
_LOG = logging.getLogger(__name__)


class RunAdmissionBusy(RuntimeError):
    """A refused start is not a started efficacy trial."""


class RunAdmissionUnavailable(RuntimeError):
    """The database did not return a valid admission decision."""


async def _cleanup(connection, driver, engine, lock_name: str) -> None:
    """Close the physical session even if release or transaction cleanup fails.

    ArenaSettings permits only mysql+asyncmy. Its driver's close() is synchronous
    and closes the transport; it does not depend on another SQL round trip.
    The lock connection is never returned to a reusable pool.
    """
    try:
        if connection is not None:
            try:
                async with asyncio.timeout(_CLEANUP_SECONDS):
                    await connection.scalar(
                        text("SELECT RELEASE_LOCK(:lock_name)"), {"lock_name": lock_name},
                    )
            except (Exception, asyncio.CancelledError):
                _LOG.warning("Admission session requires physical close after release interruption")
            finally:
                # Also covers ambiguous cancellation during GET_LOCK.
                if driver is not None:
                    driver.close()
                for operation in (connection.invalidate, connection.close):
                    try:
                        async with asyncio.timeout(_CLEANUP_SECONDS):
                            await operation()
                    except (Exception, asyncio.CancelledError):
                        _LOG.warning("Admission session bookkeeping did not complete")
    finally:
        try:
            async with asyncio.timeout(_CLEANUP_SECONDS):
                await engine.dispose()
        except (Exception, asyncio.CancelledError):
            _LOG.warning("Admission engine disposal did not complete")


async def _finish_cleanup(connection, driver, engine, lock_name: str) -> None:
    cleanup = asyncio.create_task(_cleanup(connection, driver, engine, lock_name))
    try:
        await asyncio.shield(cleanup)
    except asyncio.CancelledError:
        # Repeated cancellation can interrupt this second shield. Close the
        # physical session now so no lock survives the caller returning early;
        # remaining bounded bookkeeping may then finish in the cleanup task.
        if driver is not None:
            driver.close()
        try:
            await asyncio.shield(cleanup)
        finally:
            raise


@asynccontextmanager
async def run_admission(settings: ArenaSettings, *, family: str):
    """Acquire once without retry; release on every exit from concrete execution."""
    if family not in _FAMILIES:
        raise ValueError("Unknown experiment family")
    lock_name = AUDIT_LOCK if settings.audit_mode else _FAMILY_LOCKS.get(family)
    if lock_name is None:
        yield
        return
    engine = create_async_engine(settings.sqlalchemy_url, poolclass=NullPool)
    connection = driver = None
    try:
        async with asyncio.timeout(10):
            connection = await engine.connect()
            raw = await connection.get_raw_connection()
            driver = raw.driver_connection
            acquired = await connection.scalar(
                text("SELECT GET_LOCK(:lock_name, 0)"), {"lock_name": lock_name},
            )
        if acquired == 0:
            scope = "audit" if settings.audit_mode else family
            raise RunAdmissionBusy(f"Concurrent {scope} run limit reached")
        if acquired != 1:
            raise RunAdmissionUnavailable("Admission lock service returned no valid decision")
        yield
    finally:
        await _finish_cleanup(connection, driver, engine, lock_name)
