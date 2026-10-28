"""Read-only database readiness check."""

import asyncio

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import Base


EXPECTED_SCHEMA_VERSION = "0.1.0"


async def check_database(settings: ArenaSettings) -> tuple[str, set[str]]:
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    try:
        async with asyncio.timeout(10):
            async with engine.connect() as connection:
                version = await connection.scalar(
                    text("SELECT schema_version FROM schema_meta WHERE id = 1")
                )
                rows = await connection.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = DATABASE()"
                    )
                )
                tables = set(rows.scalars())
        if version != EXPECTED_SCHEMA_VERSION:
            raise RuntimeError("Database schema version does not match the application")
        missing = set(Base.metadata.tables) - tables
        if missing:
            raise RuntimeError("Database schema is missing required tables")
        return version, tables
    finally:
        await engine.dispose()
