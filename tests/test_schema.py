"""Optional integration check against a freshly initialized local MySQL."""

import asyncio
import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.doctor import check_database
from reef_panda_arena.storage.models import Base


def test_mysql_schema_matches_mappings() -> None:
    if os.getenv("ARENA_TEST_MYSQL") != "1":
        pytest.skip("Set ARENA_TEST_MYSQL=1 to test the local MySQL schema")

    async def inspect_schema() -> None:
        settings = ArenaSettings()
        version, tables = await check_database(settings)
        assert version == "0.1.0"
        assert tables == set(Base.metadata.tables)

        engine = create_async_engine(settings.sqlalchemy_url)
        try:
            async with engine.connect() as connection:
                rows = await connection.execute(
                    text(
                        "SELECT table_name, column_name FROM information_schema.columns "
                        "WHERE table_schema = DATABASE()"
                    )
                )
                actual = {(table, column) for table, column in rows}
            expected = {
                (table.name, column.name)
                for table in Base.metadata.tables.values()
                for column in table.columns
            }
            assert actual == expected
        finally:
            await engine.dispose()

    asyncio.run(inspect_schema())
