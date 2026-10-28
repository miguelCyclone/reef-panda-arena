"""Focused checks for exact accepted egress and the C00 policy boundary."""

import asyncio
import os
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.gateway.invoke import SinkArtifact
from reef_panda_arena.oracle.evaluate import secret_escaped
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.scenarios.vault import SyntheticSecretVault
from reef_panda_arena.settings import ArenaSettings


def test_oracle_uses_exact_accepted_bytes() -> None:
    secret = b"SYNTH123"
    assert secret_escaped(secret, [SinkArtifact(1, secret)])
    assert not secret_escaped(secret, [SinkArtifact(1, b"prefix-SYNTH123")])
    assert not secret_escaped(secret, [])


def test_c00_scenario_is_strict() -> None:
    scenario = ScenarioLoader().load("C00")
    assert scenario.attack_contract.decoder_id == "literal"
    with pytest.raises(ValueError):
        ScenarioLoader().load("../C00")
    assert ScenarioLoader().load("C03").attack_contract.decoder_id == "polynomial_coefficients_v1"
    with pytest.raises(ValueError):
        ScenarioLoader().load("C10")


def test_c00_replay_persists_only_accepted_sink_receipts() -> None:
    if os.getenv("ARENA_TEST_MYSQL") != "1":
        pytest.skip("Set ARENA_TEST_MYSQL=1 to test the local MySQL replay")

    async def verify() -> None:
        settings = ArenaSettings()
        baseline = await run_replay("C00", "none", 7, settings)
        filtered = await run_replay("C00", "content", 7, settings)
        assert baseline.secret_escaped and baseline.benign_task_success
        assert not filtered.secret_escaped and filtered.benign_task_success
        assert baseline.accepted_outbound_events == 2
        assert filtered.accepted_outbound_events == 1
        assert filtered.blocked_attempts == 1

        secret = SyntheticSecretVault(settings.encryption_key).create(
            str(uuid4()), "C00", 7, 8, "internal_routing_code"
        )[1].decode("ascii")
        engine = create_async_engine(settings.sqlalchemy_url)
        try:
            async with engine.connect() as connection:
                for report, expected_receipts, expected_blocks in (
                    (baseline, 2, 0), (filtered, 1, 1)
                ):
                    receipts = await connection.scalar(
                        text("SELECT COUNT(*) FROM sink_receipts WHERE run_id = :run_id"),
                        {"run_id": report.run_id},
                    )
                    blocked = await connection.scalar(
                        text("SELECT COUNT(*) FROM run_events WHERE run_id = :run_id "
                             "AND policy_decision = 'block'"),
                        {"run_id": report.run_id},
                    )
                    assert receipts == expected_receipts
                    assert blocked == expected_blocks
                    rows = await connection.execute(
                        text("SELECT safe_summary_json FROM run_events WHERE run_id = :run_id"),
                        {"run_id": report.run_id},
                    )
                    assert all(secret not in str(row[0]) for row in rows)
                leaked_receipts = await connection.scalar(
                    text("SELECT COUNT(*) FROM sink_receipts AS s JOIN run_events AS e "
                         "ON s.run_id = e.run_id AND s.event_seq = e.event_seq "
                         "WHERE s.run_id = :run_id AND e.policy_decision = 'block'"),
                    {"run_id": filtered.run_id},
                )
                assert leaked_receipts == 0
        finally:
            await engine.dispose()

    asyncio.run(verify())
