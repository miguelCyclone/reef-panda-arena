"""Nullable API and versioned reporting contracts without DB or model access."""

import asyncio
import importlib
import json
from pathlib import Path
from uuid import UUID

import httpx

from reef_panda_arena.api.app import RunStatus, create_app
from reef_panda_arena.api.scoring_contract import ScoreFields
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, RunScore
from reef_panda_arena.storage.report_projection import (
    PERSISTED_FIELDS, SCORING_FIELDS, project_report,
)
from reef_panda_arena.storage.reports import UNIFIED_REPORT_FIELDS


def run(identifier: int, *, status: str, scenario: str = "C32") -> ArenaRun:
    return ArenaRun(
        id=str(UUID(int=identifier)), scenario_id=scenario,
        scenario_revision="unified-v1" if scenario == "C32" else "sensitive-v1",
        mode="replay", defense_profile="transitive", model_name=None,
        model_temperature=None, prompt_version="test", seed=31, status=status,
        failure_code="model_timed_out" if status == "timed_out" else None,
        stage_snapshot_json={"attack_enabled": True},
    )


def test_status_and_reports_preserve_missing_and_historical_proxy_measurements(monkeypatch):
    api = importlib.import_module("reef_panda_arena.api.app")
    runs = [run(101, status="pending"), run(102, status="running"),
            run(103, status="timed_out"), run(104, status="completed", scenario="C12")]
    proxy = RunScore(
        run_id=runs[-1].id, attacker_attempted=True, secret_escaped=True,
        benign_task_success=True, blocked_attempts=0, accepted_outbound_events=16,
        run_duration_ms=10, oracle_version="sensitive-v1", details_json={},
    )
    rows = {item.id: project_report(item, proxy if item is runs[-1] else None)
            for item in runs}

    async def status(_settings, run_id):
        return rows.get(run_id)

    async def reports(_settings, run_id, limit):
        return [rows[run_id]] if run_id in rows else []

    async def recent(_settings, _limit, *, scenario_ids):
        assert "C00" in scenario_ids and "booking-core" not in scenario_ids
        return list(rows.values())

    monkeypatch.setattr(api, "get_run_status", status)
    monkeypatch.setattr(api, "list_reports", reports)
    monkeypatch.setattr(api, "list_recent_runs", recent)

    async def check():
        app = create_app(ArenaSettings())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://testserver") as client:
            for item in runs:
                status_response = await client.get(f"/v1/runs/{item.id}")
                report_response = await client.get(f"/v1/runs/{item.id}/report")
                assert status_response.status_code == report_response.status_code == 200
                current, report = status_response.json(), report_response.json()
                for name in SCORING_FIELDS:
                    assert current[name] == report[name], name
                for name in ("full_secret_recovered", "secret_escaped", "strict_win",
                             "attacker_win", "undetected_success"):
                    assert current[name] is None
                assert current["strict_trial_eligible"] is False
            historical = (await client.get(f"/v1/runs/{runs[-1].id}/report")).json()
            assert historical["oracle_validation"] == "fixture_proxy"
            assert historical["fixture_proxy_match"] is True
            recent_response = await client.get("/v1/runs")
            assert len(recent_response.json()) == 4
            assert (await client.get(f"/v1/runs/{UUID(int=999)}/report")).status_code == 404
        await app.state.run_manager.shutdown()

    asyncio.run(check())


def test_known_pending_run_report_has_nullable_fallback(monkeypatch):
    api = importlib.import_module("reef_panda_arena.api.app")
    row = {"run_id": str(UUID(int=105)), "scenario_id": "C00", "mode": "live",
           "defense_profile": "none", "status": "pending", "model_name": "dummy"}

    async def status(*_args):
        return row

    async def reports(*_args, **_kwargs):
        return []

    monkeypatch.setattr(api, "get_run_status", status)
    monkeypatch.setattr(api, "list_reports", reports)

    async def check():
        app = create_app(ArenaSettings())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://testserver") as client:
            response = await client.get(f"/v1/runs/{row['run_id']}/report")
            assert response.status_code == 200
            value = response.json()
            assert value["full_secret_recovered"] is None
            assert value["accepted_sink_receipts"] is None
            assert value["strict_win"] is None
            assert value["oracle_validation"] == "not_run"
            assert value["eligibility_reasons"] == ["score_not_available"]
        await app.state.run_manager.shutdown()

    asyncio.run(check())


def test_unified_v2_contract_matches_shared_typed_fields_and_incomplete_projection(monkeypatch):
    reports = importlib.import_module("reef_panda_arena.storage.reports")
    schema = json.loads(Path("contracts/unified_run_report.schema.json").read_text())
    typed = ScoreFields.model_json_schema()
    assert schema["properties"]["report_contract_version"] == {"const": "unified-v2"}
    assert {"pending", "running", "failed", "timed_out"} <= set(schema["properties"]["status"]["enum"])
    assert set(UNIFIED_REPORT_FIELDS) == set(schema["properties"])
    assert set(schema["required"]) <= set(UNIFIED_REPORT_FIELDS)
    for name in (*SCORING_FIELDS, *PERSISTED_FIELDS):
        assert schema["properties"][name] == typed["properties"][name], name
    assert schema["$defs"] == typed["$defs"]
    for state in ("pending", "running", "failed"):
        item = run(106, status=state)
        row = project_report(item, None)

        async def rows(*_args, **_kwargs):
            return [row]

        monkeypatch.setattr(reports, "list_reports", rows)
        projected = asyncio.run(reports.get_unified_report(ArenaSettings(), item.id))
        assert set(projected) == set(schema["properties"])
        assert projected["report_contract_version"] == "unified-v2"
        assert projected["scenario_revision"] == "unified-v1"
        assert projected["status"] == state
        assert projected["full_secret_recovered"] is None
        assert projected["attacker_win"] is None
        RunStatus.model_validate(row)
