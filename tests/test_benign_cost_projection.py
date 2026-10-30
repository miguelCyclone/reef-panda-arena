"""Public costs share bounded evidence and preserve unknown denominators."""

import asyncio
from copy import deepcopy
import csv
import importlib
import io
import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from reef_panda_arena.api.app import RunStatus, create_app
from reef_panda_arena.api.scoring_contract import ScoreFields
from reef_panda_arena.application.benign_cost import measure_benign_cost
from reef_panda_arena.application.benign_cost_contract import BenignCost, project_benign_cost
from reef_panda_arena.application.scoring import SCORING_VERSION
from reef_panda_arena.cli.main import _export_csv
from reef_panda_arena.gateway.observer import ContentObserver
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.report_projection import project_report
from test_benign_cost import contract
from test_utility_integrity import task
from test_utility_projection import run, score


@pytest.fixture
def measured():
    async def actual():
        work = await task("C13", profile="taint")
        work.gateway.observer = ContentObserver()
        for call in work.calls:
            await work.send(call, approved=False)
        return measure_benign_cost(work.gateway, contract(work), status="completed")
    return asyncio.run(actual())


def test_projection_preserves_actual_denominators_and_removes_stale_completed_runs(measured):
    good = BenignCost.model_validate(measured).model_dump()
    assert good == measured
    current = run()
    saved = score(current, {"scoring": {"scoring_version": SCORING_VERSION, "benign_cost": measured}})
    assert project_report(current, saved)["benign_cost"] == measured
    current.status = "failed"
    assert project_report(current, saved)["benign_cost"] is None
    current.stage_snapshot_json = deepcopy(saved.details_json)
    failed = project_report(current, saved)["benign_cost"]
    assert failed["eligible_actions"] == measured["eligible_actions"]
    assert failed["policy_false_blocks"] == measured["policy_false_blocks"]
    assert failed["eligible_runs"] == failed["observer_eligible_runs"] == failed["policy_eligible_runs"] == 0
    assert failed["observer_measurement"] == failed["policy_measurement"] == "partial"
    assert BenignCost.model_validate(failed)
    assert project_benign_cost(None, status="completed") is None


def test_private_malformed_or_inconsistent_costs_are_not_exported(measured):
    corruptions = [
        ("version", "PRIVATE"), ("eligible_actions", True), ("policy_decisions", 41),
        ("policy_false_blocks", 0), ("observer_false_alert_rate", 0),
        ("observer_measurement", "not_measured"), ("reason", "PRIVATE"),
        ("actions", measured["actions"] * 2), ("shape_matched", []),
        ("private_proposal", "PRIVATE"),
    ]
    for field, value in corruptions:
        bad = {**measured, field: value}
        assert project_benign_cost(bad, status="completed") is None, field
        with pytest.raises(ValidationError):
            ScoreFields.model_validate({"benign_cost": bad})
    for field, value in (("actor_id", "PRIVATE"), ("source_event_seqs", [256]),
                         ("observer_alert", None), ("policy_measured", False)):
        bad = deepcopy(measured)
        bad["actions"][0][field] = value
        assert project_benign_cost(bad, status="completed") is None


def test_api_status_csv_and_unified_contract_share_exact_costs(measured, monkeypatch, capsys):
    api = importlib.import_module("reef_panda_arena.api.app")
    cli = importlib.import_module("reef_panda_arena.cli.main")
    reports = importlib.import_module("reef_panda_arena.storage.reports")
    current = run()
    row = project_report(current, score(current, {}))
    row["benign_cost"] = measured
    assert RunStatus.model_validate(row).model_dump()["benign_cost"] == measured
    schema = json.loads(Path("contracts/unified_run_report.schema.json").read_text())
    assert schema["properties"]["benign_cost"] == ScoreFields.model_json_schema()["properties"]["benign_cost"]
    assert "benign_cost" in schema["required"]

    async def status(*_args):
        return row

    async def listed(*_args, **_kwargs):
        return [row]

    async def rows(*_args):
        yield row

    monkeypatch.setattr(api, "get_run_status", status)
    monkeypatch.setattr(api, "list_reports", listed)
    monkeypatch.setattr(reports, "list_reports", listed)
    monkeypatch.setattr(cli, "iter_reports", rows)

    async def check():
        app = create_app(ArenaSettings())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            for suffix in ("", "/report"):
                response = await client.get(f"/v1/runs/{row['run_id']}{suffix}")
                assert response.status_code == 200
                assert response.json()["benign_cost"] == measured
        unified = await reports.get_unified_report(ArenaSettings(), row["run_id"])
        assert unified["benign_cost"] == measured
        await app.state.run_manager.shutdown()
    asyncio.run(check())
    asyncio.run(_export_csv(ArenaSettings(), None))
    exported = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert json.loads(exported[0]["benign_cost"]) == measured
