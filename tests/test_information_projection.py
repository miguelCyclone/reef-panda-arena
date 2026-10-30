"""Public information evidence survives exports without exporting source values."""

import asyncio
from copy import deepcopy
import csv
import importlib
import io
import json

import httpx
import pytest
from pydantic import ValidationError

from reef_panda_arena.api.app import RunStatus, create_app
from reef_panda_arena.api.scoring_contract import ScoreFields
from reef_panda_arena.application.information_contract import project_information
from reef_panda_arena.application.scoring import SCORING_VERSION
from reef_panda_arena.cli.main import _export_csv
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.report_projection import project_report
from test_information import CODE, artifact, information
from test_utility_projection import run, score


@pytest.fixture
def measured():
    return information("C40", CODE, [artifact(7, b"Account code prefix SY")])


def test_absent_historical_and_stale_failure_information_remains_unknown(measured):
    current = run()
    assert project_report(current, score(current, {"observed_partial_bits": 41}))["information"] is None
    saved = score(current, {"scoring": {"scoring_version": SCORING_VERSION, "information": measured}})
    assert project_report(current, saved)["information"] == measured
    current.status = "failed"
    assert project_report(current, saved)["information"] is None
    current.stage_snapshot_json = deepcopy(saved.details_json)
    failed = project_report(current, saved)["information"]
    assert failed["measurement_status"] == "partial_run" and failed["full_reconstruction"] is None
    assert failed["recovery_state"] == "partial" and failed["recovered_reference_units"] == 2


def test_private_unbounded_or_contradictory_information_is_not_exported(measured):
    bad_values = [
        ("private_prefix", "PRIVATE"), ("version", "PRIVATE"), ("attacker_knowledge", "PRIVATE"),
        ("accepted_artifacts", True), ("accepted_artifacts", 101), ("evidence_event_seqs", [7, 7]),
        ("reference_domain_bound_bits", 64.), ("recovered_reference_units", 9),
        ("uniform_model_recovered_bits", float("nan")), ("secret_entropy_bits", 10.),
        ("incremental_information_bits", 10.), ("declared_channel_capacity_bits", 64.),
        ("recovery_state", "full"), ("full_reconstruction", True), ("recovery_artifact_bytes", 1000),
    ]
    for name, value in bad_values:
        bad = {**measured, name: value}
        assert project_information(bad, status="completed") is None, name
        with pytest.raises(ValidationError):
            ScoreFields.model_validate({"information": bad})


def test_information_is_identical_in_status_api_report_unified_and_csv(measured, monkeypatch, capsys):
    api = importlib.import_module("reef_panda_arena.api.app")
    cli = importlib.import_module("reef_panda_arena.cli.main")
    reports = importlib.import_module("reef_panda_arena.storage.reports")
    current = run()
    row = project_report(current, score(current, {"scoring": {"scoring_version": SCORING_VERSION, "information": measured}}))
    # Other fields use a complete historical projection; only information is under test.
    row = {**project_report(current, score(current, {})), "information": row["information"]}
    assert RunStatus.model_validate(row).model_dump()["information"] == measured

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
                assert response.json()["information"] == measured
        unified = await reports.get_unified_report(ArenaSettings(), row["run_id"])
        assert unified["information"] == measured
        await app.state.run_manager.shutdown()
    asyncio.run(check())
    asyncio.run(_export_csv(ArenaSettings(), None))
    exported = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert json.loads(exported[0]["information"]) == measured
    assert CODE.decode() not in json.dumps(row)
