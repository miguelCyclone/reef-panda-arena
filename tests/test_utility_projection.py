"""R09 public utility evidence is finite, nullable, and consistent across exports."""

import asyncio
import csv
import importlib
import io
import json
from pathlib import Path
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

from reef_panda_arena.api.app import RunStatus, create_app
from reef_panda_arena.api.scoring_contract import ScoreFields
from reef_panda_arena.application.utility_contract import UTILITY_FIELDS
from reef_panda_arena.cli.main import _export_csv
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, RunScore
from reef_panda_arena.storage.report_projection import project_report
from reef_panda_arena.storage.reports import REPORT_COLUMNS, UNIFIED_REPORT_FIELDS


def metadata():
    return {
        "utility_version": "unified-utility-v2", "utility_scope": "same_reader_scripted",
        "task_mechanism": "scripted_computation", "task_actor": "A2",
        "task_model_calls": 0, "task_prompt_version": None,
        "same_reader_utility": True, "utility_reason": "verified_same_reader_task",
        "contribution_verified": True, "customer_sequence_consistent": True,
        "required_action_count": 2, "accepted_required_count": 2,
        "utility_required_event_seqs": [8, 12], "utility_source_event_seqs": [2, 3],
        "utility_release_event_seqs": [5, 10], "utility_evidence_event_seqs": None,
        "utility_required_components": None, "utility_satisfied_components": None,
    }


def run(*, status="completed", snapshot=None):
    return ArenaRun(id=str(UUID(int=909)), scenario_id="C32", scenario_revision="unified-v1",
                    mode="replay", defense_profile="scoped_release", seed=31, status=status,
                    prompt_version="unified-replay-v2", stage_snapshot_json=snapshot or {})


def score(current, details):
    return RunScore(run_id=current.id, attacker_attempted=True, secret_escaped=False,
                    benign_task_success=True, blocked_attempts=0, accepted_outbound_events=2,
                    run_duration_ms=1, oracle_version="unified-v1", details_json=details)


def utility(row):
    return {name: row[name] for name in UTILITY_FIELDS}


def test_historical_utility_is_unknown_and_new_receiver_versions_are_independent():
    current = run()
    row = project_report(current, score(current, {"same_reader_utility": True}))
    assert utility(row) == dict.fromkeys(UTILITY_FIELDS)
    for scenario, version in (("C13", "sensitive-v3"), ("C17", "extension-v2")):
        current.scenario_id = scenario
        saved = score(current, {})
        saved.oracle_version = version
        saved.secret_escaped = True
        row = project_report(current, saved)
        assert row["oracle_validation"] == "independent"
        assert row["full_secret_recovered"] is True


def test_completed_utility_preserves_measured_false_zero_and_explicit_null():
    current = run(snapshot=metadata())
    updates = {"same_reader_utility": False, "accepted_required_count": 0,
               "contribution_verified": None, "utility_required_event_seqs": []}
    row = project_report(current, score(current, updates))
    assert utility(row) == {**metadata(), **updates}
    assert utility(ScoreFields.model_validate(row).model_dump()) == utility(row)


def test_failed_snapshot_keeps_declarations_without_stale_verdict_or_evidence():
    initial = {"utility_version": "unified-utility-v2", "utility_scope": "same_reader_scripted",
               "task_mechanism": "scripted_computation", "task_actor": "A2",
               "required_action_count": 2}
    current = run(status="timed_out", snapshot=initial)
    row = project_report(current, score(current, metadata()))
    assert all(row[name] == value for name, value in initial.items())
    for name in set(UTILITY_FIELDS) - set(initial):
        assert row[name] is None, name
    assert row["benign_task_success"] is None
    for name in ("same_reader_utility", "contribution_verified", "customer_sequence_consistent"):
        current.stage_snapshot_json = {**initial, name: True}
        assert project_report(current, None)[name] is None


def test_legacy_writer_cannot_claim_same_reader_utility():
    current = run()
    details = {**metadata(), "utility_version": "legacy-safe-writer-v1",
               "utility_scope": "legacy_safe_writer", "task_mechanism": "trusted_formatter",
               "task_actor": "response_writer"}
    row = project_report(current, score(current, details))
    assert row["benign_task_success"] is True
    assert row["utility_scope"] == "legacy_safe_writer"
    assert row["same_reader_utility"] is None
    assert row["contribution_verified"] is None


def test_private_or_malformed_fields_never_enter_public_utility_projection():
    current = run()
    for name in UTILITY_FIELDS:
        row = project_report(current, score(current, {**metadata(), name: "PRIVATE-MARKER"}))
        assert row[name] is None
        assert "PRIVATE-MARKER" not in json.dumps(row)
    for name, bad in (("task_model_calls", True), ("task_model_calls", 25),
                      ("required_action_count", 41), ("utility_required_event_seqs", [1, 1]),
                      ("utility_required_event_seqs", [257]),
                      ("utility_required_event_seqs", [True]),
                      ("utility_required_components", ["raw_source_proof"]),
                      ("utility_satisfied_components", ["peer_read", "peer_read"])):
        assert project_report(current, score(current, {**metadata(), name: bad}))[name] is None
    row = project_report(current, score(current, {**metadata(), "accepted_required_count": 3}))
    assert row["accepted_required_count"] is None


@pytest.mark.parametrize("name,bad", [
    ("utility_version", "private-v1"), ("utility_reason", "PRIVATE-MARKER"),
    ("task_actor", "attacker-supplied-actor"), ("task_prompt_version", "private-prompt"),
    ("same_reader_utility", 1), ("task_model_calls", True),
    ("accepted_required_count", "2"), ("required_action_count", 41),
    ("utility_required_event_seqs", [1, 1]), ("utility_release_event_seqs", [0]),
    ("utility_required_components", ["raw_source_proof"]),
])
def test_api_rejects_coercion_private_values_and_unbounded_evidence(name, bad):
    with pytest.raises(ValidationError):
        ScoreFields.model_validate({**metadata(), name: bad})


def test_schema_unified_report_and_typed_status_share_nullable_utility_fields(monkeypatch):
    reports = importlib.import_module("reef_panda_arena.storage.reports")
    schema = json.loads(Path("contracts/unified_run_report.schema.json").read_text())
    typed = ScoreFields.model_json_schema()
    assert set(UTILITY_FIELDS) <= set(REPORT_COLUMNS) & set(UNIFIED_REPORT_FIELDS)
    assert set(UTILITY_FIELDS) <= set(schema["required"])
    for name in UTILITY_FIELDS:
        assert schema["properties"][name] == typed["properties"][name], name
    current = run()
    row = project_report(current, score(current, metadata()))

    async def rows(*_args, **_kwargs):
        return [row]

    monkeypatch.setattr(reports, "list_reports", rows)
    projected = asyncio.run(reports.get_unified_report(ArenaSettings(), row["run_id"]))
    assert utility(projected) == metadata()
    assert set(projected) == set(schema["properties"])
    assert utility(RunStatus.model_validate(row).model_dump()) == metadata()


def test_api_status_report_and_csv_share_utility_including_failed_nulls(monkeypatch, capsys):
    api = importlib.import_module("reef_panda_arena.api.app")
    cli = importlib.import_module("reef_panda_arena.cli.main")
    current = run()
    row = project_report(current, score(current, metadata()))
    failed = run(status="failed", snapshot={"utility_version": "unified-utility-v2"})
    failed_row = project_report(failed, score(failed, metadata()))

    async def status(*_args):
        return row

    async def reports(*_args, **_kwargs):
        return [row]

    async def csv_rows(*_args):
        for item in (row, failed_row):
            yield item

    monkeypatch.setattr(api, "get_run_status", status)
    monkeypatch.setattr(api, "list_reports", reports)
    monkeypatch.setattr(cli, "iter_reports", csv_rows)

    async def check():
        app = create_app(ArenaSettings())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://testserver") as client:
            for expected in (metadata(), utility(failed_row)):
                for path in (f"/v1/runs/{row['run_id']}", f"/v1/runs/{row['run_id']}/report"):
                    response = await client.get(path)
                    assert response.status_code == 200
                    assert utility(response.json()) == expected
                row.update(failed_row)
        await app.state.run_manager.shutdown()

    asyncio.run(check())
    row.update(project_report(current, score(current, metadata())))
    asyncio.run(_export_csv(ArenaSettings(), None))
    exported = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert exported[0]["same_reader_utility"] == "True"
    assert exported[0]["task_model_calls"] == "0"
    assert json.loads(exported[0]["utility_required_event_seqs"]) == [8, 12]
    assert exported[1]["same_reader_utility"] == ""
    assert exported[1]["accepted_required_count"] == ""
    assert exported[1]["utility_required_event_seqs"] == ""
