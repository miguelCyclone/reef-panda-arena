"""R07 public knowledge metadata survives reports without inventing history."""

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
from reef_panda_arena.application.knowledge import KNOWLEDGE_FIELDS, knowledge_metadata
from reef_panda_arena.cli.main import _export_csv
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, RunScore
from reef_panda_arena.storage.report_projection import project_report
from reef_panda_arena.storage.reports import REPORT_COLUMNS, UNIFIED_REPORT_FIELDS


def declared(mode="key_derived_unknown"):
    return knowledge_metadata(
        "C32", mode, "a" * 64, defense_profile="content_only",
        observer_profile="literal_content",
    )


def make_run(*, status="failed", snapshot=None):
    return ArenaRun(
        id=str(UUID(int=707)), scenario_id="C32", scenario_revision="unified-v1",
        mode="replay", defense_profile="content_only", model_name=None,
        model_temperature=None, prompt_version="test", seed=31, status=status,
        failure_code="model_timed_out" if status == "failed" else None,
        stage_snapshot_json=snapshot or {},
    )


def make_score(run, details):
    return RunScore(
        run_id=run.id, attacker_attempted=True, secret_escaped=False,
        benign_task_success=True, blocked_attempts=0, accepted_outbound_events=0,
        run_duration_ms=5, oracle_version="unified-v1", details_json=details,
    )


def only_knowledge(row):
    return {name: row[name] for name in KNOWLEDGE_FIELDS}


def test_historical_metadata_stays_unknown_without_rewriting_legacy_hash():
    run = make_run(status="completed")
    details = {"fixture_hash": "legacy-hmac-value", "fixture_mode": "key_derived_unknown"}
    row = project_report(run, make_score(run, details))
    assert only_knowledge(row) == dict.fromkeys(KNOWLEDGE_FIELDS)
    assert row["fixture_hash"] == "legacy-hmac-value"
    assert only_knowledge(ScoreFields.model_validate(row).model_dump()) == dict.fromkeys(KNOWLEDGE_FIELDS)


def test_scoreless_failure_preserves_initial_access_contract_and_unmeasured_score():
    metadata = declared()
    run = make_run(snapshot=metadata)
    row = project_report(run, None)
    assert only_knowledge(row) == metadata
    assert row["full_secret_recovered"] is None
    assert row["strict_win"] is None
    assert row["scorable_completed"] is False
    # A stale result cannot relabel an incomplete run's original fixture mode.
    stale = make_score(run, declared("public_transport_control"))
    assert only_knowledge(project_report(run, stale)) == metadata


def test_completed_details_fallback_preserves_explicit_null_and_false():
    run = make_run(status="completed", snapshot=declared())
    details = {"policy_known_target": None, "decoder_convention_public": False}
    row = project_report(run, make_score(run, details))
    expected = {**declared(), **details}
    assert only_knowledge(row) == expected
    assert only_knowledge(ScoreFields.model_validate(row).model_dump()) == expected


def test_projection_drops_unrecognized_or_private_metadata_values():
    metadata = declared()
    for field in KNOWLEDGE_FIELDS:
        malicious = {**metadata, field: "PRIVATE-TARGET-SHOULD-NOT-BE-EXPORTED"}
        row = project_report(make_run(snapshot=malicious), None)
        if field == "knowledge_contract_version":
            assert only_knowledge(row) == dict.fromkeys(KNOWLEDGE_FIELDS)
        else:
            assert row[field] is None
        assert "PRIVATE-TARGET" not in json.dumps(row)
    for value in (1, "true", [], {}):
        row = project_report(make_run(snapshot={**metadata, "decoder_convention_public": value}), None)
        assert row["decoder_convention_public"] is None
    malformed = {**metadata, "fixture_template_digest": "A" * 64}
    assert project_report(make_run(snapshot=malformed), None)["fixture_template_digest"] is None


@pytest.mark.parametrize("name,value", [
    ("fixture_mode", "custom_mode"),
    ("knowledge_contract_version", "knowledge-v2"),
    ("fixture_derivation_version", "unreviewed-v1"),
    ("policy_knowledge", 1),
    ("policy_known_target", "PRIVATE-TARGET"),
    ("fixture_template_digest", "not-a-template-hash"),
    ("decoder_convention_public", "true"),
    ("decoder_convention_public", 1),
])
def test_api_metadata_types_reject_coercion_and_unrecognized_values(name, value):
    with pytest.raises(ValidationError):
        ScoreFields.model_validate({**declared(), name: value})
    assert getattr(ScoreFields.model_validate({**declared(), name: None}), name) is None


def test_json_schema_and_unified_projection_expose_exact_nullable_metadata(monkeypatch):
    reports = importlib.import_module("reef_panda_arena.storage.reports")
    schema = json.loads(Path("contracts/unified_run_report.schema.json").read_text())
    typed = ScoreFields.model_json_schema()
    assert set(KNOWLEDGE_FIELDS) <= set(REPORT_COLUMNS) & set(UNIFIED_REPORT_FIELDS)
    assert set(KNOWLEDGE_FIELDS) <= set(schema["required"])
    for name in KNOWLEDGE_FIELDS:
        assert schema["properties"][name] == typed["properties"][name], name
    assert "null" in schema["properties"]["fixture_hash"]["type"]
    row = project_report(make_run(snapshot=declared()), None)

    async def rows(*_args, **_kwargs):
        return [row]

    monkeypatch.setattr(reports, "list_reports", rows)
    projected = asyncio.run(reports.get_unified_report(ArenaSettings(), row["run_id"]))
    assert only_knowledge(projected) == declared()
    assert projected["fixture_hash"] is None
    assert set(projected) == set(schema["properties"])
    assert only_knowledge(RunStatus.model_validate(row).model_dump()) == declared()


def test_http_status_report_and_csv_keep_the_same_declared_contract(monkeypatch, capsys):
    api = importlib.import_module("reef_panda_arena.api.app")
    cli = importlib.import_module("reef_panda_arena.cli.main")
    row = project_report(make_run(snapshot=declared("public_transport_control")), None)
    historic = project_report(make_run(status="completed"), None)

    async def status(*_args):
        return row

    async def reports(*_args, **_kwargs):
        return [row]

    async def csv_rows(*_args):
        for current in (row, historic):
            yield current

    monkeypatch.setattr(api, "get_run_status", status)
    monkeypatch.setattr(api, "list_reports", reports)
    monkeypatch.setattr(cli, "iter_reports", csv_rows)

    async def check():
        app = create_app(ArenaSettings())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://testserver") as client:
            current = await client.get(f"/v1/runs/{row['run_id']}")
            report = await client.get(f"/v1/runs/{row['run_id']}/report")
            assert current.status_code == report.status_code == 200
            assert only_knowledge(current.json()) == only_knowledge(report.json()) == only_knowledge(row)
        await app.state.run_manager.shutdown()

    asyncio.run(check())
    asyncio.run(_export_csv(ArenaSettings(), None))
    exported = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert len(exported) == 2
    assert exported[0]["fixture_mode"] == "public_transport_control"
    assert exported[0]["policy_knowledge"] == "authenticated_source_content"
    assert exported[0]["decoder_convention_public"] == "True"
    assert all(exported[1][name] == "" for name in KNOWLEDGE_FIELDS)
