"""Independent request evidence remains bounded and survives real MySQL exports."""

import asyncio
from copy import deepcopy
import csv
import io
import json
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.api.app import create_app
from reef_panda_arena.api.scoring_contract import ScoreFields
from reef_panda_arena.application.live_execution import LiveExecution
from reef_panda_arena.application.live_execution_contract import project_live_execution
from reef_panda_arena.application.unified import run_unified_live
from reef_panda_arena.cli.main import _export_csv
from reef_panda_arena.model.ollama import ModelTimedOut
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun
from reef_panda_arena.storage.report_projection import project_report
from reef_panda_arena.storage.reports import get_unified_report, list_reports
from test_live_workflow import WorkingRole
from test_role_decisions import CONFIG
from test_utility_projection import run, score


def evidence():
    value = LiveExecution(CONFIG, ollama_url="http://127.0.0.1:11434").evidence()
    value.update(measurement_status="complete", total_model_calls=1, model_refusals=1,
        requests=[dict(actor_id="A2", prompt_version="independent-role-v1", compromised=False,
            outcome="refuse", input_event_seqs=[1], decision_turn=1, tokens_in=10, tokens_out=5, prior_gateway_feedback=[],
            proposal_fingerprint="a" * 64, rejection_reason=None, actions=[])])
    return value


def test_live_projection_rejects_private_fields_and_inconsistent_request_evidence():
    measured = evidence()
    corruptions = [
        ("raw_prompt", "PRIVATE"), ("model_backend", "PRIVATE"), ("total_model_calls", True),
        ("total_model_calls", 0), ("model_refusals", 0), ("requests", measured["requests"] * 2),
    ]
    for field, value in corruptions:
        bad = {**measured, field: value}
        assert project_live_execution(bad, status="completed") is None
        with pytest.raises(ValidationError):
            ScoreFields.model_validate({"live_execution": bad})
    for field, value in (("actor_id", "PRIVATE"), ("tokens_in", -1), ("tokens_out", True),
                         ("input_event_seqs", [257]), ("decision_turn", 2),
                         ("outcome", "request_failed"), ("raw_response", "PRIVATE")):
        bad = deepcopy(measured)
        bad["requests"][0][field] = value
        assert project_live_execution(bad, status="completed") is None


def test_live_projection_does_not_invent_historical_or_reuse_stale_completed_evidence():
    measured = evidence()
    current = run()
    assert project_report(current, score(current, {}))["live_execution"] is None
    saved = score(current, {"live_execution": measured})
    assert project_report(current, saved)["live_execution"] == measured
    current.status = "timed_out"
    assert project_report(current, saved)["live_execution"] is None
    current.stage_snapshot_json = {"live_execution": measured}
    failed = project_report(current, saved)["live_execution"]
    assert failed == {**measured, "measurement_status": "partial_run"}
    assert measured["measurement_status"] == "complete"


@pytest.mark.parametrize("timeout", [False, True])
def test_mysql_independent_execution_survives_status_report_unified_and_csv(timeout, capsys):
    if os.getenv("ARENA_TEST_MYSQL") != "1":
        pytest.skip("Set ARENA_TEST_MYSQL=1 for independent execution persistence")

    class LastRoleFailure(WorkingRole):
        async def complete(self, request):
            if self.actor == "A9":
                raise ModelTimedOut("Controlled final request timeout")
            return await super().complete(request)

    async def verify():
        settings, identifier = ArenaSettings(), str(uuid4())
        engine = create_async_engine(settings.sqlalchemy_url)
        app = create_app(settings)
        try:
            async def execute():
                return await run_unified_live("C29", "transitive", 31, settings=settings,
                    run_id=identifier, attack_enabled=False, model_name="controlled-independent-role",
                    caller_factory=LastRoleFailure if timeout else WorkingRole)
            if timeout:
                with pytest.raises(ModelTimedOut):
                    await execute()
            else:
                await execute()
            # These readers create new sessions after the controller disposed its engine.
            row = (await list_reports(settings, identifier, limit=1))[0]
            measured = row["live_execution"]
            assert row["mode"] == "live_multiagent"
            assert row["status"] == ("timed_out" if timeout else "completed")
            assert row["benign_task_success"] is (None if timeout else True)
            assert row["strict_win"] is None
            assert measured["measurement_status"] == ("partial_run" if timeout else "complete")
            assert measured["model_backend"] == "injected_caller" and measured["total_model_calls"] == 10
            assert measured["requests"][-1]["outcome"] == ("request_failed" if timeout else "act")
            assert row["persisted_accepted_sink_receipts"] == row["accepted_sink_receipts"] == (0 if timeout else 2)
            unified = await get_unified_report(settings, identifier)
            assert unified["live_execution"] == measured
            assert unified["notes"][0] == "Controlled injected role callers; not an Ollama experiment."
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                for suffix in ("", "/report", "/unified-report"):
                    response = await client.get(f"/v1/runs/{identifier}{suffix}")
                    assert response.status_code == 200, response.text
                    assert response.json()["live_execution"] == measured
            await _export_csv(settings, identifier)
            exported = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
            assert len(exported) == 1 and json.loads(exported[0]["live_execution"]) == measured
            schema = json.loads(Path("contracts/unified_run_report.schema.json").read_text())
            assert "live_execution" in schema["required"]
            assert schema["properties"]["live_execution"] == ScoreFields.model_json_schema()["properties"]["live_execution"]
            assert schema["$defs"]["LiveExecutionEvidence"] == ScoreFields.model_json_schema()["$defs"]["LiveExecutionEvidence"]
        finally:
            await app.state.run_manager.shutdown()
            async with async_sessionmaker(engine)() as session, session.begin():
                await session.execute(delete(ArenaRun).where(ArenaRun.id == identifier))
            await engine.dispose()
    asyncio.run(verify())
