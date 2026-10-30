"""Independent mode dispatch, live snapshots, cancellation and admission."""

import asyncio
import importlib
import os
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.api.app import create_app
from reef_panda_arena.api.manager import RunManager
from reef_panda_arena.application import unified
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun
from test_live_workflow import WorkingRole


def test_cli_dispatches_independent_model_configuration_and_rejects_incompatible_options(monkeypatch, capsys):
    cli = importlib.import_module("reef_panda_arena.cli.main")
    invoked = []
    async def runner(*args, **kwargs):
        invoked.append((args, kwargs))
        return SimpleNamespace(run_id="controlled-run")
    async def listed(*args, **kwargs):
        return [{"run_id": "controlled-run", "mode": "live_multiagent"}]
    monkeypatch.setattr(unified, "run_unified_live", runner)
    monkeypatch.setattr(cli, "list_reports", listed)
    monkeypatch.setattr("sys.argv", ["reef-panda-arena", "run", "C31", "--mode", "live_multiagent",
        "--model", "controlled-role", "--temperature", "0.25", "--top-p", "0.8", "--generation-seed", "7", "--no-attack"])
    cli.main()
    assert invoked == [(("C31", "transitive", 1), {"attack_enabled": False, "observer_profile": "metadata_schema",
        "model_name": "controlled-role", "temperature": 0.25, "top_p": 0.8, "generation_seed": 7})]
    assert '"mode": "live_multiagent"' in capsys.readouterr().out
    for args in (["C00", "--mode", "live_multiagent"], ["C31", "--mode", "live_multiagent", "--arm", "A1"],
                 ["C31", "--mode", "live_multiagent", "--rounds", "2"], ["C31", "--mode", "replay", "--top-p", "0.5"]):
        monkeypatch.setattr("sys.argv", ["reef-panda-arena", "run", *args])
        with pytest.raises(SystemExit) as result:
            cli.main()
        assert result.value.code == 1
    assert len(invoked) == 1


def test_mysql_api_independent_mode_checkpoints_before_model_io_and_cancels_without_a_defense_win(monkeypatch):
    if os.getenv("ARENA_TEST_MYSQL") != "1":
        pytest.skip("Set ARENA_TEST_MYSQL=1 for independent API lifecycle")

    async def verify():
        entered = asyncio.Event()
        class HeldRole(WorkingRole):
            async def complete(self, request):
                if self.actor == "A9":
                    entered.set()
                    await asyncio.Future()
                return await super().complete(request)

        original = unified.run_unified_live
        configurations = []
        async def controlled(*args, **kwargs):
            configurations.append(kwargs.copy())
            return await original(*args, **kwargs, caller_factory=HeldRole)
        monkeypatch.setattr(unified, "run_unified_live", controlled)
        settings = ArenaSettings().model_copy(update={"audit_mode": True})
        manager = RunManager(settings)
        app = create_app(settings, manager)
        engine = create_async_engine(settings.sqlalchemy_url)
        identifier = None
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                request = {"scenario_id": "C31", "mode": "live_multiagent", "defense_profile": "transitive",
                    "seed": 31, "model_name": "controlled-role", "temperature": 0.2,
                    "top_p": 0.75, "generation_seed": 9, "attack_enabled": False}
                for changes in ({"scenario_id": "C00", "defense_profile": "none"}, {"arm": "A1"},
                                {"round_limit": 2}, {"top_p": 1.1}, {"generation_seed": -1}):
                    result = await client.post("/v1/runs", json={**request, **changes})
                    assert result.status_code == 422
                assert not configurations and not manager._jobs
                created = await client.post("/v1/runs", json=request)
                assert created.status_code == 202, created.text
                identifier = created.json()["run_id"]
                await asyncio.wait_for(entered.wait(), timeout=10)
                # A separate database session must see the in-flight request,
                # not just the initial empty snapshot or terminal score.
                running = (await client.get(f"/v1/runs/{identifier}")).json()
                evidence = running["live_execution"]
                assert running["status"] == "running" and running["mode"] == "live_multiagent"
                assert evidence["model_backend"] == "injected_caller"
                assert evidence["total_model_calls"] == 10
                assert evidence["requests"][-1]["outcome"] == "request_started"
                assert evidence["requests"][-1]["proposal_fingerprint"] is None
                assert all(action["state"] == "accepted" for item in evidence["requests"][:-1] for action in item["actions"])
                a2 = [item for item in evidence["requests"] if item["actor_id"] == "A2"]
                assert a2[1]["prior_gateway_feedback"] == ["accepted_by_local_gateway"]
                overlap = await client.post("/v1/runs", json={"scenario_id": "C00", "mode": "replay", "defense_profile": "none", "seed": 31})
                assert overlap.status_code == 409
                cancelled = await client.post(f"/v1/runs/{identifier}/cancel")
                assert cancelled.status_code == 200, cancelled.text
                row = cancelled.json()
                assert row["status"] == "cancelled" and row["strict_win"] is None
                assert row["compromised_roles"] == []
                assert row["benign_task_success"] is None
                assert row["live_execution"]["measurement_status"] == "partial_run"
                assert row["live_execution"]["requests"][-1]["rejection_reason"] == "model_request_failed"
                assert not manager._jobs
                assert configurations[0]["top_p"] == 0.75 and configurations[0]["generation_seed"] == 9
                assert row["model_top_p"] == 0.75 and row["model_generation_seed"] == 9
        finally:
            await manager.shutdown()
            if identifier is not None:
                async with async_sessionmaker(engine)() as session, session.begin():
                    await session.execute(delete(ArenaRun).where(ArenaRun.id == identifier))
            await engine.dispose()
    asyncio.run(verify())
