"""API admission rejects overlaps and surfaces refused starts promptly."""

import asyncio

import httpx
import pytest

from reef_panda_arena.api import manager as manager_module
from reef_panda_arena.api.app import create_app
from reef_panda_arena.application.admission import RunAdmissionBusy
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.telemetry.events import lifecycle_event


def configuration():
    return ArenaSettings(_env_file=None, database_url="mysql+asyncmy://test:test@localhost/test",
                         database_socket=None, max_concurrent_runs=4, audit_mode=True)


def test_api_audit_mode_rejects_cross_family_overlap_and_reuses_slot_after_cancel(monkeypatch):
    async def verify():
        config = configuration()
        manager = manager_module.RunManager(config)
        assert manager.max_concurrent == 1

        async def held_run(*args, run_id, on_event, **kwargs):
            on_event(lifecycle_event(run_id, 0, "run.started"))
            await asyncio.Future()

        async def started_row(*args):
            return {"status": "running"}

        monkeypatch.setattr(manager_module, "run_replay", held_run)
        monkeypatch.setattr(manager_module, "get_run_status", started_row)
        app = create_app(config, manager)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://testserver") as client:
            request = {"scenario_id": "C00", "mode": "replay", "defense_profile": "none", "seed": 31}
            first = await client.post("/v1/runs", json=request)
            assert first.status_code == 202
            # This settings object has no sealing key: rejected requests must
            # validate only public seed metadata, without constructing targets.
            assert config.encryption_key_base64 is None
            for scenario_id, defense in (("C10", "taint"), ("C18", "none"),
                                         ("C23", "none"), ("C32", "transitive")):
                second = await client.post("/v1/runs", json={
                    **request, "scenario_id": scenario_id, "defense_profile": defense,
                })
                assert second.status_code == 409
                assert second.json()["detail"] == "Concurrent audit run limit reached"
            assert len(manager._jobs) == 1
            assert await manager.cancel(first.json()["run_id"])
            assert manager._jobs == {}
            third = await client.post("/v1/runs", json=request)
            assert third.status_code == 202
        await manager.shutdown()
        assert manager._jobs == {}

    asyncio.run(verify())


def test_api_refused_database_admission_preserves_safe_reason_without_status_query(monkeypatch):
    async def verify():
        config = configuration()
        manager = manager_module.RunManager(config)

        async def rejected_run(*args, **kwargs):
            raise RunAdmissionBusy("Concurrent audit run limit reached")

        async def forbidden_query(*args):
            pytest.fail("Refused admission must be reported before querying a nonexistent run")

        monkeypatch.setattr(manager_module, "run_replay", rejected_run)
        monkeypatch.setattr(manager_module, "get_run_status", forbidden_query)
        app = create_app(config, manager)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://testserver") as client:
            response = await asyncio.wait_for(client.post("/v1/runs", json={
                "scenario_id": "C00", "mode": "replay", "defense_profile": "none", "seed": 31,
            }), timeout=1)
        assert response.status_code == 409
        assert response.json()["detail"] == "Concurrent audit run limit reached"
        assert manager._jobs == {}
        await manager.shutdown()

    asyncio.run(verify())
