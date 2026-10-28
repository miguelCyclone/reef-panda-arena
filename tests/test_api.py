"""API run lifecycle and SSE timing without database polling or real sleeps."""

import asyncio
import os

import httpx
import pytest

from reef_panda_arena.api.app import create_app
from reef_panda_arena.api.manager import RunManager
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.telemetry.broadcast import SSEBroadcaster


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


def test_sse_push_and_idle_cutoff() -> None:
    async def verify() -> None:
        clock = FakeClock()
        broadcaster = SSEBroadcaster(clock=clock)
        subscriber = broadcaster.subscribe("run-1")
        broadcaster.publish("run-1", {"id": 1, "event": "tool.proposed", "data": {}})
        kind, event = await broadcaster.next_event(subscriber)
        assert kind == "event" and event["id"] == 1
        clock.now = 300.0
        kind, event = await broadcaster.next_event(subscriber)
        assert kind == "closed" and event is None
        assert broadcaster._subscribers == {}
        assert broadcaster.heartbeat_seconds >= 30

    asyncio.run(verify())


def test_api_replay_status_history_and_report() -> None:
    if os.getenv("ARENA_TEST_MYSQL") != "1":
        pytest.skip("Set ARENA_TEST_MYSQL=1 to test API persistence")

    async def verify() -> None:
        settings = ArenaSettings()
        manager = RunManager(settings)
        app = create_app(settings, manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            assert (await client.get("/health")).json() == {"status": "ok"}
            scenarios = (await client.get("/v1/scenarios")).json()
            assert len(scenarios) == 10
            assert scenarios[1]["available_modes"] == ["replay"]
            created = await client.post("/v1/runs", json={
                "scenario_id": "C00", "mode": "replay", "defense_profile": "content",
                "seed": 101, "attack_enabled": True,
            })
            assert created.status_code == 202
            run_id = created.json()["run_id"]
            job = manager._jobs.get(run_id)
            if job is not None and job.task is not None:
                await job.task
            status = (await client.get(f"/v1/runs/{run_id}")).json()
            assert status["status"] == "completed"
            assert status["secret_escaped"] is False
            assert status["benign_task_success"] is True
            history = (await client.get(f"/v1/runs/{run_id}/events")).json()["events"]
            assert history[0]["event"] == "run.started"
            assert history[-1]["event"] == "run.completed"
            assert any(event["data"]["policy_decision"] == "block" for event in history)
            report = (await client.get(f"/v1/runs/{run_id}/report")).json()
            assert report["secret_escaped"] is False
            stream = await client.get(f"/v1/runs/{run_id}/stream")
            assert "event: run.completed" in stream.text
            assert "retry: 30000" in stream.text
            assert (await client.get("/v1/runs/00000000-0000-0000-0000-000000000000")).status_code == 404
        await manager.shutdown()

    asyncio.run(verify())
