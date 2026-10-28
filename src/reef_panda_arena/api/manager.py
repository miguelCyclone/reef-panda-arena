"""Bounded in-process run jobs; MySQL remains the status system of record."""

import asyncio
from dataclasses import dataclass
from uuid import uuid4

from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.model.ollama import ModelUnavailable, OllamaCaller
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import RunEvent
from reef_panda_arena.storage.queries import get_run_status
from reef_panda_arena.telemetry.broadcast import SSEBroadcaster
from reef_panda_arena.telemetry.events import safe_event


@dataclass
class RunJob:
    run_id: str
    scenario_id: str
    mode: str
    defense_profile: str
    task: asyncio.Task | None = None
    ready: asyncio.Event | None = None


class RunManager:
    def __init__(self, settings: ArenaSettings,
                 broadcaster: SSEBroadcaster | None = None) -> None:
        self.settings = settings
        self.broadcaster = broadcaster or SSEBroadcaster()
        self.max_concurrent = settings.max_concurrent_runs
        if not 1 <= self.max_concurrent <= 4:
            raise ValueError("ARENA_MAX_CONCURRENT_RUNS must be within 1..4")
        self._jobs: dict[str, RunJob] = {}
        self._start_lock = asyncio.Lock()

    async def start(self, request) -> str:
        scenario = ScenarioLoader().load(request.scenario_id)
        if request.mode == "live" and scenario.id != "C00":
            raise ValueError("Live mode currently supports C00 only")
        if request.mode == "live":
            caller = OllamaCaller(self.settings.ollama_url)
            digest = await caller.model_digest(request.model_name or self.settings.model)
            if digest is None:
                raise ModelUnavailable("Selected local model is not installed")
        run_id = str(uuid4())
        job = RunJob(
            run_id, request.scenario_id, request.mode, request.defense_profile,
            ready=asyncio.Event(),
        )
        async with self._start_lock:
            if len(self._jobs) >= self.max_concurrent:
                raise RuntimeError("Concurrent run limit reached")
            self._jobs[run_id] = job
            job.task = asyncio.create_task(self._execute(job, request))
        try:
            await asyncio.wait_for(job.ready.wait(), timeout=10)
        except TimeoutError as error:
            job.task.cancel()
            raise RuntimeError("Run initialization timed out") from error
        if await get_run_status(self.settings, run_id) is None:
            raise RuntimeError("Run initialization failed")
        return run_id

    async def _execute(self, job: RunJob, request) -> None:
        def publish(event: RunEvent) -> None:
            self.broadcaster.publish(job.run_id, safe_event(event))
            if event.event_type == "run.started" and job.ready is not None:
                job.ready.set()

        try:
            if request.mode == "replay":
                await run_replay(
                    request.scenario_id, request.defense_profile, request.seed,
                    settings=self.settings, attack_enabled=request.attack_enabled,
                    run_id=job.run_id, on_event=publish,
                )
            else:
                from reef_panda_arena.application.live import run_live

                await run_live(
                    request.scenario_id, request.defense_profile, request.seed,
                    attack_enabled=request.attack_enabled,
                    model_name=request.model_name,
                    temperature=request.temperature,
                    settings=self.settings, run_id=job.run_id,
                    on_event=publish,
                )
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        finally:
            if job.ready is not None:
                job.ready.set()
            self._jobs.pop(job.run_id, None)

    def pending(self, run_id: str) -> dict | None:
        job = self._jobs.get(run_id)
        if job is None:
            return None
        return {
            "run_id": run_id, "scenario_id": job.scenario_id,
            "mode": job.mode, "defense_profile": job.defense_profile,
            "status": "pending", "model_name": None, "failure_code": None,
            "secret_escaped": None, "benign_task_success": None,
            "accepted_outbound_events": None,
        }

    async def cancel(self, run_id: str) -> bool:
        job = self._jobs.get(run_id)
        if job is None or job.task is None:
            return False
        job.task.cancel()
        try:
            await job.task
        except asyncio.CancelledError:
            pass
        return True

    async def shutdown(self) -> None:
        tasks = [job.task for job in self._jobs.values() if job.task is not None]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
