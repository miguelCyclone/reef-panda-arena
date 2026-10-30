"""Bounded in-process run jobs; MySQL remains the status system of record."""

import asyncio
from dataclasses import dataclass
from uuid import uuid4

from reef_panda_arena.application.controller import run_replay
from reef_panda_arena.application.admission import RunAdmissionBusy, RunAdmissionUnavailable
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.scenarios.sensitive_contract import SensitiveScenarioDefinition
from reef_panda_arena.scenarios.extension_contract import ExtensionScenarioDefinition
from reef_panda_arena.adaptive.scenario import AdaptiveScenarioDefinition
from reef_panda_arena.scenarios.unified_contract import UnifiedScenarioDefinition
from reef_panda_arena.gateway.policies import LEGACY_PROFILES, UNIFIED_PROFILES
from reef_panda_arena.adaptive.fixtures import AdaptiveFixtureRegistry
from reef_panda_arena.scenarios.extension_fixtures import ExtensionFixtureRegistry
from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
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
    startup_failure: str | None = None


class RunManager:
    def __init__(self, settings: ArenaSettings,
                 broadcaster: SSEBroadcaster | None = None) -> None:
        self.settings = settings
        self.broadcaster = broadcaster or SSEBroadcaster()
        self.max_concurrent = settings.max_concurrent_runs
        if not 1 <= self.max_concurrent <= 4:
            raise ValueError("ARENA_MAX_CONCURRENT_RUNS must be within 1..4")
        if settings.audit_mode:
            self.max_concurrent = 1
        self._jobs: dict[str, RunJob] = {}
        self._start_lock = asyncio.Lock()

    async def start(self, request) -> str:
        scenario = ScenarioLoader().load(request.scenario_id)
        if (not isinstance(scenario, UnifiedScenarioDefinition)
                and request.defense_profile not in LEGACY_PROFILES):
            raise ValueError("Unified defenses apply only to C29-C43")
        if request.mode == "live_multiagent" and not isinstance(scenario, UnifiedScenarioDefinition):
            raise ValueError("Independent multiagent mode requires C29-C43")
        if (request.top_p is not None or request.generation_seed is not None) and request.mode != "live_multiagent":
            raise ValueError("Explicit sampling options require independent multiagent mode")
        chosen_arm = None
        if isinstance(scenario, AdaptiveScenarioDefinition):
            fixtures = AdaptiveFixtureRegistry()
            seeds = fixtures.holdout_seeds if request.split == "holdout" else fixtures.development_seeds
            if request.seed not in seeds or (request.split == "holdout" and scenario.id != "C28"):
                raise ValueError("Seed is not available in this adaptive split")
            chosen_arm = request.arm or (
                "A3" if request.mode == "live_adaptive" and request.attack_enabled else
                "A1" if request.attack_enabled else "A0"
            )
            if chosen_arm not in scenario.evaluation_arms:
                raise ValueError("Adaptive arm is unavailable for this case")
            if request.mode not in scenario.mode_support:
                raise ValueError("Adaptive mode is unavailable for this case")
            if request.mode == "live_adaptive" and chosen_arm == "A1":
                raise ValueError("A1 is a scripted replay control")
            if request.mode == "replay" and chosen_arm in {"A2", "A4"}:
                raise ValueError("A2 and A4 require a local model")
            if (chosen_arm == "A5") != (request.split == "holdout"):
                raise ValueError("A5 and holdout split must be selected together")
            if chosen_arm == "A5" and not request.transfer_from_run_id:
                raise ValueError("A5 requires a completed C28 development run")
            if chosen_arm != "A5" and request.transfer_from_run_id is not None:
                raise ValueError("Transfer source applies only to A5")
            if not request.attack_enabled and chosen_arm != "A0":
                raise ValueError("No-attack control requires A0")
        elif (request.mode == "live_adaptive" or request.split != "development"
              or request.transfer_from_run_id is not None or request.round_limit != 8):
            raise ValueError("Adaptive options require C22-C28")
        if isinstance(scenario, UnifiedScenarioDefinition):
            if request.mode not in scenario.mode_support or request.defense_profile not in UNIFIED_PROFILES:
                raise ValueError("Unified cases require replay or live_multiagent and a unified defense")
            if request.arm is not None:
                raise ValueError("Unified cases use the attack toggle, not an arm")
        if isinstance(scenario, ExtensionScenarioDefinition):
            if request.seed not in ExtensionFixtureRegistry().seeds:
                raise ValueError("Seed is not available in the extension fixture registry")
        elif (not isinstance(scenario, (AdaptiveScenarioDefinition, UnifiedScenarioDefinition))
              and (request.arm is not None or request.observer_profile != "metadata_schema")):
            raise ValueError("Arm and reviewer profile apply only to C15-C21")
        if isinstance(scenario, SensitiveScenarioDefinition):
            if request.seed not in SensitiveFixtureRegistry().seeds:
                raise ValueError("Seed is not available in the sensitive fixture registry")
        if request.mode == "live" and scenario.id != "C00":
            raise ValueError("Live mode currently supports C00 only")
        if request.mode not in scenario.mode_support:
            raise ValueError("Mode is unavailable for this scenario")
        run_id = str(uuid4())
        job = RunJob(
            run_id, request.scenario_id, request.mode, request.defense_profile,
            ready=asyncio.Event(),
        )
        return await self._launch(job, request)

    async def start_booking(self, request):
        from reef_panda_arena.application.booking_contract import BookingConfig
        if type(request) is not BookingConfig:
            raise ValueError("Invalid booking configuration")
        job = RunJob(str(uuid4()), "booking-core", "booking_" + request.mode,
                     request.policy, ready=asyncio.Event())
        return await self._launch(job, request)

    async def _launch(self, job, request):
        run_id = job.run_id
        async with self._start_lock:
            if self.settings.audit_mode and self._jobs:
                raise RunAdmissionBusy("Concurrent audit run limit reached")
            if (job.scenario_id in {f"C{i}" for i in range(22, 29)}
                    and any(job.scenario_id in {f"C{i}" for i in range(22, 29)}
                            for job in self._jobs.values())):
                raise RuntimeError("Concurrent adaptive run limit reached")
            if (job.scenario_id in {f"C{i}" for i in range(29, 44)}
                    and any(job.scenario_id in {f"C{i}" for i in range(29, 44)}
                            for job in self._jobs.values())):
                raise RuntimeError("Concurrent unified run limit reached")
            if len(self._jobs) >= self.max_concurrent:
                raise RuntimeError("Concurrent run limit reached")
            self._jobs[run_id] = job
            job.task = asyncio.create_task(self._execute(job, request))
        try:
            await asyncio.wait_for(job.ready.wait(), timeout=10)
        except TimeoutError as error:
            job.task.cancel()
            raise RuntimeError("Run initialization timed out") from error
        if job.startup_failure is not None:
            raise RuntimeError(job.startup_failure)
        if await get_run_status(self.settings, run_id) is None:
            raise RuntimeError("Run initialization failed")
        return run_id

    async def _execute(self, job: RunJob, request) -> None:
        def publish(event: RunEvent) -> None:
            self.broadcaster.publish(job.run_id, safe_event(event))
            if event.event_type == "run.started" and job.ready is not None:
                job.ready.set()

        try:
            if job.scenario_id == "booking-core":
                from reef_panda_arena.application.booking import run_booking
                await run_booking(request, settings=self.settings, run_id=job.run_id, on_event=publish)
            elif request.mode == "live_multiagent":
                from reef_panda_arena.application.unified import run_unified_live

                await run_unified_live(
                    request.scenario_id, request.defense_profile, request.seed,
                    settings=self.settings, attack_enabled=request.attack_enabled,
                    observer_profile=request.observer_profile, run_id=job.run_id, on_event=publish,
                    model_name=request.model_name, temperature=request.temperature,
                    top_p=request.top_p, generation_seed=request.generation_seed,
                )
            elif request.mode == "live_adaptive":
                from reef_panda_arena.application.adaptive import run_adaptive

                await run_adaptive(
                    request.scenario_id, request.defense_profile, request.seed,
                    settings=self.settings, mode="live_adaptive",
                    arm=request.arm or ("A3" if request.attack_enabled else "A0"),
                    observer_profile=request.observer_profile,
                    round_limit=request.round_limit, split=request.split,
                    transfer_from_run_id=request.transfer_from_run_id,
                    model_name=request.model_name,
                    temperature=request.temperature,
                    run_id=job.run_id, on_event=publish,
                )
            elif request.mode == "replay":
                if job.scenario_id in {f"C{i}" for i in range(29, 44)}:
                    from reef_panda_arena.application.unified import run_unified_replay

                    await run_unified_replay(
                        request.scenario_id, request.defense_profile, request.seed,
                        settings=self.settings,
                        attack_enabled=request.attack_enabled,
                        observer_profile=request.observer_profile,
                        run_id=job.run_id, on_event=publish,
                    )
                    return
                if job.scenario_id in {f"C{i}" for i in range(22, 29)}:
                    from reef_panda_arena.application.adaptive import run_adaptive

                    await run_adaptive(
                        request.scenario_id, request.defense_profile, request.seed,
                        settings=self.settings, mode="replay",
                        arm=request.arm or ("A1" if request.attack_enabled else "A0"),
                        observer_profile=request.observer_profile,
                        round_limit=request.round_limit, split=request.split,
                        transfer_from_run_id=request.transfer_from_run_id,
                        run_id=job.run_id, on_event=publish,
                    )
                    return
                await run_replay(
                    request.scenario_id, request.defense_profile, request.seed,
                    settings=self.settings, attack_enabled=request.attack_enabled,
                    run_id=job.run_id, on_event=publish,
                    arm=request.arm, observer_profile=request.observer_profile,
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
            if job.ready is not None and not job.ready.is_set():
                job.startup_failure = "Run initialization cancelled"
        except (RunAdmissionBusy, RunAdmissionUnavailable) as error:
            job.startup_failure = str(error)
        except Exception:
            if job.ready is not None and not job.ready.is_set():
                job.startup_failure = "Run initialization failed"
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
