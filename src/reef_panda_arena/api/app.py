"""Thin typed HTTP API over application services and sanitized repositories."""

import json
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from reef_panda_arena.api.manager import RunManager
from reef_panda_arena.api.web import mount_web
from reef_panda_arena.model.ollama import ModelUnavailable
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.queries import get_run_status, list_recent_runs, list_run_events
from reef_panda_arena.storage.reports import list_reports


class StartRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    scenario_id: str = Field(pattern=r"^C0[0-9]$")
    mode: str = Field(pattern=r"^(replay|live)$")
    defense_profile: str = Field(pattern=r"^(none|allowlist|content|taint|combined)$")
    seed: int = Field(ge=0, lt=2**64)
    model_name: str | None = Field(default=None, min_length=1, max_length=160)
    temperature: float = Field(default=0.0, ge=0, le=1)
    attack_enabled: bool = True


class RunCreated(BaseModel):
    run_id: str
    status: str


class ScenarioInfo(BaseModel):
    id: str
    difficulty: int
    title: str
    channel: str
    available_modes: tuple[str, ...]


class RunStatus(BaseModel):
    run_id: str
    scenario_id: str
    mode: str
    defense_profile: str
    status: str
    model_name: str | None
    failure_code: str | None
    secret_escaped: bool | None
    benign_task_success: bool | None
    accepted_outbound_events: int | None


class EventPage(BaseModel):
    events: list[dict]
    next_cursor: int | None


def _sse(event: dict) -> str:
    payload = json.dumps(event["data"], separators=(",", ":"), sort_keys=True)
    return f"id: {event['id']}\nevent: {event['event']}\ndata: {payload}\n\n"


def create_app(settings: ArenaSettings | None = None,
               manager: RunManager | None = None) -> FastAPI:
    settings = settings or ArenaSettings()
    manager = manager or RunManager(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await manager.shutdown()

    app = FastAPI(title="Reef Panda Covert Channel Arena", lifespan=lifespan)
    app.state.run_manager = manager
    mount_web(app)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/scenarios", response_model=list[ScenarioInfo])
    async def scenarios() -> list[ScenarioInfo]:
        loader = ScenarioLoader()
        return [
            ScenarioInfo(
                id=item.id, difficulty=item.level, title=item.title,
                channel=item.allowed_channels[0].tool,
                available_modes=("replay", "live") if item.id == "C00" else ("replay",),
            )
            for item in (loader.load(scenario_id) for scenario_id in loader.list_ids())
        ]

    @app.post("/v1/runs", status_code=status.HTTP_202_ACCEPTED,
              response_model=RunCreated)
    async def start_run(body: StartRunRequest) -> RunCreated:
        try:
            run_id = await manager.start(body)
        except ModelUnavailable as error:
            raise HTTPException(503, str(error)) from error
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        except RuntimeError as error:
            raise HTTPException(409, str(error)) from error
        return RunCreated(run_id=run_id, status="pending")

    async def status_for(run_id: str) -> dict:
        row = await get_run_status(settings, run_id)
        if row is None:
            row = manager.pending(run_id)
        if row is None:
            raise HTTPException(404, "Unknown run")
        return row

    @app.get("/v1/runs", response_model=list[RunStatus])
    async def recent_runs(limit: int = Query(20, ge=1, le=50)) -> list[RunStatus]:
        return [RunStatus.model_validate(row) for row in await list_recent_runs(settings, limit)]

    @app.get("/v1/runs/{run_id}", response_model=RunStatus)
    async def run_status(run_id: UUID) -> RunStatus:
        return RunStatus.model_validate(await status_for(str(run_id)))

    @app.get("/v1/runs/{run_id}/events", response_model=EventPage)
    async def event_history(run_id: UUID, cursor: int = Query(0, ge=0),
                            limit: int = Query(100, ge=1, le=100)) -> EventPage:
        await status_for(str(run_id))
        events = await list_run_events(settings, str(run_id), cursor, limit)
        next_cursor = events[-1]["id"] + 1 if len(events) == limit else None
        return EventPage(events=events, next_cursor=next_cursor)

    @app.get("/v1/runs/{run_id}/stream")
    async def event_stream(run_id: UUID, request: Request):
        await status_for(str(run_id))
        run_key = str(run_id)

        async def generate():
            subscriber = manager.broadcaster.subscribe(run_key)
            last_id = -1
            try:
                yield "retry: 30000\n\n"
                history = await list_run_events(settings, run_key, 0, 100)
                for event in history:
                    if event["id"] > last_id:
                        last_id = event["id"]
                        yield _sse(event)
                if history and history[-1]["event"] in {
                    "run.completed", "run.failed", "run.cancelled", "run.timed_out"
                }:
                    return
                while not await request.is_disconnected():
                    kind, event = await manager.broadcaster.next_event(subscriber)
                    if kind == "closed":
                        return
                    if kind == "heartbeat":
                        yield ": heartbeat\n\n"
                        continue
                    if event["id"] <= last_id:
                        continue
                    last_id = event["id"]
                    yield _sse(event)
                    if event["event"] in {
                        "run.completed", "run.failed", "run.cancelled", "run.timed_out"
                    }:
                        return
            finally:
                manager.broadcaster.unsubscribe(subscriber)

        return StreamingResponse(
            generate(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/v1/runs/{run_id}/report")
    async def report(run_id: UUID) -> dict:
        row = await status_for(str(run_id))
        reports = await list_reports(settings, str(run_id), limit=1)
        if not reports:
            raise HTTPException(409, f"Run has no completed score ({row['status']})")
        return reports[0]

    @app.post("/v1/runs/{run_id}/cancel", response_model=RunStatus)
    async def cancel(run_id: UUID) -> RunStatus:
        run_key = str(run_id)
        await status_for(run_key)
        if await manager.cancel(run_key):
            return RunStatus.model_validate(await status_for(run_key))
        row = await status_for(run_key)
        if row["status"] in {"completed", "failed", "cancelled", "timed_out"}:
            return RunStatus.model_validate(row)
        raise HTTPException(409, "Run cannot be cancelled in this process")

    return app
