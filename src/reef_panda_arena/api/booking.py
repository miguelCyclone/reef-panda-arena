"""Typed core booking endpoints; reuse shared jobs, cancellation and SSE."""

from uuid import UUID
from typing import Literal
from pydantic import BaseModel, ConfigDict
from fastapi import HTTPException, Query, Response
from reef_panda_arena.application.booking_contract import BookingConfig, BookingReport
from reef_panda_arena.storage.booking import booking_report, recent_bookings
from reef_panda_arena.storage.booking_inspection import BookingInspection, inspect_booking


class RevealSynthetic(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    reveal_synthetic: Literal[True]


def mount_booking(app, manager, settings):
    @app.post('/v1/booking/runs',status_code=202)
    async def start(body: BookingConfig) -> dict[str,str]:
        try:
            identity=await manager.start_booking(body)
        except ValueError as error:
            raise HTTPException(422,str(error)) from error
        except RuntimeError as error:
            raise HTTPException(409,str(error)) from error
        return {'run_id':identity,'status':'running'}

    @app.get('/v1/booking/runs',response_model=list[BookingReport])
    async def recent(limit: int=Query(20,ge=1,le=50)):
        return await recent_bookings(settings,limit)

    @app.get('/v1/booking/runs/{run_id}',response_model=BookingReport)
    async def report(run_id: UUID):
        result=await booking_report(settings,str(run_id))
        if result is None:raise HTTPException(404,'Unknown booking run')
        return result

    @app.post('/v1/booking/runs/{run_id}/inspection', response_model=BookingInspection)
    async def inspection(run_id: UUID, body: RevealSynthetic, response: Response):
        response.headers['Cache-Control'] = 'no-store'
        try:
            result = await inspect_booking(settings, str(run_id))
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
        if result is None:
            raise HTTPException(404, 'Unknown booking run')
        return result
