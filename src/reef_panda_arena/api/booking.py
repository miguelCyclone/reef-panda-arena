"""Typed core booking endpoints; reuse shared jobs, cancellation and SSE."""

from uuid import UUID
from fastapi import HTTPException, Query
from reef_panda_arena.application.booking_contract import BookingConfig, BookingReport
from reef_panda_arena.storage.booking import booking_report, recent_bookings


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
