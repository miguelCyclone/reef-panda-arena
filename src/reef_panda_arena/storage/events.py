"""Idempotent redacted event and local receipt persistence."""

from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from reef_panda_arena.storage.models import RunEvent, SinkReceipt


_EVENT_FIELDS = (
    "event_type", "actor_id", "channel", "tool_name", "destination",
    "policy_decision", "reason_code", "data_class", "taint_labels_json",
    "safe_summary_json", "payload_sha256",
)
_RECEIPT_FIELDS = (
    "sink_name", "accepted", "byte_length", "payload_sha256",
    "oracle_fragment_json",
)


class EventStore(Protocol):
    async def append(self, event: RunEvent,
                     receipt: SinkReceipt | None = None) -> RunEvent: ...


class SessionEventStore:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def append(self, event: RunEvent,
                     receipt: SinkReceipt | None = None) -> RunEvent:
        existing = await self.session.scalar(
            select(RunEvent).where(
                RunEvent.run_id == event.run_id,
                RunEvent.event_seq == event.event_seq,
            )
        )
        if existing is not None:
            if any(getattr(existing, name) != getattr(event, name)
                   for name in _EVENT_FIELDS):
                raise ValueError("Conflicting event sequence")
            existing_receipt = await self.session.scalar(
                select(SinkReceipt).where(
                    SinkReceipt.run_id == event.run_id,
                    SinkReceipt.event_seq == event.event_seq,
                )
            )
            if (existing_receipt is None) != (receipt is None):
                raise ValueError("Conflicting sink receipt")
            if receipt is not None and any(
                getattr(existing_receipt, name) != getattr(receipt, name)
                for name in _RECEIPT_FIELDS
            ):
                raise ValueError("Conflicting sink receipt")
            return existing
        self.session.add(event)
        if receipt is not None:
            self.session.add(receipt)
        await self.session.commit()
        return event
