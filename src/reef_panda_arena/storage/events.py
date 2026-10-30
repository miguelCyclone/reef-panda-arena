"""Idempotent redacted event and local receipt persistence."""

import asyncio
from copy import deepcopy
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

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


_RECONCILE_SECONDS = 5


class EventPersistenceInterrupted(RuntimeError):
    """An interrupted append has a separately confirmed durable event."""

    def __init__(self, event: RunEvent, receipt: bool) -> None:
        super().__init__("Event persistence interrupted after confirmed commit")
        self.confirmed_event = event
        self.confirmed_receipt = receipt


class EventPersistenceCancelled(asyncio.CancelledError):
    """Cancellation remains cancellation even when its commit was durable."""

    def __init__(self, event: RunEvent, receipt: bool) -> None:
        super().__init__("Event persistence interrupted after confirmed commit")
        self.confirmed_event = event
        self.confirmed_receipt = receipt


def _same(row, expected: dict) -> bool:
    return row is not None and all(getattr(row, name) == value for name, value in expected.items())


class EventStore(Protocol):
    async def append(self, event: RunEvent,
                     receipt: SinkReceipt | None = None) -> RunEvent: ...


class SessionEventStore:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def append(self, event: RunEvent,
                     receipt: SinkReceipt | None = None) -> RunEvent:
        if receipt is not None and (receipt.run_id, receipt.event_seq) != (event.run_id, event.event_seq):
            raise ValueError("Sink receipt must belong to its event")
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
        identity = (event.run_id, event.event_seq)
        expected_event = deepcopy({name: getattr(event, name) for name in _EVENT_FIELDS})
        expected_receipt = (
            deepcopy({name: getattr(receipt, name) for name in _RECEIPT_FIELDS})
            if receipt is not None else None
        )
        try:
            await self.session.commit()
        except (Exception, asyncio.CancelledError) as error:
            # Do not roll back/expire the caller's run before its terminal snapshot.
            confirmed = await self._reconcile(identity, expected_event, expected_receipt)
            if confirmed is not None:
                interruption = (
                    EventPersistenceCancelled if isinstance(error, asyncio.CancelledError)
                    else EventPersistenceInterrupted
                )
                raise interruption(confirmed, bool(expected_receipt and expected_receipt["accepted"])) from error
            raise
        return event

    async def _reconcile(self, identity: tuple[str, int], expected_event: dict,
                         expected_receipt: dict | None) -> RunEvent | None:
        """One bounded fresh read, never a retry or a claim based on local ORM state."""
        async def lookup():
            try:
                async with asyncio.timeout(_RECONCILE_SECONDS):
                    bind = self.session.bind
                    engine = getattr(bind, "engine", bind)
                    if engine is None:
                        return None
                    async with async_sessionmaker(engine, expire_on_commit=False)() as fresh:
                        event = await fresh.scalar(select(RunEvent).where(
                            RunEvent.run_id == identity[0], RunEvent.event_seq == identity[1],
                        ))
                        if not _same(event, expected_event):
                            return None
                        receipt = await fresh.scalar(select(SinkReceipt).where(
                            SinkReceipt.run_id == identity[0], SinkReceipt.event_seq == identity[1],
                        ))
                        if (receipt is None) != (expected_receipt is None):
                            return None
                        if expected_receipt is not None and not _same(receipt, expected_receipt):
                            return None
                        return event
            except (Exception, asyncio.CancelledError):
                return None

        reconciliation = asyncio.create_task(lookup())
        try:
            return await asyncio.shield(reconciliation)
        except asyncio.CancelledError:
            reconciliation.cancel()
            raise
