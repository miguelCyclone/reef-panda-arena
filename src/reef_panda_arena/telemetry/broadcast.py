"""In-process event push with finite subscriber buffers and an idle cutoff."""

import asyncio
from dataclasses import dataclass
from time import monotonic
from typing import Callable, Protocol


class Clock(Protocol):
    def monotonic(self) -> float: ...


class SystemClock:
    def monotonic(self) -> float:
        return monotonic()


@dataclass(eq=False)
class Subscriber:
    run_id: str
    queue: asyncio.Queue[dict]
    connected_at: float
    closed: bool = False


class SSEBroadcaster:
    def __init__(self, clock: Clock | None = None,
                 heartbeat_seconds: int = 30,
                 idle_seconds: int = 300) -> None:
        if heartbeat_seconds < 30 or idle_seconds > 300 or idle_seconds <= 0:
            raise ValueError("SSE timing violates project limits")
        self.clock = clock or SystemClock()
        self.heartbeat_seconds = heartbeat_seconds
        self.idle_seconds = idle_seconds
        self._subscribers: dict[str, set[Subscriber]] = {}

    def subscribe(self, run_id: str) -> Subscriber:
        subscriber = Subscriber(run_id, asyncio.Queue(maxsize=128), self.clock.monotonic())
        self._subscribers.setdefault(run_id, set()).add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: Subscriber) -> None:
        subscriber.closed = True
        group = self._subscribers.get(subscriber.run_id)
        if group is not None:
            group.discard(subscriber)
            if not group:
                del self._subscribers[subscriber.run_id]

    def publish(self, run_id: str, event: dict) -> None:
        for subscriber in tuple(self._subscribers.get(run_id, ())):
            if subscriber.closed:
                continue
            try:
                subscriber.queue.put_nowait(event)
            except asyncio.QueueFull:
                self.unsubscribe(subscriber)

    async def next_event(self, subscriber: Subscriber) -> tuple[str, dict | None]:
        if subscriber.closed:
            return "closed", None
        remaining = self.idle_seconds - (self.clock.monotonic() - subscriber.connected_at)
        if remaining <= 0:
            self.unsubscribe(subscriber)
            return "closed", None
        try:
            event = await asyncio.wait_for(
                subscriber.queue.get(), timeout=min(self.heartbeat_seconds, remaining)
            )
            return "event", event
        except TimeoutError:
            if self.clock.monotonic() - subscriber.connected_at >= self.idle_seconds:
                self.unsubscribe(subscriber)
                return "closed", None
            return "heartbeat", None
