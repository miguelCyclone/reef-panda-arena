"""Receipt-relative evidence from typed actual inspections and durable receipts."""

from reef_panda_arena.gateway.observer_contract import BoundaryObservation, safe_observation, unobserved
from reef_panda_arena.storage.events import (
    EventStore, EventPersistenceInterrupted, EventPersistenceCancelled,
)
from reef_panda_arena.storage.models import RunEvent, SinkReceipt
from reef_panda_arena.telemetry.public_event import event_labels, public_summary
from reef_panda_arena.tools.registry import OUTBOUND_TOOLS


def _boundary_kind(event):
    return {"tool": "tool", "message": "peer", "memory": "memory",
            "projection": "release", "reducer": "reducer", "research": "research"}.get(event.channel, "other")


class BoundaryEventStore:
    """Persist bounded evidence, then retain factual scoring observations."""

    def __init__(self, store: EventStore, gateway) -> None:
        self.store = store
        self.gateway = gateway

    def _record(self, event, accepted):
        safe = event.safe_summary_json
        observation = safe_observation(safe.get("observation"))
        measured = observation is not None and observation["inspection_state"] == "inspected"
        self.gateway.boundary_observations.append({
            "event_seq": event.event_seq, "attempt_id": safe["attempt_id"],
            "actor_id": event.actor_id, "tool_name": event.tool_name,
            "outbound": event.tool_name in OUTBOUND_TOOLS,
            "accepted": accepted, "blocked": event.policy_decision == "block",
            "observer_measured": measured,
            "observer_profile": observation["observer_profile"] if observation else "none",
            "observer_version": observation["observer_version"] if observation else "none",
            "observer_alert": observation["alert"] if measured else None,
            "observer_phase": "before_receipt" if measured else None,
            "decision_elapsed_ms": safe["decision_elapsed_ms"],
            "observer_elapsed_ms": observation["observed_elapsed_ms"] if measured else None,
            "receipt_elapsed_ms": self.gateway.elapsed_ms() if accepted else None,
        })

    async def append(self, event: RunEvent, receipt: SinkReceipt | None = None) -> RunEvent:
        if receipt is not None and (receipt.run_id, receipt.event_seq) != (event.run_id, event.event_seq):
            raise ValueError("Sink receipt must belong to its event")
        safe = dict(event.safe_summary_json or {})
        if "lineage" in safe:
            from reef_panda_arena.gateway.lineage_evidence import validate_lineage_document
            lineage = validate_lineage_document(safe["lineage"])
            if (lineage["run_id"], lineage["event_seq"]) != (event.run_id, event.event_seq):
                raise ValueError("Lineage must belong to its event")
        attempt_id = safe.get("attempt_id", self.gateway.current_attempt_id)
        observation = safe_observation(safe.get("observation"))
        if (observation is None or observation["event_seq"] != event.event_seq or
                observation["attempt_id"] != attempt_id):
            observation = unobserved(
                boundary_kind=_boundary_kind(event), event_seq=event.event_seq, attempt_id=attempt_id,
                state="not_inspected" if event.channel == "tool" else "unsupported_boundary",
            ).model_dump(mode="json")
        safe.update(BoundaryObservation.model_validate(observation).summary())
        safe.update(attempt_id=attempt_id, boundary_evidence_version="boundary-v1",
                    accepted_sink_receipt=receipt is not None and receipt.accepted is True)
        decision_time = safe.get("decision_elapsed_ms")
        if type(decision_time) not in {int, float} or not 0 <= decision_time <= 10**12:
            safe["decision_elapsed_ms"] = self.gateway.elapsed_ms()
        # This is the ordinary persisted metadata surface, also used for SSE.
        event.safe_summary_json = public_summary(safe, event_seq=event.event_seq,
                                                run_id=event.run_id, tool_name=event.tool_name)
        event.taint_labels_json = event_labels(event)
        try:
            persisted = await self.store.append(event, receipt)
        except (EventPersistenceInterrupted, EventPersistenceCancelled) as error:
            self._record(error.confirmed_event, error.confirmed_receipt)
            raise
        self._record(persisted, receipt is not None and receipt.accepted is True)
        return persisted
