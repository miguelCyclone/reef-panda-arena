"""Safe event projection shared by MySQL history and SSE."""

from typing import Any

from reef_panda_arena.storage.models import RunEvent
from reef_panda_arena.telemetry.public_event import ACTORS, EVENTS, REASONS, contracts, event_labels, public_summary
from reef_panda_arena.telemetry.public_fields import LABELS


def lifecycle_event(run_id: str, seq: int, event_type: str) -> RunEvent:
    if event_type not in {"run.started", "run.completed", "run.failed", "run.cancelled", "run.timed_out"}:
        raise ValueError("Unknown lifecycle event")
    return RunEvent(
        run_id=run_id, event_seq=seq, event_type=event_type,
        actor_id="system", channel="run", tool_name=None, destination=None,
        policy_decision="not_applicable", reason_code=None, data_class="public",
        taint_labels_json={}, safe_summary_json={}, payload_sha256=None,
    )


def safe_event(event: RunEvent, *, accepted_sink_receipt: bool | None = None) -> dict[str, Any]:
    inputs, destinations, _ = contracts()
    summary = public_summary(event.safe_summary_json, event_seq=event.event_seq,
                             run_id=event.run_id, tool_name=event.tool_name)
    if type(accepted_sink_receipt) is bool:
        summary["accepted_sink_receipt"] = accepted_sink_receipt
    return {
        "id": event.event_seq,
        "event": event.event_type if event.event_type in EVENTS else "unknown.event",
        "data": {
            "actor_id": event.actor_id if event.actor_id in ACTORS else "unknown_actor",
            "channel": event.channel if event.channel in {"run", "tool", "message", "memory", "projection", "reducer", "research"} else "unknown",
            "tool_name": event.tool_name if event.tool_name in inputs or event.tool_name == "memory.compact" else None if event.tool_name is None else "unknown_tool",
            "destination": event.destination if event.destination in destinations else None if event.destination is None else "unknown_destination",
            "policy_decision": event.policy_decision if event.policy_decision in {"allow", "block", "review", "not_applicable"} else "unknown",
            "reason_code": event.reason_code if event.reason_code in REASONS else None if event.reason_code is None else "unrecognized_reason",
            "data_class": event.data_class if event.data_class in LABELS else "unknown",
            "taint_labels": event_labels(event),
            "summary": summary,
        },
    }
