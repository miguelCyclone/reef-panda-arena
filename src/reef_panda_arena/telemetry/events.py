"""Safe event projection shared by MySQL history and SSE."""

from typing import Any

from reef_panda_arena.storage.models import RunEvent


def lifecycle_event(run_id: str, seq: int, event_type: str) -> RunEvent:
    if event_type not in {"run.started", "run.completed", "run.failed", "run.cancelled", "run.timed_out"}:
        raise ValueError("Unknown lifecycle event")
    return RunEvent(
        run_id=run_id, event_seq=seq, event_type=event_type,
        actor_id="system", channel="run", tool_name=None, destination=None,
        policy_decision="not_applicable", reason_code=None, data_class="public",
        taint_labels_json={}, safe_summary_json={}, payload_sha256=None,
    )


def safe_event(event: RunEvent) -> dict[str, Any]:
    return {
        "id": event.event_seq,
        "event": event.event_type,
        "data": {
            "actor_id": event.actor_id,
            "channel": event.channel,
            "tool_name": event.tool_name,
            "destination": event.destination,
            "policy_decision": event.policy_decision,
            "reason_code": event.reason_code,
            "data_class": event.data_class,
            "taint_labels": event.taint_labels_json,
            "summary": event.safe_summary_json,
            "payload_sha256": (
                event.payload_sha256.hex() if event.payload_sha256 is not None else None
            ),
        },
    }
