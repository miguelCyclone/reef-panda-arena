"""Mediated reducer join for registered, actually consumed artifacts."""

import hashlib

from reef_panda_arena.gateway.budget import reserve_action
from reef_panda_arena.gateway.invoke import GatewayResult, PolicyGateway, TrustedContext
from reef_panda_arena.gateway.provenance import ArtifactRegistry, ProvenanceJoiner
from reef_panda_arena.gateway.lineage_evidence import lineage_document
from reef_panda_arena.storage.models import RunEvent
from reef_panda_arena.telemetry.call_shape import trace_phase


class ReducerCaller:
    def __init__(self, gateway: PolicyGateway, registry: ArtifactRegistry) -> None:
        if gateway.artifact_registry is not registry:
            raise ValueError("Reducer must share the gateway registry")
        self.gateway = gateway
        self.registry = registry

    async def join(
        self, context: TrustedContext, value: str,
        parent_ids: tuple[str, ...],
    ) -> GatewayResult:
        self.gateway.context_guard.validate(context, boundary="reducer")
        parent_ids = tuple(parent_ids) if type(parent_ids) in {tuple, list} else ()
        async with self.gateway._lock:
            seq = reserve_action(self.gateway)
            reason = "allowed"
            label = "unknown"
            if context.actor_id != "A8" or len(parent_ids) < 2:
                reason = "reducer_inputs_invalid"
            elif not isinstance(value, str) or len(value.encode("utf-8")) > self.gateway.max_payload_bytes:
                reason = "reducer_value_invalid"
            else:
                try:
                    if len(set(parent_ids)) != len(parent_ids):
                        raise ValueError("Duplicate reducer dependency")
                    parents = tuple(self.registry.get(item) for item in parent_ids)
                    if any(parent.actor_id != "A8" or parent.kind != "peer_receive" for parent in parents):
                        reason = "reducer_inputs_not_consumed"
                    else:
                        label = ProvenanceJoiner.join(tuple(parent.label for parent in parents))
                        if label == "unknown":
                            reason = "unknown_provenance"
                except ValueError:
                    reason = "invalid_provenance"
            prepared = (self.registry.prepare_derived(
                event_seq=seq, actor_id=context.actor_id, kind="reducer_join",
                parent_ids=parent_ids, payload=value.encode("utf-8"),
            ),) if reason == "allowed" else ()
            artifact_ids = {"value": prepared[0].artifact_id} if prepared else {}
            lineage = lineage_document(
                self.registry, context, seq=seq, boundary="reducer.join", nodes=prepared,
                inputs={"value": parent_ids} if context.actor_id == "A8" else {},
                outputs=artifact_ids, field_names=("value",), effective_labels={"value": label},
                attempt_id=self.gateway.attempt_id(context),
                coverage="complete" if reason == "allowed" else "partial",
                reasons=() if reason == "allowed" else ("denied_proposal",),
            )
            payload_hash = (
                hashlib.sha256(value.encode("utf-8")).digest()
                if isinstance(value, str) else None
            )
            event = RunEvent(
                run_id=context.run_id, event_seq=seq, event_type="artifact.reducer",
                actor_id=context.actor_id, channel="reducer", tool_name=None,
                destination="A8",
                policy_decision="allow" if reason == "allowed" else "block",
                reason_code=reason, data_class=label,
                taint_labels_json={"value": label},
                safe_summary_json={
                    "lineage": lineage,
                    "visual": {"phase": trace_phase(context)},
                    "parent_count": len(parent_ids),
                    "byte_length": len(value.encode("utf-8")) if isinstance(value, str) else 0,
                },
                payload_sha256=payload_hash,
            )
            await self.gateway.event_store.append(event)
            if reason == "allowed":
                self.registry.commit_prepared(prepared)
            else:
                self.gateway.blocked_attempts += 1
            if self.gateway.on_event is not None:
                self.gateway.on_event(event)
            return GatewayResult(
                reason == "allowed", reason,
                {"value": value} if reason == "allowed" else None,
                {"value": label}, artifact_ids,
            )
