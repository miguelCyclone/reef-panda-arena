"""Run-scoped mediated memory with immutable provenance links."""

import hashlib
from dataclasses import dataclass
from uuid import uuid4

from reef_panda_arena.gateway.budget import reserve_action
from reef_panda_arena.gateway.invoke import GatewayResult, PolicyGateway, TrustedContext
from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.gateway.lineage_evidence import lineage_document
from reef_panda_arena.storage.models import RunEvent
from reef_panda_arena.telemetry.call_shape import trace_phase


@dataclass(frozen=True)
class _MemoryValue:
    value: str
    artifact_id: str
    version: int
    slot_id: str


class MemoryCaller:
    def __init__(
        self, gateway: PolicyGateway, registry: ArtifactRegistry,
        allowed_writers: frozenset[str], allowed_readers: frozenset[str],
    ) -> None:
        if gateway.artifact_registry is not registry:
            raise ValueError("Memory and gateway must share the artifact registry")
        self.gateway = gateway
        self.registry = registry
        self.allowed_writers = gateway.context_guard.members(allowed_writers)
        self.allowed_readers = gateway.context_guard.members(allowed_readers)
        self._values: dict[str, _MemoryValue] = {}

    def _reserve(self) -> int:
        return reserve_action(self.gateway)

    async def write(
        self, context: TrustedContext, key: str, value: str,
        parent_ids: tuple[str, ...],
    ) -> GatewayResult:
        self.gateway.context_guard.validate(context, boundary="memory_write")
        parent_ids = tuple(parent_ids) if type(parent_ids) in {tuple, list} else ()
        async with self.gateway._lock:
            seq = self._reserve()
            reason = "allowed"
            labels: dict[str, str] = {}
            if context.actor_id not in self.allowed_writers:
                reason = "memory_writer_not_allowed"
            elif type(key) is not str or not key.isascii() or not 1 <= len(key) <= 64:
                reason = "invalid_memory_key"
            elif not isinstance(value, str) or len(value.encode("utf-8")) > self.gateway.max_payload_bytes:
                reason = "invalid_memory_value"
            else:
                try:
                    labels = self.gateway._artifact_labels(
                        {"value": value},
                        TrustedContext(
                            context.run_id, context.actor_id, context.role,
                            artifact_dependencies={"value": parent_ids},
                        ),
                        actor_local=self.gateway.profile == "actor_local",
                    )
                    if labels["value"] == "unknown":
                        reason = "unknown_provenance"
                except ValueError:
                    reason = "invalid_provenance"
            stored = self._values.get(key) if reason == "allowed" else None
            version = (stored.version + 1 if stored else 1) if reason == "allowed" else None
            slot_id = (stored.slot_id if stored else uuid4().hex) if reason == "allowed" else None
            prepared = (self.registry.prepare_derived(
                event_seq=seq, actor_id=context.actor_id, kind="memory_write",
                parent_ids=parent_ids, payload=value.encode("utf-8"),
            ),) if reason == "allowed" else ()
            artifacts = {"value": prepared[0].artifact_id} if prepared else {}
            lineage = lineage_document(
                self.registry, context, seq=seq, boundary="memory.write", nodes=prepared,
                inputs={"value": parent_ids} if context.actor_id in self.allowed_writers else {},
                outputs=artifacts, field_names=("value",), effective_labels=labels,
                attempt_id=self.gateway.attempt_id(context),
                coverage="complete" if reason == "allowed" else "partial",
                reasons=() if reason == "allowed" else ("denied_proposal",),
                metadata={"memory_slot_id": slot_id, "memory_version": version} if slot_id else {},
            )
            payload_hash = hashlib.sha256(value.encode("utf-8")).digest() if isinstance(value, str) else None
            event = RunEvent(
                run_id=context.run_id, event_seq=seq, event_type="memory.write",
                actor_id=context.actor_id, channel="memory", tool_name="memory.write",
                destination="local_run_memory",
                policy_decision="allow" if reason == "allowed" else "block",
                reason_code=reason, data_class=labels.get("value", "unknown"),
                taint_labels_json=labels,
                safe_summary_json={
                    "visual": {"phase": trace_phase(context)},
                    "lineage": lineage, "memory_slot_id": slot_id, "version": version,
                    "byte_length": len(value.encode("utf-8")) if isinstance(value, str) else 0,
                },
                payload_sha256=payload_hash,
            )
            await self.gateway.event_store.append(event)
            if reason == "allowed":
                self.registry.commit_prepared(prepared)
                self._values[key] = _MemoryValue(value, prepared[0].artifact_id, version, slot_id)
            else:
                self.gateway.blocked_attempts += 1
            if self.gateway.on_event is not None:
                self.gateway.on_event(event)
            return GatewayResult(reason == "allowed", reason, None, labels, artifacts)

    async def compact(self, context: TrustedContext, key: str) -> GatewayResult:
        """Canonicalize a stored value while preserving its exact parent edge."""
        self.gateway.context_guard.validate(context, boundary="memory_compact")
        async with self.gateway._lock:
            seq = self._reserve()
            stored = self._values.get(key) if context.actor_id in self.allowed_writers else None
            reason = (
                "allowed" if context.actor_id in self.allowed_writers and stored is not None
                else "memory_writer_not_allowed" if context.actor_id not in self.allowed_writers
                else "memory_key_not_found"
            )
            value = " ".join(stored.value.split()) if stored else ""
            label = self.registry.get(stored.artifact_id).label if stored else "unknown"
            prepared = (self.registry.prepare_derived(
                event_seq=seq, actor_id=context.actor_id, kind="memory_compact",
                parent_ids=(stored.artifact_id,), payload=value.encode("utf-8"),
            ),) if reason == "allowed" else ()
            artifacts = {"value": prepared[0].artifact_id} if prepared else {}
            lineage = lineage_document(
                self.registry, context, seq=seq, boundary="memory.compact", nodes=prepared,
                inputs={"value": (stored.artifact_id,)} if stored else {}, outputs=artifacts,
                field_names=("value",), effective_labels={"value": label} if stored else {},
                attempt_id=self.gateway.attempt_id(context),
                coverage="complete" if reason == "allowed" else "partial",
                reasons=() if reason == "allowed" else ("denied_proposal",),
                metadata={"memory_slot_id": stored.slot_id, "memory_version": stored.version + 1} if stored else {},
            )
            event = RunEvent(
                run_id=context.run_id, event_seq=seq, event_type="memory.compact",
                actor_id=context.actor_id, channel="memory", tool_name="memory.compact",
                destination="local_run_memory",
                policy_decision="allow" if reason == "allowed" else "block",
                reason_code=reason, data_class=label,
                taint_labels_json={"value": label} if stored else {},
                safe_summary_json={
                    "visual": {"phase": trace_phase(context)},
                    "lineage": lineage,
                    "memory_slot_id": stored.slot_id if stored else None,
                    "version": stored.version + 1 if stored else 0,
                    "byte_length": len(value.encode("utf-8")),
                },
                payload_sha256=hashlib.sha256(value.encode("utf-8")).digest() if stored else None,
            )
            await self.gateway.event_store.append(event)
            if reason == "allowed":
                assert stored is not None
                self.registry.commit_prepared(prepared)
                self._values[key] = _MemoryValue(
                    value, prepared[0].artifact_id, stored.version + 1, stored.slot_id,
                )
            else:
                self.gateway.blocked_attempts += 1
            if self.gateway.on_event is not None:
                self.gateway.on_event(event)
            return GatewayResult(
                reason == "allowed", reason,
                {"value": value} if reason == "allowed" else None,
                {"value": label} if stored else {}, artifacts,
            )

    async def read(self, context: TrustedContext, key: str) -> GatewayResult:
        self.gateway.context_guard.validate(context, boundary="memory_read")
        async with self.gateway._lock:
            seq = self._reserve()
            stored = self._values.get(key) if context.actor_id in self.allowed_readers else None
            reason = (
                "allowed" if context.actor_id in self.allowed_readers and stored is not None
                else "memory_reader_not_allowed" if context.actor_id not in self.allowed_readers
                else "memory_key_not_found"
            )
            labels: dict[str, str] = {}
            if reason == "allowed":
                assert stored is not None
                labels = self.gateway._artifact_labels(
                    {"value": stored.value},
                    TrustedContext(
                        context.run_id, context.actor_id, context.role,
                        artifact_dependencies={"value": (stored.artifact_id,)},
                    ),
                    actor_local=self.gateway.profile == "actor_local",
                )
            prepared = (self.registry.prepare_derived(
                event_seq=seq, actor_id=context.actor_id, kind="memory_read",
                parent_ids=(stored.artifact_id,), payload=stored.value.encode("utf-8"),
            ),) if reason == "allowed" else ()
            artifacts = {"value": prepared[0].artifact_id} if prepared else {}
            lineage = lineage_document(
                self.registry, context, seq=seq, boundary="memory.read", nodes=prepared,
                inputs={"value": (stored.artifact_id,)} if stored else {}, outputs=artifacts,
                field_names=("value",), effective_labels=labels,
                attempt_id=self.gateway.attempt_id(context),
                coverage="complete" if reason == "allowed" else "partial",
                reasons=() if reason == "allowed" else ("denied_proposal",),
                metadata={"memory_slot_id": stored.slot_id, "memory_version": stored.version} if stored else {},
            )
            event = RunEvent(
                run_id=context.run_id, event_seq=seq, event_type="memory.read",
                actor_id=context.actor_id, channel="memory", tool_name="memory.read",
                destination="local_run_memory",
                policy_decision="allow" if reason == "allowed" else "block",
                reason_code=reason, data_class=labels.get("value", "unknown"),
                taint_labels_json=labels,
                safe_summary_json={
                    "visual": {"phase": trace_phase(context)},
                    "lineage": lineage,
                    "memory_slot_id": stored.slot_id if stored else None,
                    "version": stored.version if stored else 0,
                },
                payload_sha256=(
                    hashlib.sha256(stored.value.encode("utf-8")).digest()
                    if stored else None
                ),
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
                {"value": stored.value} if reason == "allowed" else None,
                labels, artifacts,
            )
