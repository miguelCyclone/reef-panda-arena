"""Bounded mandatory gateway for all agent-proposed local tool operations."""

import asyncio
import hashlib
import json
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from time import monotonic
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from reef_panda_arena.gateway.context import RuntimeContextGuard, TrustedContext
from reef_panda_arena.gateway.action_evidence import CommittedToolAction, MAX_ACTION_EVIDENCE_BYTES
from reef_panda_arena.gateway.observer import ContentObserver
from reef_panda_arena.gateway.observer_contract import observe_tool
from reef_panda_arena.gateway.tool_evidence import ToolEvidence
from reef_panda_arena.gateway.lineage_evidence import lineage_document
from reef_panda_arena.gateway.observations import BoundaryEventStore
from reef_panda_arena.telemetry.call_shape import call_shape
from reef_panda_arena.gateway.policies import PolicyEngine, ProfilePolicy, VALID_PROFILES, UNIFIED_PROFILES
from reef_panda_arena.gateway.provenance import ArtifactRegistry, ProvenanceJoiner
from reef_panda_arena.gateway.budget import bounded_limits, reserve_action, reserve_event
from reef_panda_arena.gateway.taint import SOURCE_FIELDS, TaintTracker
from reef_panda_arena.storage.events import (
    EventStore, EventPersistenceInterrupted, EventPersistenceCancelled,
)
from reef_panda_arena.storage.models import RunEvent, SinkReceipt
from reef_panda_arena.tools.outbound import encode_sink_payload
from reef_panda_arena.tools.registry import (
    OUTBOUND_TOOLS, ROLE_TOOLS, TOOL_DESTINATIONS, TOOL_INPUTS,
)
from reef_panda_arena.tools.protocol import ToolAdapter
from reef_panda_arena.tools.local import prepare_local_operation, validate_local_adapter
from reef_panda_arena.telemetry.public_fields import safe_labels


class OperationsMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    shipment_id: str = Field(min_length=1, max_length=32)
    customer_id: str = Field(min_length=1, max_length=32)
    text: str = Field(min_length=1, max_length=512)


class ProposedCall(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tool_name: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any]


@dataclass(frozen=True)
class SinkArtifact:
    event_seq: int
    payload: bytes
    tool_name: str = "customer.notify"
    actor_id: str | None = None
    attempt_id: str | None = None


@dataclass(frozen=True)
class GatewayResult:
    allowed: bool
    reason: str
    data: dict[str, Any] | None
    field_labels: dict[str, str] = field(default_factory=dict)
    artifact_ids: dict[str, str] = field(default_factory=dict)


class PolicyGateway:
    def __init__(self, event_store: EventStore, tools: ToolAdapter,
                 profile: str, secret: bytes, max_calls: int,
                 max_events: int, max_payload_bytes: int,
                 allowed_attack_tool: str | None = None,
                 on_event: Callable[[RunEvent], None] | None = None,
                 policy: PolicyEngine | None = None,
                 observer: ContentObserver | None = None,
                 tool_inputs: dict[str, type[BaseModel]] | None = None,
                 tool_destinations: dict[str, str] | None = None,
                 role_tools: dict[str, set[str]] | None = None,
                 max_total_payload_bytes: int | None = None,
                 research_run_id: str | None = None,
                 artifact_registry: ArtifactRegistry | None = None, *,
                 run_id: str, runtime_roles: Mapping[str, str]) -> None:
        if profile not in VALID_PROFILES:
            raise ValueError("Unknown policy profile")
        if profile in UNIFIED_PROFILES and artifact_registry is None:
            raise ValueError("Unified profiles require a trusted artifact registry")
        self.context_guard = RuntimeContextGuard(run_id, runtime_roles)
        if research_run_id is not None and research_run_id != run_id:
            raise ValueError("Research run ID differs from runtime binding")
        if artifact_registry is not None and artifact_registry.run_id != run_id:
            raise ValueError("Artifact registry differs from runtime binding")
        self.event_store = BoundaryEventStore(event_store, self)
        validate_local_adapter(tools)
        self.tools = tools
        self.policy = policy or ProfilePolicy(profile)
        self.observer = observer
        self.tool_inputs = tool_inputs or TOOL_INPUTS
        self.tool_destinations = tool_destinations or TOOL_DESTINATIONS
        self.role_tools = role_tools or ROLE_TOOLS
        self.alerts = 0
        self.profile = profile
        self.secret = secret
        self.max_calls, self.max_events = bounded_limits(max_calls, max_events)
        self.max_payload_bytes = max_payload_bytes
        self.max_total_payload_bytes = max_total_payload_bytes
        self.accepted_payload_bytes = 0
        self.allowed_attack_tool = allowed_attack_tool
        self.on_event = on_event
        self.calls = 0
        self.events = 0
        self.taint = TaintTracker()
        self.artifact_registry = artifact_registry
        self.evidence_registry = artifact_registry or ArtifactRegistry(run_id)
        self.tool_evidence = ToolEvidence(self.evidence_registry, explicit=artifact_registry is not None)
        self.accepted_artifacts: list[SinkArtifact] = []
        self.action_evidence: list[CommittedToolAction] = []
        self.blocked_attempts = 0
        self._operations: dict[tuple[str, str], tuple[bytes, GatewayResult]] = {}
        self._lock = asyncio.Lock()
        self.boundary_observations: list[dict] = []
        self._measurement_started = monotonic()
        self._attempt = ContextVar(f"gateway_attempt_{id(self)}", default="task")

    @property
    def event_store_run_id(self) -> str:
        return self.context_guard.run_id

    @contextmanager
    def attempt_scope(self, attempt_id: str):
        """Bind a logical attempt in trusted runtime code, never model arguments."""
        if not attempt_id or len(attempt_id) > 80 or not attempt_id.isascii():
            raise ValueError("Invalid runtime attempt identifier")
        token = self._attempt.set(attempt_id)
        try:
            yield
        finally:
            self._attempt.reset(token)

    @property
    def current_attempt_id(self) -> str:
        return self._attempt.get()

    def attempt_id(self, context: TrustedContext) -> str:
        return context.attempt_id or self._attempt.get()

    def elapsed_ms(self) -> float:
        return round((monotonic() - self._measurement_started) * 1000, 3)

    async def invoke(self, context: TrustedContext, call: ProposedCall) -> GatewayResult:
        self.context_guard.validate(context, boundary="tool")
        async with self._lock:
            return await self._invoke_locked(context, call)

    async def _invoke_locked(self, context: TrustedContext, call: ProposedCall) -> GatewayResult:
        self.context_guard.validate(context, boundary="tool")
        reserve_action(self, record_event=False)
        try:
            canonical = json.dumps(
                {"tool": call.tool_name, "arguments": call.arguments},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
            canonical_valid = True
        except (TypeError, ValueError):
            canonical = b"<invalid-json>"
            canonical_valid = False
        digest = hashlib.sha256(canonical).digest()
        operation_key = None
        if context.operation_id is not None:
            operation_key = (context.actor_id, context.operation_id)
            prior = self._operations.get(operation_key)
            if prior is not None:
                if prior[0] != digest:
                    raise ValueError("Conflicting operation id")
                return prior[1]
        seq = reserve_event(self)
        destination = self.tool_destinations.get(call.tool_name)
        reason = "allowed"
        args = None
        if not canonical_valid:
            reason = "invalid_arguments"
        elif call.tool_name not in self.tool_inputs:
            reason = "unknown_tool"
        elif (context.role == "customer_worker" and self.allowed_attack_tool is not None
              and call.tool_name in OUTBOUND_TOOLS | {"memory.write"}
              and call.tool_name != self.allowed_attack_tool):
            reason = "scenario_channel_not_allowed"
        elif self.policy.requires_allowlist() and (
            context.role not in self.role_tools or call.tool_name not in self.role_tools[context.role]
        ):
            reason = "role_not_allowed"
        else:
            try:
                args = self.tool_inputs[call.tool_name].model_validate(call.arguments)
            except ValidationError:
                reason = "invalid_arguments"
        labels: dict[str, str] = {}
        if reason == "allowed":
            try:
                labels = (
                    self._artifact_labels(
                        call.arguments, context, actor_local=self.profile == "actor_local"
                    )
                    if self.artifact_registry is not None and call.tool_name in OUTBOUND_TOOLS
                    else self.taint.label_arguments(
                        context.actor_id, call.arguments, context.derived_from,
                        context.trusted_public_fields,
                    )
                )
            except ValueError:
                reason = "invalid_provenance"
        if (reason == "allowed" and self.artifact_registry is not None
                and call.tool_name in OUTBOUND_TOOLS and "unknown" in labels.values()):
            reason = "unknown_provenance"
        if (reason == "allowed" and self.artifact_registry is not None
                and call.tool_name in OUTBOUND_TOOLS
                and self.profile in {"scoped_release", "strict_no_release"}):
            scopes = {
                scope
                for ids in context.artifact_dependencies.values()
                for artifact_id in ids
                for scope in self.artifact_registry.release_scopes(artifact_id)
            }
            if scopes and self.profile == "strict_no_release":
                reason = "strict_release_denied"
            elif scopes and (
                (context.purpose, context.recipient) not in scopes
                or len(scopes) != 1
                or call.arguments.get("customer_id") != context.recipient
            ):
                reason = "release_scope_mismatch"
        payload = b""
        if reason == "allowed" and call.tool_name in OUTBOUND_TOOLS:
            payload = encode_sink_payload(call.tool_name, args)
            if len(payload) > self.max_payload_bytes:
                reason = "payload_too_large"
            elif (self.max_total_payload_bytes is not None and
                  self.accepted_payload_bytes + len(payload) > self.max_total_payload_bytes):
                reason = "total_payload_budget_exceeded"
            elif self.policy.enforces_taint() and "secret" in labels.values():
                reason = "secret_taint_to_outbound"
            elif self.policy.scans_content() and self.policy.contains_secret(
                args.model_dump(exclude_none=True), self.secret
            ):
                reason = "secret_content_match"
        decision_elapsed_ms = self.elapsed_ms()
        fields = tuple(self.tool_inputs[call.tool_name].model_fields) if call.tool_name in self.tool_inputs else ()
        observation = observe_tool(
            self.observer, tool_name=call.tool_name, arguments=call.arguments,
            role=context.role, destination=destination, labels=labels,
            event_seq=seq, attempt_id=self.attempt_id(context), elapsed_ms=self.elapsed_ms,
            trusted_fields=fields,
        )
        if observation.alert is True:
            self.alerts += 1
        data, prepared = None, None
        result_labels: dict[str, str] = {}
        if reason == "allowed":
            prepared = prepare_local_operation(self.tools, call.tool_name, args)
            data = prepared.data
            if call.tool_name in SOURCE_FIELDS:
                declared = SOURCE_FIELDS[call.tool_name]
                if set(data) != set(declared):
                    raise ValueError("Tool output does not match its classification contract")
                result_labels = {name: declared[name] for name in data}
        if reason != "allowed":
            self.blocked_attempts += 1
        event_labels = result_labels or labels
        data_class = (
            "secret" if "secret" in event_labels.values() else
            "public_outbound" if call.tool_name in OUTBOUND_TOOLS else "internal"
        )
        source_tool = call.tool_name if reason == "allowed" and result_labels else None
        memory_key = args.key if reason == "allowed" and call.tool_name == "memory.write" else None
        batch = (
            self.tool_evidence.source(context, seq, call.tool_name, data, result_labels, call.arguments)
            if source_tool else
            self.tool_evidence.arguments(
                context, seq, call.arguments, allowed=reason == "allowed",
                kind="legacy_memory_write" if memory_key is not None else "outbound_argument",
                memory_key=memory_key,
            )
        )
        accepted_sink = destination if reason == "allowed" and call.tool_name in OUTBOUND_TOOLS else None
        evidence_fields = tuple(SOURCE_FIELDS[source_tool]) if source_tool else fields
        lineage = self.tool_evidence.document(
            batch, context, seq=seq,
            boundary="tool.source" if source_tool else "tool.outbound" if call.tool_name in OUTBOUND_TOOLS else "tool.internal",
            fields=evidence_fields, labels=event_labels, attempt_id=self.attempt_id(context),
            sink=accepted_sink,
        )
        safe_summary = {
            "argument_bytes": len(canonical), "field_count": len(call.arguments),
            "visual": call_shape(context, call.tool_name, call.arguments),
            "attempt_id": self.attempt_id(context),
            "decision_elapsed_ms": decision_elapsed_ms,
            "lineage": lineage, **observation.summary(),
        }
        event = RunEvent(
            run_id=context.run_id,
            event_seq=seq,
            event_type="tool.proposed",
            actor_id=context.actor_id,
            channel="tool",
            tool_name=call.tool_name if call.tool_name in self.tool_inputs else "unknown_tool",
            destination=destination,
            policy_decision="allow" if reason == "allowed" else "block",
            reason_code=reason,
            data_class=data_class,
            taint_labels_json=safe_labels(event_labels, evidence_fields),
            safe_summary_json=safe_summary,
            payload_sha256=digest,
        )
        receipt = None
        if reason == "allowed" and call.tool_name in OUTBOUND_TOOLS:
            receipt = SinkReceipt(
                run_id=context.run_id,
                event_seq=seq,
                sink_name=destination,
                accepted=True,
                byte_length=len(payload),
                payload_sha256=hashlib.sha256(payload).digest(),
                oracle_fragment_json=None,
            )
        try:
            await self.event_store.append(event, receipt)
        except (EventPersistenceInterrupted, EventPersistenceCancelled) as error:
            if error.confirmed_receipt and receipt is not None:
                self._retain_receipt(seq, payload, call.tool_name, context)
            raise
        self.tool_evidence.publish(
            batch, context, source_tool=source_tool, memory_key=memory_key,
        )
        if prepared is not None:
            prepared.publish()
        if source_tool:
            self.taint.record_read(context.actor_id, source_tool, data)
            observe_source = getattr(self.policy, "observe_source", None)
            if observe_source is not None:
                observe_source(source_tool, data)
        if receipt is not None:
            self._retain_receipt(seq, payload, call.tool_name, context)
        self.action_evidence.append(CommittedToolAction(
            seq, context.actor_id, event.tool_name, reason == "allowed", reason,
            self.attempt_id(context), tuple(batch.outputs.items()),
            canonical if canonical_valid and len(canonical) <= MAX_ACTION_EVIDENCE_BYTES else b"",
            tuple((name, tuple(parents)) for name, parents in batch.inputs.items()),
        ))
        result_artifacts = batch.outputs if source_tool else {}
        if self.on_event is not None:
            self.on_event(event)
        result = GatewayResult(reason == "allowed", reason, data, result_labels, result_artifacts)
        if operation_key is not None:
            self._operations[operation_key] = (digest, result)
        return result


    def _retain_receipt(self, seq: int, payload: bytes, tool_name: str, context: TrustedContext) -> None:
        self.accepted_artifacts.append(SinkArtifact(
            seq, payload, tool_name, context.actor_id, self.attempt_id(context),
        ))
        self.accepted_payload_bytes += len(payload)

    def _artifact_labels(
        self, payload: dict[str, Any], context: TrustedContext, *,
        actor_local: bool = False,
    ) -> dict[str, str]:
        """Resolve runtime-owned dependencies; actor-local deliberately loses relay taint."""
        assert self.artifact_registry is not None
        if not set(context.artifact_dependencies) <= set(payload):
            raise ValueError("Provenance names an absent field")
        if not context.trusted_public_fields <= set(payload):
            raise ValueError("Trusted public field is absent")
        if context.trusted_public_fields & set(context.artifact_dependencies):
            raise ValueError("A dependent field cannot be declared public")
        labels: dict[str, str] = {}
        for field in payload:
            if field in context.trusted_public_fields:
                labels[field] = "public"
            else:
                ids = context.artifact_dependencies.get(field, ())
                dependency_labels = tuple(self.artifact_registry.get(item).label for item in ids)
                labels[field] = (
                    "secret" if self.taint.has_secret_read(context.actor_id) else "public"
                ) if actor_local and ids else ProvenanceJoiner.join(dependency_labels)
        return labels

    async def record_research_event(
        self, *, actor_id: str, event_type: str, reason_code: str,
        candidate_hash: str | None = None,
        summary: dict[str, int | bool | str] | None = None,
    ) -> None:
        """Persist only bounded, non-payload adaptive metadata in sequence."""
        context = self.context_guard.context_for(actor_id)
        self.context_guard.validate(context, boundary="research")
        if event_type not in {"candidate.validated", "candidate.rejected"}:
            raise ValueError("Unknown adaptive event type")
        if not reason_code.isascii() or len(reason_code) > 80:
            raise ValueError("Invalid adaptive reason code")
        if candidate_hash is not None and (
            len(candidate_hash) != 64 or
            any(char not in "0123456789abcdef" for char in candidate_hash)
        ):
            raise ValueError("Invalid canonical candidate hash")
        safe = summary or {}
        if len(safe) > 8 or any(
            not isinstance(key, str) or len(key) > 40 or
            not isinstance(value, (int, bool, str)) or
            isinstance(value, str) and len(value) > 80
            for key, value in safe.items()
        ):
            raise ValueError("Unsafe adaptive event summary")
        async with self._lock:
            seq = reserve_event(self)
            event = RunEvent(
                run_id=context.run_id, event_seq=seq,
                event_type=event_type, actor_id=actor_id,
                channel="research", tool_name=None, destination=None,
                policy_decision="review", reason_code=reason_code,
                data_class="internal", taint_labels_json={},
                safe_summary_json={
                    **safe,
                    **({"candidate_hash": candidate_hash} if candidate_hash else {}),
                    "lineage": lineage_document(
                        self.evidence_registry, context, seq=seq, boundary="research",
                        attempt_id=self.attempt_id(context),
                    ),
                },
                payload_sha256=None,
            )
            await self.event_store.append(event)
            if self.on_event is not None:
                self.on_event(event)

    async def forward_message(
        self, context: TrustedContext, recipient: str, payload: dict[str, Any],
    ) -> GatewayResult:
        """Mediate a narrow structured operations-to-writer handoff."""
        self.context_guard.validate(context, boundary="legacy_message")
        async with self._lock:
            seq = reserve_action(self)
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            digest = hashlib.sha256(canonical).digest()
            reason = "allowed"
            message = None
            if (type(recipient) is not str or context.role != "operations_worker"
                    or self.context_guard.runtime_roles.get(recipient) != "response_writer"):
                reason = "message_route_not_allowed"
            elif len(canonical) > 1024:
                reason = "message_too_large"
            else:
                try:
                    message = OperationsMessage.model_validate(payload)
                except ValidationError:
                    reason = "invalid_message"
            labels: dict[str, str] = {}
            if reason == "allowed":
                try:
                    labels = (
                        self._artifact_labels(
                            payload, context, actor_local=self.profile == "actor_local"
                        )
                        if self.artifact_registry is not None
                        else self.taint.label_arguments(
                            context.actor_id, payload, context.derived_from,
                            context.trusted_public_fields,
                        )
                    )
                except ValueError:
                    reason = "invalid_provenance"
            if (reason == "allowed" and self.artifact_registry is not None
                    and "unknown" in labels.values()):
                reason = "unknown_provenance"
            if (reason == "allowed" and self.profile not in UNIFIED_PROFILES
                    and self.policy.enforces_taint() and "secret" in labels.values()):
                reason = "secret_taint_to_message"
            if reason == "allowed" and self.policy.scans_content() and self.policy.contains_secret(
                payload, self.secret
            ):
                reason = "secret_content_match"
            if reason != "allowed":
                self.blocked_attempts += 1
            batch = self.tool_evidence.arguments(
                context, seq, payload, allowed=reason == "allowed", kind="legacy_message",
            )
            message_lineage = self.tool_evidence.document(
                batch, context, seq=seq, boundary="legacy_message",
                fields=tuple(OperationsMessage.model_fields), labels=labels,
                attempt_id=self.attempt_id(context),
                recipient=recipient if type(recipient) is str and recipient in self.context_guard.runtime_roles else None,
            )
            message_event = RunEvent(
                run_id=context.run_id, event_seq=seq, event_type="agent.message",
                actor_id=context.actor_id, channel="message", tool_name=None,
                destination=recipient if type(recipient) is str and recipient in self.context_guard.runtime_roles else "invalid",
                policy_decision="allow" if reason == "allowed" else "block",
                reason_code=reason,
                data_class="secret" if "secret" in labels.values() else "internal",
                taint_labels_json=safe_labels(labels, tuple(OperationsMessage.model_fields)),
                safe_summary_json={
                    "argument_bytes": len(canonical), "field_count": len(payload),
                    "attempt_id": self.attempt_id(context),
                    "observer_coverage": "not_inspected", "observer_phase": None,
                    "lineage": message_lineage,
                },
                payload_sha256=digest,
            )
            await self.event_store.append(message_event)
            if reason == "allowed":
                self.tool_evidence.publish(batch, context, recipient=recipient)
            message_artifacts = batch.outputs
            if self.on_event is not None:
                self.on_event(message_event)
            return GatewayResult(
                reason == "allowed", reason, message.model_dump() if message else None,
                labels, message_artifacts,
            )
