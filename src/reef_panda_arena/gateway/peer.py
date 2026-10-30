"""Run-local mediated peer delivery with authenticated immutable lineage."""

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from secrets import token_bytes
from uuid import uuid4

from reef_panda_arena.gateway.budget import reserve_action, reserve_event
from reef_panda_arena.gateway.invoke import GatewayResult, PolicyGateway, TrustedContext
from reef_panda_arena.gateway.provenance import ArtifactRegistry, ProvenanceJoiner
from reef_panda_arena.gateway.lineage_evidence import SAFE_FIELDS, lineage_document
from reef_panda_arena.telemetry.public_fields import safe_labels
from reef_panda_arena.storage.models import RunEvent
from reef_panda_arena.telemetry.call_shape import trace_phase


_ENVELOPE_VERSION = "peer-envelope-v1"
_MESSAGE_KINDS = {"artifact", "request", "control"}


def _canonical(value) -> bytes:
    """Finite JSON without coercing keys or retaining mutable caller objects."""
    def validate(item, depth=0):
        if depth > 32:
            raise ValueError("Peer JSON nesting limit exceeded")
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("Peer JSON keys must be strings")
            for child in item.values():
                validate(child, depth + 1)
        elif type(item) is list:
            for child in item:
                validate(child, depth + 1)
        elif item is not None and type(item) not in {str, bool, int, float}:
            raise ValueError("Invalid peer JSON value")
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _snapshot(context: TrustedContext, payload: dict, kind: str):
    if type(payload) is not dict:
        raise ValueError("Peer payload must be an object")
    canonical = _canonical({"kind": kind, "payload": payload})
    copied = json.loads(canonical)["payload"]
    dependencies = {}
    for name, parents in context.artifact_dependencies.items():
        if type(name) is not str or type(parents) not in {tuple, list}:
            raise ValueError("Invalid peer dependency map")
        ids = tuple(parents)
        if any(type(parent) is not str or not parent for parent in ids):
            raise ValueError("Invalid peer dependency ID")
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate peer dependency")
        dependencies[name] = ids
    public = frozenset(context.trusted_public_fields)
    if any(type(name) is not str for name in public):
        raise ValueError("Invalid public field declaration")
    return replace(context, artifact_dependencies=dependencies,
                   trusted_public_fields=public), copied, canonical


@dataclass(frozen=True)
class _QueuedMessage:
    envelope: bytes
    origin_mac: bytes


class PeerMessageCaller:
    """Only this wrapper may turn a proposed A-to-B message into a consumed one."""

    def __init__(
        self, gateway: PolicyGateway, registry: ArtifactRegistry,
        routes: frozenset[tuple[str, str]],
    ) -> None:
        if gateway.artifact_registry is not registry:
            raise ValueError("Peer caller must share the gateway artifact registry")
        routes = frozenset(routes)
        gateway.context_guard.members(actor for route in routes for actor in route)
        if not routes or any(
            sender == recipient or sender not in {f"A{i}" for i in range(10)}
            or recipient not in {f"A{i}" for i in range(10)}
            for sender, recipient in routes
        ):
            raise ValueError("Invalid peer route set")
        self.gateway = gateway
        self.registry = registry
        self.routes = routes
        self._origin_key = token_bytes(32)
        self._queued: dict[str, _QueuedMessage] = {}
        self._max_envelope_bytes = gateway.max_payload_bytes * 4 + 4096

    def _reserve(self) -> int:
        return reserve_action(self.gateway)

    def _origin_mac(self, envelope: bytes) -> bytes:
        return hmac.digest(self._origin_key, b"reef-panda:peer-envelope-v1\0" + envelope, "sha256")

    def _verify(self, message_id: str, queued: _QueuedMessage) -> dict:
        """Authenticate bytes, then validate every parent before any child exists."""
        if (type(queued.envelope) is not bytes or type(queued.origin_mac) is not bytes
                or len(queued.envelope) > self._max_envelope_bytes
                or not hmac.compare_digest(queued.origin_mac, self._origin_mac(queued.envelope))):
            raise ValueError("Invalid peer envelope MAC")
        item = json.loads(queued.envelope)
        if type(item) is not dict or set(item) != {
            "version", "run_id", "sender", "recipient", "kind", "message_id",
            "event_seq", "payload", "artifact_ids", "parent_ids", "public_fields",
        }:
            raise ValueError("Invalid peer envelope shape")
        if _canonical(item) != queued.envelope:
            raise ValueError("Noncanonical peer envelope")
        if (item["version"] != _ENVELOPE_VERSION or item["run_id"] != self.registry.run_id
                or item["message_id"] != message_id or item["kind"] not in _MESSAGE_KINDS
                or (item["sender"], item["recipient"]) not in self.routes
                or type(item["event_seq"]) is not int or item["event_seq"] < 1
                or type(item["payload"]) is not dict or not item["payload"]
                or type(item["artifact_ids"]) is not dict or type(item["parent_ids"]) is not dict
                or type(item["public_fields"]) is not list):
            raise ValueError("Invalid peer envelope metadata")
        payload = item["payload"]
        if set(payload) != set(item["artifact_ids"]) or set(payload) != set(item["parent_ids"]):
            raise ValueError("Peer envelope field mismatch")
        public = item["public_fields"]
        if any(type(name) is not str for name in public) or sorted(set(public)) != public or not set(public) <= set(payload):
            raise ValueError("Invalid peer public fields")
        if len(_canonical({"kind": item["kind"], "payload": payload})) > self.gateway.max_payload_bytes:
            raise ValueError("Peer payload exceeds limit")
        for name, value in payload.items():
            artifact_id, parents = item["artifact_ids"][name], item["parent_ids"][name]
            if (type(artifact_id) is not str or type(parents) is not list
                    or any(type(parent) is not str or not parent for parent in parents)
                    or len(set(parents)) != len(parents)
                    or (name in public) != (not parents)):
                raise ValueError("Invalid peer envelope dependencies")
            artifact = self.registry.get(artifact_id)
            registered_parents = tuple(self.registry.get(parent) for parent in parents)
            if (artifact.run_id != item["run_id"] or artifact.actor_id != item["sender"]
                    or artifact.event_seq != item["event_seq"]
                    or artifact.kind != ("peer_send" if parents else "trusted_public_message")
                    or artifact.parent_ids != tuple(parents)
                    or artifact.payload_sha256 != hashlib.sha256(_canonical(value)).hexdigest()
                    or any(parent.run_id != item["run_id"] for parent in registered_parents)
                    or artifact.label != (ProvenanceJoiner.join(tuple(parent.label for parent in registered_parents)) if parents else "public")):
                raise ValueError("Peer artifact differs from authenticated envelope")
        return item

    async def send(
        self, context: TrustedContext, recipient: str, payload: dict,
        *, kind: str = "artifact",
    ) -> GatewayResult:
        self.gateway.context_guard.validate(context, boundary="peer_send")
        # Snapshot before even awaiting the gateway lock; caller references never
        # cross a suspension point into message or artifact construction.
        snapshot_error = False
        try:
            context, payload, canonical = _snapshot(context, payload, kind)
        except (AttributeError, TypeError, ValueError, RecursionError):
            payload, canonical, snapshot_error = {}, b"<invalid-json>", True
        async with self.gateway._lock:
            seq = self._reserve()
            reason = "allowed"
            labels: dict[str, str] = {}
            message_id = uuid4().hex
            envelope = {}
            try:
                if snapshot_error:
                    reason = "invalid_provenance"
                elif not isinstance(payload, dict) or not payload:
                    reason = "invalid_message"
                elif type(kind) is not str or kind not in _MESSAGE_KINDS:
                    reason = "invalid_message_kind"
                elif type(recipient) is not str or (context.actor_id, recipient) not in self.routes:
                    reason = "message_route_not_allowed"
                elif len(canonical) > self.gateway.max_payload_bytes:
                    reason = "message_too_large"
                else:
                    labels = self.gateway._artifact_labels(
                        payload, context, actor_local=self.gateway.profile == "actor_local",
                    )
                    if "unknown" in labels.values():
                        reason = "unknown_provenance"
                    envelope = {
                        "version": _ENVELOPE_VERSION, "run_id": context.run_id,
                        "sender": context.actor_id, "recipient": recipient,
                        "kind": kind, "message_id": message_id, "event_seq": seq,
                        "payload": payload,
                        "artifact_ids": {name: "0" * 32 for name in payload},
                        "parent_ids": {name: list(context.artifact_dependencies.get(name, ())) for name in payload},
                        "public_fields": sorted(context.trusted_public_fields),
                    }
                    # Registry IDs are fixed-width UUID hex strings; reserve the
                    # exact envelope size before committing an allow decision.
                    if len(_canonical(envelope)) > self._max_envelope_bytes:
                        reason = "message_too_large"
            except (TypeError, ValueError, RecursionError):
                reason = "invalid_provenance"
            prepared = ()
            artifact_ids: dict[str, str] = {}
            queued = None
            if reason == "allowed":
                prepared = tuple(
                    self.registry.prepare_derived(
                        event_seq=seq, actor_id=context.actor_id, kind="peer_send",
                        parent_ids=context.artifact_dependencies[name], payload=_canonical(value),
                    ) if context.artifact_dependencies.get(name) else self.registry.prepare_source(
                        event_seq=seq, actor_id=context.actor_id, kind="trusted_public_message",
                        label="public", payload=_canonical(value),
                    ) for name, value in payload.items()
                )
                artifact_ids = {name: node.artifact_id for name, node in zip(payload, prepared)}
                envelope["artifact_ids"] = artifact_ids
                encoded = _canonical(envelope)
                queued = _QueuedMessage(encoded, self._origin_mac(encoded))
            inputs = ({name: context.artifact_dependencies.get(name, ()) for name in payload}
                      if not snapshot_error else {})
            lineage = lineage_document(
                self.registry, context, seq=seq, boundary="peer.send", nodes=prepared,
                inputs=inputs, outputs=artifact_ids, field_names=SAFE_FIELDS,
                effective_labels=labels, attempt_id=self.gateway.attempt_id(context),
                dependency_basis={name: "explicit_registered_parents" if inputs[name] else
                                  "trusted_public_contract" for name in inputs},
                coverage="complete" if reason == "allowed" else "partial",
                reasons=() if reason == "allowed" else ("denied_proposal",),
                metadata={"message_id": message_id, "sender_id": context.actor_id,
                          "recipient_id": recipient} if reason == "allowed" else {},
            )
            digest = hashlib.sha256(canonical).digest()
            event = RunEvent(
                run_id=context.run_id, event_seq=seq, event_type="agent.message",
                actor_id=context.actor_id, channel="message", tool_name=None,
                destination=recipient if type(recipient) is str and (context.actor_id, recipient) in self.routes else "invalid",
                policy_decision="allow" if reason == "allowed" else "block",
                reason_code=reason, data_class=(
                    "secret" if "secret" in labels.values() else
                    "unknown" if "unknown" in labels.values() else "internal"
                ),
                taint_labels_json=safe_labels(labels, SAFE_FIELDS),
                safe_summary_json={
                    "lineage": lineage,
                    "visual": {
                        "phase": trace_phase(context),
                        **({"representation": "decimal_bytes"} if "byte_values" in payload else {}),
                        **({"representation": "semantic_summary"} if context.trace_representation == "semantic_summary" else {}),
                    },
                    "argument_bytes": len(canonical), "field_count": len(payload),
                    "payload_kind": kind if type(kind) is str and kind in _MESSAGE_KINDS else "invalid",
                    "envelope_version": _ENVELOPE_VERSION,
                    **({"message_id": message_id} if reason == "allowed" else {}),
                },
                payload_sha256=digest,
            )
            await self.gateway.event_store.append(event)
            if reason == "allowed":
                self.registry.commit_prepared(prepared)
                self._queued[message_id] = queued
            else:
                self.gateway.blocked_attempts += 1
            if self.gateway.on_event is not None:
                self.gateway.on_event(event)
            return GatewayResult(
                reason == "allowed", reason,
                {"message_id": message_id} if reason == "allowed" else None,
                dict(labels), dict(artifact_ids),
            )

    async def receive(self, context: TrustedContext, message_id: str) -> GatewayResult:
        self.gateway.context_guard.validate(context, boundary="peer_receive")
        async with self.gateway._lock:
            reserve_action(self.gateway, record_event=False)
            queued = self._queued.get(message_id)
            if queued is None:
                raise ValueError("Unknown or already consumed peer message")
            seq = reserve_event(self.gateway)
            envelope = None
            reason = "allowed"
            try:
                envelope = self._verify(message_id, queued)
            except (TypeError, ValueError, RecursionError, UnicodeError):
                reason = "invalid_runtime_origin"
            if envelope is not None:
                if context.actor_id != envelope["recipient"]:
                    reason = "message_recipient_mismatch"
            payload = envelope["payload"] if envelope else {}
            canonical = _canonical({"kind": envelope["kind"], "payload": payload}) if envelope else None
            labels: dict[str, str] = {}
            artifacts: dict[str, str] = {}
            if reason == "allowed":
                label_context = TrustedContext(
                    context.run_id, context.actor_id, context.role,
                    artifact_dependencies={name: (parent,) for name, parent in envelope["artifact_ids"].items()},
                )
                labels = self.gateway._artifact_labels(
                    payload, label_context, actor_local=self.gateway.profile == "actor_local",
                )
            prepared = ()
            inputs = ({name: (parent,) for name, parent in envelope["artifact_ids"].items()}
                      if envelope else {})
            if reason == "allowed":
                prepared = tuple(self.registry.prepare_derived(
                    event_seq=seq, actor_id=context.actor_id, kind="peer_receive",
                    parent_ids=inputs[name], payload=_canonical(payload[name]),
                ) for name in payload)
                artifacts = {name: node.artifact_id for name, node in zip(payload, prepared)}
            lineage = lineage_document(
                self.registry, context, seq=seq, boundary="peer.receive", nodes=prepared,
                inputs=inputs, outputs=artifacts, field_names=SAFE_FIELDS,
                effective_labels=labels, attempt_id=self.gateway.attempt_id(context),
                coverage="complete" if reason == "allowed" else "partial",
                reasons=() if reason == "allowed" else ("denied_proposal",),
                metadata={"message_id": message_id, "sender_id": envelope["sender"],
                          "recipient_id": envelope["recipient"]} if envelope else {},
            )
            event = RunEvent(
                run_id=context.run_id, event_seq=seq, event_type="agent.receive",
                actor_id=context.actor_id, channel="message", tool_name=None,
                destination=context.actor_id,
                policy_decision="allow" if reason == "allowed" else "block",
                reason_code=reason, data_class=(
                    "secret" if "secret" in labels.values() else "internal"
                ),
                taint_labels_json=safe_labels(labels, SAFE_FIELDS),
                safe_summary_json={
                    "lineage": lineage,
                    "visual": {"phase": trace_phase(context)},
                    "argument_bytes": len(canonical) if canonical is not None else None,
                    "field_count": len(payload) if envelope else None,
                    **({"message_id": message_id} if envelope else {}),
                    "payload_kind": envelope["kind"] if envelope else "invalid",
                    "envelope_version": _ENVELOPE_VERSION,
                    "integrity_verified": envelope is not None,
                },
                payload_sha256=hashlib.sha256(canonical).digest() if canonical is not None else None,
            )
            await self.gateway.event_store.append(event)
            if reason == "allowed":
                self.registry.commit_prepared(prepared)
                del self._queued[message_id]
            else:
                self.gateway.blocked_attempts += 1
            if self.gateway.on_event is not None:
                self.gateway.on_event(event)
            return GatewayResult(
                reason == "allowed", reason, payload if reason == "allowed" else None,
                dict(labels), dict(artifacts),
            )
