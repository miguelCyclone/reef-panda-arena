"""Bounded, payload-free lineage documents committed with boundary events."""

import json
import re
from collections.abc import Mapping

from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.gateway.taint import SOURCE_FIELDS
from reef_panda_arena.telemetry.public_fields import safe_field_map


MAX_NODES = 16
MAX_PARENTS = 16
MAX_REFERENCES = 128
MAX_DOCUMENT_BYTES = 32 * 1024
LABELS = frozenset({"public", "internal", "secret", "unknown"})
SOURCE_KINDS = {f"{source}.{field}": (source, field)
                for source, fields in SOURCE_FIELDS.items() for field in fields}
SAFE_FIELDS = frozenset({field for fields in SOURCE_FIELDS.values() for field in fields} | {
    "shipment_id", "customer_id", "text", "value", "category", "metric_name",
    "metrics", "labels", "key", "message", "action_id", "context", "case_id",
    "step_index", "schedule", "patient_reference", "recipient", "specialty", "requested_time_window",
})
TRANSFORMS = frozenset(SOURCE_KINDS) | frozenset({
    "source_read", "derived", "trusted_public_message", "peer_send", "peer_receive",
    "memory_write", "memory_read", "memory_compact", "reducer_join", "trusted_projection",
    "outbound_argument", "legacy_message", "legacy_memory_write", "legacy_memory_read",
    "legacy_memory_compact", "trusted_public_argument", "unknown_argument",
})
DEPENDENCY_BASES = frozenset({
    "explicit_registered_parents", "conservative_actor_exposure", "trusted_source_contract",
    "trusted_public_contract", "trusted_projection", "unknown",
})
BOUNDARIES = frozenset({
    "tool.source", "tool.outbound", "tool.other", "tool.internal", "peer.send", "peer.receive",
    "memory.write", "memory.read", "memory.compact", "reducer.join",
    "projection.release", "legacy.message", "legacy_message", "research",
})
REASONS = frozenset({
    "missing_dependencies", "unregistered_parent", "invalid_dependencies",
    "boundary_not_instrumented", "historical_evidence_unavailable", "unknown_provenance",
    "invalid_provenance", "no_output", "denied_proposal", "source_contract_unavailable",
    "conservative_actor_exposure", "evidence_budget_exceeded",
})
SINKS = frozenset({"mock_customer_outbound", "local_analytics_sink",
                   "mock_external_approval_queue", "local_shared_memory", "local_workflow_state", "mock_clinic"})
_METADATA_FIELDS = frozenset({"message_id", "sender_id", "recipient_id", "memory_slot_id", "memory_version"})
_DOCUMENT_FIELDS = frozenset({"version", "run_id", "event_seq", "actor_id", "boundary", "attempt_id",
                              "coverage", "reasons", "nodes", "inputs", "outputs", "receipt", "metadata"})
_NODE_FIELDS = frozenset({"artifact_id", "run_id", "event_seq", "actor_id", "field", "source_type",
                          "source_field", "transform", "parent_ids", "stored_label", "effective_label",
                          "dependency_basis", "release_purpose", "release_recipient"})


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid lineage-v1 evidence")


def _identifier(value) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is not None


def _artifact_id(value) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def _field(value) -> bool:
    return type(value) is str and (value in SAFE_FIELDS or re.fullmatch(r"field:(?:[0-9]|1[0-5])", value) is not None)


def validate_lineage_document(document: dict) -> dict:
    """Validate and detach persisted/public metadata without a runtime registry."""
    try:
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise ValueError("lineage_evidence_budget_exceeded")
        result = json.loads(encoded)
        _require(type(result) is dict and set(result) == _DOCUMENT_FIELDS)
        _require(result["version"] == "lineage-v1" and result["boundary"] in BOUNDARIES)
        _require(_identifier(result["run_id"]) and _identifier(result["actor_id"]))
        _require(type(result["event_seq"]) is int and result["event_seq"] >= 0)
        _require(type(result["attempt_id"]) is str and re.fullmatch(r"task|attack:live|attack:[1-9][0-9]*|candidate:[1-9][0-9]*", result["attempt_id"]) is not None)
        _require(result["coverage"] in {"complete", "partial", "not_instrumented"})
        _require(type(result["reasons"]) is list and len(result["reasons"]) <= len(REASONS)
                 and all(reason in REASONS for reason in result["reasons"]))
        nodes, inputs, outputs = result["nodes"], result["inputs"], result["outputs"]
        _require(type(nodes) is list and type(inputs) is dict and type(outputs) is dict)
        if max(len(nodes), len(inputs), len(outputs)) > MAX_NODES:
            raise ValueError("lineage_evidence_budget_exceeded")
        references = 0
        ids, fields = set(), set()
        for node in nodes:
            _require(type(node) is dict and set(node) == _NODE_FIELDS)
            _require(_artifact_id(node["artifact_id"]) and node["artifact_id"] not in ids)
            _require(node["run_id"] == result["run_id"] and node["event_seq"] == result["event_seq"]
                     and node["actor_id"] == result["actor_id"])
            _require(_field(node["field"]) and node["field"] not in fields)
            _require(node["transform"] in TRANSFORMS and node["dependency_basis"] in DEPENDENCY_BASES)
            _require(node["stored_label"] in LABELS and node["effective_label"] in LABELS)
            parents = node["parent_ids"]
            _require(type(parents) is list and len(parents) <= MAX_PARENTS
                     and all(_artifact_id(parent) for parent in parents) and len(set(parents)) == len(parents))
            source = SOURCE_KINDS.get(node["transform"], (None, None))
            _require((node["source_type"], node["source_field"]) == source)
            scope = (node["release_purpose"], node["release_recipient"])
            _require(scope == (None, None) or (
                node["transform"] == "trusted_projection" and node["stored_label"] == "public"
                and len(parents) == 1 and scope in {("shipping_delay_notice", "CUS-008"), ("medical_booking", "mock_clinic")}))
            _require(outputs.get(node["field"]) == node["artifact_id"])
            _require(inputs.get(node["field"], []) == parents)
            references += len(parents)
            ids.add(node["artifact_id"])
            fields.add(node["field"])
        _require(set(outputs) == fields)
        for field, parents in inputs.items():
            _require(_field(field) and type(parents) is list and len(parents) <= MAX_PARENTS
                     and all(_artifact_id(parent) for parent in parents) and len(set(parents)) == len(parents))
            references += len(parents)
        references += len(outputs)
        metadata = result["metadata"]
        _require(type(metadata) is dict and set(metadata) <= _METADATA_FIELDS)
        for name, value in metadata.items():
            _require((type(value) is int and value >= 1) if name == "memory_version" else
                     _artifact_id(value) if name in {"message_id", "memory_slot_id"} else _identifier(value))
        receipt = result["receipt"]
        if receipt is not None:
            _require(type(receipt) is dict and set(receipt) == {"event_seq", "accepted", "argument_artifact_ids", "sink"})
            _require(receipt["event_seq"] == result["event_seq"] and type(receipt["accepted"]) is bool
                     and receipt["sink"] in SINKS)
            arguments = receipt["argument_artifact_ids"]
            _require(type(arguments) is list and len(arguments) <= MAX_NODES
                     and len(set(arguments)) == len(arguments) and set(arguments) <= ids)
            references += len(arguments)
        if references > MAX_REFERENCES:
            raise ValueError("lineage_evidence_budget_exceeded")
        return result
    except (TypeError, KeyError, RecursionError, OverflowError) as error:
        raise ValueError("Invalid lineage-v1 evidence") from error


def lineage_document(
    registry: ArtifactRegistry, context, *, seq: int, boundary: str, nodes=(),
    inputs: Mapping | None = None, outputs: Mapping | None = None, field_names=(),
    effective_labels: Mapping | None = None, dependency_basis="explicit_registered_parents",
    coverage="complete", reasons=(), receipt=None, metadata=None, attempt_id=None,
) -> dict:
    """Prepare safe journal metadata before any event, receipt or node publication.

    Invalid/unregistered input references on a denied proposal are explicitly
    omitted as partial evidence. Essential evidence is never silently truncated.
    """
    registry.validate_prepared(nodes)
    inputs, outputs, effective_labels = dict(inputs or {}), dict(outputs or {}), dict(effective_labels or {})
    _require(context.run_id == registry.run_id)
    _require(set(field_names) <= SAFE_FIELDS)
    raw_fields = set(inputs) | set(outputs) | set(effective_labels)
    _require(all(type(field) is str for field in raw_fields))
    if len(raw_fields) > MAX_NODES:
        raise ValueError("lineage_evidence_budget_exceeded")
    mapping = safe_field_map(raw_fields, field_names)
    safe_inputs = {}
    reason_set = set(reasons)
    for field, parents in inputs.items():
        if type(parents) not in {tuple, list}:
            parents = ()
            coverage = "partial"
            reason_set.add("invalid_dependencies")
        if len(parents) > MAX_PARENTS:
            raise ValueError("lineage_evidence_budget_exceeded")
        registered = []
        for parent_id in parents:
            try:
                parent = registry.get(parent_id)
                if parent.run_id != context.run_id or parent.event_seq > seq:
                    raise ValueError("Invalid parent ownership")
            except (ValueError, TypeError):
                coverage = "partial"
                reason_set.add("unregistered_parent")
                continue
            if parent_id in registered:
                coverage = "partial"
                reason_set.add("invalid_dependencies")
                continue
            registered.append(parent_id)
        safe_inputs[mapping[field]] = registered
    reverse_outputs = {artifact_id: field for field, artifact_id in outputs.items()}
    _require(len(reverse_outputs) == len(outputs) == len(nodes))
    public_nodes = []
    for node in nodes:
        field = reverse_outputs.get(node.artifact_id)
        _require(field is not None and node.run_id == context.run_id and node.actor_id == context.actor_id and node.event_seq == seq)
        transform = node.kind if node.kind in TRANSFORMS else "derived" if node.parent_ids else "source_read"
        source_type, source_field = SOURCE_KINDS.get(transform, (None, None))
        basis = dependency_basis.get(field, "unknown") if isinstance(dependency_basis, Mapping) else dependency_basis
        public_nodes.append({
            "artifact_id": node.artifact_id, "run_id": node.run_id, "event_seq": node.event_seq,
            "actor_id": node.actor_id, "field": mapping[field], "source_type": source_type,
            "source_field": source_field, "transform": transform, "parent_ids": list(node.parent_ids),
            "stored_label": node.label, "effective_label": effective_labels.get(field, node.label),
            "dependency_basis": basis, "release_purpose": node.release_purpose,
            "release_recipient": node.release_recipient,
        })
    document = {
        "version": "lineage-v1", "run_id": context.run_id, "event_seq": seq,
        "actor_id": context.actor_id, "boundary": boundary,
        "attempt_id": attempt_id or context.attempt_id or "task", "coverage": coverage,
        "reasons": sorted(reason_set), "nodes": public_nodes, "inputs": safe_inputs,
        "outputs": {mapping[field]: artifact_id for field, artifact_id in outputs.items()},
        "receipt": receipt, "metadata": dict(metadata or {}),
    }
    return validate_lineage_document(document)
