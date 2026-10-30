"""Versioned tool lineage independent of legacy taint enforcement selection."""

import json
from dataclasses import dataclass, field
from uuid import uuid4

from reef_panda_arena.gateway.lineage_evidence import lineage_document
from reef_panda_arena.gateway.provenance import Artifact, ArtifactRegistry
from reef_panda_arena.gateway.taint import SOURCE_FIELDS


def _bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class EvidenceBatch:
    nodes: tuple[Artifact, ...]
    inputs: dict[str, tuple[str, ...]]
    outputs: dict[str, str]
    bases: dict[str, str]
    coverage: str = "complete"
    reasons: tuple[str, ...] = ()
    metadata: dict = field(default_factory=dict)


class ToolEvidence:
    """Sources are exact versions; unspecific legacy outputs overapproximate exposure.

    This registry does not select or change the enforcing policy. An actor's
    prior observed sources are a conservative dependency set, not proof that
    a particular output value mathematically depends on every source.
    """

    def __init__(self, registry: ArtifactRegistry, *, explicit: bool) -> None:
        self.registry = registry
        self.explicit = explicit
        self._sources: dict[str, dict[str, str]] = {}
        self._exposure: dict[str, list[str]] = {}
        self._memory: dict[str, tuple[str, int, str]] = {}

    def source(self, context, seq: int, tool: str, data: dict,
               labels: dict[str, str], arguments: dict) -> EvidenceBatch:
        nodes, inputs, outputs, bases = [], {}, {}, {}
        coverage, reasons, metadata = "complete", (), {}
        memory = self._memory.get(arguments.get("key")) if tool == "memory.read" else None
        for name, label in labels.items():
            if memory is not None:
                parents = (memory[2],)
                node = self.registry.prepare_derived(
                    event_seq=seq, actor_id=context.actor_id, kind="legacy_memory_read",
                    parent_ids=parents, payload=_bytes(data[name]),
                )
                inputs[name] = parents
                bases[name] = "explicit_registered_parents"
                metadata = {"memory_slot_id": memory[0], "memory_version": memory[1]}
            else:
                node = self.registry.prepare_source(
                    event_seq=seq, actor_id=context.actor_id, label=label,
                    payload=_bytes(data[name]), kind=f"{tool}.{name}",
                )
                bases[name] = "trusted_source_contract"
                if tool == "memory.read":
                    coverage, reasons = "partial", ("missing_dependencies",)
            nodes.append(node)
            outputs[name] = node.artifact_id
        return EvidenceBatch(tuple(nodes), inputs, outputs, bases, coverage, reasons, metadata)

    def arguments(self, context, seq: int, arguments: dict, *, allowed: bool,
                  kind: str, memory_key: str | None = None) -> EvidenceBatch:
        nodes, inputs, outputs, bases = [], {}, {}, {}
        coverage, reasons = "complete", set()
        sources = self._sources.get(context.actor_id, {})
        exposed = tuple(self._exposure.get(context.actor_id, ()))
        for name, value in arguments.items():
            if self.explicit or name in context.artifact_dependencies:
                parents = tuple(context.artifact_dependencies.get(name, ()))
                basis = "explicit_registered_parents"
            elif context.derived_from.get(name):
                references = context.derived_from[name]
                parents = tuple(dict.fromkeys(sources[ref] for ref in references if ref in sources))
                basis = "explicit_registered_parents"
                if any(ref not in sources for ref in references):
                    coverage = "partial"
                    reasons.add("missing_dependencies")
            else:
                parents, basis = exposed, "conservative_actor_exposure"
            registered = []
            for parent in parents:
                try:
                    self.registry.get(parent)
                except (ValueError, TypeError):
                    if allowed:
                        raise ValueError("Unknown accepted argument dependency")
                    coverage = "partial"
                    reasons.add("unregistered_parent")
                else:
                    if parent not in registered:
                        registered.append(parent)
            parents = tuple(registered)
            inputs[name] = parents
            bases[name] = basis
            if not allowed:
                continue
            if parents:
                node = self.registry.prepare_derived(
                    event_seq=seq, actor_id=context.actor_id, kind=kind,
                    parent_ids=parents, payload=_bytes(value),
                )
            else:
                public = name in context.trusted_public_fields
                node = self.registry.prepare_source(
                    event_seq=seq, actor_id=context.actor_id,
                    label="public" if public else "unknown", payload=_bytes(value),
                    kind="trusted_public_argument" if public else "unknown_argument",
                )
                bases[name] = "trusted_public_contract" if public else "unknown"
                if not public:
                    coverage = "partial"
                    reasons.add("unknown_provenance")
            outputs[name] = node.artifact_id
            nodes.append(node)
        metadata = {}
        if memory_key is not None and allowed:
            previous = self._memory.get(memory_key)
            metadata = {
                "memory_slot_id": previous[0] if previous else uuid4().hex,
                "memory_version": previous[1] + 1 if previous else 1,
            }
        return EvidenceBatch(tuple(nodes), inputs, outputs, bases, coverage, tuple(sorted(reasons)), metadata)

    def document(self, batch: EvidenceBatch, context, *, seq: int, boundary: str,
                 fields: tuple[str, ...], labels: dict[str, str], attempt_id: str,
                 sink: str | None = None, recipient: str | None = None) -> dict:
        metadata = dict(batch.metadata)
        if recipient is not None:
            metadata.update(sender_id=context.actor_id, recipient_id=recipient)
        return lineage_document(
            self.registry, context, seq=seq, boundary=boundary, nodes=batch.nodes,
            inputs=batch.inputs, outputs=batch.outputs, field_names=fields,
            effective_labels=labels, dependency_basis=batch.bases,
            coverage=batch.coverage, reasons=batch.reasons, metadata=metadata,
            attempt_id=attempt_id,
            receipt=({
                "event_seq": seq, "accepted": True,
                "argument_artifact_ids": list(batch.outputs.values()), "sink": sink,
            } if sink is not None else None),
        )

    def publish(self, batch: EvidenceBatch, context, *, source_tool: str | None = None,
                recipient: str | None = None, memory_key: str | None = None) -> None:
        self.registry.commit_prepared(batch.nodes)
        if source_tool is not None:
            sources = self._sources.setdefault(context.actor_id, {})
            for name, artifact_id in batch.outputs.items():
                sources[f"{source_tool}.{name}"] = artifact_id
            self._expose(context.actor_id, batch.outputs.values())
        if recipient is not None:
            self._expose(recipient, batch.outputs.values())
        if memory_key is not None:
            self._memory[memory_key] = (
                batch.metadata["memory_slot_id"], batch.metadata["memory_version"],
                batch.outputs["message"],
            )

    def _expose(self, actor: str, artifact_ids) -> None:
        exposed = self._exposure.setdefault(actor, [])
        for artifact_id in artifact_ids:
            if artifact_id not in exposed:
                exposed.append(artifact_id)
