"""Detached per-actor model inputs backed by committed same-actor artifacts."""

from dataclasses import dataclass
import hashlib
import json

from reef_panda_arena.gateway.invoke import GatewayResult
from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.model.role_contract import bounded_data


@dataclass(frozen=True, slots=True, repr=False)
class RoleInput:
    run_id: str
    actor_id: str
    _encoded: str
    _metadata: str
    field_artifacts: tuple[tuple[str, str], ...]
    event_seqs: tuple[int, ...]

    @property
    def artifact_ids(self):
        return tuple(identity for _, identity in self.field_artifacts)

    def metadata(self):
        return json.loads(self._metadata)

    def values(self):
        return json.loads(self._encoded)


def accepted_role_input(result: GatewayResult, *, registry: ArtifactRegistry, actor_id: str) -> RoleInput:
    if type(result) is not GatewayResult or result.allowed is not True or type(result.data) is not dict:
        raise ValueError("Role input requires an accepted boundary result")
    if not result.artifact_ids or not set(result.artifact_ids) <= set(result.data):
        raise ValueError("Role input lacks published field evidence")
    if actor_id not in {f"A{index}" for index in range(10)}:
        raise ValueError("Unknown model role")
    values, sequences = {}, set()
    for name, identity in result.artifact_ids.items():
        artifact = registry.get(identity)
        if artifact.run_id != registry.run_id or artifact.actor_id != actor_id:
            raise ValueError("Role input is owned by a different runtime actor")
        value = result.data[name]
        if artifact.kind.startswith(("shipment.lookup.", "private.account.", "operations.incident.")):
            encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()
        elif artifact.kind == "peer_receive" or artifact.kind == "trusted_projection":
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
        elif artifact.kind in {"memory_read", "memory_compact"} and type(value) is str:
            encoded = value.encode()
        else:
            raise ValueError("Artifact is not a supported model input boundary")
        if hashlib.sha256(encoded).hexdigest() != artifact.payload_sha256:
            raise ValueError("Role input differs from committed bytes")
        values[name] = value
        sequences.add(artifact.event_seq)
    metadata = {"labels": {name: result.field_labels.get(name, "unknown") for name in values},
                "release_scopes": {name: registry.release_scopes(identity)
                                   for name, identity in result.artifact_ids.items()}}
    if any(label not in {"public", "internal", "secret", "unknown"} for label in metadata["labels"].values()):
        raise ValueError("Unknown effective role label")
    return RoleInput(registry.run_id, actor_id, bounded_data(values), bounded_data(metadata),
                     tuple(sorted(result.artifact_ids.items())), tuple(sorted(sequences)))
