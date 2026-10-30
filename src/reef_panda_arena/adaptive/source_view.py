"""Detached proposer input created only from a validated published source read."""

import hashlib
import json
from dataclasses import dataclass

from reef_panda_arena.adaptive.fixtures import AdaptiveCase
from reef_panda_arena.adaptive.release import AdaptiveReleasePolicy
from reef_panda_arena.gateway.invoke import GatewayResult
from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.gateway.taint import SOURCE_FIELDS


@dataclass(frozen=True, slots=True, repr=False)
class AcceptedSourceView:
    """Only granted source data and the public task hint; no receiver/oracle state.

    Immutable serialized data avoids sharing nested fixture dictionaries with a
    proposer. The property returns a fresh copy for each consumer. This is an
    application contract inside trusted Python, not a process isolation claim.
    """

    scenario_id: str
    public_hint: str
    _source_json: bytes

    @property
    def source_record(self) -> dict:
        return json.loads(self._source_json)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")


def accepted_source_view(
    case: AdaptiveCase, source: GatewayResult, *, registry: ArtifactRegistry,
    run_id: str, actor_id: str,
) -> AcceptedSourceView:
    """Validate accepted bytes against their published same-reader source roots."""
    if not isinstance(source, GatewayResult) or source.allowed is not True or source.reason != "allowed":
        raise ValueError("Adaptive proposer requires an accepted source read")
    AdaptiveReleasePolicy.validate_source(case, source)
    if registry.run_id != run_id or actor_id != "customer_worker":
        raise ValueError("Adaptive source runtime binding differs")
    expected_tool = "adaptive.holdout" if case.split == "holdout" else "adaptive.source"
    if case.source_tool != expected_tool or (case.split == "holdout" and case.scenario_id != "C28"):
        raise ValueError("Adaptive source contract differs")
    fields = SOURCE_FIELDS[expected_tool]
    if (set(source.data) != set(fields) or set(source.artifact_ids) != set(fields)
            or any(type(value) is not str for value in source.artifact_ids.values())
            or len(set(source.artifact_ids.values())) != len(fields)):
        raise ValueError("Adaptive source evidence is incomplete")
    encoded = _canonical(source.data)
    if len(encoded) > 4096 or encoded != _canonical(case.source_record):
        raise ValueError("Adaptive source data differs from the authorized case")
    sequences = set()
    for name, artifact_id in source.artifact_ids.items():
        artifact = registry.get(artifact_id)
        if (artifact.run_id != run_id or artifact.actor_id != actor_id
                or artifact.kind != f"{expected_tool}.{name}" or artifact.label != "secret"
                or artifact.parent_ids or artifact.release_purpose is not None
                or artifact.release_recipient is not None
                or artifact.payload_sha256 != hashlib.sha256(_canonical(source.data[name])).hexdigest()):
            raise ValueError("Adaptive source does not match its published provenance")
        sequences.add(artifact.event_seq)
    if len(sequences) != 1:
        raise ValueError("Adaptive source fields came from different reads")
    record = json.loads(encoded)
    hint = record["release_tier" if case.split == "holdout" else "public_hint"]
    if type(hint) is not str or hint != case.public_hint:
        raise ValueError("Adaptive source task hint differs")
    return AcceptedSourceView(case.scenario_id, hint, encoded)


def require_source_view(source: AcceptedSourceView, scenario_id: str) -> AcceptedSourceView:
    if type(source) is not AcceptedSourceView or source.scenario_id != scenario_id:
        raise ValueError("Proposer requires an accepted source view for this scenario")
    return source
