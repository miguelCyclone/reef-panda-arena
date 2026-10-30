"""Public configuration evidence for matched legitimate-work comparisons."""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError

from reef_panda_arena.gateway.observer import ContentObserver
from reef_panda_arena.gateway.research_observer import ResearchObserver


Digest = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]


class ComparisonContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["benign-match-v1"] = "benign-match-v1"
    source_revision: Digest
    configuration_digest: Digest
    budget_digest: Digest
    fixture_cohort: Digest
    observer_profile: Literal["content", "literal_content", "metadata_schema", "structural_math",
                              "provenance_release", "none"]
    observer_version: Literal["content-v2", "research-v2", "none"]
    observer_history: Literal["none", "prior_inspected_proposals_in_run"]
    max_gateway_actions: Annotated[StrictInt, Field(ge=1, le=40)]
    max_decision_turns: Annotated[StrictInt, Field(ge=1, le=12)]
    max_model_calls: Annotated[StrictInt, Field(ge=1, le=24)]
    max_wall_seconds: Annotated[StrictInt, Field(ge=1, le=900)]
    task_schedule: Literal["sensitive-interleaved-v3", "extension-interleaved-v2",
                           "adaptive-interleaved-v2", "unified-interleaved-v2", "independent-shipping-v2", "independent-shipping-v3"]
    control_context: Literal["task_only", "public_transport_probe", "positive_control", "attacked"]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def source_revision():
    """Hash package implementation files only, never local credentials or payloads."""
    root = Path(__file__).resolve().parents[1]
    result = hashlib.sha256(b"reef-panda-implementation-v1")
    for path in sorted(root.rglob("*.py")):
        result.update(path.relative_to(root).as_posix().encode())
        result.update(path.read_bytes())
    return result.hexdigest()


def declare_comparison(gateway, scenario, shipping, *, key, decisions, seconds, schedule,
                       attack_enabled, transport_probe=False, positive_control=False, extra_limits=None):
    """Snapshot actual runtime scope and caps before the task starts.

    The cohort HMAC binds a fixture-key domain without exposing the key or a
    target-dependent hash. Fresh authenticated-envelope nonces need not match.
    """
    observer = gateway.observer
    if type(observer) is ContentObserver:
        profile, version, history = "content", "content-v2", "none"
    elif type(observer) is ResearchObserver:
        profile, version, history = observer.profile, "research-v2", "prior_inspected_proposals_in_run"
    elif observer is None:
        profile, version, history = "none", "none", "none"
    else:
        return None
    configuration = {
        "scenario": scenario.model_dump(mode="json"), "shipping": shipping,
        "roles": dict(gateway.context_guard.runtime_roles),
        "role_tools": {role: sorted(names) for role, names in gateway.role_tools.items()},
        "tools": {name: schema.model_json_schema() for name, schema in gateway.tool_inputs.items()},
        "destinations": gateway.tool_destinations,
    }
    limits = {
        "actions": gateway.max_calls, "events": gateway.max_events,
        "payload_bytes": gateway.max_payload_bytes, "total_payload_bytes": gateway.max_total_payload_bytes,
        "decisions": decisions.max_turns, "model_calls": decisions.max_model_calls,
        "seconds": seconds, "extra": extra_limits,
    }
    return ComparisonContract(
        source_revision=source_revision(), configuration_digest=digest(configuration),
        budget_digest=digest(limits),
        fixture_cohort=hmac.new(key, b"reef-panda-benign-match-cohort-v1", hashlib.sha256).hexdigest(),
        observer_profile=profile, observer_version=version, observer_history=history,
        max_gateway_actions=gateway.max_calls, max_decision_turns=decisions.max_turns,
        max_model_calls=decisions.max_model_calls, max_wall_seconds=seconds,
        task_schedule=schedule, control_context=("positive_control" if positive_control else
                                                "attacked" if attack_enabled else
                                                "public_transport_probe" if transport_probe else "task_only"),
    ).model_dump(mode="json")


def validated_comparison(value):
    try:
        return ComparisonContract.model_validate(value).model_dump(mode="json")
    except (ValidationError, TypeError, ValueError):
        return None
