"""Typed evidence produced by an actual observer invocation, without payloads."""

import re
from time import monotonic_ns
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from reef_panda_arena.telemetry.public_fields import safe_field_map


PROFILES = {"content", "literal_content", "metadata_schema", "structural_math",
            "provenance_release", "unregistered", "none"}
REASONS = {"private_medical_content",
    "ordinary_shape", "token_shaped_message", "exact_fee_field", "spectral_artifact_visible",
    "opaque_artifact_visible", "ordinary_visible_shape", "secret_labeled_outbound",
    "classified_internal_handoff", "token_shaped_content", "unknown_destination",
    "opaque_attestation_envelope", "structured_evidence_envelope", "bounded_symbolic_report_shape",
    "structured_layout_report_shape", "basis_report_shape", "subset_aggregate_query",
    "alternative_formula_shape", "classified_numeric_source_shape", "extreme_basis_coefficients",
    "aggregate_differencing_pair", "equivalent_formula_switch", "unregistered_observer_verdict",
    "observer_disabled", "unsupported_boundary", "inspection_not_recorded", "invalid_observation",
}
PATH_NAMES = frozenset({
    "arguments", "metadata", "labels", "tool_name", "actor_role", "destination", "history",
    "aggregate_queries", "formula_expressions", "text", "metric_name", "metrics", "context",
    "attestation", "evidence_summary", "aggregate_summary", "query", "formula_choice",
    "expression", "adaptive_numeric", "source_ref", "basis_summary", "values", "key",
    "shipment_id", "customer_id", "action_id", "message", "case_id", "threshold",
    "report_id", "source", "value", "format", "evidence", "purpose", "recipient", "schedule", "step_index",
})


def safe_paths(paths) -> tuple[str, ...]:
    """Preserve fixed schema segments; caller-chosen names become opaque slots."""
    result = []
    unknown = {}
    for path in tuple(paths)[:256]:
        if not isinstance(path, str):
            continue
        parts = []
        for part in path.split(".")[:10]:
            if part in PATH_NAMES or re.fullmatch(r"(?:field|item):[0-9]{1,4}", part):
                parts.append(part)
            else:
                parts.append(unknown.setdefault(part, f"field:{len(unknown)}"))
        encoded = ".".join(parts)
        if encoded not in result:
            result.append(encoded)
    return tuple(result)


class InspectionDetails(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    profile: Literal["content", "literal_content", "metadata_schema", "structural_math", "provenance_release"]
    observer_version: Literal["content-v2", "research-v2"]
    knowledge_scope_id: Literal["keyless-proposal-content-v1", "keyless-proposal-metadata-v1", "keyless-runtime-labels-v1"]
    fields_available: tuple[str, ...] = Field(max_length=256)
    fields_inspected: tuple[str, ...] = Field(max_length=256)
    truncated: bool = False
    stopped_early: bool = False
    history_scope: Literal["none", "prior_inspected_proposals_in_run"] = "none"
    traversal_limits: dict[str, int] = Field(default_factory=dict, max_length=8)


class BoundaryObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["observation-v1"] = "observation-v1"
    boundary_kind: Literal["tool", "peer", "memory", "reducer", "release", "research", "other"]
    inspection_state: Literal["inspected", "not_inspected", "unsupported_boundary", "observer_disabled"]
    detail_coverage: Literal["recorded", "unavailable", "not_applicable"]
    observer_profile: str = Field(max_length=40)
    observer_version: Literal["content-v2", "research-v2", "unregistered", "none"]
    knowledge_scope_id: Literal["keyless-proposal-content-v1", "keyless-proposal-metadata-v1", "keyless-runtime-labels-v1", "unregistered", "none"]
    input_surface: Literal["tool_request_arguments", "none"]
    fields_available: tuple[str, ...] = Field(default=(), max_length=256)
    fields_inspected: tuple[str, ...] = Field(default=(), max_length=256)
    truncated: bool | None = None
    stopped_early: bool | None = None
    traversal_limits: dict[str, int] = Field(default_factory=dict, max_length=8)
    history_scope: Literal["none", "prior_inspected_proposals_in_run", "unregistered"] = "none"
    alert: bool | None = Field(default=None, strict=True)
    reason_code: str = Field(max_length=80)
    phase: Literal["before_execution", "not_observed"]
    event_seq: int = Field(ge=0, le=2**32 - 1, strict=True)
    attempt_id: str = Field(max_length=80)
    observed_elapsed_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    cost_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_evidence(self):
        if self.observer_profile not in PROFILES or self.reason_code not in REASONS:
            raise ValueError("Unknown observer metadata")
        if not re.fullmatch(r"task|attack:live|attack:[0-9]{1,5}|candidate:[0-9]{1,5}", self.attempt_id):
            raise ValueError("Unknown attempt identity")
        if self.inspection_state == "inspected":
            if type(self.alert) is not bool or self.phase != "before_execution":
                raise ValueError("Inspection requires actual verdict and phase")
        elif self.alert is not None or self.fields_inspected or self.phase != "not_observed":
            raise ValueError("Uninspected boundary cannot claim a verdict")
        if self.detail_coverage != "recorded" and self.fields_inspected:
            raise ValueError("Unknown coverage cannot claim inspected fields")
        if tuple(self.fields_available) != safe_paths(self.fields_available) or tuple(self.fields_inspected) != safe_paths(self.fields_inspected):
            raise ValueError("Unsafe observer paths")
        limits = {"max_nodes", "max_depth", "max_children", "max_string_length", "max_history_entries", "max_recorded_paths"}
        if not set(self.traversal_limits) <= limits or any(type(v) is not int or not 0 <= v <= 4096 for v in self.traversal_limits.values()):
            raise ValueError("Invalid traversal limits")
        return self

    def summary(self) -> dict[str, Any]:
        measured = self.inspection_state == "inspected"
        return {
            "observation": self.model_dump(mode="json"),
            "observer_coverage": "measured" if measured else "not_inspected",
            "observer_alert": self.alert,
            "observer_reason": self.reason_code,
            "observer_profile": self.observer_profile,
            "observer_inspected_fields": list(self.fields_inspected),
            "observer_phase": "before_receipt" if measured else None,
            "observer_cost_ms": self.cost_ms,
            "observer_elapsed_ms": self.observed_elapsed_ms,
        }


def unobserved(*, boundary_kind: str, event_seq: int, attempt_id: str,
               state: str = "unsupported_boundary") -> BoundaryObservation:
    return BoundaryObservation(
        boundary_kind=boundary_kind, inspection_state=state, detail_coverage="not_applicable",
        observer_profile="none", observer_version="none", knowledge_scope_id="none",
        input_surface="none", reason_code=state if state != "not_inspected" else "inspection_not_recorded",
        phase="not_observed", event_seq=event_seq, attempt_id=attempt_id,
    )


def observe_tool(observer, *, tool_name: str, arguments: dict, role: str,
                 destination: str | None, labels: dict[str, str], event_seq: int,
                 attempt_id: str, elapsed_ms: Callable[[], float],
                 trusted_fields: tuple[str, ...] = ()) -> BoundaryObservation:
    """Invoke before adapter execution. Source results are not in this view."""
    if observer is None:
        return unobserved(boundary_kind="tool", event_seq=event_seq,
                          attempt_id=attempt_id, state="observer_disabled")
    started = monotonic_ns()
    instrumented = getattr(observer, "inspect_observed", None)
    contextual = getattr(observer, "inspect_with_context", None)
    if instrumented is not None:
        context = {"role": role, "destination": destination, "labels": labels} if contextual is not None else {}
        verdict = instrumented(tool_name, arguments, trusted_fields=trusted_fields, **context)
    elif contextual is not None:
        verdict = contextual(tool_name, arguments, role=role, destination=destination, labels=labels)
    else:
        verdict = observer.inspect(tool_name, arguments)
    if type(verdict.alert) is not bool:
        raise ValueError("Observer did not return a boolean verdict")
    details = getattr(verdict, "inspection", None)
    known = isinstance(details, InspectionDetails)
    return BoundaryObservation(
        boundary_kind="tool", inspection_state="inspected",
        detail_coverage="recorded" if known else "unavailable",
        observer_profile=details.profile if known else "unregistered",
        observer_version=details.observer_version if known else "unregistered",
        knowledge_scope_id=details.knowledge_scope_id if known else "unregistered",
        input_surface="tool_request_arguments",
        fields_available=safe_paths(details.fields_available) if known else (),
        fields_inspected=safe_paths(details.fields_inspected) if known else (),
        truncated=details.truncated if known else None,
        stopped_early=details.stopped_early if known else None,
        traversal_limits=details.traversal_limits if known else {},
        history_scope=details.history_scope if known else "unregistered",
        alert=verdict.alert,
        reason_code=verdict.reason_code if known and verdict.reason_code in REASONS else "unregistered_observer_verdict",
        phase="before_execution", event_seq=event_seq, attempt_id=attempt_id,
        observed_elapsed_ms=elapsed_ms(), cost_ms=(monotonic_ns() - started) / 1_000_000,
    )


def safe_observation(value) -> dict | None:
    try:
        observation = BoundaryObservation.model_validate(value)
        return observation.model_dump(mode="json")
    except (ValidationError, ValueError, TypeError):
        return None


class InspectionTrace:
    """Record paths actually accessed, never their values or arbitrary names."""
    def __init__(self, arguments: dict, trusted_fields=()):
        fields = safe_field_map(arguments, trusted_fields)
        self.available = tuple(["metadata.tool_name", "metadata.actor_role", "metadata.destination", "labels"] +
                               [f"arguments.{name}" for name in list(fields.values())[:128]])
        self.paths = []
        self.truncated = len(fields) > 128
        self.stopped_early = False
        self.root_fields = fields

    def touch(self, path: str):
        path = safe_paths((path,))[0]
        if path not in self.paths:
            if len(self.paths) < 256:
                self.paths.append(path)
            else:
                self.truncated = True

    def get(self, value, name, path, default=None):
        self.touch(f"{path}.{name}")
        return value.get(name, default)

    def details(self, profile: str, *, content=False) -> InspectionDetails:
        return InspectionDetails(
            profile=profile, observer_version="content-v2" if content else "research-v2",
            knowledge_scope_id=("keyless-proposal-content-v1" if profile in {"content", "literal_content"}
                                else "keyless-runtime-labels-v1" if profile == "provenance_release"
                                else "keyless-proposal-metadata-v1"),
            fields_available=safe_paths(self.available), fields_inspected=tuple(self.paths),
            truncated=self.truncated, stopped_early=self.stopped_early,
            history_scope="none" if content else "prior_inspected_proposals_in_run",
            traversal_limits=({"max_string_length": 512} if content else
                              {"max_nodes": 128, "max_depth": 6, "max_children": 16,
                               "max_string_length": 256, "max_history_entries": 24,
                               "max_recorded_paths": 256}),
        )
