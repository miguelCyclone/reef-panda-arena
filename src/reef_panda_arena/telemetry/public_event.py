"""Versioned metadata projection for ordinary event history and SSE."""

import math
import re
from functools import lru_cache

from reef_panda_arena.gateway.observer_contract import (
    BoundaryObservation, PROFILES, REASONS as OBSERVER_REASONS, safe_observation,
)
from reef_panda_arena.telemetry.public_fields import LABELS, safe_field_map, safe_labels


ACTORS = frozenset({"booking_agent", "system", "supervisor", "operations_worker", "customer_worker", "response_writer"} |
                   {f"A{i}" for i in range(10)})
EVENTS = frozenset({"booking.evaluated", "run.started", "run.completed", "run.failed", "run.cancelled", "run.timed_out",
                    "agent.decision", "tool.proposed", "agent.message", "agent.receive", "candidate.validated", "candidate.rejected",
                    "memory.write", "memory.read", "memory.compact", "projection.release", "artifact.release", "artifact.reducer"})
REASONS = frozenset({
    "allowed", "invalid_arguments", "invalid_message", "invalid_message_kind", "invalid_provenance",
    "invalid_runtime_origin", "message_integrity_failed", "message_not_found", "message_recipient_mismatch",
    "message_route_not_allowed", "message_too_large", "payload_too_large", "release_scope_mismatch",
    "role_not_allowed", "scenario_channel_not_allowed", "secret_content_match", "secret_taint_to_message",
    "secret_taint_to_outbound", "strict_release_denied", "total_payload_budget_exceeded", "unknown_provenance",
    "unknown_tool", "invalid_memory_key", "invalid_memory_value", "memory_writer_not_allowed",
    "memory_reader_not_allowed", "memory_key_not_found", "reducer_inputs_invalid", "reducer_inputs_not_consumed",
    "reducer_value_invalid", "invalid_release_scope_or_source", "data_only_ast", "invalid_model_output",
    "duplicate_candidate", "unsupported_hypothesis", "candidate_context_mismatch", "candidate_too_large",
    "lineage_evidence_budget_exceeded", "evidence_budget_exceeded",
})
REPRESENTATIONS = frozenset({"decimal_bytes", "semantic_summary", "literal", "base64", "polynomial_coefficients_v1",
                            "fourier_fixture_v1", "finite_orthogonal_basis_fixture", "finite_aggregate_differencing_fixture",
                            "finite_semantically_equivalent_formula_fixture", "bounded_symbolic_math", "report_layout"})
NUMBERS = frozenset({"argument_bytes", "field_count", "byte_length", "version", "parent_count", "round",
                     "rounds_remaining", "model_calls_used", "gateway_calls_used", "decision_elapsed_ms"})
FAMILIES = frozenset({"report_layout", "bounded_symbolic_math", "prebuilt_opaque_fixture",
                     "approved_summary", "structured_handoff"})


@lru_cache(maxsize=1)
def contracts():
    from reef_panda_arena.tools.registry import TOOL_INPUTS, TOOL_DESTINATIONS
    from reef_panda_arena.tools.booking import BOOKING_INPUTS, BOOKING_DESTINATIONS
    from reef_panda_arena.tools.adaptive import ADAPTIVE_TOOL_INPUTS, ADAPTIVE_TOOL_DESTINATIONS
    from reef_panda_arena.tools.extension import EXTENSION_TOOL_INPUTS, EXTENSION_TOOL_DESTINATIONS
    from reef_panda_arena.tools.sensitive import SENSITIVE_TOOL_INPUTS, SENSITIVE_TOOL_DESTINATIONS
    from reef_panda_arena.tools.unified import UNIFIED_TOOL_INPUTS, UNIFIED_DESTINATIONS
    from reef_panda_arena.gateway.taint import SOURCE_FIELDS
    inputs = {**BOOKING_INPUTS, **TOOL_INPUTS, **ADAPTIVE_TOOL_INPUTS, **EXTENSION_TOOL_INPUTS,
              **SENSITIVE_TOOL_INPUTS, **UNIFIED_TOOL_INPUTS}
    destinations = set({**BOOKING_DESTINATIONS, **TOOL_DESTINATIONS, **ADAPTIVE_TOOL_DESTINATIONS,
                        **EXTENSION_TOOL_DESTINATIONS, **SENSITIVE_TOOL_DESTINATIONS,
                        **UNIFIED_DESTINATIONS}.values())
    destinations.update(ACTORS | {"CUS-008", "local_run_memory", "invalid", "unapproved"})
    return inputs, destinations, SOURCE_FIELDS


def event_labels(event) -> dict:
    inputs, _, sources = contracts()
    trusted = set(sources.get(event.tool_name, {}))
    if event.tool_name in inputs:
        trusted.update(inputs[event.tool_name].model_fields)
    if event.channel == "memory":
        trusted = {"value"}
    if event.channel in {"projection", "reducer"}:
        trusted = {"category", "value"}
    lineage = (event.safe_summary_json or {}).get("lineage")
    if isinstance(lineage, dict) and lineage.get("version") == "lineage-v1":
        from reef_panda_arena.gateway.lineage_evidence import validate_lineage_document
        try:
            document = validate_lineage_document(lineage)
            if document["run_id"] == event.run_id and document["event_seq"] == event.event_seq:
                trusted.update(document["inputs"])
                trusted.update(document["outputs"])
        except (ValueError, TypeError):
            pass
    labels = event.taint_labels_json if isinstance(event.taint_labels_json, dict) else {}
    return safe_labels(dict(list(labels.items())[:64]), trusted)


def public_summary(value, *, event_seq=None, run_id=None, tool_name=None) -> dict:
    if not isinstance(value, dict):
        return {}
    result = {}
    if "booking_outcome" in value:
        from reef_panda_arena.application.booking_contract import safe_booking_outcome
        outcome = safe_booking_outcome(value["booking_outcome"])
        if outcome is not None:
            result["booking_outcome"] = outcome
    if "booking_decision" in value:
        from reef_panda_arena.application.booking_contract import safe_booking_decision
        decision = safe_booking_decision(value["booking_decision"])
        if decision is not None:
            result["booking_decision"] = decision
    for key in NUMBERS:
        number = value.get(key)
        if type(number) in {int, float} and 0 <= number <= 10**12 and math.isfinite(number):
            result[key] = number
    if value.get("boundary_evidence_version") == "boundary-v1":
        result["boundary_evidence_version"] = "boundary-v1"
        if type(value.get("accepted_sink_receipt")) is bool:
            result["accepted_sink_receipt"] = value["accepted_sink_receipt"]
    attempt = value.get("attempt_id")
    if type(attempt) is str and re.fullmatch(r"task|attack:live|attack:[0-9]{1,5}|candidate:[0-9]{1,5}", attempt):
        result["attempt_id"] = attempt
    for key in ("message_id", "memory_slot_id"):
        identifier = value.get(key)
        if type(identifier) is str and re.fullmatch(r"[0-9a-f]{32}", identifier):
            result[key] = identifier
    if type(value.get("envelope_version")) is str and value.get("envelope_version") in {"peer-envelope-v1", "peer-envelope-v2"}:
        result["envelope_version"] = value["envelope_version"]
    if type(value.get("integrity_verified")) is bool:
        result["integrity_verified"] = value["integrity_verified"]
    if type(value.get("payload_kind")) is str and value.get("payload_kind") in {"artifact", "request", "control", "peer_send", "response", "approval", "notice", "delegation", "trusted_public_message", "invalid"}:
        result["payload_kind"] = value["payload_kind"]
    if type(value.get("purpose")) is str and value.get("purpose") in {"shipping_delay_notice", "unapproved"}:
        result["purpose"] = value["purpose"]
    if value.get("reader_input_version") == "reader-inputs-v2":
        result["reader_input_version"] = "reader-inputs-v2"
    if value.get("release_version") == "route-decision-v2":
        result["release_version"] = "route-decision-v2"
    if type(value.get("recipient")) is str and value.get("recipient") in {"CUS-008", "unapproved"}:
        result["recipient"] = value["recipient"]
    if type(value.get("family")) is str and value.get("family") in FAMILIES:
        result["family"] = value["family"]
    visual = value.get("visual")
    if isinstance(visual, dict):
        shape = {}
        if type(visual.get("phase")) is str and visual.get("phase") in {"attack", "benign", "control", "unclassified"}:
            shape["phase"] = visual["phase"]
        if type(visual.get("representation")) is str and visual.get("representation") in REPRESENTATIONS:
            shape["representation"] = visual["representation"]
        inputs = contracts()[0]
        trusted = inputs[tool_name].model_fields if tool_name in inputs else ()
        if isinstance(visual.get("fields"), list):
            shape["fields"] = list(safe_field_map(visual["fields"][:64], trusted).values())
        carriers = {"metrics." + key for key in ("byte_values", "poly_coefficients", "spectral_summary",
                    "basis_summary", "aggregate_summary", "formula_choice", "adaptive_numeric", "adaptive_layout")}
        if type(visual.get("carrier")) is str and visual.get("carrier") in carriers:
            shape["carrier"] = visual["carrier"]
        if type(visual.get("style")) is str and visual.get("style") in {"plain", "prefix", "suffix", "bracket"}:
            shape["style"] = visual["style"]
        if isinstance(visual.get("operators"), list):
            shape["operators"] = [item if item in {"add", "subtract"} else "unknown"
                                  for item in visual["operators"][:16] if type(item) is str]
        result["visual"] = shape
    observation = safe_observation(value.get("observation"))
    if observation is not None and (event_seq is None or observation["event_seq"] == event_seq):
        result.update(BoundaryObservation.model_validate(observation).summary())
    else:
        result.update(observer_coverage="not_inspected", observer_alert=None, observer_phase=None)
        if type(value.get("observer_profile")) is str and value.get("observer_profile") in PROFILES:
            result["observer_profile"] = value["observer_profile"]
    lineage = value.get("lineage")
    if isinstance(lineage, dict) and lineage.get("version") == "lineage-v1":
        from reef_panda_arena.gateway.lineage_evidence import validate_lineage_document
        try:
            safe = validate_lineage_document(lineage)
            if ((event_seq is None or safe["event_seq"] == event_seq) and
                    (run_id is None or safe["run_id"] == run_id)):
                result["lineage"] = safe
        except (ValueError, TypeError):
            pass
    return result
