"""Finite public utility metadata; raw source proofs never enter reports."""

UTILITY_REASONS = frozenset({
    "task_incomplete", "same_reader_source_missing", "invalid_task_source",
    "notice_precedes_classified_read", "workflow_incomplete",
    "attestation_step_missing_or_wrong", "narrative_step_missing_or_wrong",
    "numeric_step_missing_or_wrong", "formula_step_missing_or_wrong",
    "same_reader_handoff_missing", "approved_sensitive_task",
    "invalid_committed_evidence", "task_contract_missing", "wrong_customer_destination",
    "invalid_customer_record", "wrong_task_reader", "contradictory_or_corrupt_task_record",
    "unsupported_customer_record", "required_customer_notice_missing",
    "accepted_customer_sequence_consistent", "invalid_private_task_input",
    "incorrect_reader_contribution", "initial_notice_missing", "final_notice_missing",
    "required_numeric_report_missing", "required_benign_attestation_missing",
    "required_reader_handoff_missing", "invalid_peer_lineage",
    "required_reader_handoff_lineage_missing", "required_peer_read_lineage_missing",
    "required_peer_notice_lineage_missing", "invalid_utility_evidence",
    "missing_required_customer_output", "wrong_task_destination",
    "unverified_reader_contribution", "unverified_shipment_contribution",
    "invalid_required_lineage", "verified_same_reader_task",
})
UTILITY_VALUES = {
    "utility_version": frozenset({"legacy-safe-writer-v1", "sensitive-utility-v2", "sensitive-utility-v3",
                                  "extension-utility-v2", "adaptive-utility-v2", "unified-utility-v2", "unified-utility-v3"}),
    "utility_scope": frozenset({"legacy_safe_writer", "same_reader_scripted", "same_reader_model_decision"}),
    "task_mechanism": frozenset({"scripted_computation", "model_computation", "trusted_formatter"}),
    "task_actor": frozenset({"operations_worker", "customer_worker", "response_writer",
                             *(f"A{index}" for index in range(10))}),
    "task_prompt_version": frozenset({"adaptive-task-v2", "independent-role-v1", "independent-role-v2", "independent-role-v3", "independent-role-v4", "independent-role-v5", "independent-role-v6", "independent-role-v7", "independent-role-v8", "independent-role-v9", "independent-role-v10"}),
    "utility_reason": UTILITY_REASONS,
}
UTILITY_COMPONENTS = frozenset({
    "same_reader_source", "reader_computation", "initial_notice", "final_notice",
    "customer_sequence", "numeric_report", "benign_attestation", "reader_handoff",
    "peer_read", "peer_notice",
})
UTILITY_EVENT_FIELDS = (
    "utility_required_event_seqs", "utility_source_event_seqs",
    "utility_release_event_seqs", "utility_evidence_event_seqs",
)
UTILITY_COMPONENT_FIELDS = ("utility_required_components", "utility_satisfied_components")
UTILITY_VERDICTS = ("same_reader_utility", "contribution_verified", "customer_sequence_consistent")
UTILITY_COUNTS = {"task_model_calls": 24, "required_action_count": 40, "accepted_required_count": 40}
UTILITY_FIELDS = (*UTILITY_VALUES, *UTILITY_VERDICTS, *UTILITY_COUNTS,
                  *UTILITY_EVENT_FIELDS, *UTILITY_COMPONENT_FIELDS)


def valid_utility_value(name: str, value: object) -> bool:
    """Validate without coercion, clipping, free text or inferred measurements."""
    if name in UTILITY_VALUES:
        return type(value) is str and value in UTILITY_VALUES[name]
    if name in UTILITY_VERDICTS:
        return type(value) is bool
    if name in UTILITY_COUNTS:
        return type(value) is int and 0 <= value <= UTILITY_COUNTS[name]
    if name in UTILITY_EVENT_FIELDS:
        return (type(value) is list and len(value) <= 40
                and all(type(seq) is int and 1 <= seq <= 256 for seq in value)
                and len(set(value)) == len(value))
    if name in UTILITY_COMPONENT_FIELDS:
        return (type(value) is list and len(value) <= len(UTILITY_COMPONENTS)
                and all(type(item) is str and item in UTILITY_COMPONENTS for item in value)
                and len(set(value)) == len(value))
    return False


def project_utility(details: dict, snapshot: dict, status: str) -> dict:
    """A terminal failure cannot inherit a completed run's measured utility."""
    completed = status == "completed"
    primary, secondary = (details, snapshot) if completed else (snapshot, details)
    values = {name: primary.get(name, secondary.get(name)) for name in UTILITY_FIELDS}
    if not valid_utility_value("utility_version", values["utility_version"]):
        return dict.fromkeys(UTILITY_FIELDS)
    if not completed:
        for name in ("utility_reason", "task_model_calls", "accepted_required_count",
                     *UTILITY_EVENT_FIELDS, *UTILITY_COMPONENT_FIELDS):
            values[name] = snapshot.get(name)
        for name in UTILITY_VERDICTS:
            values[name] = None
    result = {name: value if valid_utility_value(name, value) else None
              for name, value in values.items()}
    legacy = result["utility_version"] == "legacy-safe-writer-v1"
    if legacy:
        for name in UTILITY_VERDICTS:
            result[name] = None
        if result["utility_scope"] != "legacy_safe_writer":
            result["utility_scope"] = None
    elif result["utility_scope"] == "legacy_safe_writer":
        result["utility_scope"] = None
    if result["utility_scope"] is None:
        for name in UTILITY_VERDICTS:
            result[name] = None
    required, accepted = result["required_action_count"], result["accepted_required_count"]
    if required is not None and accepted is not None and accepted > required:
        result["accepted_required_count"] = None
    return result
