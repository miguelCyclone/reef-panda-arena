"""Typed, nullable score fields shared by status and scoreless report responses."""

from typing import Annotated, Literal

from pydantic import BaseModel, Field, StrictBool, StrictInt, StrictStr, field_validator

from reef_panda_arena.application.live_execution_contract import LiveExecutionEvidence
from reef_panda_arena.application.benign_cost_contract import BenignCost
from reef_panda_arena.application.information_contract import InformationEvidence
from reef_panda_arena.application.knowledge import KNOWLEDGE_VALUES
from reef_panda_arena.application.utility_contract import (
    UTILITY_COMPONENTS, UTILITY_FIELDS, UTILITY_VALUES, valid_utility_value,
)

from reef_panda_arena.scenarios.fixture_knowledge import FixtureMode


class RecoveryEvidence(BaseModel):
    event_seqs: list[int]
    attempt_ids: list[str]
    decisive_event_seq: int
    validation_method: Literal["independent_accepted_artifact_decode"]
    observer_measured: bool
    pre_alert_event_seqs: list[int]
    post_alert_event_seqs: list[int]
    block_event_seqs: list[int]
    strict_win: bool | None


class BoundaryObservation(BaseModel):
    event_seq: int
    attempt_id: str | None = None
    outbound: bool
    accepted: bool
    blocked: bool
    observer_measured: bool
    observer_alert: bool | None = None
    observer_phase: Literal["before_receipt", "after_receipt"] | None = None
    decision_elapsed_ms: float | None = Field(default=None, ge=0)
    observer_elapsed_ms: float | None = Field(default=None, ge=0)
    receipt_elapsed_ms: float | None = Field(default=None, ge=0)


class ScoreFields(BaseModel):
    live_execution: LiveExecutionEvidence | None = None
    information: InformationEvidence | None = None
    benign_cost: BenignCost | None = None
    utility_version: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(UTILITY_VALUES["utility_version"]), None]})
    utility_scope: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(UTILITY_VALUES["utility_scope"]), None]})
    task_mechanism: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(UTILITY_VALUES["task_mechanism"]), None]})
    task_actor: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(UTILITY_VALUES["task_actor"]), None]})
    task_prompt_version: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(UTILITY_VALUES["task_prompt_version"]), None]})
    utility_reason: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(UTILITY_VALUES["utility_reason"]), None]})
    same_reader_utility: StrictBool | None = None
    contribution_verified: StrictBool | None = None
    customer_sequence_consistent: StrictBool | None = None
    task_model_calls: StrictInt | None = Field(default=None, ge=0, le=24)
    required_action_count: StrictInt | None = Field(default=None, ge=0, le=40)
    accepted_required_count: StrictInt | None = Field(default=None, ge=0, le=40)
    utility_required_event_seqs: list[Annotated[StrictInt, Field(ge=1, le=256)]] | None = Field(default=None, max_length=40)
    utility_source_event_seqs: list[Annotated[StrictInt, Field(ge=1, le=256)]] | None = Field(default=None, max_length=40)
    utility_release_event_seqs: list[Annotated[StrictInt, Field(ge=1, le=256)]] | None = Field(default=None, max_length=40)
    utility_evidence_event_seqs: list[Annotated[StrictInt, Field(ge=1, le=256)]] | None = Field(default=None, max_length=40)
    utility_required_components: list[Annotated[StrictStr, Field(json_schema_extra={"enum": sorted(UTILITY_COMPONENTS)})]] | None = Field(default=None, max_length=10)
    utility_satisfied_components: list[Annotated[StrictStr, Field(json_schema_extra={"enum": sorted(UTILITY_COMPONENTS)})]] | None = Field(default=None, max_length=10)
    fixture_mode: FixtureMode | None = None
    fixture_derivation_version: StrictStr | None = Field(default=None, max_length=64, json_schema_extra={"enum": [*sorted(KNOWLEDGE_VALUES["fixture_derivation_version"]), None]})
    fixture_template_digest: StrictStr | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    knowledge_contract_version: Literal["knowledge-v1"] | None = None
    protected_target_kind: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(KNOWLEDGE_VALUES["protected_target_kind"]), None]})
    attacker_knowledge: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(KNOWLEDGE_VALUES["attacker_knowledge"]), None]})
    policy_knowledge: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(KNOWLEDGE_VALUES["policy_knowledge"]), None]})
    policy_known_target: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(KNOWLEDGE_VALUES["policy_known_target"]), None]})
    observer_knowledge: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(KNOWLEDGE_VALUES["observer_knowledge"]), None]})
    receiver_knowledge: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(KNOWLEDGE_VALUES["receiver_knowledge"]), None]})
    receiver_target_comparison: StrictStr | None = Field(default=None, max_length=96, json_schema_extra={"enum": [*sorted(KNOWLEDGE_VALUES["receiver_target_comparison"]), None]})
    decoder_convention_public: StrictBool | None = None
    audit_mode: bool | None = None
    decision_budget_version: str | None = None
    decision_accounting: str | None = None
    max_decision_turns: int | None = Field(default=None, ge=1)
    max_total_model_calls: int | None = Field(default=None, ge=1)
    decision_turns: int | None = Field(default=None, ge=0)
    scripted_turns: int | None = Field(default=None, ge=0)
    total_model_calls: int | None = Field(default=None, ge=0)
    scoring_version: str = "unscored"
    failure_code: str | None = None
    attack_enabled: bool | None = None
    attacker_attempted: bool | None = None
    candidate_status: str | None = None
    candidate_eligible: bool | None = None
    valid_candidates: int | None = Field(default=None, ge=0)
    invalid_candidates: int | None = Field(default=None, ge=0)
    duplicate_candidates: int | None = Field(default=None, ge=0)
    unsupported_candidates: int | None = Field(default=None, ge=0)
    invalid_attempt: bool | None = None
    oracle_validation: Literal["independent", "fixture_proxy", "unavailable", "not_run", "unknown"] = "not_run"
    oracle_available: bool | None = None
    oracle_reason: str | None = None
    observer_scope: str = "outbound_tools"
    observer_coverage: str = "not_inspected"
    relevant_observer_measured: bool | None = None
    scorable_completed: bool = False
    strict_trial_eligible: bool = False
    eligibility_reasons: list[str] = Field(default_factory=lambda: ["score_not_available"])
    attempted_egress: bool | None = None
    outbound_proposals: int | None = Field(default=None, ge=0)
    accepted_egress: bool | None = None
    accepted_sink_receipts: int | None = Field(default=None, ge=0)
    attempted_attack_egress: bool | None = None
    accepted_attack_egress: bool | None = None
    full_secret_recovered: bool | None = None
    secret_escaped: bool | None = None
    benign_task_success: bool | None = None
    strict_win: bool | None = None
    attacker_win: bool | None = None
    undetected_success: bool | None = None
    pre_egress_alerts: int | None = Field(default=None, ge=0)
    post_egress_alerts: int | None = Field(default=None, ge=0)
    relevant_blocks: int | None = Field(default=None, ge=0)
    all_run_alerts: int | None = Field(default=None, ge=0)
    all_run_blocks: int | None = Field(default=None, ge=0)
    blocked_attempts: int | None = Field(default=None, ge=0)
    accepted_outbound_events: int | None = Field(default=None, ge=0)
    recovery_evidence: list[RecoveryEvidence] = Field(default_factory=list)
    boundary_observations: list[BoundaryObservation] = Field(default_factory=list)
    fixture_proxy_match: bool | None = None
    persisted_accepted_sink_receipts: int | None = Field(default=None, ge=0)
    persisted_outbound_proposals: int | None = Field(default=None, ge=0)
    persisted_blocked_attempts: int | None = Field(default=None, ge=0)
    persisted_valid_candidates: int | None = Field(default=None, ge=0)
    persisted_invalid_candidates: int | None = Field(default=None, ge=0)
    persisted_duplicate_candidates: int | None = Field(default=None, ge=0)
    persisted_unsupported_candidates: int | None = Field(default=None, ge=0)

    @field_validator(*KNOWLEDGE_VALUES)
    @classmethod
    def validate_knowledge_value(cls, value, info):
        if value is not None and value not in KNOWLEDGE_VALUES[info.field_name]:
            raise ValueError("Unknown public knowledge metadata value")
        return value

    @field_validator(*UTILITY_FIELDS)
    @classmethod
    def validate_utility_value(cls, value, info):
        if value is not None and not valid_utility_value(info.field_name, value):
            raise ValueError("Unknown or invalid public utility metadata value")
        return value
