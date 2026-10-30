"""Public booking configuration and bounded, value-free model decision evidence."""

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class BookingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    mode: Literal["live", "replay"] = "live"
    arm: Literal["A0", "A1", "A2", "A3", "A4"] = "A0"
    policy: Literal["schema", "content", "actor_taint", "restricted_release", "transitive"] = "schema"
    seed: int = Field(default=31, ge=0, lt=2**64)
    variant: Literal[0, 1] = 0
    model: str = Field(default="qwen2.5:3b-instruct-q4_K_M", min_length=1, max_length=160)
    temperature: float = Field(default=0.0, ge=0, le=1)
    generation_seed: int = Field(default=31, ge=0, lt=2**31)


class BookingDecisionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    turn: int = Field(ge=1, le=4)
    source_event_seq: int | None = Field(default=None, ge=1, le=40)
    outcome: Literal["started", "valid", "invalid", "failed"] = "started"
    action: Literal["read", "send", "refuse", "finish"] | None = None
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    proposal_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


def safe_booking_decision(value):
    try:
        return BookingDecisionEvidence.model_validate(value).model_dump(mode="json")
    except (ValueError, TypeError):
        return None


class BookingReport(BaseModel):
    """The core report has its own version; it does not relabel historical scores."""
    model_config = ConfigDict(extra="forbid")
    version: Literal["booking-report-v1"]
    experiment_id: Literal["booking-core"]
    run_id: str
    config: BookingConfig
    status: Literal["running", "completed", "failed", "cancelled", "timed_out"]
    model_backend: Literal["ollama", "injected_caller", "scripted_replay"]
    model_digest: str | None
    model_originated: bool
    implementation_sha256: str
    prompt_version: str
    fixture_version: str
    receiver_version: str
    receiver_commitment: str
    reviewer_version: str
    oracle_version: str
    fixture_mode: Literal["key_derived_unknown"]
    authorized_output: dict[str, str]
    pair_id: str
    limits: dict[str, int]
    failure_code: str | None
    decisions: list[BookingDecisionEvidence] = Field(default_factory=list,max_length=4)
    private_read_event_seqs: list[int] = Field(default_factory=list,max_length=4)
    reader_consumption_turns: list[int] = Field(default_factory=list,max_length=4)
    outbound_proposals: int = 0
    benign_proposals_evaluated: int = 0
    false_alerts: int = 0
    false_blocks: int = 0
    stop_reason: str | None = None
    started: bool = True
    completed: bool = False
    eligible: bool = False
    failed: bool = False
    cancelled: bool = False
    timed_out: bool = False
    accepted_outbound: bool | None = None
    accepted_outbound_count: int = 0
    pre_egress_alert: bool | None = None
    pre_egress_block: bool | None = None
    benign_task_success: bool | None = None
    strict_win: bool | None = None
    unauthorized_attribute_recovered: bool | None = None
    recovered_components: list[Literal["private_detail"]] = Field(default_factory=list,max_length=1)
    partial_recovery: bool | None = None
    recovered_event_seqs: list[int] = Field(default_factory=list,max_length=4)
    incorrect_reconstruction_events: list[int] = Field(default_factory=list,max_length=4)
    incomplete_reconstruction_events: list[int] = Field(default_factory=list,max_length=4)
    receiver_evaluated_artifacts: int = 0
    outbound_inspections: int = 0
    outbound_observation_opportunities: int = 0
    boundary_observations: list[dict] = Field(default_factory=list,max_length=32)
    authorized_inference_baseline: dict | None = None
    accepted_event_seqs: list[int] = Field(default_factory=list,max_length=4)
    run_duration_ms: int | None = None
    persisted_accepted_outbound_count: int | None = None
    receipt_count_consistent: bool | None = None


class BookingOutcomeEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    eligible: bool
    benign_task_success: bool | None
    unauthorized_attribute_recovered: bool | None
    accepted_event_seqs: list[int] = Field(max_length=4)
    recovered_event_seqs: list[int] = Field(max_length=4)


def safe_booking_outcome(value):
    try:
        return BookingOutcomeEvidence.model_validate(value).model_dump(mode="json")
    except (ValueError, TypeError):
        return None
