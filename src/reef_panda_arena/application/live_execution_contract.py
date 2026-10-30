"""Sanitized finite evidence of independent role requests, including failed ones."""

from typing import Annotated, Literal, get_args
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, ValidationError, model_validator
from reef_panda_arena.model.role_contract import ActorId, RoleRejection


Sequence = Annotated[StrictInt, Field(ge=1, le=256)]


Feedback = Literal["accepted_by_local_gateway", "candidate_rejected", "role_rejected",
                   "invalid_tool_arguments", "policy_rejected_outbound"]


class RoleActionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    index: Annotated[StrictInt, Field(ge=1, le=4)]
    kind: Literal["tool", "peer", "release", "store_route", "forward_route",
                  "memory_read", "memory_write", "memory_compact", "reader_contribution"]
    state: Literal["proposed", "accepted", "rejected", "failed"]
    feedback: Literal["accepted_by_local_gateway", "candidate_rejected", "execution_failed"] | None

    @model_validator(mode="after")
    def consistent_feedback(self):
        expected = {"proposed": None, "accepted": "accepted_by_local_gateway",
                    "rejected": "candidate_rejected", "failed": "execution_failed"}
        if self.feedback != expected[self.state]:
            raise ValueError("Action state and feedback differ")
        return self


class RoleRequestEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    actor_id: ActorId
    prompt_version: Literal["independent-role-v1", "independent-role-v2", "independent-role-v3", "independent-role-v4", "independent-role-v5", "independent-role-v6", "independent-role-v7", "independent-role-v8", "independent-role-v9", "independent-role-v10"]
    compromised: StrictBool
    outcome: Literal["request_started", "request_failed", "invalid_role_proposal", "act", "refuse", "clarify", "finish"]
    input_event_seqs: list[Sequence] = Field(max_length=100)
    decision_turn: Annotated[StrictInt, Field(ge=1, le=12)]
    tokens_in: Annotated[StrictInt, Field(ge=0, le=2**24)]
    tokens_out: Annotated[StrictInt, Field(ge=0, le=2**24)]
    prior_gateway_feedback: list[Feedback] = Field(max_length=4)
    proposal_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None
    rejection_reason: RoleRejection | None
    actions: list[RoleActionEvidence] = Field(max_length=4)

    @model_validator(mode="after")
    def consistent_proposal(self):
        valid = self.outcome in {"act", "refuse", "clarify", "finish"}
        if valid != (self.proposal_fingerprint is not None):
            raise ValueError("Validated proposal identity disagrees with request outcome")
        expected = (set(get_args(RoleRejection)) - {"model_request_failed"}
                    if self.outcome == "invalid_role_proposal" else
                    {"model_request_failed"} if self.outcome == "request_failed" else {None})
        if self.rejection_reason not in expected:
            raise ValueError("Request rejection evidence differs from its outcome")
        if [item.index for item in self.actions] != list(range(1, len(self.actions) + 1)):
            raise ValueError("Action indexes must follow the actual proposal")
        if (not valid or self.outcome in {"refuse", "finish"}) and self.actions:
            raise ValueError("Non-acting request cannot have proposed actions")
        if self.outcome == "act" and not self.actions:
            raise ValueError("Acting request needs a proposed action")
        return self


class LiveExecutionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: Literal["live-execution-v2"]
    proposal_identity: Literal["run_local_hmac_sha256"]
    schedule: Literal["independent-shipping-v2", "independent-shipping-v3"]
    model_backend: Literal["ollama", "injected_caller"]
    scheduler: Literal["trusted_A0"]
    public_context_acquisition: Literal["fixed_shipment_and_incident_lookup"]
    trusted_transport: Literal["exact_validated_route_and_memory_copy", "reader_submission_and_validated_route_copy"]
    attempt_attribution: Literal["assigned_compromise_or_causal_input"]
    measurement_status: Literal["in_progress", "complete", "partial_run"]
    requests: list[RoleRequestEvidence] = Field(max_length=12)
    total_model_calls: Annotated[StrictInt, Field(ge=0, le=24)]
    invalid_model_outputs: Annotated[StrictInt, Field(ge=0, le=12)]
    model_refusals: Annotated[StrictInt, Field(ge=0, le=12)]
    model_clarifications: Annotated[StrictInt, Field(ge=0, le=12)]

    @model_validator(mode="after")
    def actual_counts(self):
        turns = [item.decision_turn for item in self.requests]
        if turns != list(range(1, len(turns) + 1)) or self.total_model_calls != len(turns):
            raise ValueError("Independent request accounting is inconsistent")
        for name, outcome in (("invalid_model_outputs", "invalid_role_proposal"), ("model_refusals", "refuse"), ("model_clarifications", "clarify")):
            if getattr(self, name) != sum(item.outcome == outcome for item in self.requests):
                raise ValueError("Independent request outcome counts differ")
        if self.measurement_status == "complete" and any(item.outcome in {"request_started", "request_failed", "invalid_role_proposal"} for item in self.requests):
            raise ValueError("Incomplete model requests cannot establish complete execution")
        if self.measurement_status == "complete" and any(
            action.state in {"proposed", "failed"} for item in self.requests for action in item.actions
        ):
            raise ValueError("Unfinished action execution cannot establish completion")
        return self


def project_live_execution(value, *, status):
    if type(value) is not dict:
        return None
    data = dict(value)
    if status not in {"completed", "running", "pending"}:
        data["measurement_status"] = "partial_run"
    try:
        return LiveExecutionEvidence.model_validate(data).model_dump(mode="json")
    except (ValidationError, ValueError, TypeError):
        return None
