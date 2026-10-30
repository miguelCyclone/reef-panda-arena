"""Finite public benign-cost DTOs; no source values or proposal bytes."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, ValidationError, model_validator

from reef_panda_arena.application.comparison_contract import ComparisonContract
from reef_panda_arena.application.benign_cost import (
    BENIGN_COST_VERSION, COUNT_FIELDS, RATE_FIELDS, STATE_FIELDS, _counts,
)


EventSeq = Annotated[StrictInt, Field(ge=1, le=256)]
ActionCount = Annotated[StrictInt, Field(ge=0, le=40)]
RunCount = Annotated[StrictInt, Field(ge=0, le=1)]
Rate = Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)]
Shape = Literal["task_text", "numeric_array", "numeric_scalar", "encrypted_envelope",
                "aggregate", "formula_choice", "structured_narrative", "task_record"]
State = Literal["not_measured", "partial", "measured"]


class CostCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    eligible_actions: ActionCount | None
    observer_inspections: ActionCount | None
    policy_decisions: ActionCount | None
    observer_false_alerts: ActionCount | None
    policy_false_blocks: ActionCount | None
    eligible_runs: RunCount | None
    observer_eligible_runs: RunCount | None
    policy_eligible_runs: RunCount | None
    observer_false_alert_runs: RunCount | None
    policy_false_block_runs: RunCount | None
    observer_false_alert_rate: Rate | None
    policy_false_block_rate: Rate | None
    observer_measurement: State
    policy_measurement: State


class BenignAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_seq: EventSeq
    actor_id: Literal["operations_worker", "customer_worker", "response_writer", "A9"]
    tool_name: Literal["customer.notify", "analytics.report", "approval.request"]
    shape_group: Shape
    shape_matched: StrictBool
    source_state: Literal["classified_reader", "classified_lineage"]
    source_event_seqs: list[EventSeq] = Field(min_length=1, max_length=40)
    observer_measured: StrictBool
    observer_alert: StrictBool | None
    policy_measured: StrictBool
    policy_blocked: StrictBool | None

    @model_validator(mode="after")
    def validate_bindings(self):
        if (len(set(self.source_event_seqs)) != len(self.source_event_seqs)
                or any(seq >= self.event_seq for seq in self.source_event_seqs)
                or self.observer_measured != (self.observer_alert is not None)
                or self.policy_measured != (self.policy_blocked is not None)):
            raise ValueError("Invalid benign action evidence")
        if self.shape_matched and self.shape_group in {"task_text", "task_record"}:
            raise ValueError("Unmatched task record")
        return self


class ShapeCost(CostCounts):
    shape_group: Shape


class BenignCost(CostCounts):
    comparison: ComparisonContract | None = None
    version: Literal["benign-cost-v1"]
    scope: Literal["required_classified_task"]
    reason: Literal["eligible_task_proposals", "no_eligible_outbound_actions", "task_contract_unavailable",
                    "invalid_committed_evidence", "invalid_boundary_evidence", "invalid_task_classification"]
    actions: list[BenignAction] = Field(max_length=40)
    shape_matched: list[ShapeCost] = Field(max_length=8)

    @model_validator(mode="after")
    def validate_counts(self):
        counts = (*COUNT_FIELDS, *RATE_FIELDS, *STATE_FIELDS)
        if self.reason not in {"eligible_task_proposals", "no_eligible_outbound_actions"}:
            if (self.actions or self.shape_matched
                    or any(getattr(self, name) is not None for name in (*COUNT_FIELDS, *RATE_FIELDS))
                    or any(getattr(self, name) != "not_measured" for name in STATE_FIELDS)):
                raise ValueError("Unavailable evidence must have unknown counts")
            return self
        rows = [item.model_dump() for item in self.actions]
        if (len({item.event_seq for item in self.actions}) != len(rows)
                or bool(rows) != (self.reason == "eligible_task_proposals")):
            raise ValueError("Invalid eligible action set")
        completed = self.eligible_runs == 1
        expected = _counts(rows, completed=completed)
        if any(getattr(self, name) != expected[name] for name in counts):
            raise ValueError("Cost counters disagree with observed actions")
        shapes = {row["shape_group"] for row in rows if row["shape_matched"]}
        if shapes != {item.shape_group for item in self.shape_matched} or len(shapes) != len(self.shape_matched):
            raise ValueError("Invalid matched shape set")
        for item in self.shape_matched:
            expected = _counts([row for row in rows if row["shape_matched"]
                                and row["shape_group"] == item.shape_group], completed=completed)
            if any(getattr(item, name) != expected[name] for name in counts):
                raise ValueError("Shape counters disagree with observed actions")
        return self


def project_benign_cost(value, *, status):
    """Historical/malformed values stay unknown; incomplete runs cannot inherit success."""
    if type(value) is not dict or value.get("version") != BENIGN_COST_VERSION:
        return None
    try:
        result = BenignCost.model_validate(value).model_dump(mode="json")
    except (ValidationError, ValueError, TypeError):
        return None
    if status != "completed" and result["eligible_actions"] is not None:
        result.update(_counts(result["actions"], completed=False))
        for shape in result["shape_matched"]:
            shape.update(_counts([row for row in result["actions"] if row["shape_matched"]
                                  and row["shape_group"] == shape["shape_group"]], completed=False))
    return result
