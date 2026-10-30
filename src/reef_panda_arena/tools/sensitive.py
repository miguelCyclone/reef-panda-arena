"""Narrow local tools and fixed-shape artifacts for sensitive replay cases."""

from typing import Any, Literal


from reef_panda_arena.tools.registry import (
    ROLE_TOOLS, TOOL_DESTINATIONS, TOOL_INPUTS, MockToolRegistry, ToolInput,
)


SOURCE_TOOL_BY_SCENARIO = {
    "C10": "customer.eligibility",
    "C11": "customer.fee",
    "C12": "customer.priority",
    "C13": "operations.sensor",
    "C14": "operations.route",
}


class SensitiveLookup(ToolInput):
    case_id: Literal["C10", "C11", "C12", "C13", "C14"]


class WorkflowStep(ToolInput):
    step_index: Literal[1, 2, 3]
    schedule: Literal["HOURLY", "DAILY"]


SENSITIVE_TOOL_INPUTS = {
    **TOOL_INPUTS,
    **{name: SensitiveLookup for name in SOURCE_TOOL_BY_SCENARIO.values()},
    "workflow.step": WorkflowStep,
}
SENSITIVE_TOOL_DESTINATIONS = {
    **TOOL_DESTINATIONS,
    **{name: "local_sensitive_store" for name in SOURCE_TOOL_BY_SCENARIO.values()},
    "workflow.step": "local_workflow_state",
}


def role_tools_for(scenario_id: str) -> dict[str, set[str]]:
    permissions = {role: set(tools) for role, tools in ROLE_TOOLS.items()}
    actor = "operations_worker" if scenario_id in {"C13", "C14"} else "customer_worker"
    permissions[actor].update({
        SOURCE_TOOL_BY_SCENARIO[scenario_id], "customer.notify",
        "analytics.report", "approval.request",
    })
    if scenario_id == "C12":
        permissions[actor].add("workflow.step")
    return permissions


class SensitiveToolAdapter:
    def __init__(self, shipping_fixture: dict, secret: bytes,
                 scenario_id: str, source_record: dict[str, Any],
                 expected_public_value: str) -> None:
        self.delegate = MockToolRegistry(shipping_fixture, secret)
        self.scenario_id = scenario_id
        self.source_record = source_record
        self.expected_public_value = expected_public_value
        self.workflow_steps: list[int] = []

    def execute(self, name: str, args: ToolInput) -> dict[str, Any]:
        if name in SOURCE_TOOL_BY_SCENARIO.values():
            if name != SOURCE_TOOL_BY_SCENARIO[self.scenario_id] or args.case_id != self.scenario_id:
                raise ValueError("Wrong sensitive case source")
            return self.source_record.copy()
        if name == "workflow.step":
            self.validate_step(args)
            self.workflow_steps.append(args.step_index)
            return {"status": "recorded_local_workflow_step"}
        return self.delegate.execute(name, args)

    def validate_step(self, args: WorkflowStep) -> None:
        if (self.scenario_id != "C12" or args.step_index != len(self.workflow_steps) + 1
                or args.schedule != self.expected_public_value):
            raise ValueError("Invalid sensitive workflow step")
