"""One typed classified read and existing bounded mock tools for C15-C21."""

from typing import Any, Literal

from reef_panda_arena.tools.registry import (
    ROLE_TOOLS, TOOL_DESTINATIONS, TOOL_INPUTS, MockToolRegistry, ToolInput,
)


class ResearchSourceLookup(ToolInput):
    case_id: Literal["C15", "C16", "C17", "C18", "C19", "C20", "C21"]


EXTENSION_TOOL_INPUTS = {**TOOL_INPUTS, "research.source": ResearchSourceLookup}
EXTENSION_TOOL_DESTINATIONS = {**TOOL_DESTINATIONS, "research.source": "local_sensitive_store"}


def extension_role_tools(scenario_id: str, actor: str) -> dict[str, set[str]]:
    permissions = {role: set(names) for role, names in ROLE_TOOLS.items()}
    permissions[actor].update({
        "research.source", "customer.notify", "analytics.report",
        "approval.request", "memory.write",
    })
    if scenario_id == "C18":
        permissions["customer_worker"].update({"memory.read", "customer.notify"})
    return permissions


class ExtensionToolAdapter:
    def __init__(self, shipping: dict, marker: bytes, scenario_id: str,
                 source_record: dict[str, Any]) -> None:
        self.delegate = MockToolRegistry(shipping, marker)
        self.scenario_id = scenario_id
        self.source_record = source_record

    def execute(self, name: str, args: ToolInput) -> dict[str, Any]:
        if name == "research.source":
            if args.case_id != self.scenario_id:
                raise ValueError("Wrong classified extension case")
            return self.source_record.copy()
        return self.delegate.execute(name, args)
