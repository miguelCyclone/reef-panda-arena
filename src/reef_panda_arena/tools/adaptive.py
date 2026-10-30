"""Typed synthetic source adapters and role scopes for adaptive cases."""

from typing import Any, Literal

from reef_panda_arena.tools.registry import (
    ROLE_TOOLS, TOOL_DESTINATIONS, TOOL_INPUTS, MockToolRegistry, ToolInput,
)


class AdaptiveSourceLookup(ToolInput):
    case_id: Literal["C22", "C23", "C24", "C25", "C26", "C27", "C28"]


class AdaptiveHoldoutLookup(ToolInput):
    case_id: Literal["C28"]


ADAPTIVE_TOOL_INPUTS = {
    **TOOL_INPUTS, "adaptive.source": AdaptiveSourceLookup,
    "adaptive.holdout": AdaptiveHoldoutLookup,
}
ADAPTIVE_TOOL_DESTINATIONS = {
    **TOOL_DESTINATIONS,
    "adaptive.source": "local_sensitive_store",
    "adaptive.holdout": "local_sensitive_store",
}


def adaptive_role_tools() -> dict[str, set[str]]:
    roles = {role: set(names) for role, names in ROLE_TOOLS.items()}
    roles["customer_worker"].update({"adaptive.source", "adaptive.holdout"})
    return roles


class AdaptiveToolAdapter:
    def __init__(self, shipping: dict, marker: bytes, scenario_id: str,
                 source_tool: str, source_record: dict[str, Any]) -> None:
        self.delegate = MockToolRegistry(shipping, marker)
        self.scenario_id = scenario_id
        self.source_tool = source_tool
        self.source_record = source_record

    def execute(self, name: str, args: ToolInput) -> dict[str, Any]:
        if name in {"adaptive.source", "adaptive.holdout"}:
            if name != self.source_tool or args.case_id != self.scenario_id:
                raise ValueError("Wrong adaptive source case or split")
            return self.source_record.copy()
        return self.delegate.execute(name, args)
