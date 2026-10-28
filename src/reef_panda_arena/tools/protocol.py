"""Execution contract for already validated local tool calls."""

from typing import Protocol

from reef_panda_arena.tools.registry import ToolInput


class ToolAdapter(Protocol):
    def execute(self, name: str, args: ToolInput) -> dict: ...
