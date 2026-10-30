"""Prepare fixed local adapters; publish mutable local state after event commit."""

from copy import deepcopy
from dataclasses import dataclass
from typing import Callable

from reef_panda_arena.tools.booking import BookingToolAdapter
from reef_panda_arena.tools.adaptive import AdaptiveToolAdapter
from reef_panda_arena.tools.extension import ExtensionToolAdapter
from reef_panda_arena.tools.registry import MockToolRegistry
from reef_panda_arena.tools.sensitive import SensitiveToolAdapter
from reef_panda_arena.tools.unified import UnifiedToolAdapter


_LOCAL_ADAPTERS = frozenset({
    MockToolRegistry, SensitiveToolAdapter, ExtensionToolAdapter,
    AdaptiveToolAdapter, UnifiedToolAdapter, BookingToolAdapter,
})


def validate_local_adapter(adapter) -> None:
    """Runtime wiring accepts the shipped in-process adapters only.

    Arbitrary host Python mutation is outside the agent-facing boundary. This
    check prevents a newly supplied duck-typed network adapter being accepted
    without an explicit review of the local execution contract.
    """
    if type(adapter) not in _LOCAL_ADAPTERS:
        raise ValueError("Unregistered local tool adapter")
    if type(adapter) is not MockToolRegistry and type(adapter.delegate) is not MockToolRegistry:
        raise ValueError("Unregistered local tool delegate")


@dataclass(frozen=True)
class PreparedLocalOperation:
    data: dict
    publish: Callable[[], None]


def _no_mutation() -> None:
    pass


def prepare_local_operation(adapter, name: str, args) -> PreparedLocalOperation:
    """No external I/O or mock acceptance occurs in these preparation calls."""
    validate_local_adapter(adapter)
    if name == "memory.write":
        memory = adapter if type(adapter) is MockToolRegistry else adapter.delegate
        key, message = args.key, args.message

        def publish_memory() -> None:
            memory._memory[key] = message

        return PreparedLocalOperation({"status": "stored_local_memory"}, publish_memory)
    if name == "workflow.step":
        if type(adapter) is not SensitiveToolAdapter:
            raise ValueError("Unregistered local workflow adapter")
        adapter.validate_step(args)
        step = args.step_index

        def publish_step() -> None:
            adapter.workflow_steps.append(step)

        return PreparedLocalOperation({"status": "recorded_local_workflow_step"}, publish_step)
    # All remaining registered execute branches are reads or pure local result
    # preparation. The event/receipt transaction defines outbound acceptance.
    return PreparedLocalOperation(deepcopy(adapter.execute(name, args)), _no_mutation)
