"""Shared finite action and event reservations for every gateway family."""

from typing import Protocol


MAX_MEDIATED_ACTIONS = 40


class GatewayBudgetExceeded(RuntimeError):
    """No further mediated effect is permitted within the run's configured cap."""


# Existing unified controllers and callers catch the same generic exception.
UnifiedBudgetExceeded = GatewayBudgetExceeded


class ActionBudgetState(Protocol):
    max_calls: int
    max_events: int
    calls: int
    events: int


def bounded_limits(max_calls: int, max_events: int) -> tuple[int, int]:
    if type(max_calls) is not int or max_calls <= 0 or type(max_events) is not int or max_events <= 0:
        raise ValueError("Gateway action and event limits must be positive integers")
    return min(max_calls, MAX_MEDIATED_ACTIONS), max_events


def reserve_event(state: ActionBudgetState) -> int:
    """Reserve one redacted event; caller holds its gateway lock."""
    if state.events >= state.max_events:
        raise GatewayBudgetExceeded("Gateway event budget exhausted")
    state.events += 1
    return state.events


def reserve_action(state: ActionBudgetState, *, record_event: bool = True) -> int:
    """Charge one attempt before effects, preserving tighter configured caps.

    The caller holds its gateway lock. Idempotent tool retries still consume an
    action; they reserve an event only if they need a new persisted decision.
    """
    if state.calls >= min(state.max_calls, MAX_MEDIATED_ACTIONS):
        raise GatewayBudgetExceeded("Gateway action budget exhausted")
    if record_event and state.events >= state.max_events:
        raise GatewayBudgetExceeded("Gateway event budget exhausted")
    state.calls += 1
    return reserve_event(state) if record_event else state.events
