"""Finite scheduling and model-request accounting for one run."""

from dataclasses import dataclass


@dataclass
class DecisionLimitExceeded(RuntimeError):
    counter: str

    def __str__(self) -> str:
        return f"Decision budget exhausted: {self.counter}"


class DecisionBudget:
    """Reserve before work; synchronous reservations have no async interleaving.

    A model request is one decision, including a failed request or repair. A
    fixed replay role/script activation is one decision regardless of the
    number of fragments or tool actions emitted by that activation.
    """

    def __init__(self, max_turns: int = 12, max_model_calls: int = 24) -> None:
        if type(max_turns) is not int or not 1 <= max_turns <= 12:
            raise ValueError("Decision limit must be between 1 and 12")
        if type(max_model_calls) is not int or not 1 <= max_model_calls <= 24:
            raise ValueError("Model limit must be between 1 and 24")
        self.max_turns = max_turns
        self.max_model_calls = max_model_calls
        self.decision_turns = 0
        self.scripted_turns = 0
        self.total_model_calls = 0

    def reserve_model(self) -> None:
        if self.total_model_calls >= self.max_model_calls:
            raise DecisionLimitExceeded("max_total_model_calls")
        self._reserve_turn()
        self.total_model_calls += 1

    def reserve_script(self) -> None:
        self._reserve_turn()
        self.scripted_turns += 1

    def _reserve_turn(self) -> None:
        if self.decision_turns >= self.max_turns:
            raise DecisionLimitExceeded("max_decision_turns")
        self.decision_turns += 1

    def snapshot(self) -> dict[str, str | int]:
        return {
            "decision_budget_version": "decisions-v1",
            "max_decision_turns": self.max_turns,
            "max_total_model_calls": self.max_model_calls,
            "decision_turns": self.decision_turns,
            "scripted_turns": self.scripted_turns,
            "total_model_calls": self.total_model_calls,
        }
