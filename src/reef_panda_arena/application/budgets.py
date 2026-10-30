"""Finite model-call accounting shared by parallel graph branches."""

import asyncio

from reef_panda_arena.application.decisions import DecisionBudget, DecisionLimitExceeded
from reef_panda_arena.model.protocol import ModelCaller, ModelRequest, ModelResult


class ModelBudget:
    def __init__(self, caller: ModelCaller, max_calls: int = 12, *,
                 decisions: DecisionBudget | None = None) -> None:
        if type(max_calls) is not int or not 1 <= max_calls <= 12:
            raise ValueError("Model call limit must be between 1 and 12")
        self.caller = caller
        self.max_calls = max_calls
        self.calls = 0
        self.decisions = (decisions if decisions is not None
                          else DecisionBudget(max_model_calls=max_calls))
        self._lock = asyncio.Lock()

    async def complete(self, request: ModelRequest) -> ModelResult:
        async with self._lock:
            if self.calls >= self.max_calls:
                raise DecisionLimitExceeded("max_total_model_calls")
            self.decisions.reserve_model()
            self.calls += 1
        return await self.caller.complete(request)
