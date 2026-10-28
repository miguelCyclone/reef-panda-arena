"""Finite model-call accounting shared by parallel graph branches."""

import asyncio

from reef_panda_arena.model.protocol import ModelCaller, ModelRequest, ModelResult


class ModelBudget:
    def __init__(self, caller: ModelCaller, max_calls: int = 12) -> None:
        self.caller = caller
        self.max_calls = max_calls
        self.calls = 0
        self._lock = asyncio.Lock()

    async def complete(self, request: ModelRequest) -> ModelResult:
        async with self._lock:
            if self.calls >= self.max_calls:
                raise RuntimeError("Model call budget exceeded")
            self.calls += 1
        return await self.caller.complete(request)
