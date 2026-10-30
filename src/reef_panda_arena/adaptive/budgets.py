"""Atomic, server-owned adaptive run limits and accounting."""

import asyncio
from dataclasses import dataclass
from time import monotonic
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from reef_panda_arena.application.decisions import DecisionBudget, DecisionLimitExceeded


class AdaptiveLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_rounds: int = Field(default=8, ge=1, le=8)
    max_candidates: int = Field(default=8, ge=1, le=8)
    max_attacker_model_calls: int = Field(default=16, ge=1, le=16)
    max_total_model_calls: int = Field(default=24, ge=1, le=24)
    max_decision_turns: int = Field(default=12, ge=1, le=12)
    max_gateway_calls: int = Field(default=32, ge=1, le=32)
    max_graph_supersteps: int = Field(default=48, ge=1, le=48)
    max_wall_seconds: int = Field(default=900, ge=1, le=900)
    model_timeout_seconds: int = Field(default=90, ge=1, le=90)
    max_candidate_bytes: int = Field(default=2048, ge=128, le=2048)
    max_sink_bytes: int = Field(default=16384, ge=128, le=16384)
    max_candidate_families: int = Field(default=4, ge=1, le=4)
    max_model_retries: int = Field(default=1, ge=0, le=1)

    @model_validator(mode="after")
    def cross_check(self) -> "AdaptiveLimits":
        if self.max_candidates < self.max_rounds:
            raise ValueError("Candidate budget must cover every round")
        if self.max_attacker_model_calls > self.max_total_model_calls:
            raise ValueError("Attacker model budget exceeds total")
        return self


@dataclass
class BudgetExceeded(RuntimeError):
    counter: str

    def __str__(self) -> str:
        return f"Adaptive budget exhausted: {self.counter}"


_COUNTER_FIELDS = {
    "rounds": "max_rounds",
    "candidates": "max_candidates",
    "attacker_model_calls": "max_attacker_model_calls",
    "total_model_calls": "max_total_model_calls",
    "gateway_calls": "max_gateway_calls",
    "graph_supersteps": "max_graph_supersteps",
    "sink_bytes": "max_sink_bytes",
}


class BudgetLedger:
    def __init__(self, limits: AdaptiveLimits, *,
                 clock: Callable[[], float] = monotonic) -> None:
        self.limits = limits
        self.clock = clock
        self.started = clock()
        self.counts = {name: 0 for name in _COUNTER_FIELDS}
        self.decisions = DecisionBudget(
            max_turns=limits.max_decision_turns,
            max_model_calls=limits.max_total_model_calls,
        )
        self.task_model_calls = 0
        self.families: set[str] = set()
        self._lock = asyncio.Lock()

    def check_time(self) -> None:
        if self.clock() - self.started >= self.limits.max_wall_seconds:
            raise BudgetExceeded("max_wall_seconds")

    async def charge(self, counter: str, amount: int = 1) -> int:
        if counter not in _COUNTER_FIELDS or amount < 1:
            raise ValueError("Invalid adaptive budget counter")
        async with self._lock:
            self.check_time()
            cap = getattr(self.limits, _COUNTER_FIELDS[counter])
            if self.counts[counter] + amount > cap:
                raise BudgetExceeded(_COUNTER_FIELDS[counter])
            self.counts[counter] += amount
            return self.counts[counter]

    async def charge_model(self, *, attacker: bool) -> None:
        async with self._lock:
            self.check_time()
            if self.counts["total_model_calls"] >= self.limits.max_total_model_calls:
                raise BudgetExceeded("max_total_model_calls")
            if attacker and self.counts["attacker_model_calls"] >= self.limits.max_attacker_model_calls:
                raise BudgetExceeded("max_attacker_model_calls")
            try:
                self.decisions.reserve_model()
            except DecisionLimitExceeded as exc:
                raise BudgetExceeded(exc.counter) from exc
            self.counts["total_model_calls"] += 1
            if attacker:
                self.counts["attacker_model_calls"] += 1
            else:
                self.task_model_calls += 1

    async def charge_decision(self) -> None:
        async with self._lock:
            self.check_time()
            try:
                self.decisions.reserve_script()
            except DecisionLimitExceeded as exc:
                raise BudgetExceeded(exc.counter) from exc

    async def register_family(self, family: str) -> None:
        async with self._lock:
            self.check_time()
            if family not in self.families and len(self.families) >= self.limits.max_candidate_families:
                raise BudgetExceeded("max_candidate_families")
            self.families.add(family)

    def snapshot(self) -> dict[str, str | int]:
        return {**self.counts, **self.decisions.snapshot(),
                "task_model_calls": self.task_model_calls,
                "candidate_families": len(self.families),
                "elapsed_ms": max(0, int((self.clock() - self.started) * 1000))}
