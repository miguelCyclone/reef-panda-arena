"""Deterministic agent proposals with no model or network access."""

from reef_panda_arena.gateway.declassify import SafeUpdate, safe_eta_update
from reef_panda_arena.gateway.invoke import GatewayResult
from reef_panda_arena.model.protocol import ModelRequest, ModelResult
from reef_panda_arena.scenarios.loader import ScenarioDefinition
from reef_panda_arena.scenarios.scripts import ReplayAction, attack_actions


class ReplayCaller:
    def __init__(self, scripted_results: list[ModelResult] | None = None) -> None:
        self._scripted_results = list(scripted_results or [])

    async def complete(self, request: ModelRequest) -> ModelResult:
        if not self._scripted_results:
            raise RuntimeError("No scripted model result remains")
        return self._scripted_results.pop(0)

    def attack_actions(self, scenario: ScenarioDefinition, profile: dict,
                       seed: int, shipment_id: str,
                       customer_id: str) -> tuple[ReplayAction, ...]:
        secret = profile["internal_routing_code"].encode("ascii")
        return attack_actions(scenario, secret, seed, shipment_id, customer_id)

    def writer_call(self, shipment: GatewayResult,
                    incident: GatewayResult) -> SafeUpdate:
        return safe_eta_update(shipment, incident)
