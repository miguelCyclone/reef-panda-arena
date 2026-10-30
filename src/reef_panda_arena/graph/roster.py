"""Fixed ten-agent roster and bounded internal routes for unified replay."""

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class AgentRole:
    actor_id: str
    purpose: str


LEGACY_RUNTIME_ROLES = MappingProxyType({
    name: name for name in ("operations_worker", "customer_worker", "response_writer")
})


AGENTS = (
    AgentRole("A0", "supervisor"),
    AgentRole("A1", "shipment_worker"),
    AgentRole("A2", "private_account_worker"),
    AgentRole("A3", "routing_worker"),
    AgentRole("A4", "operations_worker"),
    AgentRole("A5", "compliance_worker"),
    AgentRole("A6", "analytics_request_worker"),
    AgentRole("A7", "memory_coordinator"),
    AgentRole("A8", "response_writer"),
    AgentRole("A9", "customer_notifier"),
)

BENIGN_ROUTES = frozenset({
    ("A1", "A8"), ("A2", "A3"), ("A3", "A5"),
    ("A4", "A6"), ("A5", "A7"), ("A6", "A8"),
    ("A7", "A8"), ("A8", "A9"),
})


class AgentRoster:
    def __init__(self, compromised_roles: tuple[str, ...] = ()) -> None:
        ids = {agent.actor_id for agent in AGENTS}
        if len(compromised_roles) > 2 or len(set(compromised_roles)) != len(compromised_roles):
            raise ValueError("At most two distinct compromised roles are allowed")
        if not set(compromised_roles) <= ids:
            raise ValueError("Unknown compromised role")
        self.compromised_roles = tuple(compromised_roles)
        self.roles = MappingProxyType({agent.actor_id: agent for agent in AGENTS})
        self.runtime_roles = MappingProxyType({actor_id: actor_id for actor_id in self.roles})

    def is_compromised(self, actor_id: str) -> bool:
        return actor_id in self.compromised_roles
