"""Immutable runtime identity binding shared by every mediated boundary."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


@dataclass(frozen=True)
class TrustedContext:
    run_id: str
    actor_id: str
    role: str
    operation_id: str | None = None
    derived_from: dict[str, tuple[str, ...]] = field(default_factory=dict)
    trusted_public_fields: frozenset[str] = frozenset()
    artifact_dependencies: dict[str, tuple[str, ...]] = field(default_factory=dict)
    purpose: str | None = None
    recipient: str | None = None
    trace_phase: str | None = None
    trace_representation: str | None = None
    attempt_id: str | None = None


class RuntimeContextError(ValueError):
    """A caller-supplied identity disagrees with the trusted runtime binding."""


REGISTERED_BOUNDARIES = frozenset({
    "tool", "legacy_message", "peer_send", "peer_receive", "memory_write",
    "memory_read", "memory_compact", "reducer", "projection", "research",
})


@dataclass(frozen=True)
class RuntimeContextGuard:
    run_id: str
    runtime_roles: Mapping[str, str]

    def __post_init__(self) -> None:
        if type(self.run_id) is not str or not self.run_id:
            raise ValueError("A nonempty runtime run ID is required")
        if not isinstance(self.runtime_roles, Mapping) or not self.runtime_roles:
            raise ValueError("An explicit runtime actor-to-role mapping is required")
        roles = dict(self.runtime_roles)
        if any(type(actor) is not str or not actor or type(role) is not str or not role
               for actor, role in roles.items()):
            raise ValueError("Runtime actor and role IDs must be nonempty strings")
        object.__setattr__(self, "runtime_roles", MappingProxyType(roles))

    def role_for(self, actor_id: str) -> str:
        if type(actor_id) is not str or actor_id not in self.runtime_roles:
            raise RuntimeContextError("unknown_runtime_actor")
        return self.runtime_roles[actor_id]

    def validate(self, context: TrustedContext, *, boundary: str) -> None:
        if type(boundary) is not str or boundary not in REGISTERED_BOUNDARIES:
            raise RuntimeContextError("unregistered_runtime_boundary")
        if not isinstance(context, TrustedContext):
            raise RuntimeContextError("invalid_runtime_context")
        if type(context.run_id) is not str or context.run_id != self.run_id:
            raise RuntimeContextError("context_run_mismatch")
        role = self.role_for(context.actor_id)
        if type(context.role) is not str or context.role != role:
            raise RuntimeContextError("role_context_mismatch")

    def context_for(self, actor_id: str) -> TrustedContext:
        """Bind actor-only trusted diagnostics without accepting a claimed role/run."""
        return TrustedContext(self.run_id, actor_id, self.role_for(actor_id))

    def members(self, actor_ids) -> frozenset[str]:
        """Snapshot configured boundary permissions and reject undeclared actors."""
        members = frozenset(actor_ids)
        for actor_id in members:
            self.role_for(actor_id)
        return members
