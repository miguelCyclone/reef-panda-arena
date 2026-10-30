"""Runtime identity and boundary contracts fail before data or state access."""

import asyncio
from dataclasses import FrozenInstanceError, replace

import pytest

from reef_panda_arena.gateway.context import RuntimeContextError, RuntimeContextGuard
from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
from reef_panda_arena.gateway.memory import MemoryCaller
from reef_panda_arena.gateway.peer import PeerMessageCaller
from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.gateway.reducer import ReducerCaller
from reef_panda_arena.gateway.release import ProjectionCaller, ROUTE_PURPOSE, ROUTE_RECIPIENT
from reef_panda_arena.graph.roster import AgentRoster, LEGACY_RUNTIME_ROLES
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.tools.unified import (
    UNIFIED_DESTINATIONS, UNIFIED_ROLE_TOOLS, UNIFIED_TOOL_INPUTS, UnifiedToolAdapter,
)


class MemoryEventStore:
    def __init__(self):
        self.events, self.receipts = [], []

    async def append(self, event, receipt=None):
        self.events.append(event)
        if receipt is not None:
            self.receipts.append(receipt)
        return event


def SpyAdapter():
    adapter = UnifiedToolAdapter(ScenarioLoader().shipping_fixture(), b"SYNTH123")
    adapter.executed = []
    execute = adapter.execute

    def observed_execute(name, args):
        adapter.executed.append(name)
        return execute(name, args)

    adapter.execute = observed_execute
    return adapter


def gateway_for(profile="none", *, roles=None, registry=None, research_run_id=None,
                max_calls=40, max_events=48):
    store, adapter = MemoryEventStore(), SpyAdapter()
    registry = registry if registry is not None else ArtifactRegistry("bound-run")
    gateway = PolicyGateway(
        store, adapter, profile, b"SYNTH123", max_calls, max_events, 4096,
        tool_inputs=UNIFIED_TOOL_INPUTS, tool_destinations=UNIFIED_DESTINATIONS,
        role_tools=UNIFIED_ROLE_TOOLS, artifact_registry=registry,
        run_id="bound-run", runtime_roles=roles if roles is not None else AgentRoster().runtime_roles,
        research_run_id=research_run_id,
    )
    return gateway, registry, store, adapter


def effects(gateway, registry, store, adapter):
    return (gateway.calls, gateway.events, dict(registry._artifacts), list(store.events),
            list(store.receipts), list(adapter.executed), list(gateway.accepted_artifacts))


def test_runtime_binding_is_explicit_immutable_and_rejects_unknown_boundaries():
    roles = {"A2": "A2", "A6": "A6"}
    gateway, registry, store, adapter = gateway_for(roles=roles)
    roles["A6"] = "A2"
    roles["invented"] = "A2"
    guard = gateway.context_guard
    assert dict(guard.runtime_roles) == {"A2": "A2", "A6": "A6"}
    with pytest.raises(TypeError):
        guard.runtime_roles["A6"] = "A2"
    with pytest.raises(FrozenInstanceError):
        guard.run_id = "foreign-run"
    before = effects(gateway, registry, store, adapter)
    with pytest.raises(RuntimeContextError, match="unregistered_runtime_boundary"):
        guard.validate(TrustedContext("bound-run", "A2", "A2"), boundary="unmediated")
    assert effects(gateway, registry, store, adapter) == before
    with pytest.raises(ValueError, match="registry differs"):
        gateway_for(registry=ArtifactRegistry("foreign-run"))
    with pytest.raises(ValueError, match="Research run ID differs"):
        gateway_for(research_run_id="foreign-run")
    with pytest.raises(ValueError, match="explicit runtime"):
        RuntimeContextGuard("bound-run", {})
    assert gateway_for(research_run_id="bound-run")[0].event_store_run_id == "bound-run"
    with pytest.raises(AttributeError):
        gateway.event_store_run_id = "foreign-run"
    with pytest.raises(TypeError):
        LEGACY_RUNTIME_ROLES["customer_worker"] = "operations_worker"


def test_foreign_run_unknown_actor_and_role_claim_have_zero_effects_even_under_none():
    async def verify(profile):
        gateway, registry, store, adapter = gateway_for(profile)
        call = ProposedCall(tool_name="private.account", arguments={"customer_id": "CUS-008"})
        invalid = (
            (TrustedContext("foreign-run", "A6", "A2"), "context_run_mismatch"),
            (TrustedContext("bound-run", "A6", "A2"), "role_context_mismatch"),
            (TrustedContext("bound-run", "unknown", "A2"), "unknown_runtime_actor"),
        )
        for context, reason in invalid:
            with pytest.raises(RuntimeContextError, match=reason):
                await gateway.invoke(context, call)
        assert gateway.calls == gateway.events == 0
        assert not registry._artifacts and not store.events and not store.receipts
        assert adapter.executed == [] and gateway.accepted_artifacts == []
        assert not gateway.taint.has_secret_read("A6")
        valid = await gateway.invoke(TrustedContext("bound-run", "A2", "A2"), call)
        assert valid.allowed and adapter.executed == ["private.account"]
        assert all(event.run_id == "bound-run" for event in store.events)
        assert all(artifact.run_id == "bound-run" for artifact in registry._artifacts.values())

    for profile in ("none", "transitive"):
        asyncio.run(verify(profile))


def test_identity_guard_runs_before_operation_cache_hits():
    async def verify():
        gateway, registry, store, adapter = gateway_for()
        call = ProposedCall(tool_name="private.account", arguments={"customer_id": "CUS-008"})
        context = TrustedContext("bound-run", "A2", "A2", operation_id="source-once")
        result = await gateway.invoke(context, call)
        assert result.allowed
        before = effects(gateway, registry, store, adapter)
        for invalid in (replace(context, role="A6"), replace(context, run_id="foreign-run")):
            with pytest.raises(RuntimeContextError):
                await gateway.invoke(invalid, call)
        assert effects(gateway, registry, store, adapter) == before
        assert await gateway.invoke(context, call) is result
        assert gateway.calls == before[0] + 1
        assert effects(gateway, registry, store, adapter)[1:] == before[1:]

    asyncio.run(verify())


def test_valid_actor_tool_permissions_remain_profile_policy_decisions():
    async def verify(profile, expected):
        gateway, _, store, adapter = gateway_for(profile)
        result = await gateway.invoke(TrustedContext("bound-run", "A6", "A6"),
            ProposedCall(tool_name="private.account", arguments={"customer_id": "CUS-008"}))
        assert result.allowed is expected
        assert result.reason == ("allowed" if expected else "role_not_allowed")
        assert len(adapter.executed) == int(expected)
        assert store.events[-1].run_id == "bound-run"

    asyncio.run(verify("allowlist_only", False))
    asyncio.run(verify("none", True))


class NoReads(dict):
    def get(self, *args):
        raise AssertionError("Unauthorized stored-value lookup")

    def __getitem__(self, key):
        raise AssertionError("Unauthorized stored-value read")

    def __contains__(self, key):
        raise AssertionError("Unauthorized stored-value membership check")


def test_every_peer_memory_reducer_projection_boundary_checks_identity_first():
    async def verify():
        gateway, registry, store, adapter = gateway_for()
        peer = PeerMessageCaller(gateway, registry, frozenset({("A2", "A9")}))
        memory = MemoryCaller(gateway, registry, frozenset({"A2", "A7"}), frozenset({"A8"}))
        reducer, projection = ReducerCaller(gateway, registry), ProjectionCaller(gateway, registry)
        peer._queued, memory._values = NoReads(), NoReads()
        operations = (
            ("A2", lambda c: peer.send(c, "A9", {"text": "public"})),
            ("A9", lambda c: peer.receive(c, "unread-message")),
            ("A2", lambda c: memory.write(c, "key", "value", ("unread-parent",))),
            ("A7", lambda c: memory.compact(c, "key")),
            ("A8", lambda c: memory.read(c, "key")),
            ("A8", lambda c: reducer.join(c, "value", ("unread-1", "unread-2"))),
            ("A3", lambda c: projection.release_route(c, source_id="unread-parent", source_code="SYNTH123",
                purpose=ROUTE_PURPOSE, recipient=ROUTE_RECIPIENT)),
        )
        before = effects(gateway, registry, store, adapter)
        for actor, operation in operations:
            for context in (TrustedContext("foreign-run", actor, actor),
                            TrustedContext("bound-run", actor, "claimed-role")):
                with pytest.raises(RuntimeContextError):
                    await operation(context)
        assert effects(gateway, registry, store, adapter) == before

    asyncio.run(verify())


def test_boundary_permissions_are_frozen_and_apply_under_none_without_private_reads():
    async def verify():
        gateway, registry, store, adapter = gateway_for()
        writers, readers, routes = {"A2", "A7"}, {"A8"}, {("A2", "A9")}
        memory = MemoryCaller(gateway, registry, writers, readers)
        peer = PeerMessageCaller(gateway, registry, routes)
        writers.add("A6")
        readers.add("A6")
        routes.add(("A6", "A9"))
        memory._values = NoReads()
        def forbidden_source_lookup(*_args):
            raise AssertionError("Denied boundary must not read a source")
        registry.get = forbidden_source_lookup
        context = TrustedContext("bound-run", "A6", "A6", trusted_public_fields=frozenset({"text"}))
        results = [await memory.write(context, "key", "value", ("unread-parent",)),
                   await memory.read(context, "key"), await memory.compact(context, "key"),
                   await peer.send(context, "A9", {"text": "public"}),
                   await ReducerCaller(gateway, registry).join(context, "value", ("unread-1", "unread-2")),
                   await ProjectionCaller(gateway, registry).release_route(context,
                       source_id="unread-parent", source_code="SYNTH123", purpose=ROUTE_PURPOSE,
                       recipient=ROUTE_RECIPIENT)]
        results.append(await ProjectionCaller(gateway, registry).release_route(
            TrustedContext("bound-run", "A3", "A3"), source_id="unread-parent",
            source_code="SYNTH123", purpose=ROUTE_PURPOSE, recipient="CUS-WRONG"))
        assert all(not result.allowed and result.data is None for result in results)
        assert not registry._artifacts and not store.receipts and not adapter.executed
        assert all(event.policy_decision == "block" and event.run_id == "bound-run" for event in store.events)

    asyncio.run(verify())


def test_legacy_message_and_research_diagnostics_use_bound_identity():
    async def verify():
        gateway, registry, store, adapter = gateway_for(roles=LEGACY_RUNTIME_ROLES)
        before = effects(gateway, registry, store, adapter)
        for context in (TrustedContext("foreign-run", "operations_worker", "operations_worker"),
                        TrustedContext("bound-run", "customer_worker", "operations_worker")):
            with pytest.raises(RuntimeContextError):
                await gateway.forward_message(context, "response_writer", {})
        with pytest.raises(RuntimeContextError, match="unknown_runtime_actor"):
            await gateway.record_research_event(actor_id="invented", event_type="candidate.rejected",
                                                reason_code="invalid_candidate")
        assert effects(gateway, registry, store, adapter) == before
        await gateway.record_research_event(actor_id="customer_worker", event_type="candidate.rejected",
                                            reason_code="invalid_candidate")
        assert store.events[-1].run_id == "bound-run"
        assert store.events[-1].actor_id == "customer_worker"
        assert store.receipts == [] and not adapter.executed

        aliases, alias_registry, alias_store, alias_adapter = gateway_for(roles={
            "A4": "operations_worker", "A6": "customer_worker", "A8": "response_writer",
        })
        payload = {"shipment_id": "SHP-1042", "customer_id": "CUS-008", "text": "Public update."}
        sender = TrustedContext("bound-run", "A4", "operations_worker",
                                trusted_public_fields=frozenset(payload))
        for recipient in ("response_writer", "A6", "missing-actor"):
            blocked = await aliases.forward_message(sender, recipient, payload)
            assert not blocked.allowed and blocked.reason == "message_route_not_allowed"
        assert not alias_registry._artifacts and not alias_store.receipts and not alias_adapter.executed
        accepted = await aliases.forward_message(sender, "A8", payload)
        assert accepted.allowed
        assert alias_store.events[-1].destination == "A8"
        assert alias_registry._artifacts and not alias_store.receipts

    asyncio.run(verify())


def test_shared_action_cap_stops_mixed_boundary_effects_and_preserves_receipts():
    from reef_panda_arena.gateway.budget import GatewayBudgetExceeded, UnifiedBudgetExceeded

    async def verify():
        roles = {**AgentRoster().runtime_roles, **LEGACY_RUNTIME_ROLES}
        gateway, registry, store, adapter = gateway_for(roles=roles, max_calls=9)
        source = await gateway.invoke(TrustedContext("bound-run", "A2", "A2"),
            ProposedCall(tool_name="private.account", arguments={"customer_id": "CUS-008"}))
        public = {"shipment_id": "SHP-1042", "customer_id": "CUS-008", "text": "Public update."}
        notice = await gateway.invoke(TrustedContext("bound-run", "A9", "A9",
            trusted_public_fields=frozenset(public)),
            ProposedCall(tool_name="customer.notify", arguments=public))
        assert notice.allowed and len(store.receipts) == 1
        handoff = await gateway.forward_message(TrustedContext(
            "bound-run", "operations_worker", "operations_worker",
            trusted_public_fields=frozenset(public)), "response_writer", public)
        assert handoff.allowed
        peer = PeerMessageCaller(gateway, registry, frozenset({("A2", "A9")}))
        sent = await peer.send(TrustedContext("bound-run", "A2", "A2",
            trusted_public_fields=frozenset({"text"})), "A9", {"text": "Public update."})
        received = await peer.receive(TrustedContext("bound-run", "A9", "A9"), sent.data["message_id"])
        memory = MemoryCaller(gateway, registry, frozenset({"A2", "A7"}), frozenset({"A8"}))
        written = await memory.write(TrustedContext("bound-run", "A2", "A2"),
            "task", "private-derived", (source.artifact_ids["code"],))
        compacted = await memory.compact(TrustedContext("bound-run", "A7", "A7"), "task")
        read = await memory.read(TrustedContext("bound-run", "A8", "A8"), "task")
        assert written.allowed and compacted.allowed and read.allowed
        denied = await ReducerCaller(gateway, registry).join(TrustedContext("bound-run", "A8", "A8"),
            "joined", (read.artifact_ids["value"], received.artifact_ids["text"]))
        assert not denied.allowed
        assert gateway.calls == gateway.events == 9
        before = effects(gateway, registry, store, adapter)
        with pytest.raises(GatewayBudgetExceeded, match="action budget"):
            await ProjectionCaller(gateway, registry).release_route(
                TrustedContext("bound-run", "A3", "A3"), source_id=source.artifact_ids["code"],
                source_code="SYNTH123", purpose=ROUTE_PURPOSE, recipient=ROUTE_RECIPIENT)
        assert effects(gateway, registry, store, adapter) == before
        assert len(store.receipts) == len(gateway.accepted_artifacts) == 1
        assert UnifiedBudgetExceeded is GatewayBudgetExceeded

    asyncio.run(verify())


def test_cached_retries_and_conflicts_consume_actions_without_duplicate_events():
    from reef_panda_arena.gateway.budget import GatewayBudgetExceeded

    async def verify():
        gateway, registry, store, adapter = gateway_for(max_calls=3, max_events=1)
        context = TrustedContext("bound-run", "A2", "A2", operation_id="source-once")
        call = ProposedCall(tool_name="private.account", arguments={"customer_id": "CUS-008"})
        first = await gateway.invoke(context, call)
        assert await gateway.invoke(context, call) is first
        with pytest.raises(ValueError, match="Conflicting operation id"):
            await gateway.invoke(context, ProposedCall(tool_name="private.account",
                                                       arguments={"customer_id": "CUS-OTHER"}))
        assert gateway.calls == 3 and gateway.events == 1
        before = effects(gateway, registry, store, adapter)
        with pytest.raises(GatewayBudgetExceeded):
            await gateway.invoke(context, call)
        assert effects(gateway, registry, store, adapter) == before
        assert adapter.executed == ["private.account"] and len(store.events) == 1
        peer_gateway, peer_registry, peer_store, _ = gateway_for(max_calls=2)
        peer = PeerMessageCaller(peer_gateway, peer_registry, frozenset({("A2", "A9")}))
        recipient = TrustedContext("bound-run", "A9", "A9")
        for _ in range(2):
            with pytest.raises(ValueError, match="Unknown or already consumed"):
                await peer.receive(recipient, "missing-message")
        assert peer_gateway.calls == 2 and peer_gateway.events == 0
        with pytest.raises(GatewayBudgetExceeded):
            await peer.receive(recipient, "missing-message")
        assert peer_store.events == peer_store.receipts == []

    asyncio.run(verify())


def test_diagnostics_use_only_event_budget_and_action_overrides_cannot_exceed_forty():
    from reef_panda_arena.gateway.budget import GatewayBudgetExceeded

    async def verify():
        gateway, registry, store, adapter = gateway_for(max_calls=1, max_events=2)
        context = TrustedContext("bound-run", "A2", "A2")
        unknown = ProposedCall(tool_name="unknown.tool", arguments={})
        assert not (await gateway.invoke(context, unknown)).allowed
        await gateway.record_research_event(actor_id="A2", event_type="candidate.rejected",
                                            reason_code="invalid_candidate")
        assert gateway.calls == 1 and gateway.events == 2
        before = effects(gateway, registry, store, adapter)
        with pytest.raises(GatewayBudgetExceeded, match="event budget"):
            await gateway.record_research_event(actor_id="A2", event_type="candidate.rejected",
                                                reason_code="invalid_candidate")
        with pytest.raises(GatewayBudgetExceeded, match="action budget"):
            await gateway.invoke(context, unknown)
        assert effects(gateway, registry, store, adapter) == before
        capped, registry, store, adapter = gateway_for(max_calls=999, max_events=100)
        assert capped.max_calls == 40 and capped.max_events == 100
        for _ in range(40):
            assert not (await capped.invoke(context, unknown)).allowed
        before = effects(capped, registry, store, adapter)
        with pytest.raises(GatewayBudgetExceeded):
            await capped.invoke(context, unknown)
        assert effects(capped, registry, store, adapter) == before
        assert not registry._artifacts and not store.receipts and not adapter.executed

    asyncio.run(verify())
    for invalid in (0, -1, True, 1.5):
        with pytest.raises(ValueError, match="positive integers"):
            gateway_for(max_calls=invalid)
