"""Peer lineage and the intentionally weak actor-local baseline."""

import asyncio
import hashlib
import json
from dataclasses import replace

import pytest

from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
from reef_panda_arena.gateway.provenance import ArtifactRegistry, ProvenanceJoiner
from reef_panda_arena.graph.roster import AgentRoster
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.tools.registry import MockToolRegistry


class MemoryEventStore:
    def __init__(self) -> None:
        self.events = []
        self.receipts = []

    async def append(self, event, receipt=None):
        self.events.append(event)
        if receipt is not None:
            self.receipts.append(receipt)
        return event


def test_registry_rejects_missing_lineage_and_preserves_uncertainty() -> None:
    registry = ArtifactRegistry("run-1")
    secret = registry.record_source(
        event_seq=1, actor_id="A2", label="secret", payload=b"synthetic",
    )
    assert registry.record_derived(
        event_seq=2, actor_id="A8", kind="peer_receive",
        parent_ids=(secret.artifact_id,), payload=b"summary",
    ).label == "secret"
    assert ProvenanceJoiner.join(()) == "unknown"
    assert ProvenanceJoiner.join(("public", "unknown")) == "unknown"
    with pytest.raises(ValueError, match="Unknown artifact"):
        registry.record_derived(
            event_seq=3, actor_id="A8", kind="transform",
            parent_ids=("model_claimed_id",), payload=b"summary",
        )
    with pytest.raises(ValueError, match="requires trusted dependencies"):
        registry.record_derived(
            event_seq=3, actor_id="A8", kind="transform",
            parent_ids=(), payload=b"summary",
        )


async def peer_then_outbound(profile: str):
    fixture = ScenarioLoader().shipping_fixture()
    store = MemoryEventStore()
    registry = ArtifactRegistry("run-1")
    gateway = PolicyGateway(
        store, MockToolRegistry(fixture, b"SYNTH123"), profile,
        b"SYNTH123", max_calls=8, max_events=12, max_payload_bytes=4096,
        role_tools={
            "operations_worker": {"customer.profile"},
            "response_writer": {"customer.notify"},
        },
        artifact_registry=registry, run_id=registry.run_id,
        runtime_roles={"A4": "operations_worker", "A8": "response_writer"},
    )
    source = await gateway.invoke(
        TrustedContext("run-1", "A4", "operations_worker"),
        ProposedCall(tool_name="customer.profile", arguments={"customer_id": "CUS-008"}),
    )
    assert source.allowed
    secret_id = source.artifact_ids["internal_routing_code"]
    assert registry.get(secret_id).label == "secret"

    peer = await gateway.forward_message(
        TrustedContext(
            "run-1", "A4", "operations_worker",
            artifact_dependencies={"text": (secret_id,)},
            trusted_public_fields=frozenset({"shipment_id", "customer_id"}),
        ),
        "A8",
        {"shipment_id": "SHP-1042", "customer_id": "CUS-008", "text": "Routine update."},
    )
    assert peer.allowed
    peer_id = peer.artifact_ids["text"]
    assert registry.get(peer_id).label == "secret"

    outbound = await gateway.invoke(
        TrustedContext(
            "run-1", "A8", "response_writer",
            artifact_dependencies={"text": (peer_id,)},
            trusted_public_fields=frozenset({"shipment_id", "customer_id"}),
        ),
        ProposedCall(
            tool_name="customer.notify",
            arguments={
                "shipment_id": "SHP-1042", "customer_id": "CUS-008",
                "text": "Routine update.",
            },
        ),
    )
    return outbound, store


def test_transitive_blocks_peer_derived_outbound_actor_local_loses_label() -> None:
    transitive, transitive_store = asyncio.run(peer_then_outbound("transitive"))
    actor_local, actor_store = asyncio.run(peer_then_outbound("actor_local"))
    assert not transitive.allowed
    assert transitive.reason == "secret_taint_to_outbound"
    assert transitive_store.events[-1].taint_labels_json["text"] == "secret"
    assert transitive_store.receipts == []
    assert actor_local.allowed
    assert actor_store.events[-1].taint_labels_json["text"] == "public"
    assert len(actor_store.receipts) == 1


def test_missing_outbound_provenance_fails_closed() -> None:
    fixture = ScenarioLoader().shipping_fixture()
    store = MemoryEventStore()
    gateway = PolicyGateway(
        store, MockToolRegistry(fixture, b"SYNTH123"), "transitive",
        b"SYNTH123", 3, 5, 4096,
        role_tools={"response_writer": {"customer.notify"}},
        artifact_registry=ArtifactRegistry("run-1"), run_id="run-1",
        runtime_roles={"A8": "response_writer"},
    )
    result = asyncio.run(gateway.invoke(
        TrustedContext(
            "run-1", "A8", "response_writer",
            trusted_public_fields=frozenset({"shipment_id", "customer_id"}),
        ),
        ProposedCall(
            tool_name="customer.notify",
            arguments={
                "shipment_id": "SHP-1042", "customer_id": "CUS-008",
                "text": "Unattributed text",
            },
        ),
    ))
    assert not result.allowed
    assert result.reason == "unknown_provenance"
    assert store.receipts == []


def test_trusted_route_release_checks_source_value_and_scope() -> None:
    import json

    from reef_panda_arena.gateway.release import (
        ROUTE_PURPOSE, ROUTE_RECIPIENT, TrustedProjection,
    )

    registry = ArtifactRegistry("run-2")
    source = registry.record_source(
        event_seq=1, actor_id="A2", label="secret",
        payload=json.dumps("SYNTH123").encode("utf-8"),
        kind="private.account.code",
    )
    projection = TrustedProjection(registry)
    with pytest.raises(ValueError, match="differs"):
        projection.release_route(
            event_seq=2, actor_id="A3", source_id=source.artifact_id,
            source_code="SYNTH999", purpose=ROUTE_PURPOSE,
            recipient=ROUTE_RECIPIENT,
        )
    with pytest.raises(ValueError, match="scope"):
        projection.release_route(
            event_seq=2, actor_id="A3", source_id=source.artifact_id,
            source_code="SYNTH123", purpose="unrelated",
            recipient=ROUTE_RECIPIENT,
        )
    released = projection.release_route(
        event_seq=2, actor_id="A3", source_id=source.artifact_id,
        source_code="SYNTH123", purpose=ROUTE_PURPOSE,
        recipient=ROUTE_RECIPIENT,
    )
    assert released.category in {"standard", "priority"}
    assert registry.get(released.artifact_id).label == "public"
    assert registry.release_scopes(released.artifact_id) == (
        (ROUTE_PURPOSE, ROUTE_RECIPIENT),
    )
    descendant = registry.record_derived(
        event_seq=3, actor_id="A8", kind="peer_receive",
        parent_ids=(released.artifact_id,), payload=released.category.encode("ascii"),
    )
    assert registry.release_scopes(descendant.artifact_id) == (
        (ROUTE_PURPOSE, ROUTE_RECIPIENT),
    )


def test_peer_delivery_is_separate_from_egress_and_preserves_runtime_truth() -> None:
    from reef_panda_arena.gateway.peer import PeerMessageCaller

    async def verify(profile: str):
        fixture = ScenarioLoader().shipping_fixture()
        store = MemoryEventStore()
        registry = ArtifactRegistry("peer-run")
        gateway = PolicyGateway(
            store, MockToolRegistry(fixture, b"SYNTH123"), profile,
            b"SYNTH123", 8, 12, 4096,
            artifact_registry=registry, run_id=registry.run_id,
            runtime_roles=AgentRoster().runtime_roles,
        )
        source = registry.record_source(
            event_seq=0, actor_id="A2", label="secret", payload=b"synthetic",
        )
        peer = PeerMessageCaller(gateway, registry, frozenset({("A2", "A9")}))
        sent = await peer.send(
            TrustedContext(
                "peer-run", "A2", "A2",
                artifact_dependencies={"text": (source.artifact_id,)},
            ),
            "A9", {"text": "Routine update."},
        )
        assert sent.allowed
        delivery = await peer.receive(
            TrustedContext("peer-run", "A9", "A9"),
            sent.data["message_id"],
        )
        assert delivery.allowed
        assert registry.get(delivery.artifact_ids["text"]).label == "secret"
        assert store.receipts == []
        assert [item.event_type for item in store.events] == [
            "agent.message", "agent.receive",
        ]
        return store.events[-1].taint_labels_json["text"]

    assert asyncio.run(verify("transitive")) == "secret"
    assert asyncio.run(verify("actor_local")) == "public"


def test_peer_receive_rejects_tampered_runtime_origin() -> None:
    from reef_panda_arena.gateway.peer import PeerMessageCaller

    async def verify() -> None:
        store = MemoryEventStore()
        registry = ArtifactRegistry("peer-run")
        gateway = PolicyGateway(
            store,
            MockToolRegistry(ScenarioLoader().shipping_fixture(), b"SYNTH123"),
            "transitive", b"SYNTH123", 8, 12, 4096,
            artifact_registry=registry, run_id=registry.run_id,
            runtime_roles=AgentRoster().runtime_roles,
        )
        peer = PeerMessageCaller(gateway, registry, frozenset({("A2", "A9")}))
        sent = await peer.send(
            TrustedContext(
                "peer-run", "A2", "A2",
                trusted_public_fields=frozenset({"text"}),
            ),
            "A9", {"text": "Public update."}, kind="control",
        )
        assert sent.allowed
        message_id = sent.data["message_id"]
        peer._queued[message_id] = replace(
            peer._queued[message_id], origin_mac=b"\x00" * 32,
        )
        received = await peer.receive(
            TrustedContext("peer-run", "A9", "A9"), message_id,
        )
        assert not received.allowed
        assert received.reason == "invalid_runtime_origin"
        assert received.artifact_ids == {}
        assert store.receipts == []

    asyncio.run(verify())


def peer_boundary(store=None, *, max_payload_bytes=4096):
    from reef_panda_arena.gateway.peer import PeerMessageCaller

    store = store or MemoryEventStore()
    registry = ArtifactRegistry("peer-run")
    gateway = PolicyGateway(
        store, MockToolRegistry(ScenarioLoader().shipping_fixture(), b"SYNTH123"),
        "transitive", b"SYNTH123", 12, 16, max_payload_bytes,
        artifact_registry=registry, run_id=registry.run_id,
        runtime_roles=AgentRoster().runtime_roles,
    )
    peer = PeerMessageCaller(gateway, registry, frozenset({("A2", "A9")}))
    return peer, registry, store, gateway


def test_peer_snapshots_nested_values_and_provenance_before_await() -> None:
    async def verify():
        payload = {"byte_values": [1, 2], "note": {"nested": ["public"]}}
        expected = {"byte_values": [1, 2], "note": {"nested": ["public"]}}
        dependencies = {}
        public_fields = {"note"}

        class MutatingStore(MemoryEventStore):
            async def append(self, event, receipt=None):
                if event.event_type == "agent.message":
                    await asyncio.sleep(0)
                    payload["byte_values"][0] = 99
                    payload["note"]["nested"][0] = "changed during append"
                    dependencies["byte_values"][:] = [public.artifact_id]
                    public_fields.clear()
                    public_fields.add("byte_values")
                return await super().append(event, receipt)

        peer, registry, store, gateway = peer_boundary(MutatingStore())
        secret = registry.record_source(event_seq=0, actor_id="A2", label="secret", payload=b"dummy")
        public = registry.record_source(event_seq=0, actor_id="A2", label="public", payload=b"public")
        dependencies["byte_values"] = [secret.artifact_id]
        sent = await peer.send(TrustedContext(
            "peer-run", "A2", "A2", artifact_dependencies=dependencies,
            trusted_public_fields=public_fields,
        ), "A9", payload)
        assert sent.allowed
        original_send_id = sent.artifact_ids["byte_values"]
        assert registry.get(original_send_id).parent_ids == (secret.artifact_id,)
        payload["byte_values"].append(100)
        payload["note"]["nested"][0] = "changed after send"
        dependencies.clear()
        sent.artifact_ids["byte_values"] = public.artifact_id
        sent.field_labels["byte_values"] = "public"
        message_id = sent.data["message_id"]
        queued = peer._queued[message_id]
        assert type(queued.envelope) is bytes and type(queued.origin_mac) is bytes
        received = await peer.receive(TrustedContext("peer-run", "A9", "A9"), message_id)
        assert received.allowed and received.data == expected
        child = registry.get(received.artifact_ids["byte_values"])
        assert child.parent_ids == (original_send_id,) and child.label == "secret"
        assert received.field_labels == {"byte_values": "secret", "note": "public"}
        canonical = json.dumps({"kind": "artifact", "payload": expected}, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False).encode()
        assert store.events[0].payload_sha256 == store.events[1].payload_sha256 == hashlib.sha256(canonical).digest()
        assert all(event.safe_summary_json["observer_coverage"] == "not_inspected" for event in store.events)
        assert len(gateway.boundary_observations) == 2
        assert not any(item["accepted"] for item in gateway.boundary_observations)
        assert store.receipts == []
        with pytest.raises(ValueError, match="already consumed"):
            await peer.receive(TrustedContext("peer-run", "A9", "A9"), message_id)

    asyncio.run(verify())


def test_peer_rejects_modified_signed_bytes_maps_and_queue_identity() -> None:
    async def verify(tamper):
        peer, registry, store, _ = peer_boundary()
        secret = registry.record_source(event_seq=0, actor_id="A2", label="secret", payload=b"dummy")
        public = registry.record_source(event_seq=0, actor_id="A2", label="public", payload=b"public")
        sent = await peer.send(TrustedContext(
            "peer-run", "A2", "A2", artifact_dependencies={"values": (secret.artifact_id,)},
        ), "A9", {"values": [1, 2]})
        message_id = sent.data["message_id"]
        original = peer._queued[message_id]
        envelope = json.loads(original.envelope)
        if tamper == "payload":
            envelope["payload"]["values"][0] = 99
        elif tamper == "artifact_map":
            envelope["artifact_ids"]["values"] = public.artifact_id
        elif tamper == "parent_map":
            envelope["parent_ids"]["values"] = [public.artifact_id]
        elif tamper == "signed_wrong_parent":
            envelope["artifact_ids"]["values"] = public.artifact_id
        elif tamper == "registered_parent":
            parent_id = sent.artifact_ids["values"]
            registry._artifacts[parent_id] = replace(registry.get(parent_id), payload_sha256="0" * 64)
        elif tamper == "queue_identity":
            message_id = "different-runtime-message-id"
            peer._queued[message_id] = original
        if tamper not in {"queue_identity", "registered_parent"}:
            encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            peer._queued[message_id] = replace(original, envelope=encoded,
                origin_mac=peer._origin_mac(encoded) if tamper == "signed_wrong_parent" else original.origin_mac)
        before = dict(registry._artifacts)
        received = await peer.receive(TrustedContext("peer-run", "A9", "A9"), message_id)
        assert not received.allowed and received.reason == "invalid_runtime_origin"
        assert received.artifact_ids == {} and received.data is None
        assert registry._artifacts == before
        assert message_id in peer._queued
        assert store.receipts == []
        assert store.events[-1].safe_summary_json["integrity_verified"] is False
        assert store.events[-1].policy_decision == "block"

    for tamper in ("payload", "artifact_map", "parent_map", "queue_identity", "signed_wrong_parent", "registered_parent"):
        asyncio.run(verify(tamper))


def test_peer_public_control_survives_wrong_recipient_and_is_consumed_once() -> None:
    async def verify():
        peer, registry, store, _ = peer_boundary()
        sent = await peer.send(TrustedContext(
            "peer-run", "A2", "A2", trusted_public_fields=frozenset({"text"}),
        ), "A9", {"text": "Public update."}, kind="control")
        message_id = sent.data["message_id"]
        before = dict(registry._artifacts)
        wrong = await peer.receive(TrustedContext("peer-run", "A8", "A8"), message_id)
        assert not wrong.allowed and wrong.reason == "message_recipient_mismatch"
        assert registry._artifacts == before and message_id in peer._queued
        good = await peer.receive(TrustedContext("peer-run", "A9", "A9"), message_id)
        assert good.allowed and good.data == {"text": "Public update."}
        assert registry.get(good.artifact_ids["text"]).label == "public"
        assert message_id not in peer._queued and store.receipts == []

    asyncio.run(verify())


def test_peer_invalid_dependencies_json_and_size_fail_before_artifact_registration() -> None:
    async def verify(case):
        peer, registry, store, _ = peer_boundary(max_payload_bytes=256)
        source = registry.record_source(event_seq=0, actor_id="A2", label="secret", payload=b"dummy")
        payload = {"value": [1, 2]}
        dependencies = {"value": (source.artifact_id,)}
        public_fields = frozenset()
        if case == "duplicates":
            dependencies["value"] *= 2
        elif case == "unknown":
            dependencies["value"] = ("not_registered",)
        elif case == "absent_dependency":
            dependencies["absent"] = (source.artifact_id,)
        elif case == "absent_public":
            public_fields = frozenset({"absent"})
        elif case == "public_with_parents":
            public_fields = frozenset({"value"})
        elif case == "null_payload":
            payload = None
        elif case == "non_string_key":
            payload["value"] = {1: "coerced"}
        elif case == "nonfinite":
            payload["value"] = float("nan")
        elif case == "cycle":
            payload["value"].append(payload)
        elif case == "oversize":
            payload["value"] = "x" * 512
        before = dict(registry._artifacts)
        sent = await peer.send(TrustedContext(
            "peer-run", "A2", "A2", artifact_dependencies=dependencies,
            trusted_public_fields=public_fields,
        ), "A9", payload)
        assert not sent.allowed and sent.artifact_ids == {}
        assert registry._artifacts == before and peer._queued == {}
        assert store.receipts == [] and store.events[-1].policy_decision == "block"

    for case in ("duplicates", "unknown", "absent_dependency", "absent_public",
                 "public_with_parents", "null_payload", "non_string_key", "nonfinite", "cycle", "oversize"):
        asyncio.run(verify(case))
