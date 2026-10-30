"""Prepared lineage is atomic with each mediated boundary's journal event."""

import asyncio
import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest

from reef_panda_arena.gateway.context import TrustedContext
from reef_panda_arena.gateway.invoke import PolicyGateway
from reef_panda_arena.gateway.lineage_evidence import lineage_document, validate_lineage_document
from reef_panda_arena.gateway.memory import MemoryCaller
from reef_panda_arena.gateway.peer import PeerMessageCaller
from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.gateway.reducer import ReducerCaller
from reef_panda_arena.gateway.release import ProjectionCaller, ROUTE_PURPOSE, ROUTE_RECIPIENT
from reef_panda_arena.graph.roster import AgentRoster
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.tools.unified import UnifiedToolAdapter


class InspectingStore:
    def __init__(self, registry):
        self.registry = registry
        self.events = []
        self.fail = False
        self.before_append = None
        self.prepared_ids = []

    async def append(self, event, receipt=None):
        assert receipt is None  # These internal boundaries do not accept egress.
        document = validate_lineage_document(event.safe_summary_json["lineage"])
        self.prepared_ids = [node["artifact_id"] for node in document["nodes"]]
        assert all(identifier not in self.registry._artifacts for identifier in self.prepared_ids)
        if self.before_append:
            self.before_append(event)
        await asyncio.sleep(0)
        if self.fail:
            raise RuntimeError("Controlled persistence failure")
        self.events.append(event)
        return event


def boundary_setup(profile="actor_local"):
    registry = ArtifactRegistry("lineage-run")
    source = registry.record_source(
        event_seq=0, actor_id="A2", label="secret", kind="private.account.code",
        payload=json.dumps("SYNTH123").encode(),
    )
    store = InspectingStore(registry)
    gateway = PolicyGateway(
        store, UnifiedToolAdapter(ScenarioLoader().shipping_fixture(), b"SYNTH123"),
        profile, b"SYNTH123", 40, 48, 4096, artifact_registry=registry,
        run_id=registry.run_id, runtime_roles=AgentRoster().runtime_roles,
    )
    peer = PeerMessageCaller(gateway, registry, frozenset({("A2", "A8"), ("A2", "A9")}))
    memory = MemoryCaller(gateway, registry, frozenset({"A6"}), frozenset({"A7"}))
    return gateway, registry, store, peer, memory, source


def context(actor, **kwargs):
    return TrustedContext("lineage-run", actor, actor, **kwargs)


@pytest.mark.parametrize("boundary", ["send", "receive", "write", "read", "compact", "reducer", "projection"])
def test_append_failure_publishes_no_child_queue_or_memory_version(boundary):
    async def verify():
        gateway, registry, store, peer, memory, source = boundary_setup()
        parents = (source.artifact_id,)
        if boundary == "send":
            operation = lambda: peer.send(context("A2", artifact_dependencies={"text": parents}), "A9", {"text": "public shape"})
        elif boundary == "receive":
            sent = await peer.send(context("A2", artifact_dependencies={"text": parents}), "A9", {"text": "public shape"})
            operation = lambda: peer.receive(context("A9"), sent.data["message_id"])
        elif boundary == "write":
            operation = lambda: memory.write(context("A6"), "private-key", "public shape", parents)
        elif boundary in {"read", "compact"}:
            await memory.write(context("A6"), "private-key", "  public   shape  ", parents)
            operation = (lambda: memory.read(context("A7"), "private-key")) if boundary == "read" else (
                lambda: memory.compact(context("A6"), "private-key"))
        elif boundary == "reducer":
            received = []
            for value in ("left", "right"):
                sent = await peer.send(context("A2", artifact_dependencies={"text": parents}), "A8", {"text": value})
                received.append((await peer.receive(context("A8"), sent.data["message_id"])).artifact_ids["text"])
            operation = lambda: ReducerCaller(gateway, registry).join(context("A8"), "joined", tuple(received))
        else:
            operation = lambda: ProjectionCaller(gateway, registry).release_route(
                context("A3"), source_id=source.artifact_id, source_code="SYNTH123",
                purpose=ROUTE_PURPOSE, recipient=ROUTE_RECIPIENT,
            )
        before = (dict(registry._artifacts), dict(peer._queued), dict(memory._values), list(store.events))
        store.fail = True
        with pytest.raises(RuntimeError, match="persistence failure"):
            await operation()
        assert store.prepared_ids  # A real child was prepared but never published.
        assert (registry._artifacts, peer._queued, memory._values, store.events) == before
        assert all(identifier not in registry._artifacts for identifier in store.prepared_ids)
        assert gateway.accepted_artifacts == []

    asyncio.run(verify())


def test_prepared_batch_is_immutable_detached_and_published_all_at_once():
    registry = ArtifactRegistry("lineage-run")
    source = registry.prepare_source(event_seq=1, actor_id="A2", label="secret", payload=b"dummy")
    assert registry._artifacts == {} and registry._last_event_seq == 0
    with pytest.raises(FrozenInstanceError):
        source.label = "public"
    other = registry.prepare_source(event_seq=1, actor_id="A2", label="public", payload=b"public")
    with pytest.raises(ValueError, match="ownership"):
        registry.commit_prepared((source, replace(other, run_id="foreign")))
    assert registry._artifacts == {}
    registry.commit_prepared((source, other))
    parents = [source.artifact_id]
    child = registry.prepare_derived(event_seq=2, actor_id="A6", kind="memory_write", parent_ids=parents, payload=b"public shape")
    parents[:] = [other.artifact_id]
    assert child.parent_ids == (source.artifact_id,) and child.label == "secret"
    assert child.artifact_id not in registry._artifacts
    registry.commit_prepared((child,))
    assert registry.get(child.artifact_id) == child


def test_memory_versions_keep_opaque_slot_and_snapshot_parent_dependencies():
    async def verify():
        _, registry, store, _, memory, source = boundary_setup()
        public = registry.record_source(event_seq=0, actor_id="A2", label="public", payload=b"public")
        parent_ids = [source.artifact_id]
        store.before_append = lambda event: parent_ids.__setitem__(slice(None), [public.artifact_id])
        written = await memory.write(context("A6"), "SYNTH123-private-memory-key", "  public   shape  ", parent_ids)
        store.before_append = None
        compacted = await memory.compact(context("A6"), "SYNTH123-private-memory-key")
        read = await memory.read(context("A7"), "SYNTH123-private-memory-key")
        assert registry.get(written.artifact_ids["value"]).parent_ids == (source.artifact_id,)
        assert registry.get(compacted.artifact_ids["value"]).parent_ids == (written.artifact_ids["value"],)
        assert registry.get(read.artifact_ids["value"]).parent_ids == (compacted.artifact_ids["value"],)
        documents = [event.safe_summary_json["lineage"] for event in store.events]
        assert [item["metadata"]["memory_version"] for item in documents] == [1, 2, 2]
        assert len({item["metadata"]["memory_slot_id"] for item in documents}) == 1
        assert documents[-1]["nodes"][0]["stored_label"] == "secret"
        assert documents[-1]["nodes"][0]["effective_label"] == "public"
        safe = json.dumps([event.safe_summary_json for event in store.events])
        assert "SYNTH123-private-memory-key" not in safe and "key_sha256" not in safe
        assert hashlib.sha256(b"SYNTH123-private-memory-key").hexdigest() not in safe
        assert "payload_sha256" not in safe

    asyncio.run(verify())


def test_peer_unknown_field_uses_same_safe_slot_in_lineage_and_taint():
    async def verify():
        _, registry, store, peer, _, source = boundary_setup()
        name = "SYNTH123-private-field-name"
        sent = await peer.send(context("A2", artifact_dependencies={name: (source.artifact_id,)}), "A9", {name: "public shape"})
        received = await peer.receive(context("A9"), sent.data["message_id"])
        assert received.allowed and name in received.data  # Private runtime delivery stays intact.
        for event in store.events:
            document = event.safe_summary_json["lineage"]
            assert set(document["outputs"]) == set(event.taint_labels_json) == {"field:0"}
            assert name not in json.dumps(document) and name not in json.dumps(event.taint_labels_json)
            assert "payload_sha256" not in json.dumps(document)
        assert store.events[-1].safe_summary_json["lineage"]["nodes"][0]["stored_label"] == "secret"
        assert registry.get(received.artifact_ids[name]).label == "secret"

    asyncio.run(verify())


def test_release_preserves_secret_parent_and_scope_even_if_postcommit_callback_fails():
    async def verify():
        gateway, registry, store, _, _, source = boundary_setup()
        def fail_callback(event):
            raise RuntimeError("Controlled callback failure")
        gateway.on_event = fail_callback
        with pytest.raises(RuntimeError, match="callback failure"):
            await ProjectionCaller(gateway, registry).release_route(
                context("A3"), source_id=source.artifact_id, source_code="SYNTH123",
                purpose=ROUTE_PURPOSE, recipient=ROUTE_RECIPIENT,
            )
        node = store.events[-1].safe_summary_json["lineage"]["nodes"][0]
        assert node["parent_ids"] == [source.artifact_id]
        assert node["stored_label"] == "public" and node["effective_label"] == "public"
        assert (node["release_purpose"], node["release_recipient"]) == (ROUTE_PURPOSE, ROUTE_RECIPIENT)
        assert registry.get(node["artifact_id"]).parent_ids == (source.artifact_id,)

    asyncio.run(verify())


def test_lineage_bounds_and_partial_unknown_inputs_are_explicit():
    registry = ArtifactRegistry("lineage-run")
    parents = tuple(registry.record_source(event_seq=0, actor_id="A2", label="public", payload=b"public").artifact_id for _ in range(16))
    nodes = tuple(registry.prepare_derived(event_seq=1, actor_id="A2", kind="peer_send", parent_ids=parents, payload=b"public") for _ in range(5))
    with pytest.raises(ValueError, match="lineage_evidence_budget_exceeded"):
        lineage_document(registry, context("A2"), seq=1, boundary="peer.send", nodes=nodes,
                         inputs={f"raw-{i}": parents for i in range(5)},
                         outputs={f"raw-{i}": node.artifact_id for i, node in enumerate(nodes)})
    assert all(node.artifact_id not in registry._artifacts for node in nodes)
    document = lineage_document(registry, context("A2"), seq=1, boundary="peer.send",
                                inputs={"raw-secret-name": ("attacker-invented-id",)})
    assert document["coverage"] == "partial" and document["reasons"] == ["unregistered_parent"]
    assert document["inputs"] == {"field:0": []}
    assert "attacker-invented-id" not in json.dumps(document)
    document["metadata"]["payload_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="Invalid lineage"):
        validate_lineage_document(document)
