"""Restart-only graph validation and atomic event/receipt interruption evidence."""

import asyncio
from copy import deepcopy

import pytest

from reef_panda_arena.storage import events as event_storage
from reef_panda_arena.storage.models import RunEvent, SinkReceipt


def boundary(seq=1, *, run_id="run-1", lineage=None):
    return RunEvent(
        run_id=run_id, event_seq=seq, event_type="tool.proposed", actor_id="A8",
        channel="tool", tool_name="customer.notify", destination="mock_customer_outbound",
        policy_decision="allow", reason_code="allowed", data_class="secret",
        taint_labels_json={}, safe_summary_json={"lineage": lineage} if lineage else {},
        payload_sha256=None,
    )


def receipt(seq=1, *, run_id="run-1"):
    return SinkReceipt(
        run_id=run_id, event_seq=seq, sink_name="mock_customer_outbound",
        accepted=True, byte_length=8, payload_sha256=b"D" * 32, oracle_fragment_json=None,
    )


class CommitSession:
    def __init__(self, error, *, durable=True, conflicting=False):
        self.bind = object()
        self.error = error
        self.durable = durable
        self.conflicting = conflicting
        self.pending = []
        self.stored = []
        self.fresh_reads = 0
        self.rollbacks = 0

    async def scalar(self, _):
        return None

    def add(self, row):
        self.pending.append(row)

    async def commit(self):
        if self.durable:
            self.stored = deepcopy(self.pending)
            if self.conflicting:
                self.stored[-1].byte_length += 1
        raise self.error("private exception details must not become public evidence")

    async def rollback(self):
        self.rollbacks += 1


class FreshSession:
    def __init__(self, original):
        self.original = original

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def scalar(self, statement):
        self.original.fresh_reads += 1
        model = statement.column_descriptions[0]["entity"]
        return next((row for row in self.original.stored if isinstance(row, model)), None)


def install_fresh_session(monkeypatch, session):
    monkeypatch.setattr(event_storage, "async_sessionmaker", lambda *_, **__: lambda: FreshSession(session))


@pytest.mark.parametrize("error,expected", [
    (RuntimeError, event_storage.EventPersistenceInterrupted),
    (asyncio.CancelledError, event_storage.EventPersistenceCancelled),
])
def test_commit_interruption_confirms_one_durable_event_and_receipt(monkeypatch, error, expected):
    session = CommitSession(error)
    install_fresh_session(monkeypatch, session)
    event, accepted = boundary(), receipt()
    with pytest.raises(expected) as captured:
        asyncio.run(event_storage.SessionEventStore(session).append(event, accepted))
    interrupted = captured.value
    assert interrupted.confirmed_event is not event
    assert interrupted.confirmed_event.safe_summary_json == event.safe_summary_json
    assert interrupted.confirmed_receipt is True
    assert isinstance(interrupted.__cause__, error)
    assert "private exception" not in str(interrupted)
    assert session.fresh_reads == 2 and session.rollbacks == 0


@pytest.mark.parametrize("durable,conflicting", [(False, False), (True, True)])
def test_unconfirmed_or_conflicting_commit_preserves_primary_failure(monkeypatch, durable, conflicting):
    session = CommitSession(RuntimeError, durable=durable, conflicting=conflicting)
    install_fresh_session(monkeypatch, session)
    with pytest.raises(RuntimeError) as captured:
        asyncio.run(event_storage.SessionEventStore(session).append(boundary(), receipt()))
    assert type(captured.value) is RuntimeError
    assert session.fresh_reads <= 2 and session.rollbacks == 0


def test_receipt_cannot_be_attached_to_a_different_event():
    session = CommitSession(RuntimeError)
    with pytest.raises(ValueError, match="belong to its event"):
        asyncio.run(event_storage.SessionEventStore(session).append(boundary(), receipt(2)))
    assert not session.pending and session.fresh_reads == 0


from reef_panda_arena.gateway.observer_contract import BoundaryObservation, unobserved
from reef_panda_arena.storage.lineage import reconstruct_lineage


def artifact(seq, *, parents=(), transform="derived", label="secret", effective=None,
             field="text", basis="explicit_registered_parents"):
    return {
        "artifact_id": f"{seq:032x}", "run_id": "run-1", "event_seq": seq,
        "actor_id": "A8", "field": field,
        "source_type": "private.account" if transform == "private.account.code" else None,
        "source_field": "code" if transform == "private.account.code" else None,
        "transform": transform, "parent_ids": [f"{parent:032x}" for parent in parents],
        "stored_label": label, "effective_label": effective or label,
        "dependency_basis": basis, "release_purpose": None, "release_recipient": None,
    }


def journal_event(node, boundary_kind, *, accepted=False, metadata=None):
    seq, field = node["event_seq"], node["field"]
    document = {
        "version": "lineage-v1", "run_id": "run-1", "event_seq": seq, "actor_id": "A8",
        "boundary": boundary_kind, "attempt_id": "task", "coverage": "complete", "reasons": [],
        "nodes": [node], "inputs": {field: node["parent_ids"]},
        "outputs": {field: node["artifact_id"]}, "metadata": metadata or {},
        "receipt": {"event_seq": seq, "accepted": True, "argument_artifact_ids": [node["artifact_id"]],
                    "sink": "mock_customer_outbound"} if accepted else None,
    }
    event = boundary(seq, lineage=document)
    event.tool_name = node["source_type"] if boundary_kind == "tool.source" else (
        "customer.notify" if boundary_kind == "tool.outbound" else None
    )
    event.taint_labels_json = {field: node["effective_label"]}
    event.safe_summary_json["observation"] = unobserved(
        boundary_kind="other", event_seq=seq, attempt_id="task",
    ).model_dump(mode="json")
    return event


def detached_journal(events):
    # JSON round-trip discards ORM identity and all runtime object references.
    import json
    return json.loads(json.dumps([{
        "run_id": event.run_id, "event_seq": event.event_seq, "actor_id": event.actor_id,
        "event_type": event.event_type, "policy_decision": event.policy_decision,
        "tool_name": event.tool_name, "taint_labels_json": event.taint_labels_json,
        "safe_summary_json": event.safe_summary_json,
    } for event in events]))


def graph_journal():
    specs = [
        artifact(1, transform="private.account.code", field="code", basis="trusted_source_contract"),
        artifact(2, parents=(1,), transform="peer_send"),
        artifact(3, parents=(2,), transform="peer_receive"),
        artifact(4, parents=(3,), transform="memory_write"),
        artifact(5, parents=(4,), transform="memory_compact"),
        artifact(6, parents=(5,), transform="memory_read"),
        artifact(7, transform="trusted_public_message", label="public", basis="trusted_public_contract"),
        artifact(8, parents=(6, 7), transform="reducer_join"),
        artifact(9, parents=(8,), transform="outbound_argument", effective="public"),
    ]
    kinds = ["tool.source", "peer.send", "peer.receive", "memory.write", "memory.compact",
             "memory.read", "peer.send", "reducer.join", "tool.outbound"]
    rows = [journal_event(node, kind, accepted=node["event_seq"] == 9)
            for node, kind in zip(specs, kinds, strict=True)]
    rows[-1].safe_summary_json["observation"] = BoundaryObservation(
        boundary_kind="tool", inspection_state="inspected", detail_coverage="recorded",
        observer_profile="metadata_schema", observer_version="research-v2",
        knowledge_scope_id="keyless-proposal-metadata-v1", input_surface="tool_request_arguments",
        fields_available=("arguments.text",), fields_inspected=("arguments.text",),
        alert=False, reason_code="ordinary_visible_shape", phase="before_execution",
        event_seq=9, attempt_id="task", truncated=False, stopped_early=False,
    ).model_dump(mode="json")
    return detached_journal(rows), [receipt(9)]


def test_detached_multihop_memory_reducer_graph_preserves_truth_and_observations():
    import json
    rows, receipts = graph_journal()
    rows[0]["safe_summary_json"]["payload_sha256"] = "private-low-domain-commitment"
    graph = reconstruct_lineage("run-1", list(reversed(rows)), receipts, run_status="failed")
    assert graph["complete"] is True and graph["run_status"] == "failed"
    assert graph["counts"]["accepted_receipts"] == graph["counts"]["linked_receipts"] == 1
    assert len(graph["nodes"]) == 9 and len(graph["edges"]) == 8
    assert graph["nodes"][-1]["stored_label"] == "secret"
    assert graph["nodes"][-1]["effective_label"] == "public"
    assert graph["nodes"][7]["parent_ids"] == [f"{value:032x}" for value in (6, 7)]
    assert graph["boundaries"][1]["observation"]["alert"] is None
    assert graph["boundaries"][-1]["observation"]["alert"] is False
    assert graph["boundaries"][-1]["observation"]["phase"] == "before_execution"
    assert "private-low-domain-commitment" not in json.dumps(graph)
    assert "payload_sha256" not in json.dumps(graph)


def test_scoped_public_release_keeps_secret_edge_and_blocked_proposal_has_no_receipt():
    source = artifact(1, transform="private.account.code", field="code", basis="trusted_source_contract")
    release = artifact(2, parents=(1,), transform="trusted_projection", label="public",
                       field="category", basis="trusted_projection")
    release.update(release_purpose="shipping_delay_notice", release_recipient="CUS-008")
    outbound = artifact(3, parents=(2,), transform="outbound_argument", label="public")
    public = artifact(4, transform="trusted_public_argument", label="public", basis="trusted_public_contract")
    events = [journal_event(source, "tool.source"), journal_event(release, "projection.release"),
              journal_event(outbound, "tool.outbound", accepted=True),
              journal_event(public, "tool.outbound", accepted=True)]
    denied = deepcopy(events[-1])
    denied.event_seq = 5
    denied.policy_decision = "block"
    denied.safe_summary_json["observation"] = None
    denied.safe_summary_json["lineage"].update(
        event_seq=5, nodes=[], inputs={"text": [release["artifact_id"]]}, outputs={}, receipt=None,
    )
    events.append(denied)
    graph = reconstruct_lineage("run-1", detached_journal(events), [receipt(3), receipt(4)])
    assert graph["complete"] is True
    assert graph["nodes"][1]["parent_ids"] == [source["artifact_id"]]
    assert graph["nodes"][1]["release_purpose"] == "shipping_delay_notice"
    assert graph["nodes"][3]["parent_ids"] == []
    assert len(graph["receipts"]) == 2 and graph["boundaries"][-1]["outputs"] == {}


@pytest.mark.parametrize("corruption,expected", [
    ("missing_parent", "unresolved_parent"),
    ("join", "stored_label_join_mismatch"),
    ("source_label", "source_label_mismatch"),
    ("cycle", "lineage_cycle"),
    ("duplicate", "duplicate_artifact_definition"),
    ("cross_run", "invalid_lineage_document"),
    ("missing_receipt", "claimed_receipt_missing"),
    ("blocked_receipt", "accepted_receipt_on_denied_event"),
    ("observation", "observation_event_mismatch"),
    ("attempt", "observation_attempt_mismatch"),
    ("effective_label", "effective_label_event_mismatch"),
    ("source_boundary", "source_boundary_mismatch"),
    ("unsafe_metadata", "invalid_lineage_document"),
])
def test_inconsistent_journal_is_never_a_complete_graph(corruption, expected):
    rows, receipts = graph_journal()
    document = rows[-1]["safe_summary_json"]["lineage"]
    if corruption == "missing_parent":
        document["nodes"][0]["parent_ids"] = document["inputs"]["text"] = ["f" * 32]
    elif corruption == "join":
        document["nodes"][0]["stored_label"] = "public"
    elif corruption == "source_label":
        rows[0]["safe_summary_json"]["lineage"]["nodes"][0]["stored_label"] = "public"
    elif corruption == "cycle":
        first = rows[0]["safe_summary_json"]["lineage"]
        first["nodes"][0]["parent_ids"] = first["inputs"]["code"] = [f"{9:032x}"]
    elif corruption == "duplicate":
        document["nodes"][0]["artifact_id"] = f"{1:032x}"
        document["outputs"]["text"] = f"{1:032x}"
        document["receipt"]["argument_artifact_ids"] = [f"{1:032x}"]
    elif corruption == "cross_run":
        document["nodes"][0]["run_id"] = "other-run"
    elif corruption == "missing_receipt":
        receipts = []
    elif corruption == "blocked_receipt":
        rows[-1]["policy_decision"] = "block"
    elif corruption == "observation":
        rows[-1]["safe_summary_json"]["observation"]["event_seq"] = 8
    elif corruption == "attempt":
        rows[-1]["safe_summary_json"]["observation"]["attempt_id"] = "attack:1"
    elif corruption == "effective_label":
        document["nodes"][0]["effective_label"] = "secret"
    elif corruption == "source_boundary":
        rows[0]["safe_summary_json"]["lineage"]["boundary"] = "peer.send"
    else:
        document["metadata"]["private-code"] = "DO-NOT-EXPORT"
    graph = reconstruct_lineage("run-1", rows, receipts)
    assert graph["complete"] is False
    assert expected in {error["code"] for error in graph["validation_errors"]}
    assert "DO-NOT-EXPORT" not in str(graph)


def test_historical_missing_evidence_and_truncated_pages_remain_incomplete():
    graph = reconstruct_lineage("run-1", [boundary()], [receipt()])
    assert graph["coverage"] == "not_instrumented" and not graph["complete"]
    assert graph["counts"]["accepted_receipts"] == 1 and not graph["receipts"][0]["linked"]
    assert graph["boundaries"][0]["observation"] is None
    rows, receipts = graph_journal()
    graph = reconstruct_lineage("run-1", rows, receipts, truncated=True)
    assert graph["truncated"] is True and not graph["complete"]


async def mediated_journal(store, run_id, profile="actor_local"):
    """Exercise real local wrappers, then return only detached journal data."""
    from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
    from reef_panda_arena.gateway.memory import MemoryCaller
    from reef_panda_arena.gateway.peer import PeerMessageCaller
    from reef_panda_arena.gateway.provenance import ArtifactRegistry
    from reef_panda_arena.gateway.reducer import ReducerCaller
    from reef_panda_arena.gateway.release import ProjectionCaller, ROUTE_PURPOSE, ROUTE_RECIPIENT
    from reef_panda_arena.gateway.research_observer import ResearchObserver
    from reef_panda_arena.graph.roster import AgentRoster
    from reef_panda_arena.scenarios.loader import ScenarioLoader
    from reef_panda_arena.tools.unified import (
        UNIFIED_DESTINATIONS, UNIFIED_ROLE_TOOLS, UNIFIED_TOOL_INPUTS, UnifiedToolAdapter,
    )

    registry = ArtifactRegistry(run_id)
    gateway = PolicyGateway(
        store, UnifiedToolAdapter(ScenarioLoader().shipping_fixture(), b"SYNTH123"),
        profile, b"", max_calls=40, max_events=48, max_payload_bytes=4096,
        artifact_registry=registry, run_id=run_id, runtime_roles=AgentRoster().runtime_roles,
        tool_inputs=UNIFIED_TOOL_INPUTS, tool_destinations=UNIFIED_DESTINATIONS,
        role_tools=UNIFIED_ROLE_TOOLS, observer=ResearchObserver("metadata_schema"),
    )
    peer = PeerMessageCaller(gateway, registry, frozenset({
        ("A2", "A5"), ("A6", "A8"), ("A4", "A8"), ("A8", "A9"), ("A2", "A3"), ("A3", "A9"),
    }))

    def context(actor, **kwargs):
        return TrustedContext(run_id, actor, actor, **kwargs)

    async def deliver(sender, recipient, text, parent=None):
        sent = await peer.send(context(
            sender, artifact_dependencies={"text": (parent,)} if parent else {},
            trusted_public_fields=frozenset() if parent else frozenset({"text"}),
        ), recipient, {"text": text})
        assert sent.allowed
        received = await peer.receive(context(recipient), sent.data["message_id"])
        assert received.allowed
        return received.artifact_ids["text"]

    source = await gateway.invoke(context("A2"), ProposedCall(
        tool_name="private.account", arguments={"customer_id": "CUS-008"},
    ))
    secret_id = source.artifact_ids["code"]
    delivered = await deliver("A2", "A5", "Routine representation", secret_id)
    memory = MemoryCaller(gateway, registry, frozenset({"A5"}), frozenset({"A6"}))
    assert (await memory.write(context("A5"), "private-key-name", "Routine  representation", (delivered,))).allowed
    assert (await memory.compact(context("A5"), "private-key-name")).allowed
    read = await memory.read(context("A6"), "private-key-name")
    first = await deliver("A6", "A8", read.data["value"], read.artifact_ids["value"])
    second = await deliver("A4", "A8", "Independent public update")
    reduced = await ReducerCaller(gateway, registry).join(context("A8"), "Combined update", (first, second))
    assert reduced.allowed
    outgoing = await deliver("A8", "A9", reduced.data["value"], reduced.artifact_ids["value"])

    async def notify(parent=None, *, purpose=None, recipient=None, text="Combined update"):
        result = await gateway.invoke(context(
            "A9", artifact_dependencies={"text": (parent,)} if parent else {},
            trusted_public_fields=frozenset({"shipment_id", "customer_id"} | ({"text"} if not parent else set())),
            purpose=purpose, recipient=recipient,
        ), ProposedCall(tool_name="customer.notify", arguments={
            "shipment_id": "SHP-1042", "customer_id": "CUS-008", "text": text,
        }))
        return result

    assert (await notify(outgoing)).allowed is (profile == "actor_local")
    released_source = await deliver("A2", "A3", source.data["code"], secret_id)
    released = await ProjectionCaller(gateway, registry).release_route(
        context("A3"), source_id=released_source, source_code=source.data["code"],
        purpose=ROUTE_PURPOSE, recipient=ROUTE_RECIPIENT,
    )
    assert released.allowed
    released_parent = await deliver("A3", "A9", released.data["category"], released.artifact_ids["category"])
    assert (await notify(released_parent, purpose=ROUTE_PURPOSE, recipient=ROUTE_RECIPIENT,
                         text=released.data["category"])).allowed
    if profile == "scoped_release":
        denied = await notify(released_parent, purpose="unapproved", recipient=ROUTE_RECIPIENT)
        assert not denied.allowed and denied.reason == "release_scope_mismatch"
    assert (await notify(text="Independent public control")).allowed
    return gateway.events


class DetachedJournalStore:
    def __init__(self):
        self.events = []
        self.receipts = []

    async def append(self, event, receipt=None):
        self.events.extend(detached_journal([event]))
        if receipt is not None:
            self.receipts.append({
                "run_id": receipt.run_id, "event_seq": receipt.event_seq,
                "sink_name": receipt.sink_name, "accepted": receipt.accepted,
            })
        return event


def assert_mediated_graph(graph, profile="actor_local"):
    import json
    assert graph["complete"] is True, graph["validation_errors"]
    assert graph["counts"]["accepted_receipts"] == graph["counts"]["linked_receipts"] == (
        3 if profile == "actor_local" else 2
    )
    nodes = {node["artifact_id"]: node for node in graph["nodes"]}
    transforms = {node["transform"] for node in nodes.values()}
    assert {"private.account.code", "peer_send", "peer_receive", "memory_write", "memory_compact",
            "memory_read", "reducer_join", "trusted_projection", "outbound_argument"} <= transforms
    reducer = next(node for node in nodes.values() if node["transform"] == "reducer_join")
    assert len(reducer["parent_ids"]) == 2
    assert all(nodes[parent]["transform"] == "peer_receive" for parent in reducer["parent_ids"])
    release = next(node for node in nodes.values() if node["transform"] == "trusted_projection")
    assert release["stored_label"] == "public" and release["parent_ids"]
    assert nodes[release["parent_ids"][0]]["stored_label"] == "secret"
    divergent = [node for node in nodes.values() if node["stored_label"] == "secret"
                 and node["effective_label"] == "public"]
    assert any(node["transform"] == "outbound_argument" for node in divergent) is (profile == "actor_local")
    memory = [item["metadata"] for item in graph["boundaries"] if item["boundary"].startswith("memory.")]
    assert len({item["memory_slot_id"] for item in memory}) == 1
    assert [item["memory_version"] for item in memory] == [1, 2, 2]
    inspections = [item["observation"] for item in graph["boundaries"]]
    assert any(item["inspection_state"] == "inspected" for item in inspections)
    assert any(item["inspection_state"] == "unsupported_boundary" and item["alert"] is None for item in inspections)
    serialized = json.dumps(graph)
    for forbidden in ("SYNTH123", "private-key-name", "payload_sha256", "oracle_fragment"):
        assert forbidden not in serialized


@pytest.mark.parametrize("profile", ["actor_local", "scoped_release"])
def test_actual_gateway_chain_reloads_from_detached_journal_only(profile):
    store = DetachedJournalStore()
    asyncio.run(mediated_journal(store, "run-1", profile))
    # The completed coroutine drops gateway, registry, adapters and raw payloads.
    graph = reconstruct_lineage("run-1", store.events, store.receipts, run_status="failed")
    assert_mediated_graph(graph, profile)


def test_reader_query_and_disposal_have_independent_finite_deadlines(monkeypatch):
    from types import SimpleNamespace
    from reef_panda_arena.storage import lineage

    observed = []

    class BlockedSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        def begin(self):
            return self

        async def execute(self, _):
            try:
                observed.append("query")
                await asyncio.Future()
            finally:
                observed.append("query_cancelled")

    class BlockedEngine:
        async def dispose(self):
            try:
                observed.append("dispose")
                await asyncio.Future()
            finally:
                observed.append("dispose_cancelled")

    monkeypatch.setattr(lineage, "create_async_engine", lambda *_, **__: BlockedEngine())
    monkeypatch.setattr(lineage, "async_sessionmaker", lambda *_, **__: BlockedSession)
    monkeypatch.setattr(lineage, "_QUERY_SECONDS", 0.01)
    monkeypatch.setattr(lineage, "_DISPOSE_SECONDS", 0.01)

    async def verify():
        started = asyncio.get_running_loop().time()
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(lineage.load_run_lineage(
                SimpleNamespace(sqlalchemy_url="unused"), "run-1",
            ), timeout=1)
        assert asyncio.get_running_loop().time() - started < 0.5

    asyncio.run(verify())
    assert observed == ["query", "query_cancelled", "dispose", "dispose_cancelled"]


def test_mysql_reload_uses_only_persisted_lineage_and_actual_receipts(monkeypatch):
    import os
    if os.getenv("ARENA_TEST_MYSQL") != "1":
        pytest.skip("Set ARENA_TEST_MYSQL=1 for the bounded persisted lineage reload")
    from uuid import uuid4
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from reef_panda_arena.application.admission import run_admission
    from reef_panda_arena.gateway.provenance import ArtifactRegistry
    from reef_panda_arena.scenarios.loader import ScenarioLoader
    from reef_panda_arena.scenarios.vault import SyntheticSecretVault
    from reef_panda_arena.settings import ArenaSettings
    from reef_panda_arena.storage.lineage import load_run_lineage
    from reef_panda_arena.storage.models import ArenaRun
    from reef_panda_arena.storage.queries import list_run_events
    from reef_panda_arena.telemetry.events import lifecycle_event

    def forbidden_private_read(*_, **__):
        pytest.fail("A restarted lineage reader must not recreate private runtime state")

    async def verify():
        settings, run_id = ArenaSettings(), str(uuid4())
        async with run_admission(settings, family="unified"):
            engine = create_async_engine(settings.sqlalchemy_url)
            try:
                async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                    run = ArenaRun(
                        id=run_id, scenario_id="C29", scenario_revision="unified-v1", mode="replay",
                        defense_profile="actor_local", seed=31, status="running",
                        benign_goal_json={"goal_id": "lineage_reload_control"}, prompt_version="lineage-test-v1",
                    )
                    session.add(run)
                    store = event_storage.SessionEventStore(session)
                    started = lifecycle_event(run_id, 0, "run.started")
                    # Historical metadata claims cannot manufacture a persisted receipt.
                    started.safe_summary_json = {"accepted_sink_receipt": True, "sink_payload_sha256": "historical-hash"}
                    await store.append(started)
                    last_seq = await mediated_journal(store, run_id)
                    run.status = "completed"
                    await store.append(lifecycle_event(run_id, last_seq + 1, "run.completed"))
            finally:
                await engine.dispose()
        # All local registry/adapters and their session have now been discarded.
        monkeypatch.setattr(ArtifactRegistry, "__init__", forbidden_private_read)
        monkeypatch.setattr(ScenarioLoader, "shipping_fixture", forbidden_private_read)
        monkeypatch.setattr(SyntheticSecretVault, "__init__", forbidden_private_read)
        graph = await load_run_lineage(settings, run_id)
        assert_mediated_graph(graph)
        assert graph["run_status"] == "completed"
        history = await list_run_events(settings, run_id)
        assert history[0]["data"]["summary"]["accepted_sink_receipt"] is False
        accepted = {row["event_seq"] for row in graph["receipts"] if row["accepted"]}
        assert {row["id"] for row in history if row["data"]["summary"]["accepted_sink_receipt"]} == accepted
        assert "historical-hash" not in str(history) and "payload_sha256" not in str(history)

    asyncio.run(verify())


@pytest.mark.parametrize("cancel_lookup", [False, True])
def test_reconciliation_is_bounded_and_does_not_consume_a_new_cancellation(monkeypatch, cancel_lookup):
    session = CommitSession(RuntimeError)
    monkeypatch.setattr(event_storage, "_RECONCILE_SECONDS", 0.01)

    async def verify():
        started, stopped = asyncio.Event(), asyncio.Event()

        class BlockedFreshSession(FreshSession):
            async def scalar(self, _):
                self.original.fresh_reads += 1
                started.set()
                try:
                    await asyncio.Future()
                finally:
                    stopped.set()

        monkeypatch.setattr(event_storage, "async_sessionmaker",
                            lambda *_, **__: lambda: BlockedFreshSession(session))
        append = asyncio.create_task(event_storage.SessionEventStore(session).append(boundary(), receipt()))
        await asyncio.wait_for(started.wait(), timeout=1)
        if cancel_lookup:
            append.cancel()
            with pytest.raises(asyncio.CancelledError):
                await append
        else:
            with pytest.raises(RuntimeError) as captured:
                await asyncio.wait_for(append, timeout=1)
            assert type(captured.value) is RuntimeError
        await asyncio.wait_for(stopped.wait(), timeout=1)
        assert session.fresh_reads == 1 and session.rollbacks == 0

    asyncio.run(verify())
