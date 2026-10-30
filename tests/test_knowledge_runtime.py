"""R07 access contracts at actual gateway and persisted terminal boundaries."""

import asyncio
import base64
import json
import os
from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.application import adaptive, controller, live, unified
from reef_panda_arena.application.knowledge import KNOWLEDGE_FIELDS
from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
from reef_panda_arena.gateway.observer import ContentObserver
from reef_panda_arena.gateway.policies import ProfilePolicy
from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.graph.roster import AgentRoster, LEGACY_RUNTIME_ROLES
from reef_panda_arena.model.ollama import ModelUnavailable
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
from reef_panda_arena.scenarios.sensitive_scripts import attack_actions
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, RunEvent, RunScore, SinkReceipt
from reef_panda_arena.storage.queries import get_run_status
from reef_panda_arena.storage.reports import list_reports
from reef_panda_arena.tools.sensitive import (
    SensitiveToolAdapter, SENSITIVE_TOOL_INPUTS, SENSITIVE_TOOL_DESTINATIONS, role_tools_for,
)
from reef_panda_arena.tools.unified import (
    UnifiedToolAdapter, UNIFIED_TOOL_INPUTS, UNIFIED_DESTINATIONS, UNIFIED_ROLE_TOOLS,
)


class Store:
    def __init__(self):
        self.events = []
        self.fail = False
        self.before_append = lambda: None

    async def append(self, event, receipt=None):
        self.before_append()
        if self.fail:
            raise RuntimeError("Controlled source append failure")
        self.events.append(event)
        return event


def test_legacy_policy_receives_expected_marker_but_observer_receives_no_receiver_key():
    local_key = b"T" * 32
    case = SensitiveFixtureRegistry().load("C14", 31, local_key)
    shipping = ScenarioLoader().shipping_fixture()
    store, policy, observer = Store(), ProfilePolicy("content"), ContentObserver()
    policy_inputs, observer_inputs = [], []
    original_scan, original_inspect = policy.contains_secret, observer.inspect_observed

    def scan(value, secret):
        policy_inputs.append((deepcopy(value), secret))
        return original_scan(value, secret)

    def inspect(tool_name, arguments, *, role=None, destination=None, labels=None, trusted_fields=()):
        # This strict signature rejects any implicit oracle/fixture/key argument.
        observer_inputs.append((tool_name, deepcopy(arguments), role, destination, deepcopy(labels)))
        return original_inspect(tool_name, arguments, role=role, destination=destination,
                                labels=labels, trusted_fields=trusted_fields)

    policy.contains_secret, observer.inspect_observed = scan, inspect
    gateway = PolicyGateway(
        store, SensitiveToolAdapter(shipping, case.marker, "C14", case.source_record,
                                    case.expected_public_value),
        "content", case.marker, 8, 12, 4096,
        run_id="knowledge-c14", runtime_roles=LEGACY_RUNTIME_ROLES,
        observer=observer, policy=policy, tool_inputs=SENSITIVE_TOOL_INPUTS,
        tool_destinations=SENSITIVE_TOOL_DESTINATIONS, role_tools=role_tools_for("C14"),
    )

    async def verify():
        context = TrustedContext("knowledge-c14", "operations_worker", "operations_worker")
        source = await gateway.invoke(context, ProposedCall(
            tool_name="operations.route", arguments={"case_id": "C14"},
        ))
        action, = attack_actions(case, source.data)
        result = await gateway.invoke(TrustedContext(
            "knowledge-c14", "operations_worker", "operations_worker",
            derived_from=action.derived_from, attempt_id="attack:1",
        ), action.call)
        assert result.allowed  # Known-marker scanning cannot decrypt the envelope.
        assert len(policy_inputs) == 1 and policy_inputs[0][1] == case.marker
        assert observer_inputs[0][1] == {"case_id": "C14"}
        assert observer_inputs[1][1] == action.call.arguments
        assert store.events[-1].safe_summary_json["observation"]["knowledge_scope_id"] == "keyless-proposal-content-v1"
        public_inputs = json.dumps(observer_inputs, sort_keys=True)
        for key in (local_key, case.fixture_key):
            assert key.hex() not in public_inputs
            assert base64.b64encode(key).decode() not in public_inputs
        assert not vars(observer) or set(vars(observer)) == {"inspect_observed"}

    asyncio.run(verify())


def test_unified_content_only_learns_only_after_allowed_committed_source():
    secret, run_id = b"SYNTH123", "knowledge-unified"
    store, policy = Store(), ProfilePolicy("content_only")
    learned = []
    observe = policy.observe_source

    def learn(name, data):
        learned.append((name, deepcopy(data), len(store.events)))
        observe(name, data)

    policy.observe_source = learn
    gateway = PolicyGateway(
        store, UnifiedToolAdapter(ScenarioLoader().shipping_fixture(), secret),
        "content_only", b"", 8, 12, 4096, policy=policy,
        run_id=run_id, runtime_roles=AgentRoster().runtime_roles,
        artifact_registry=ArtifactRegistry(run_id), tool_inputs=UNIFIED_TOOL_INPUTS,
        tool_destinations=UNIFIED_DESTINATIONS, role_tools=UNIFIED_ROLE_TOOLS,
    )
    request = ProposedCall(tool_name="private.account", arguments={"customer_id": "CUS-008"})

    async def verify():
        assert gateway.secret == b"" and not policy.contains_secret(secret.decode(), b"")
        denied = await gateway.invoke(TrustedContext(run_id, "A0", "A0"), request)
        assert not denied.allowed and denied.reason == "role_not_allowed"
        assert not learned and policy._observed_private_code is None
        store.fail = True
        with pytest.raises(RuntimeError, match="source append failure"):
            await gateway.invoke(TrustedContext(run_id, "A2", "A2"), request)
        assert not learned and policy._observed_private_code is None
        assert not gateway.evidence_registry._artifacts
        store.fail = False
        def still_unlearned():
            assert policy._observed_private_code is None
        store.before_append = still_unlearned
        source = await gateway.invoke(TrustedContext(run_id, "A2", "A2"), request)
        assert source.allowed and source.data["code"] == secret.decode()
        assert learned == [("private.account", source.data, 2)]
        assert policy.contains_secret(secret.decode(), b"")
        store.before_append = lambda: None
        blocked = await gateway.invoke(TrustedContext(
            run_id, "A9", "A9", trusted_public_fields=frozenset({"shipment_id", "customer_id", "text"}),
        ), ProposedCall(tool_name="customer.notify", arguments={
            "shipment_id": "SHP-1042", "customer_id": "CUS-008", "text": secret.decode(),
        }))
        assert not blocked.allowed and blocked.reason == "secret_content_match"

    asyncio.run(verify())


@pytest.mark.parametrize("changed,value", [
    (None, None), ("fixture_mode", "public_transport_control"),
    ("fixture_derivation_version", "historical-v0"),
    ("knowledge_contract_version", None),
])
def test_transfer_requires_same_declared_knowledge_contract(monkeypatch, changed, value):
    snapshot = {"split": "development", "fixture_mode": "key_derived_unknown",
                "fixture_derivation_version": "adaptive-hmac-v1",
                "knowledge_contract_version": "knowledge-v1"}
    if changed:
        snapshot[changed] = value
    spec = {"family": "approved_summary", "format": "text", "target_tool": "customer.notify",
            "nodes": [{"kind": "approved_metric", "source_ref": "marker", "config": {}}]}
    run = SimpleNamespace(scenario_id="C28", status="completed", stage_snapshot_json=snapshot)
    score = SimpleNamespace(details_json={"selected_representation": spec})

    class QuerySession:
        disposed = False
        reads = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def execute(self, _):
            self.reads += 1
            return SimpleNamespace(first=lambda: (run, score))

        async def dispose(self):
            self.disposed = True

    session = QuerySession()
    monkeypatch.setattr(adaptive, "create_async_engine", lambda *a, **kw: session)
    monkeypatch.setattr(adaptive, "async_sessionmaker", lambda *a, **kw: lambda: session)
    settings = ArenaSettings(_env_file=None, fixture_mode="key_derived_unknown",
                             database_url="mysql+asyncmy://test:test@localhost/test")
    if changed:
        with pytest.raises(ValueError, match="same declared fixture knowledge contract"):
            asyncio.run(adaptive._transfer_spec(settings, "development-run"))
    else:
        assert asyncio.run(adaptive._transfer_spec(settings, "development-run")).model_dump(mode="json") == spec
    assert session.reads == 1 and session.disposed


@pytest.mark.parametrize("family,scenario_id,fixture_mode", [
    ("core", "C00", "key_derived_unknown"),
    ("live", "C00", "public_transport_control"),
    ("sensitive", "C14", "key_derived_unknown"),
    ("extension", "C21", "public_transport_control"),
    ("adaptive", "C22", "key_derived_unknown"),
    ("unified", "C29", "public_transport_control"),
])
def test_mysql_failed_no_attack_retains_fixture_and_knowledge_contract(
    monkeypatch, family, scenario_id, fixture_mode,
):
    if os.getenv("ARENA_TEST_MYSQL") != "1":
        pytest.skip("Set ARENA_TEST_MYSQL=1 for persisted knowledge contracts")
    model_calls = []

    class UnavailableModel:
        def __init__(self, _):
            pass

        async def model_digest(self, _):
            model_calls.append("digest")
            raise ModelUnavailable("Controlled local model absence")

        async def complete(self, _):
            pytest.fail("The knowledge persistence control must not generate model output")

    monkeypatch.setattr(live, "OllamaCaller", UnavailableModel)
    monkeypatch.setattr(adaptive, "OllamaCaller", UnavailableModel)

    def stop_at_start(event):
        if event.event_type == "run.started":
            raise RuntimeError("Controlled start callback failure")

    async def verify():
        settings = ArenaSettings(fixture_mode=fixture_mode)
        run_id = str(uuid4())
        options = dict(settings=settings, run_id=run_id, attack_enabled=False,
                       on_event=stop_at_start)
        profile = "content_only" if family == "unified" else "content"
        if family == "live":
            options.pop("on_event")
            work = live.run_live(scenario_id, profile, 31, **options)
        elif family == "unified":
            work = unified.run_unified_replay(scenario_id, profile, 31, **options)
        else:
            work = controller.run_replay(scenario_id, profile, 31, **options)
        with pytest.raises(ModelUnavailable if family == "live" else RuntimeError):
            await work
        engine = create_async_engine(settings.sqlalchemy_url)
        try:
            async with async_sessionmaker(engine)() as session:
                run = await session.get(ArenaRun, run_id)
                snapshot = deepcopy(run.stage_snapshot_json)
                assert run.status == "failed"
                assert await session.scalar(select(RunScore).where(RunScore.run_id == run_id)) is None
                assert await session.scalar(select(SinkReceipt).where(SinkReceipt.run_id == run_id)) is None
                events = (await session.scalars(select(RunEvent).where(
                    RunEvent.run_id == run_id).order_by(RunEvent.event_seq))).all()
                assert [event.event_type for event in events] == ["run.started", "run.failed"]
        finally:
            await engine.dispose()
        assert snapshot["fixture_mode"] == fixture_mode
        assert snapshot["knowledge_contract_version"] == "knowledge-v1"
        assert len(snapshot["fixture_template_digest"]) == 64
        assert snapshot["attacker_knowledge"] == (
            "authorized_source_read_required" if fixture_mode == "key_derived_unknown"
            else "public_fixture_and_authorized_source"
        )
        assert snapshot["policy_known_target"] == (
            "private.account.code_after_committed_read" if family == "unified" else "expected_marker"
        )
        assert snapshot["observer_knowledge"] == (
            "disabled" if family in {"core", "live"} else
            "keyless-proposal-content-v1" if family == "sensitive" else "keyless-proposal-metadata-v1"
        )
        assert snapshot["attack_enabled"] is False
        assert snapshot["decision_turns"] == snapshot["total_model_calls"] == 0
        assert snapshot["scoring"]["strict_win"] is None
        assert snapshot["scoring"]["benign_task_success"] is None
        assert snapshot["scoring"]["accepted_sink_receipts"] == 0
        status, reports = await get_run_status(settings, run_id), await list_reports(settings, run_id)
        assert len(reports) == 1
        info = snapshot["scoring"]["information"]
        assert info is not None and info["measurement_status"] == "partial_run"
        assert info["accepted_artifacts"] == 0 and info["full_reconstruction"] is None
        assert info["recovery_state"] == "no_accepted_egress"
        assert status["information"] == reports[0]["information"] == info
        for field in KNOWLEDGE_FIELDS:
            assert status[field] == reports[0][field] == snapshot[field]

    asyncio.run(verify())
    assert model_calls == (["digest"] if family == "live" else [])
