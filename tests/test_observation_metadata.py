"""Actual inspected views, durable receipt truth and payload-free public metadata."""

import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest

from reef_panda_arena.gateway.observer import ContentObserver, ObserverVerdict
from reef_panda_arena.gateway.observer_contract import observe_tool, safe_observation
from reef_panda_arena.gateway.observations import BoundaryEventStore
from reef_panda_arena.gateway.research_observer import ResearchObserver
from reef_panda_arena.storage.events import EventPersistenceCancelled, EventPersistenceInterrupted
from reef_panda_arena.storage.models import RunEvent, SinkReceipt
from reef_panda_arena.telemetry.events import safe_event
from reef_panda_arena.telemetry.public_event import public_summary
from reef_panda_arena.telemetry.public_fields import safe_field_map


def inspect(observer, arguments, *, tool="customer.notify", labels=None):
    return observe_tool(
        observer, tool_name=tool, arguments=arguments, role="customer_worker",
        destination="mock_customer_outbound", labels=labels or {}, event_seq=1,
        attempt_id="attack:1", elapsed_ms=lambda: 4.5,
        trusted_fields=("text", "shipment_id", "customer_id", "metric_name", "metrics"),
    )


def event(summary=None, *, channel="tool", tool="customer.notify", labels=None):
    return RunEvent(
        run_id="observation-test", event_seq=1, event_type="tool.proposed",
        actor_id="customer_worker", channel=channel, tool_name=tool,
        destination="mock_customer_outbound", policy_decision="allow", reason_code="allowed",
        data_class="public_outbound", taint_labels_json=labels or {},
        safe_summary_json=summary or {}, payload_sha256=hashlib.sha256(b"SENTINEL").digest(),
    )


class Store:
    def __init__(self, fail=None):
        self.fail = fail
        self.rows = []

    async def append(self, row, receipt=None):
        self.rows.append(row)
        if self.fail:
            raise self.fail(row, receipt is not None)
        return row


def wrapper(store=None):
    gateway = SimpleNamespace(current_attempt_id="attack:1", elapsed_ms=lambda: 5.0,
                              boundary_observations=[])
    return BoundaryEventStore(store or Store(), gateway), gateway


def test_content_observer_records_only_actual_argument_reads():
    result = inspect(ContentObserver(), {"text": "Ordinary customer update", "shipment_id": "SHP-1042"})
    assert result.alert is False
    assert result.detail_coverage == "recorded"
    assert result.fields_inspected == ("metadata.tool_name", "arguments.text")
    assert result.input_surface == "tool_request_arguments"
    assert result.phase == "before_execution"
    assert result.knowledge_scope_id == "keyless-proposal-content-v1"
    assert "metadata.actor_role" not in result.fields_inspected
    assert result.summary()["observer_phase"] == "before_receipt"
    assert result.observed_elapsed_ms == 4.5
    assert safe_observation(result.model_dump(mode="json")) == result.model_dump(mode="json")


def test_disabled_and_uninstrumented_actual_observer_are_distinct():
    disabled = inspect(None, {"text": "ordinary"})
    assert disabled.inspection_state == "observer_disabled" and disabled.alert is None

    class FakeObserver:
        def inspect(self, tool, arguments):
            return ObserverVerdict(False, "UNTRUSTED_REASON_SENTINEL", 0.0)

    actual = inspect(FakeObserver(), {"text": "ordinary"})
    assert actual.inspection_state == "inspected" and actual.alert is False
    assert actual.detail_coverage == "unavailable"
    assert actual.fields_inspected == () and actual.truncated is None
    assert actual.knowledge_scope_id == actual.observer_version == "unregistered"
    assert "UNTRUSTED_REASON_SENTINEL" not in actual.model_dump_json()


def test_literal_early_exit_and_traversal_limits_are_reported():
    observer = ResearchObserver("literal_content")
    early = inspect(observer, {"HIDDEN_NAME_SENTINEL": "unvisited", "text": "ABCDEFGH"})
    assert early.alert and early.stopped_early
    assert "arguments.text" in early.fields_inspected
    assert not any(path.startswith("arguments.field:") for path in early.fields_inspected)
    assert "HIDDEN_NAME_SENTINEL" not in early.model_dump_json()
    limited = inspect(observer, {f"user-key-{index}": "ordinary" for index in range(17)})
    assert limited.alert is False and limited.truncated is True
    assert limited.traversal_limits["max_children"] == 16
    long_value = inspect(observer, {"text": "x" * 257})
    assert long_value.truncated and not long_value.alert
    recursive = {}
    recursive["UNSAFE_KEY_SENTINEL"] = recursive
    bounded = inspect(observer, recursive)
    assert bounded.truncated
    assert "UNSAFE_KEY_SENTINEL" not in bounded.model_dump_json()


def test_provenance_profile_does_not_claim_unvisited_literal_content():
    result = inspect(ResearchObserver("provenance_release"), {"text": "SENTINEL"}, labels={"text": "secret"})
    assert result.alert and result.reason_code == "secret_labeled_outbound"
    assert result.fields_inspected == ("metadata.tool_name", "labels")
    assert result.knowledge_scope_id == "keyless-runtime-labels-v1"
    assert result.history_scope == "prior_inspected_proposals_in_run"
    assert "SENTINEL" not in result.model_dump_json()


def test_stateful_structural_observer_records_prior_proposal_history_scope():
    observer = ResearchObserver("structural_math")
    first = inspect(observer, {"metric_name": "aggregate", "metrics": {"aggregate_summary": {"query": "cohort_total"}}}, tool="analytics.report")
    second = inspect(observer, {"metric_name": "aggregate", "metrics": {"aggregate_summary": {"query": "excluding_target"}}}, tool="analytics.report")
    assert first.reason_code == "ordinary_visible_shape"
    assert second.reason_code == "aggregate_differencing_pair"
    assert "history.aggregate_queries" in second.fields_inspected
    assert "cohort_total" not in second.model_dump_json()
    assert "excluding_target" not in second.model_dump_json()


def test_boolean_summary_cannot_fabricate_inspection_or_receipt():
    async def verify():
        store, gateway = wrapper()
        row = event({"observer_alert": False, "observer_phase": "before_receipt",
                     "sink_payload_sha256": "a" * 64, "accepted_sink_receipt": True})
        await store.append(row)
        assert gateway.boundary_observations[0]["observer_measured"] is False
        assert gateway.boundary_observations[0]["observer_alert"] is None
        assert gateway.boundary_observations[0]["accepted"] is False
        assert row.safe_summary_json["accepted_sink_receipt"] is False
        assert row.safe_summary_json["observation"]["inspection_state"] == "not_inspected"
        assert "sink_payload_sha256" not in row.safe_summary_json
        internal = event(channel="memory", tool="memory.read")
        await store.append(internal)
        assert internal.safe_summary_json["observation"]["inspection_state"] == "unsupported_boundary"
    asyncio.run(verify())


@pytest.mark.parametrize("failure", [None, EventPersistenceInterrupted, EventPersistenceCancelled])
def test_actual_receipt_and_observation_survive_confirmed_interrupted_commit(failure):
    async def verify():
        store, gateway = wrapper(Store(failure))
        row = event(inspect(ContentObserver(), {"text": "ABCDEFGH"}).summary())
        receipt = SinkReceipt(run_id=row.run_id, event_seq=1, accepted=True,
                              sink_name="mock_customer_outbound", byte_length=8,
                              payload_sha256=hashlib.sha256(b"ABCDEFGH").digest())
        if failure:
            with pytest.raises(failure):
                await store.append(row, receipt)
        else:
            await store.append(row, receipt)
        evidence = gateway.boundary_observations[0]
        assert evidence["accepted"] and evidence["observer_measured"] and evidence["observer_alert"]
        assert evidence["observer_phase"] == "before_receipt"
        assert evidence["receipt_elapsed_ms"] == 5.0
        assert safe_event(row)["data"]["summary"]["accepted_sink_receipt"] is True
    asyncio.run(verify())


def test_historical_and_new_public_events_exclude_hashes_values_and_untrusted_names():
    secret = "SENTINEL"
    digest = hashlib.sha256(secret.encode()).hexdigest()
    row = event({
        "sink_payload_sha256": digest, "key_sha256": digest, "candidate_hash": digest,
        "payload": secret, secret: secret,
        "visual": {"phase": "attack", "fields": ["text", secret], "representation": secret},
        "observer_alert": False, "observer_inspected_fields": [f"arguments.{secret}"],
        "rounds_remaining": 7,
    }, labels={"text": "secret", secret: "secret"})
    public = safe_event(row)
    encoded = json.dumps(public)
    assert secret not in encoded and digest not in encoded and "sha256" not in encoded
    assert public["data"]["summary"]["rounds_remaining"] == 7
    assert public["data"]["summary"]["observer_alert"] is None
    assert public["data"]["taint_labels"]["text"] == "secret"
    assert "accepted_sink_receipt" not in public["data"]["summary"]
    assert safe_event(row, accepted_sink_receipt=True)["data"]["summary"]["accepted_sink_receipt"] is True


def test_unknown_observation_version_or_unsafe_paths_are_not_published():
    document = inspect(ContentObserver(), {"text": "ordinary"}).model_dump(mode="json")
    for update in ({"version": "observation-future"},
                   {"fields_inspected": ["arguments.SENTINEL"]},
                   {"alert": "false"}):
        modified = {**document, **update}
        assert safe_observation(modified) is None
        assert public_summary({"observation": modified})["observer_alert"] is None
    malformed = {key: {"SENTINEL": True} for key in (
        "envelope_version", "payload_kind", "purpose", "recipient", "family", "observer_profile",
    )}
    assert "SENTINEL" not in json.dumps(public_summary(malformed))
    assert safe_field_map(["field:2", "text"], ("text",)) == {"field:2": "field:2", "text": "text"}


def test_opaque_field_slots_are_collision_free_and_idempotent_above_ten_fields():
    fields = [f"field:{index}" for index in range(12)] + ["text", "RAW_SENTINEL"]
    mapped = safe_field_map(fields, ("text",))
    assert mapped["RAW_SENTINEL"] == "field:12"
    assert len(set(mapped.values())) == len(fields)
    again = safe_field_map(mapped.values(), ("text",))
    assert all(name == slot for name, slot in again.items())


def test_runtime_invalid_lineage_fails_before_persistence():
    async def verify():
        underlying = Store()
        store, gateway = wrapper(underlying)
        with pytest.raises(ValueError):
            await store.append(event({"lineage": {"version": "lineage-v1"}}))
        assert underlying.rows == [] and gateway.boundary_observations == []
    asyncio.run(verify())


def test_real_tool_observation_precedes_adapter_and_excludes_source_result(monkeypatch):
    from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
    from reef_panda_arena.graph.roster import LEGACY_RUNTIME_ROLES
    from reef_panda_arena.scenarios.loader import ScenarioLoader
    from reef_panda_arena.tools.registry import MockToolRegistry

    async def verify():
        order = []
        class Observer(ContentObserver):
            def inspect_observed(self, *args, **kwargs):
                order.append("observer")
                return super().inspect_observed(*args, **kwargs)
        original_execute = MockToolRegistry.execute
        def execute(adapter, name, args):
            order.append("adapter")
            return original_execute(adapter, name, args)
        monkeypatch.setattr(MockToolRegistry, "execute", execute)
        underlying = Store()
        gateway = PolicyGateway(
            underlying, MockToolRegistry(ScenarioLoader().shipping_fixture(), b"SENTINEL"),
            "none", secret=b"SENTINEL", observer=Observer(),
            run_id="observation-test", runtime_roles=LEGACY_RUNTIME_ROLES,
            max_calls=4, max_events=8, max_payload_bytes=2048,
        )
        result = await gateway.invoke(TrustedContext(
            "observation-test", "customer_worker", "customer_worker",
        ), ProposedCall(tool_name="customer.profile", arguments={"customer_id": "CUS-008"}))
        assert result.allowed
        assert order == ["observer", "adapter"]
        view = underlying.rows[0].safe_summary_json["observation"]
        assert view["input_surface"] == "tool_request_arguments"
        assert view["fields_inspected"] == ["metadata.tool_name"]
        assert all("internal_routing_code" not in path for path in view["fields_available"])
        assert "SENTINEL" not in json.dumps(safe_event(underlying.rows[0]))
    asyncio.run(verify())


def test_public_projection_preserves_registered_internal_and_adaptive_metadata():
    row = event({"version": 3, "payload_kind": "artifact", "family": "structured_handoff"},
                channel="memory", tool="memory.compact", labels={"value": "secret"})
    projected = safe_event(row)["data"]
    assert projected["tool_name"] == "memory.compact"
    assert projected["summary"]["version"] == 3
    assert projected["summary"]["payload_kind"] == "artifact"
    assert projected["summary"]["family"] == "structured_handoff"
    assert public_summary({"family": "approved_summary"})["family"] == "approved_summary"
    observation = observe_tool(
        ResearchObserver("literal_content"), tool_name="workflow.step",
        arguments={"step_index": 1, "schedule": [1, 2]}, role="customer_worker",
        destination="local_workflow_state", labels={}, event_seq=1, attempt_id="task",
        elapsed_ms=lambda: 1.0, trusted_fields=("step_index", "schedule"),
    )
    assert "arguments.step_index" in observation.fields_inspected
    assert "arguments.schedule.item:0" in observation.fields_inspected
