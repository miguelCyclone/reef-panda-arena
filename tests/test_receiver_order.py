"""An earlier unrelated accepted record must not conceal later recoverable egress."""

import json
from dataclasses import replace

import pytest

from reef_panda_arena.gateway.invoke import SinkArtifact
from reef_panda_arena.oracle.sensitive import SensitiveOracle, SENSITIVE_ORACLE_VERSION
from reef_panda_arena.oracle.extension import ExtensionOracle, EXTENSION_ORACLE_VERSION
from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
from reef_panda_arena.scenarios.extension_fixtures import ExtensionFixtureRegistry
from reef_panda_arena.scenarios.sensitive_scripts import attack_actions
from reef_panda_arena.scenarios.extension_scripts import suspect_actions, transport_controls
from reef_panda_arena.tools.outbound import encode_sink_payload
from reef_panda_arena.tools.registry import TOOL_INPUTS


def artifact(seq, call):
    return SinkArtifact(seq, encode_sink_payload(call.tool_name, TOOL_INPUTS[call.tool_name].model_validate(
        call.arguments)), call.tool_name)


@pytest.mark.parametrize("prefix", ["invalid_json", "other_issued_fixture"])
def test_c14_later_issued_accepted_object_still_recovers_after_failed_prefix(prefix):
    registry = SensitiveFixtureRegistry()
    case = registry.load("C14", 31, b"T" * 32)
    attack, = attack_actions(case, case.source_record)
    if prefix == "invalid_json":
        first = SinkArtifact(1, b"{", "approval.request")
    else:
        other = registry.load("C14", 31, b"U" * 32)
        call, = attack_actions(other, other.source_record)
        first = artifact(1, call.call)
    received = artifact(2, attack.call)
    oracle = SensitiveOracle()
    assert not oracle.evaluate(case, [first]).full_reconstruction
    for records in ([first, received], [received, first]):
        result = oracle.evaluate(case, records)
        assert result.full_reconstruction and result.evidence_event_seqs == (2,)
        assert result.unscorable_reason is None
    assert SENSITIVE_ORACLE_VERSION == "sensitive-v4"


@pytest.mark.parametrize("scenario_id", ["C16", "C17", "C19", "C20", "C21"])
def test_structured_extension_receiver_continues_after_unrelated_invalid_record(scenario_id):
    case = ExtensionFixtureRegistry().load(scenario_id, 31, b"T" * 32)
    calls = suspect_actions(case)
    accepted = [artifact(index + 2, action.call) for index, action in enumerate(calls)]
    prefix = SinkArtifact(1, b"{", calls[0].call.tool_name)
    result = ExtensionOracle().evaluate(case, [prefix, *accepted])
    assert result.full_reconstruction and result.unscorable_reason is None
    assert EXTENSION_ORACLE_VERSION == "extension-v2"


@pytest.mark.parametrize("scenario_id", ["C17", "C21"])
def test_real_benign_artifact_prefix_cannot_hide_later_attack(scenario_id):
    case = ExtensionFixtureRegistry().load(scenario_id, 31, b"T" * 32)
    first = artifact(1, transport_controls(case)[0])
    attacks = [artifact(index + 2, action.call) for index, action in enumerate(suspect_actions(case))]
    oracle = ExtensionOracle()
    assert not oracle.evaluate(case, [first]).full_reconstruction
    assert oracle.evaluate(case, [first, *attacks]).full_reconstruction
    assert oracle.evaluate(case, [*attacks, first]).full_reconstruction


def test_unknown_basis_vector_does_not_mask_later_valid_codeword():
    case = ExtensionFixtureRegistry().load("C17", 31, b"T" * 32)
    attack, = suspect_actions(case)
    valid = artifact(2, attack.call)
    payload = json.loads(valid.payload)
    payload["metrics"]["basis_summary"]["values"] = [0.3] * 4
    unrelated = replace(valid, event_seq=1, payload=json.dumps(payload).encode())
    assert ExtensionOracle().evaluate(case, [unrelated]).unscorable_reason == "unknown_basis_vector"
    assert ExtensionOracle().evaluate(case, [unrelated, valid]).full_reconstruction
