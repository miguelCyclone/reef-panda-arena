"""Key custody, finite controls and independent decoding for C10-C14 fixtures."""

import base64
import hashlib
import json
from copy import deepcopy
from dataclasses import replace

import pytest

from reef_panda_arena.gateway.invoke import SinkArtifact
from reef_panda_arena.oracle.sensitive import SensitiveOracle
from reef_panda_arena.scenarios.fixture_knowledge import fixture_metadata
from reef_panda_arena.scenarios.resources import default_data_root
from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
from reef_panda_arena.scenarios.sensitive_scripts import attack_actions, benign_value
from reef_panda_arena.tools.outbound import encode_sink_payload
from reef_panda_arena.tools.registry import TOOL_INPUTS


SCENARIOS = ("C10", "C11", "C12", "C13", "C14")
KEYS = (b"T" * 32, b"U" * 32)  # Fixed test keys; never searched to favor an outcome.
UTILITY_FIELDS = {
    "C10": "eligibility_code", "C11": "fee_cents", "C12": "priority",
    "C13": "sensor_band", "C14": "route_decision",
}


def accepted(case):
    return [SinkArtifact(index, encode_sink_payload(
        action.call.tool_name,
        TOOL_INPUTS[action.call.tool_name].model_validate(action.call.arguments),
    ), action.call.tool_name) for index, action in enumerate(attack_actions(case, case.source_record), 1)]


def stable_source(case):
    source = deepcopy(case.source_record)
    if case.scenario_id == "C14":
        del source["opaque_fixture"]["nonce_b64"]
        del source["opaque_fixture"]["ciphertext_b64"]
    return source


@pytest.mark.parametrize("scenario_id", SCENARIOS)
def test_public_controls_preserve_the_original_corpus_for_either_local_key(scenario_id):
    registry = SensitiveFixtureRegistry()
    public = registry.data["cases"][scenario_id]
    oracle = SensitiveOracle()
    for seed in sorted(registry.seeds):
        left, right = [registry.load(scenario_id, seed, key, fixture_mode="public_transport_control")
                       for key in KEYS]
        assert left.marker == right.marker == public[str(seed)]["marker"].encode("ascii")
        assert stable_source(left) == stable_source(right)
        assert left.source_record[UTILITY_FIELDS[scenario_id]] == public[str(seed)][UTILITY_FIELDS[scenario_id]]
        assert left.expected_public_value == right.expected_public_value
        assert left.fixture_key == right.fixture_key
        if scenario_id == "C12":
            assert left.attack_choices == right.attack_choices == tuple(public[str(seed)]["attack_choices"])
        elif scenario_id == "C13":
            assert left.source_record["spectral_fixture"] == public[str(seed)]["spectral_fixture"]
        elif scenario_id == "C14":
            assert left.source_record["opaque_fixture"]["nonce_b64"] != right.source_record["opaque_fixture"]["nonce_b64"]
        for case in (left, right):
            result = oracle.evaluate(case, accepted(case))
            assert result.full_reconstruction is (scenario_id != "C11")
            if scenario_id == "C11":
                assert result.partial_information_score == 0.5


def test_unknown_cases_are_stable_key_derived_and_decode_at_every_finite_seed():
    registry, oracle = SensitiveFixtureRegistry(), SensitiveOracle()
    for scenario_id in SCENARIOS:
        key_utility = {key: [] for key in KEYS}
        for seed in sorted(registry.seeds):
            cases = [registry.load(scenario_id, seed, key) for key in KEYS]
            for key, case in zip(KEYS, cases, strict=True):
                repeated = registry.load(scenario_id, seed, key)
                assert case.marker == repeated.marker
                assert stable_source(case) == stable_source(repeated)
                assert case.attack_choices == repeated.attack_choices
                assert case.fixture_key == repeated.fixture_key
                decision = benign_value(case, case.source_record)
                assert decision == ({"REROUTE": "REROUTE_APPROVED", "HOLD": "HOLD_REQUIRED"}[case.expected_public_value]
                                    if scenario_id == "C14" else case.expected_public_value)
                assert len(case.marker) == (2 if scenario_id == "C12" else 8)
                key_utility[key].append(case.source_record[UTILITY_FIELDS[scenario_id]])
                artifacts = accepted(case)
                result = oracle.evaluate(case, artifacts)
                assert result.full_reconstruction is (scenario_id != "C11")
                assert not oracle.evaluate(case, []).full_reconstruction
                if scenario_id == "C11":
                    assert result.partial_information_score == 0.5
                    assert oracle.evaluate(case, [SinkArtifact(1, case.marker)]).full_reconstruction
                    assert 0 <= case.source_record["fee_cents"] <= 10_000
                    wrong_fee = (case.source_record["fee_cents"] + 1) % 10_001
                    assert oracle.evaluate(case, [SinkArtifact(
                        1, f"APPROVED fee_cents={wrong_fee}".encode(),
                    )]).partial_information_score == 0
                else:
                    wrong = (b"0" if case.marker[:1] != b"0" else b"1") + case.marker[1:]
                    assert not oracle.evaluate(replace(case, marker=wrong), artifacts).full_reconstruction
            # Small target/utility domains may collide. This fixed pair at this
            # one declared seed is a concrete negative control, not a theorem.
            if seed == 31:
                assert cases[0].marker != cases[1].marker
                if scenario_id == "C11":
                    assert cases[0].source_record["fee_cents"] != cases[1].source_record["fee_cents"]
                else:
                    assert not oracle.evaluate(replace(cases[0], marker=cases[1].marker), accepted(cases[0])).full_reconstruction
        # Independent keyed utility material changes the finite sequence; do
        # not require every one-bit decision to differ between two keys.
        assert key_utility[KEYS[0]] != key_utility[KEYS[1]]


@pytest.mark.parametrize("fixture_mode", ["key_derived_unknown", "public_transport_control"])
def test_c14_requires_its_receiver_key_and_authenticated_issued_bytes(fixture_mode):
    registry = SensitiveFixtureRegistry()
    case = registry.load("C14", 31, KEYS[0], fixture_mode=fixture_mode)
    artifacts = accepted(case)
    oracle = SensitiveOracle()
    wrong_key = oracle.evaluate(replace(case, fixture_key=b"W" * 32), artifacts)
    assert not wrong_key.full_reconstruction and wrong_key.unscorable_reason == "authentication_failed"
    assert not oracle.evaluate(replace(case, fixture_key=None), artifacts).full_reconstruction
    changed = deepcopy(case.source_record)
    evidence = changed["opaque_fixture"]
    ciphertext = bytearray(base64.b64decode(evidence["ciphertext_b64"]))
    ciphertext[-1] ^= 1
    evidence["ciphertext_b64"] = base64.b64encode(ciphertext).decode("ascii")
    damaged_case = replace(case, source_record=changed)
    damaged_artifacts = accepted(damaged_case)
    # Original issued-fixture admission rejects altered bytes first.
    assert oracle.evaluate(case, damaged_artifacts).unscorable_reason == "unknown_fixture"
    # Even a matching issued-envelope reference cannot make a damaged tag valid.
    damaged = oracle.evaluate(damaged_case, damaged_artifacts)
    assert not damaged.full_reconstruction and damaged.unscorable_reason == "authentication_failed"
    assert "fixture_key" not in case.source_record and "local_key" not in json.dumps(case.source_record)


def test_public_template_bytes_digest_and_detached_views_remain_immutable():
    path = default_data_root() / "fixtures" / "sensitive_cases.json"
    before = path.read_bytes()
    registry = SensitiveFixtureRegistry()
    assert registry.template_digest == hashlib.sha256(before).hexdigest()
    pristine = registry.data
    view = registry.data
    view["cases"]["C12"]["31"]["marker"] = "00"
    view["cases"]["C13"]["31"]["spectral_fixture"]["coefficients"][0] = -1
    for mode in ("key_derived_unknown", "public_transport_control"):
        case = registry.load("C13", 31, KEYS[0], fixture_mode=mode)
        original = deepcopy(case.source_record)
        case.source_record["spectral_fixture"]["coefficients"][0] = -1
        assert registry.load("C13", 31, KEYS[0], fixture_mode=mode).source_record == original
        metadata = fixture_metadata("C13", mode, registry.template_digest)
        assert metadata == {
            "fixture_mode": mode,
            "fixture_derivation_version": "sensitive-key-derived-v1" if mode == "key_derived_unknown" else "sensitive-public-control-v1",
            "fixture_template_digest": hashlib.sha256(before).hexdigest(),
        }
    assert registry.data == pristine
    assert path.read_bytes() == before


def test_sensitive_mode_and_key_gate_fail_closed():
    registry = SensitiveFixtureRegistry()
    for invalid in (b"short", bytearray(b"T" * 32), None):
        with pytest.raises(ValueError, match="key"):
            registry.load("C10", 31, invalid)
    with pytest.raises(ValueError, match="mode"):
        registry.load("C10", 31, KEYS[0], fixture_mode="public")
    for invalid_seed in (True, 2**64, -1):
        with pytest.raises(ValueError, match="seed"):
            registry.load("C10", invalid_seed, KEYS[0])
