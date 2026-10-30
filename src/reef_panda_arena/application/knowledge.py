"""Public access contracts for fixtures, policies, observers and receivers.

These declarations describe configured access, not evidence that a read or an
inspection occurred. Actual boundary events and receipt evidence establish that.
No function here accepts a protected target or a private key.
"""

import hashlib
import json

from reef_panda_arena.gateway.policies import VALID_PROFILES
from reef_panda_arena.scenarios.fixture_knowledge import (
    FixtureMode, fixture_metadata, FIXTURE_MODES, CORE_DERIVATION_VERSION,
    SENSITIVE_DERIVATION_VERSION, SENSITIVE_PUBLIC_DERIVATION_VERSION,
    EXTENSION_DERIVATION_VERSION, ADAPTIVE_DERIVATION_VERSION,
)


KNOWLEDGE_FIELDS = (
    "fixture_mode", "fixture_derivation_version", "fixture_template_digest",
    "knowledge_contract_version", "protected_target_kind", "attacker_knowledge",
    "policy_knowledge", "policy_known_target", "observer_knowledge",
    "receiver_knowledge", "receiver_target_comparison", "decoder_convention_public",
)


KNOWLEDGE_VALUES = {
    "fixture_mode": FIXTURE_MODES,
    "fixture_derivation_version": frozenset({
        CORE_DERIVATION_VERSION, SENSITIVE_DERIVATION_VERSION,
        SENSITIVE_PUBLIC_DERIVATION_VERSION, EXTENSION_DERIVATION_VERSION,
        ADAPTIVE_DERIVATION_VERSION,
    }),
    "knowledge_contract_version": frozenset({"knowledge-v1"}),
    "protected_target_kind": frozenset({
        "marker", "marker_and_exact_fee", "private_nibble",
        "private_individual_value", "private_formula_bit",
    }),
    "attacker_knowledge": frozenset({
        "authorized_source_read_required", "public_fixture_and_authorized_source",
    }),
    "policy_knowledge": frozenset({
        "privileged_known_secret", "authenticated_source_content",
        "no_content_inspection", "runtime_provenance",
    }),
    "policy_known_target": frozenset({
        "none", "expected_marker", "private.account.code_after_committed_read",
    }),
    "observer_knowledge": frozenset({
        "disabled", "keyless-proposal-content-v1", "keyless-proposal-metadata-v1",
        "keyless-runtime-labels-v1",
    }),
    "receiver_knowledge": frozenset({
        "sealed_aead_key_and_issued_fixture", "public_control_aead_key_and_issued_fixture",
        "public_decoder_conventions", "public_finite_codebook",
        "public_decoder_and_issued_attack_id",
    }),
    "receiver_target_comparison": frozenset({"sealed_expected_target", "public_control_expected_target"}),
}


def shipping_template_digest(public_fixture: dict) -> str:
    """Hash canonical public shipping JSON, before any private source is added."""
    return hashlib.sha256(json.dumps(
        public_fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def knowledge_metadata(
    scenario_id: str, fixture_mode: FixtureMode, template_digest: str, *,
    defense_profile: str, observer_profile: str | None,
) -> dict:
    """Record access classes without implying high entropy or secret algorithms."""
    if defense_profile not in VALID_PROFILES:
        raise ValueError("Unknown policy knowledge contract")
    observers = {
        None: "disabled",
        "content": "keyless-proposal-content-v1",
        "literal_content": "keyless-proposal-content-v1",
        "metadata_schema": "keyless-proposal-metadata-v1",
        "structural_math": "keyless-proposal-metadata-v1",
        "provenance_release": "keyless-runtime-labels-v1",
    }
    if observer_profile not in observers:
        raise ValueError("Unknown observer knowledge contract")
    policy_known_target = "none"
    if defense_profile in {"content", "combined", "declassify_strict"}:
        policy_knowledge = "privileged_known_secret"
        # C11's fee is not the marker supplied to the legacy content scanner.
        policy_known_target = "expected_marker"
    elif defense_profile == "content_only":
        policy_knowledge = "authenticated_source_content"
        policy_known_target = "private.account.code_after_committed_read"
    elif defense_profile in {"none", "allowlist", "allowlist_only"}:
        policy_knowledge = "no_content_inspection"
    else:
        policy_knowledge = "runtime_provenance"
    # C17/C19/C20 literal fallback markers publicly spell the same numeric target;
    # they do not introduce an independent eight-symbol secret.
    target = {
        "C11": "marker_and_exact_fee", "C17": "private_nibble",
        "C19": "private_individual_value", "C20": "private_formula_bit",
        "C23": "private_nibble", "C26": "private_nibble",
    }.get(scenario_id, "marker")
    opaque = scenario_id in {"C14", "C21", "C24"}
    if opaque:
        receiver = ("sealed_aead_key_and_issued_fixture"
                    if fixture_mode == "key_derived_unknown" else
                    "public_control_aead_key_and_issued_fixture")
    elif scenario_id in {"C06", "C17"}:
        receiver = "public_finite_codebook"
    elif scenario_id == "C20":
        receiver = "public_decoder_and_issued_attack_id"
    else:
        receiver = "public_decoder_conventions"
    return {
        **fixture_metadata(scenario_id, fixture_mode, template_digest),
        "knowledge_contract_version": "knowledge-v1",
        "protected_target_kind": target,
        "attacker_knowledge": (
            "authorized_source_read_required" if fixture_mode == "key_derived_unknown"
            else "public_fixture_and_authorized_source"
        ),
        "policy_knowledge": policy_knowledge,
        "policy_known_target": policy_known_target,
        "observer_knowledge": observers[observer_profile],
        "receiver_knowledge": receiver,
        "receiver_target_comparison": (
            "sealed_expected_target" if fixture_mode == "key_derived_unknown"
            else "public_control_expected_target"
        ),
        # Even AEAD algorithms and AAD formats are public; their key is separate.
        "decoder_convention_public": True,
    }
