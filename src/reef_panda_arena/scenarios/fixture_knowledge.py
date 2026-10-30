"""Trusted fixture modes and metadata that contain no protected target material."""

import re
from typing import Literal


FixtureMode = Literal["key_derived_unknown", "public_transport_control"]
FIXTURE_MODES = frozenset({"key_derived_unknown", "public_transport_control"})

# Intentionally public synthetic key, not a credential. Public transport controls
# can be reproduced from this literal and the public scenario/seed contracts.
# Their randomized AEAD envelopes still use fresh nonces on every construction.
PUBLIC_TRANSPORT_CONTROL_KEY = b"reef-panda-public-control-key-v1"

CORE_DERIVATION_VERSION = "vault-hmac-rejection-v1"
SENSITIVE_DERIVATION_VERSION = "sensitive-key-derived-v1"
SENSITIVE_PUBLIC_DERIVATION_VERSION = "sensitive-public-control-v1"
EXTENSION_DERIVATION_VERSION = "extension-hmac-v1"
ADAPTIVE_DERIVATION_VERSION = "adaptive-hmac-v1"


def _validate_mode(fixture_mode: FixtureMode) -> None:
    if type(fixture_mode) is not str or fixture_mode not in FIXTURE_MODES:
        raise ValueError("Unknown fixture mode")


def effective_fixture_key(local_key: bytes, fixture_mode: FixtureMode) -> bytes:
    """Choose the trusted derivation key; never change the private storage key.

    Unknown means unavailable from public fixtures alone before an authorized
    source read. It does not imply high entropy or a secret decoder convention.
    There is no user/model-provided key override in this mode contract.
    """
    _validate_mode(fixture_mode)
    if type(local_key) is not bytes or len(local_key) != 32:
        raise ValueError("Local fixture key must be 32 bytes")
    return local_key if fixture_mode == "key_derived_unknown" else PUBLIC_TRANSPORT_CONTROL_KEY


def fixture_metadata(scenario_id: str, fixture_mode: FixtureMode, template_digest: str) -> dict[str, str]:
    """Describe only the derivation scheme and the unchanged public template."""
    _validate_mode(fixture_mode)
    if type(scenario_id) is not str or re.fullmatch(r"C(?:[0-3][0-9]|4[0-3])", scenario_id) is None:
        raise ValueError("Unknown fixture scenario")
    if type(template_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", template_digest) is None:
        raise ValueError("Fixture template digest must be a full public SHA256")
    number = int(scenario_id[1:])
    if 10 <= number <= 14:
        version = SENSITIVE_DERIVATION_VERSION if fixture_mode == "key_derived_unknown" else SENSITIVE_PUBLIC_DERIVATION_VERSION
    elif 15 <= number <= 21:
        version = EXTENSION_DERIVATION_VERSION
    elif 22 <= number <= 28:
        version = ADAPTIVE_DERIVATION_VERSION
    else:
        version = CORE_DERIVATION_VERSION
    return {
        "fixture_mode": fixture_mode,
        "fixture_derivation_version": version,
        "fixture_template_digest": template_digest,
    }
