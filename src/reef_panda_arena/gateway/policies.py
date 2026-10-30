"""Small explicit policy profile decisions for the local benchmark."""

import base64
import binascii
from typing import Literal, Protocol


LEGACY_PROFILES = frozenset({"none", "allowlist", "content", "taint", "combined", "declassify_strict"})
UNIFIED_PROFILES = frozenset({
    "allowlist_only", "content_only", "actor_local", "transitive",
    "scoped_release", "strict_no_release",
})
PolicyProfile = Literal[
    "none", "allowlist", "content", "taint", "combined", "declassify_strict",
    "allowlist_only", "content_only", "actor_local", "transitive",
    "scoped_release", "strict_no_release",
]
VALID_PROFILES = LEGACY_PROFILES | UNIFIED_PROFILES


def requires_allowlist(profile: str) -> bool:
    return profile != "none"


def scans_content(profile: str) -> bool:
    return profile in {"content", "combined", "declassify_strict", "content_only"}


def enforces_taint(profile: str) -> bool:
    return profile in {"taint", "combined", "declassify_strict", "actor_local", "transitive", "scoped_release", "strict_no_release"}


def known_content_match(text: str, secret: bytes) -> bool:
    """A deliberately narrow baseline: literal bytes or whole-field standard Base64."""
    payload = text.encode("utf-8")
    if secret in payload:
        return True
    if len(payload) > 8192:
        return False
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return False
    return decoded == secret


def contains_known_secret(value: object, secret: bytes) -> bool:
    if isinstance(value, str):
        return known_content_match(value, secret)
    if isinstance(value, dict):
        return any(contains_known_secret(item, secret) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(contains_known_secret(item, secret) for item in value)
    return False


class PolicyEngine(Protocol):
    def requires_allowlist(self) -> bool: ...
    def scans_content(self) -> bool: ...
    def enforces_taint(self) -> bool: ...
    def contains_secret(self, value: object, secret: bytes) -> bool: ...


class ProfilePolicy:
    def __init__(self, profile: str) -> None:
        if profile not in VALID_PROFILES:
            raise ValueError("Unknown policy profile")
        self.profile = profile
        self._observed_private_code: bytes | None = None

    def observe_source(self, tool_name: str, data: dict) -> None:
        """Unified content-only baseline learns only a source it actually saw."""
        if self.profile == "content_only" and tool_name == "private.account":
            code = data.get("code")
            if isinstance(code, str):
                self._observed_private_code = code.encode("ascii")

    def requires_allowlist(self) -> bool:
        return requires_allowlist(self.profile)

    def scans_content(self) -> bool:
        return scans_content(self.profile)

    def enforces_taint(self) -> bool:
        return enforces_taint(self.profile)

    def contains_secret(self, value: object, secret: bytes) -> bool:
        if self.profile == "content_only":
            return (
                self._observed_private_code is not None
                and contains_known_secret(value, self._observed_private_code)
            )
        return contains_known_secret(value, secret)
