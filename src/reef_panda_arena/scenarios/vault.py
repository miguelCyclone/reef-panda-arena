"""Synthetic per-run secrets, encrypted before database storage."""

import hmac
import os
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from reef_panda_arena.storage.models import SyntheticVault
from reef_panda_arena.scenarios.fixture_knowledge import FixtureMode, effective_fixture_key


ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MAX_DERIVATION_BLOCKS = 8


class SyntheticSecretVault:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("Vault encryption key must be 32 bytes")
        self.key = key
        self.cipher = AESGCM(key)

    def create(self, run_id: str, scenario_id: str, seed: int, length: int,
               label: str, *, fixture_mode: FixtureMode = "key_derived_unknown") -> tuple[SyntheticVault, bytes]:
        if type(length) is not int or type(seed) is not int or not 2 <= length <= 32 or not 0 <= seed < 2**64:
            raise ValueError("Invalid synthetic secret parameters")
        derivation_key = effective_fixture_key(self.key, fixture_mode)
        chars = bytearray()
        for counter in range(MAX_DERIVATION_BLOCKS):
            digest = hmac.digest(
                derivation_key, f"{scenario_id}:{seed}:{counter}".encode(), "sha256"
            )
            for value in digest:
                if value < 252:
                    chars.append(ALPHABET[value % len(ALPHABET)])
                    if len(chars) == length:
                        break
            if len(chars) == length:
                break
        else:
            raise ValueError("Synthetic secret derivation budget exhausted")
        secret = bytes(chars)
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, secret, run_id.encode())
        row = SyntheticVault(
            id=str(uuid4()),
            run_id=run_id,
            label=label,
            secret_nonce=nonce,
            secret_ciphertext=ciphertext,
        )
        return row, secret

    def create_fixed(self, run_id: str, label: str,
                     secret: bytes) -> SyntheticVault:
        """Encrypt a finite trusted synthetic fixture reference for one run."""
        if not 2 <= len(secret) <= 32:
            raise ValueError("Invalid fixed synthetic marker length")
        nonce = os.urandom(12)
        return SyntheticVault(
            id=str(uuid4()), run_id=run_id, label=label,
            secret_nonce=nonce,
            secret_ciphertext=self.cipher.encrypt(nonce, secret, run_id.encode()),
        )

    def decrypt(self, row: SyntheticVault) -> bytes:
        return self.cipher.decrypt(
            row.secret_nonce, row.secret_ciphertext, row.run_id.encode()
        )
