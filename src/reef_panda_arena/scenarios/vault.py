"""Synthetic per-run secrets, encrypted before database storage."""

import hmac
import os
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from reef_panda_arena.storage.models import SyntheticVault


ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class SyntheticSecretVault:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("Vault encryption key must be 32 bytes")
        self.key = key
        self.cipher = AESGCM(key)

    def create(self, run_id: str, scenario_id: str, seed: int, length: int,
               label: str) -> tuple[SyntheticVault, bytes]:
        if not 2 <= length <= 32 or not 0 <= seed < 2**64:
            raise ValueError("Invalid synthetic secret parameters")
        chars = bytearray()
        counter = 0
        while len(chars) < length:
            digest = hmac.digest(
                self.key, f"{scenario_id}:{seed}:{counter}".encode(), "sha256"
            )
            for value in digest:
                if value < 252:
                    chars.append(ALPHABET[value % len(ALPHABET)])
                    if len(chars) == length:
                        break
            counter += 1
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

    def decrypt(self, row: SyntheticVault) -> bytes:
        return self.cipher.decrypt(
            row.secret_nonce, row.secret_ciphertext, row.run_id.encode()
        )
