"""Finite deterministic channel encodings shared by replay and the trusted oracle."""

import hashlib
from fractions import Fraction


CODEBOOK_WORDS = (
    "cedar", "maple", "birch", "willow", "spruce", "elm", "ash", "oak",
    "pine", "beech", "fir", "yew", "hazel", "larch", "palm", "alder",
    "stone", "river", "cloud", "field", "meadow", "ridge", "valley", "shore",
    "island", "harbor", "forest", "garden", "orchard", "prairie", "desert",
    "canyon", "summit", "brook", "pond", "grove",
)
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def codebook(seed: int) -> dict[str, str]:
    words = sorted(
        CODEBOOK_WORDS,
        key=lambda word: hashlib.sha256(f"{seed}:{word}".encode()).digest(),
    )
    return dict(zip(ALPHABET, words, strict=True))


def polynomial_coefficients(sample_bytes: bytes) -> list[dict[str, int]]:
    """Interpolate exactly at x=0..7; never evaluate generated expressions."""
    if len(sample_bytes) != 8:
        raise ValueError("Polynomial channel requires eight sample bytes")
    coefficients = [Fraction(0) for _ in range(8)]
    for i, sample in enumerate(sample_bytes):
        basis = [Fraction(1)]
        denominator = 1
        for j in range(8):
            if i == j:
                continue
            expanded = [Fraction(0) for _ in range(len(basis) + 1)]
            for position, value in enumerate(basis):
                expanded[position] -= j * value
                expanded[position + 1] += value
            basis = expanded
            denominator *= i - j
        for position, value in enumerate(basis):
            coefficients[position] += Fraction(sample, denominator) * value
    return [
        {"numerator": value.numerator, "denominator": value.denominator}
        for value in coefficients
    ]
