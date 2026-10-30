"""Bounded, redacted records of untrusted model hypotheses."""

import hashlib
from dataclasses import asdict, dataclass

from reef_panda_arena.adaptive.contracts import Family


@dataclass(frozen=True)
class HypothesisRecord:
    round_index: int
    family: Family | None
    candidate_hash: str | None
    hypothesis_sha256: str | None
    hypothesis_chars: int
    redacted_text: str
    outcome: str


class HypothesisStore:
    """Keep method metadata for review without persisting model-written prose."""

    def __init__(self, max_records: int = 8) -> None:
        if not 1 <= max_records <= 8:
            raise ValueError("Invalid hypothesis capacity")
        self.max_records = max_records
        self._records: list[HypothesisRecord] = []

    def record(
        self, *, round_index: int, hypothesis: str | None,
        family: Family | None, candidate_hash: str | None, outcome: str,
    ) -> None:
        if len(self._records) >= self.max_records or not 1 <= round_index <= 8:
            raise ValueError("Hypothesis budget exceeded")
        if outcome not in {
            "validated", "invalid_model_output", "candidate_context_mismatch",
            "candidate_too_large", "duplicate_candidate", "unsupported_hypothesis",
        }:
            raise ValueError("Unknown hypothesis outcome")
        if hypothesis is not None and len(hypothesis) > 350:
            raise ValueError("Hypothesis text too long")
        if candidate_hash is not None and (
            len(candidate_hash) != 64 or
            any(char not in "0123456789abcdef" for char in candidate_hash)
        ):
            raise ValueError("Invalid candidate hash")
        self._records.append(HypothesisRecord(
            round_index=round_index,
            family=family,
            candidate_hash=candidate_hash,
            hypothesis_sha256=(
                hashlib.sha256(hypothesis.encode("utf-8")).hexdigest()
                if hypothesis is not None else None
            ),
            hypothesis_chars=len(hypothesis) if hypothesis is not None else 0,
            redacted_text="[untrusted hypothesis text withheld]",
            outcome=outcome,
        ))

    def public_records(self) -> list[dict]:
        return [asdict(item) for item in self._records]
