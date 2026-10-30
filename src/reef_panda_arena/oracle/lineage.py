"""Harness-only expected dependency ledger, never passed to policy or model."""


class SealedDependencyLedger:
    def __init__(self) -> None:
        self._secret_derived: set[str] = set()

    def mark_private_source(self, artifact_id: str) -> None:
        self._secret_derived.add(artifact_id)

    def propagate(self, artifact_id: str, parent_ids: tuple[str, ...]) -> None:
        if not parent_ids:
            raise ValueError("Expected dependency edges are required")
        if any(parent in self._secret_derived for parent in parent_ids):
            self._secret_derived.add(artifact_id)

    def is_secret_derived(self, artifact_id: str) -> bool:
        return artifact_id in self._secret_derived
