"""Bounded private evidence of tool calls whose boundary event committed.

Raw arguments stay in the local trusted process for independent task scoring.
This type is never serialized into events, model input, API or public reports.
"""

import json
from dataclasses import dataclass


MAX_ACTION_EVIDENCE_BYTES = 32768


@dataclass(frozen=True, slots=True, repr=False)
class CommittedToolAction:
    event_seq: int
    actor_id: str
    tool_name: str
    allowed: bool
    reason: str
    attempt_id: str
    artifact_ids: tuple[tuple[str, str], ...]
    _call_json: bytes
    input_artifact_ids: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @property
    def arguments(self) -> dict | None:
        if not self._call_json:
            return None
        try:
            value = json.loads(self._call_json)["arguments"]
        except (ValueError, KeyError, TypeError):
            return None
        return value if isinstance(value, dict) else None

    @property
    def artifact_map(self) -> dict[str, str]:
        return dict(self.artifact_ids)

    @property
    def input_map(self) -> dict[str, tuple[str, ...]]:
        return dict(self.input_artifact_ids)
