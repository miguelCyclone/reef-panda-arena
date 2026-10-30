"""Run-local, runtime-authored dependency graph for mediated artifacts."""

from dataclasses import dataclass
from hashlib import sha256
from typing import Literal
from uuid import uuid4


Label = Literal["public", "internal", "secret", "unknown"]
MAX_ARTIFACT_BATCH = 16
MAX_ARTIFACT_PARENTS = 16


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    run_id: str
    event_seq: int
    kind: str
    actor_id: str
    label: Label
    parent_ids: tuple[str, ...]
    payload_sha256: str
    release_purpose: str | None = None
    release_recipient: str | None = None


class ProvenanceJoiner:
    """Upper bound of registered labels; uncertainty never becomes public."""

    @staticmethod
    def join(labels: tuple[Label, ...]) -> Label:
        if not labels:
            return "unknown"
        if "secret" in labels:
            return "secret"
        if "unknown" in labels:
            return "unknown"
        if "internal" in labels:
            return "internal"
        return "public"


class ArtifactRegistry:
    """Only trusted runtime code records accepted source and derived operations.

    The registry stores hashes and labels, never the source payload or sealed oracle
    truth. A derived artifact must name existing parents from this same run.
    """

    def __init__(self, run_id: str) -> None:
        if not run_id:
            raise ValueError("Run ID is required")
        self.run_id = run_id
        self._artifacts: dict[str, Artifact] = {}
        self._last_event_seq = 0

    def get(self, artifact_id: str) -> Artifact:
        try:
            return self._artifacts[artifact_id]
        except KeyError as exc:
            raise ValueError("Unknown artifact dependency") from exc

    def prepare_source(
        self, *, event_seq: int, actor_id: str, label: Label,
        payload: bytes, kind: str = "source_read",
    ) -> Artifact:
        if label not in {"public", "internal", "secret", "unknown"}:
            raise ValueError("Invalid source label")
        return self._prepare(event_seq, actor_id, kind, label, (), payload)

    def prepare_derived(
        self, *, event_seq: int, actor_id: str, kind: str,
        parent_ids: tuple[str, ...], payload: bytes,
    ) -> Artifact:
        parent_ids = tuple(parent_ids)
        if not parent_ids:
            raise ValueError("Derived artifact requires trusted dependencies")
        if len(parent_ids) > MAX_ARTIFACT_PARENTS:
            raise ValueError("Artifact parent budget exceeded")
        parents = tuple(self.get(parent_id) for parent_id in parent_ids)
        if len(set(parent_ids)) != len(parent_ids):
            raise ValueError("Duplicate artifact dependency")
        label = ProvenanceJoiner.join(tuple(parent.label for parent in parents))
        return self._prepare(event_seq, actor_id, kind, label, parent_ids, payload)

    def prepare_release(
        self, *, event_seq: int, actor_id: str, source_id: str,
        payload: bytes, purpose: str, recipient: str,
    ) -> Artifact:
        """Trusted application release keeps its secret parent and scope."""
        source = self.get(source_id)
        if source.label != "secret" or not purpose or not recipient:
            raise ValueError("Invalid trusted release")
        return self._prepare(
            event_seq, actor_id, "trusted_projection", "public",
            (source_id,), payload, purpose, recipient,
        )

    def has_ancestor_kind(self, artifact_id: str, kind: str) -> bool:
        seen: set[str] = set()
        pending = [artifact_id]
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            artifact = self.get(current)
            if artifact.kind == kind:
                return True
            pending.extend(artifact.parent_ids)
        return False

    def release_scopes(self, artifact_id: str) -> tuple[tuple[str, str], ...]:
        """Find every trusted release on the ancestry of an artifact."""
        scopes: set[tuple[str, str]] = set()
        seen: set[str] = set()
        pending = [artifact_id]
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            artifact = self.get(current)
            if artifact.release_purpose is not None:
                assert artifact.release_recipient is not None
                scopes.add((artifact.release_purpose, artifact.release_recipient))
            pending.extend(artifact.parent_ids)
        return tuple(sorted(scopes))

    def _prepare(
        self, event_seq: int, actor_id: str, kind: str, label: Label,
        parent_ids: tuple[str, ...], payload: bytes,
        release_purpose: str | None = None,
        release_recipient: str | None = None,
    ) -> Artifact:
        if type(event_seq) is not int or event_seq < self._last_event_seq:
            raise ValueError("Artifact event sequence cannot move backwards")
        if not actor_id or not kind or not isinstance(payload, bytes):
            raise ValueError("Invalid trusted artifact metadata")
        artifact = Artifact(
            uuid4().hex, self.run_id, event_seq, kind, actor_id, label,
            tuple(parent_ids), sha256(payload).hexdigest(),
            release_purpose, release_recipient,
        )
        self.validate_prepared((artifact,))
        return artifact

    def validate_prepared(self, nodes: tuple[Artifact, ...]) -> None:
        """Validate the whole immutable publication batch before persistence.

        Parents must already be published. Preparing a child of another pending
        node would invent a boundary that has not yet committed.
        """
        if type(nodes) is not tuple or len(nodes) > MAX_ARTIFACT_BATCH:
            raise ValueError("Artifact batch budget exceeded")
        ids: set[str] = set()
        event_seq = None
        for node in nodes:
            if not isinstance(node, Artifact) or node.run_id != self.run_id:
                raise ValueError("Invalid prepared artifact ownership")
            if (type(node.event_seq) is not int or node.event_seq < self._last_event_seq
                    or (event_seq is not None and node.event_seq != event_seq)):
                raise ValueError("Artifact event sequence cannot move backwards or mix events")
            event_seq = node.event_seq
            if (node.artifact_id in ids or node.artifact_id in self._artifacts
                    or not node.artifact_id or not node.actor_id or not node.kind
                    or node.label not in {"public", "internal", "secret", "unknown"}
                    or type(node.parent_ids) is not tuple
                    or len(node.parent_ids) > MAX_ARTIFACT_PARENTS
                    or len(set(node.parent_ids)) != len(node.parent_ids)):
                raise ValueError("Invalid prepared artifact metadata")
            parents = tuple(self.get(parent_id) for parent_id in node.parent_ids)
            if any(parent.run_id != self.run_id or parent.event_seq > node.event_seq for parent in parents):
                raise ValueError("Invalid prepared artifact parent ownership")
            if node.release_purpose is not None or node.release_recipient is not None:
                if (node.kind != "trusted_projection" or node.label != "public"
                        or len(parents) != 1 or parents[0].label != "secret"
                        or not node.release_purpose or not node.release_recipient):
                    raise ValueError("Invalid prepared release")
            elif parents and node.label != ProvenanceJoiner.join(tuple(parent.label for parent in parents)):
                raise ValueError("Prepared artifact label differs from registered parents")
            ids.add(node.artifact_id)

    def commit_prepared(self, nodes: tuple[Artifact, ...]) -> None:
        """Publish synchronously after confirmed atomic event/receipt append.

        The gateway lock spans prepare, append and this call. No await or callback
        is permitted between the confirmed append and local publication.
        """
        self.validate_prepared(nodes)
        self._artifacts.update((node.artifact_id, node) for node in nodes)
        if nodes:
            self._last_event_seq = nodes[0].event_seq

    def record_source(self, **kwargs) -> Artifact:
        """Compatibility for trusted direct setup; mediated calls use prepare."""
        artifact = self.prepare_source(**kwargs)
        self.commit_prepared((artifact,))
        return artifact

    def record_derived(self, **kwargs) -> Artifact:
        """Compatibility for trusted direct setup; mediated calls use prepare."""
        artifact = self.prepare_derived(**kwargs)
        self.commit_prepared((artifact,))
        return artifact

    def record_release(self, **kwargs) -> Artifact:
        """Compatibility for trusted direct setup; mediated calls use prepare."""
        artifact = self.prepare_release(**kwargs)
        self.commit_prepared((artifact,))
        return artifact
