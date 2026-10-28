"""Field provenance for controlled tool results and conservative agent outputs."""

from collections.abc import Mapping


SOURCE_FIELDS: dict[str, dict[str, str]] = {
    "shipment.lookup": {
        "id": "internal",
        "status": "internal",
        "customer_id": "internal",
    },
    "operations.incident": {
        "id": "internal",
        "cause_code": "internal",
        "eta": "internal",
    },
    "memory.read": {"message": "secret"},
    "customer.profile": {
        "id": "internal",
        "name": "internal",
        "internal_routing_code": "secret",
    },
}


class TaintTracker:
    """Tracks structured read fields; free-form model output inherits actor secret taint."""

    def __init__(self) -> None:
        self._source_labels: dict[str, dict[str, str]] = {}
        self._secret_readers: set[str] = set()

    def record_read(self, actor_id: str, tool_name: str, data: Mapping[str, object]) -> dict[str, str]:
        declared = SOURCE_FIELDS.get(tool_name)
        if declared is None or set(data) != set(declared):
            raise ValueError("Tool output does not match its classification contract")
        labels = {field: declared[field] for field in data}
        actor_sources = self._source_labels.setdefault(actor_id, {})
        for field, label in labels.items():
            actor_sources[f"{tool_name}.{field}"] = label
            if label == "secret":
                self._secret_readers.add(actor_id)
        return labels

    def label_arguments(
        self,
        actor_id: str,
        arguments: Mapping[str, object],
        derived_from: Mapping[str, tuple[str, ...]],
        trusted_public_fields: frozenset[str],
    ) -> dict[str, str]:
        if not set(derived_from) <= set(arguments):
            raise ValueError("Provenance names an absent argument field")
        if not trusted_public_fields <= set(arguments):
            raise ValueError("Declassification names an absent argument field")
        actor_sources = self._source_labels.get(actor_id, {})
        labels: dict[str, str] = {}
        for field in arguments:
            if field in trusted_public_fields:
                labels[field] = "public"
                continue
            sources = derived_from.get(field)
            if sources:
                source_labels = [actor_sources.get(source) for source in sources]
                if None in source_labels:
                    raise ValueError("Unknown provenance source")
                labels[field] = (
                    "secret" if "secret" in source_labels else
                    "internal" if "internal" in source_labels else "public"
                )
            else:
                labels[field] = "secret" if actor_id in self._secret_readers else "public"
        return labels
