"""Opaque field slots for metadata whose names may be caller-controlled."""

from collections.abc import Iterable, Mapping
import re


LABELS = frozenset({"public", "secret", "unknown", "internal", "public_outbound"})


def safe_field_map(field_names: Iterable[str], trusted_fields: Iterable[str] = ()) -> dict[str, str]:
    trusted = frozenset(trusted_fields)
    names = sorted({name for name in field_names if type(name) is str})
    reserved = {name for name in names if name in trusted or re.fullmatch(r"field:[0-9]{1,4}", name)}
    result = {}
    index = 0
    for name in names:
        if name in reserved:
            result[name] = name
            continue
        while f"field:{index}" in reserved:
            index += 1
        slot = f"field:{index}"
        result[name] = slot
        reserved.add(slot)
        index += 1
    return result


def safe_labels(labels: Mapping[str, str], trusted_fields: Iterable[str] = ()) -> dict[str, str]:
    mapping = safe_field_map(labels, trusted_fields)
    return {mapping[name]: label if type(label) is str and label in LABELS else "unknown"
            for name, label in labels.items() if name in mapping}
