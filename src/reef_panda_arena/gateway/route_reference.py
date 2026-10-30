"""Validate exact transport of an already released route, without new disclosure."""

import hashlib
import json

from reef_panda_arena.gateway.release import RouteDecision, ROUTE_PURPOSE, ROUTE_RECIPIENT


def require_released_route(registry, identity, value):
    decision = RouteDecision.parse(value)
    encoded = json.dumps(decision.payload(), sort_keys=True, separators=(",", ":")).encode("ascii")
    digest = hashlib.sha256(encoded).hexdigest()
    node = registry.get(identity)
    if (node.label != "public" or node.payload_sha256 != digest
            or registry.release_scopes(identity) != ((ROUTE_PURPOSE, ROUTE_RECIPIENT),)):
        raise ValueError("Route reference is not the exact scoped public value")
    pending, seen = [identity], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if len(seen) > 640:
            raise ValueError("Route reference ancestry exceeds the bound")
        ancestor = registry.get(current)
        if (ancestor.kind == "trusted_projection" and ancestor.actor_id == "A3"
                and ancestor.payload_sha256 == digest and ancestor.release_purpose == ROUTE_PURPOSE
                and ancestor.release_recipient == ROUTE_RECIPIENT):
            return decision.payload()
        pending.extend(ancestor.parent_ids)
    raise ValueError("No matching trusted route projection")
