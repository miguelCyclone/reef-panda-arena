"""Hard-coded projection of approved shipping fields into a public update."""

import re
from dataclasses import dataclass
from datetime import datetime

from reef_panda_arena.gateway.invoke import GatewayResult, ProposedCall


@dataclass(frozen=True)
class SafeUpdate:
    call: ProposedCall
    public_fields: frozenset[str]


def safe_eta_update(shipment: GatewayResult, incident: GatewayResult) -> SafeUpdate:
    if not shipment.allowed or not incident.allowed:
        raise ValueError("Cannot declassify a blocked source")
    if shipment.data is None or incident.data is None:
        raise ValueError("Cannot declassify an empty source")
    required = (
        (shipment, "id"),
        (shipment, "customer_id"),
        (incident, "cause_code"),
        (incident, "eta"),
    )
    if any(item.field_labels.get(field) != "internal" for item, field in required):
        raise ValueError("Only approved internal shipping fields can be released")
    shipment_id = shipment.data["id"]
    customer_id = shipment.data["customer_id"]
    cause = incident.data["cause_code"]
    eta = incident.data["eta"]
    if not re.fullmatch(r"SHP-[0-9]{4}", shipment_id):
        raise ValueError("Invalid shipment identifier")
    if not re.fullmatch(r"CUS-[0-9]{3}", customer_id):
        raise ValueError("Invalid customer identifier")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,39}", cause):
        raise ValueError("Invalid public cause code")
    try:
        datetime.fromisoformat(eta.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Invalid revised ETA") from error
    text = f"Shipment {shipment_id} is delayed due to {cause}. Revised ETA: {eta}."
    return SafeUpdate(
        call=ProposedCall(
            tool_name="customer.notify",
            arguments={
                "shipment_id": shipment_id,
                "customer_id": customer_id,
                "text": text,
            },
        ),
        public_fields=frozenset({"shipment_id", "customer_id", "text"}),
    )
