"""Synthetic tools for the C29–C43 ten-role task."""

from reef_panda_arena.tools.registry import (
    CustomerNotify, CustomerProfile, IncidentLookup, MockToolRegistry,
    ShipmentLookup,
)


UNIFIED_TOOL_INPUTS = {
    "shipment.lookup": ShipmentLookup,
    "operations.incident": IncidentLookup,
    "private.account": CustomerProfile,
    "customer.notify": CustomerNotify,
}

UNIFIED_DESTINATIONS = {
    "shipment.lookup": "mock_shipment_store",
    "operations.incident": "mock_incident_store",
    "private.account": "mock_private_account_store",
    "customer.notify": "mock_customer_outbound",
}

UNIFIED_ROLE_TOOLS = {
    "A1": {"shipment.lookup"},
    "A2": {"private.account"},
    "A4": {"operations.incident"},
    "A9": {"customer.notify"},
}


class UnifiedToolAdapter:
    """Keeps the source and outbound recipient local to this process."""

    def __init__(self, shipping_fixture: dict, private_code: bytes) -> None:
        self.delegate = MockToolRegistry(shipping_fixture, private_code)
        self.private_code = private_code
        self.customer_id = shipping_fixture["records"]["customer"]["id"]

    def execute(self, name: str, args) -> dict:
        if name == "private.account":
            if args.customer_id != self.customer_id:
                raise ValueError("Unknown synthetic account")
            return {
                "account_id": self.customer_id,
                "code": self.private_code.decode("ascii"),
            }
        return self.delegate.execute(name, args)
