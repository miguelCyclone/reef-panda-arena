"""In-memory actual source reads shared by adaptive custody and budget tests."""

from reef_panda_arena.adaptive.source_view import accepted_source_view
from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
from reef_panda_arena.graph.roster import LEGACY_RUNTIME_ROLES
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.tools.adaptive import (
    ADAPTIVE_TOOL_DESTINATIONS, ADAPTIVE_TOOL_INPUTS, AdaptiveToolAdapter, adaptive_role_tools,
)


class MemoryEvents:
    def __init__(self):
        self.events = []
        self.receipts = []

    async def append(self, event, receipt=None):
        self.events.append(event)
        if receipt is not None:
            self.receipts.append(receipt)
        return event


def source_gateway(case, *, run_id="source-custody-test", observer=None, denied=False, profile="none"):
    store = MemoryEvents()
    roles = adaptive_role_tools()
    if denied:
        roles["customer_worker"].discard(case.source_tool)
    gateway = PolicyGateway(
        store, AdaptiveToolAdapter(ScenarioLoader().shipping_fixture(), case.marker,
                                   case.scenario_id, case.source_tool, case.source_record),
        "allowlist" if denied else profile, secret=case.marker,
        run_id=run_id, runtime_roles=LEGACY_RUNTIME_ROLES, observer=observer,
        tool_inputs=ADAPTIVE_TOOL_INPUTS, tool_destinations=ADAPTIVE_TOOL_DESTINATIONS,
        role_tools=roles, max_calls=32, max_events=100, max_payload_bytes=2048,
        research_run_id=run_id,
    )

    async def invoke(actor, call, *, operation_id, derived_from=None, **kwargs):
        return await gateway.invoke(TrustedContext(
            run_id, actor, actor, operation_id=operation_id,
            derived_from=derived_from or {}, trusted_public_fields=kwargs.get("public_fields", frozenset()),
        ), call)
    return gateway, store, invoke


async def read_source(case, gateway, *, actor="customer_worker", operation_id="source"):
    return await gateway.invoke(TrustedContext(
        gateway.event_store_run_id, actor, actor, operation_id=operation_id,
    ), ProposedCall(tool_name=case.source_tool, arguments={"case_id": case.scenario_id}))


async def granted_view(case):
    gateway, _, _ = source_gateway(case)
    source = await read_source(case, gateway)
    return accepted_source_view(case, source, registry=gateway.evidence_registry,
                                run_id=gateway.event_store_run_id, actor_id="customer_worker")


def model_task_answer(context):
    """Controlled caller computes from its supplied source; no fixture lookup."""
    from reef_panda_arena.adaptive.contracts import LegitimateContribution
    source = context["classified_source"]
    raw = source.get("private_nibble", source.get("restricted_metric"))
    band = sum(raw >= boundary for boundary in (4, 8, 12))
    return LegitimateContribution(**context["public_shipping_facts"], risk_band=band,
                                  route_action="HOLD" if raw < 8 else "REROUTE")
