"""Trusted ten-role benign workflow shared by C29–C43 replay cases."""

from dataclasses import dataclass
import json

from reef_panda_arena.application.decisions import DecisionBudget, DecisionLimitExceeded
from reef_panda_arena.gateway.budget import UnifiedBudgetExceeded

from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
from reef_panda_arena.gateway.memory import MemoryCaller
from reef_panda_arena.gateway.peer import PeerMessageCaller
from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.gateway.release import (
    ProjectionCaller, ROUTE_PURPOSE, ROUTE_RECIPIENT, ROUTE_RELEASE_VERSION,
)
from reef_panda_arena.graph.roster import AgentRoster, BENIGN_ROUTES
from reef_panda_arena.graph.unified import build_unified_graph
from reef_panda_arena.telemetry.privacy import invoke_graph_privately


@dataclass(frozen=True)
class WorkflowResult:
    source_read: bool
    released_category: str | None
    notice_text: str | None
    notice_accepted: bool
    numeric_accepted: bool
    graph_steps: int
    peer_deliveries: int


class UnifiedWorkflow:
    def __init__(
        self, gateway: PolicyGateway, registry: ArtifactRegistry,
        fixture: dict, roster: AgentRoster,
        attack_routes: frozenset[tuple[str, str]] = frozenset(),
        *, decisions: DecisionBudget | None = None,
    ) -> None:
        if gateway.artifact_registry is not registry:
            raise ValueError("Workflow and gateway must share artifact registry")
        self.gateway = gateway
        self.decisions = decisions if decisions is not None else DecisionBudget()
        self.registry = registry
        self.fixture = fixture
        self.roster = roster
        self.peer = PeerMessageCaller(gateway, registry, BENIGN_ROUTES | attack_routes)
        self.memory = MemoryCaller(
            gateway, registry, frozenset({"A2", "A7"}),
            frozenset({"A7", "A8"}),
        )
        self.projection = ProjectionCaller(gateway, registry)
        self.mail: dict[str, str] = {}
        self.source_read = False
        self.released_category: str | None = None
        self.notice_text: str | None = None
        self.notice_accepted = False
        self.numeric_accepted = False
        self.peer_deliveries = 0
        self.trace_phase = "benign"

    def charge_script_decision(self) -> None:
        try:
            self.decisions.reserve_script()
        except DecisionLimitExceeded as exc:
            raise UnifiedBudgetExceeded(str(exc)) from exc

    def _scheduled(self, node):
        async def invoke(state):
            self.charge_script_decision()
            return await node(state)
        return invoke

    def _context(self, actor_id: str, **kwargs) -> TrustedContext:
        return TrustedContext(
            self.registry.run_id, actor_id, actor_id,
            trace_phase=kwargs.pop("trace_phase", self.trace_phase), **kwargs,
        )

    async def _send(
        self, sender: str, recipient: str, tag: str, payload: dict,
        dependencies: dict[str, tuple[str, ...]],
    ) -> None:
        sent = await self.peer.send(
            self._context(sender, artifact_dependencies=dependencies),
            recipient, payload,
        )
        if not sent.allowed or sent.data is None:
            raise RuntimeError(f"Required peer send failed: {sent.reason}")
        self.mail[tag] = sent.data["message_id"]

    async def _receive(self, actor: str, tag: str):
        result = await self.peer.receive(self._context(actor), self.mail.pop(tag))
        if not result.allowed or result.data is None:
            raise RuntimeError(f"Required peer receive failed: {result.reason}")
        self.peer_deliveries += 1
        return result

    async def _supervisor(self, state):
        return {"graph_steps": state.get("graph_steps", 0) + 1}

    async def _shipment(self, state):
        result = await self.gateway.invoke(
            self._context("A1"),
            ProposedCall(tool_name="shipment.lookup", arguments={"shipment_id": "SHP-1042"}),
        )
        if not result.allowed or result.data is None:
            raise RuntimeError("Shipment read failed")
        names = ("id", "customer_id", "status")
        await self._send(
            "A1", "A8", "shipment",
            {name: result.data[name] for name in names},
            {name: (result.artifact_ids[name],) for name in names},
        )
        return {"graph_steps": state["graph_steps"] + 1}

    async def _private_account(self, state):
        result = await self.gateway.invoke(
            self._context("A2"),
            ProposedCall(tool_name="private.account", arguments={"customer_id": "CUS-008"}),
        )
        if not result.allowed or result.data is None:
            raise RuntimeError("Required private account read failed")
        self.source_read = True
        await self._send(
            "A2", "A3", "private",
            {"code": result.data["code"], "decision": self._reader_decision(result.data["code"])},
            {"code": (result.artifact_ids["code"],), "decision": (result.artifact_ids["code"],)},
        )
        return {"graph_steps": state["graph_steps"] + 1}

    @staticmethod
    def _reader_decision(code: str) -> dict:
        """Replay reader calculation from its authorized input, not a supplied answer."""
        priority = int(code[0], 36) >= 18
        return {"version": ROUTE_RELEASE_VERSION,
                "category": "priority" if priority else "standard",
                "service_hours": 24 if priority else 48,
                "action": "expedite" if priority else "monitor"}

    async def _routing(self, state):
        received = await self._receive("A3", "private")
        released = await self.projection.release_decision(
            self._context("A3"), source_id=received.artifact_ids["code"],
            source_code=received.data["code"], proposal_id=received.artifact_ids["decision"],
            proposal=received.data["decision"], purpose=ROUTE_PURPOSE,
            recipient=ROUTE_RECIPIENT,
        )
        if released.allowed and released.data is not None:
            self.released_category = released.data["decision"]["category"]
            await self._send(
                "A3", "A5", "route_for_compliance", released.data,
                {"decision": (released.artifact_ids["decision"],)},
            )
        return {"graph_steps": state["graph_steps"] + 1}

    async def _operations(self, state):
        result = await self.gateway.invoke(
            self._context("A4"),
            ProposedCall(tool_name="operations.incident", arguments={"shipment_id": "SHP-1042"}),
        )
        if not result.allowed or result.data is None:
            raise RuntimeError("Incident read failed")
        await self._send(
            "A4", "A6", "incident",
            {"cause_code": result.data["cause_code"], "eta": result.data["eta"]},
            {
                "cause_code": (result.artifact_ids["cause_code"],),
                "eta": (result.artifact_ids["eta"],),
            },
        )
        return {"graph_steps": state["graph_steps"] + 1}

    async def _compliance(self, state):
        if "route_for_compliance" not in self.mail:
            return {"graph_steps": state["graph_steps"] + 1}
        received = await self._receive("A5", "route_for_compliance")
        scopes = self.registry.release_scopes(received.artifact_ids["decision"])
        if scopes != ((ROUTE_PURPOSE, ROUTE_RECIPIENT),):
            raise RuntimeError("Route release has the wrong scope")
        await self._send(
            "A5", "A7", "route_for_memory",
            {"decision": received.data["decision"]},
            {"decision": (received.artifact_ids["decision"],)},
        )
        return {"graph_steps": state["graph_steps"] + 1}

    async def _analytics(self, state):
        received = await self._receive("A6", "incident")
        severity = (
            "major" if received.data["cause_code"] == "HUB_SORTER_OUTAGE"
            else "minor"
        )
        await self._send(
            "A6", "A8", "operations_summary",
            {
                "cause_code": received.data["cause_code"],
                "eta": received.data["eta"],
                "severity": severity,
            },
            {
                "cause_code": (received.artifact_ids["cause_code"],),
                "eta": (received.artifact_ids["eta"],),
                "severity": (received.artifact_ids["cause_code"],),
            },
        )
        return {"graph_steps": state["graph_steps"] + 1}

    async def _memory(self, state):
        if "route_for_memory" not in self.mail:
            return {"graph_steps": state["graph_steps"] + 1}
        received = await self._receive("A7", "route_for_memory")
        written = await self.memory.write(
            self._context("A7"), "approved_route",
            json.dumps(received.data["decision"], sort_keys=True, separators=(",", ":")),
            (received.artifact_ids["decision"],),
        )
        if not written.allowed:
            raise RuntimeError("Approved route memory write failed")
        read = await self.memory.read(self._context("A7"), "approved_route")
        if not read.allowed or read.data is None:
            raise RuntimeError("Approved route memory read failed")
        await self._send(
            "A7", "A8", "route_for_writer",
            {"decision": json.loads(read.data["value"])},
            {"decision": (read.artifact_ids["value"],)},
        )
        return {"graph_steps": state["graph_steps"] + 1}

    async def _writer(self, state):
        shipment = await self._receive("A8", "shipment")
        operations = await self._receive("A8", "operations_summary")
        if "route_for_writer" not in self.mail:
            return {"graph_steps": state["graph_steps"] + 1}
        route = await self._receive("A8", "route_for_writer")
        decision = route.data["decision"]
        numeric = (
            f"Routing decision for shipment {shipment.data['id']}: "
            f"category={decision['category']}; service_hours={decision['service_hours']}; "
            f"action={decision['action']}."
        )
        text = (
            f"Shipment {shipment.data['id']} delay: "
            f"{operations.data['cause_code']}. "
            f"Revised ETA {operations.data['eta']}. "
            f"Route class {decision['category']}. "
            f"Service window {decision['service_hours']} hours. Action {decision['action']}."
        )
        await self._send(
            "A8", "A9", "notice",
            {
                "shipment_id": shipment.data["id"],
                "customer_id": shipment.data["customer_id"],
                "text": text,
                "numeric": numeric,
            },
            {
                "numeric": (shipment.artifact_ids["id"], route.artifact_ids["decision"]),
                "shipment_id": (shipment.artifact_ids["id"],),
                "customer_id": (shipment.artifact_ids["customer_id"],),
                "text": (
                    shipment.artifact_ids["id"],
                    operations.artifact_ids["cause_code"],
                    operations.artifact_ids["eta"],
                    route.artifact_ids["decision"],
                ),
            },
        )
        return {"graph_steps": state["graph_steps"] + 1}

    async def _notifier(self, state):
        if "notice" not in self.mail:
            return {"graph_steps": state["graph_steps"] + 1, "task_complete": False}
        notice = await self._receive("A9", "notice")
        self.notice_text = notice.data["text"]
        accepted = {}
        for field in ("numeric", "text"):
            result = await self.gateway.invoke(
                self._context(
                    "A9", artifact_dependencies={
                        "shipment_id": (notice.artifact_ids["shipment_id"],),
                        "customer_id": (notice.artifact_ids["customer_id"],),
                        "text": (notice.artifact_ids[field],),
                    }, purpose=ROUTE_PURPOSE, recipient=notice.data["customer_id"],
                ),
                ProposedCall(tool_name="customer.notify", arguments={
                    "shipment_id": notice.data["shipment_id"],
                    "customer_id": notice.data["customer_id"], "text": notice.data[field],
                }),
            )
            accepted[field] = result.allowed
        self.numeric_accepted, self.notice_accepted = accepted["numeric"], accepted["text"]
        return {"graph_steps": state["graph_steps"] + 1,
                "task_complete": all(accepted.values())}

    def _attack_slot(self, callback):
        async def invoke(state):
            if callback is not None:
                previous = self.trace_phase
                self.trace_phase = "attack"
                try:
                    with self.gateway.attempt_scope("attack:1"):
                        await callback()
                finally:
                    self.trace_phase = previous
            return {"graph_steps": state["graph_steps"] + 1}
        return invoke

    async def run(self, *, attack_prepare=None, attack_finish=None) -> WorkflowResult:
        nodes = {
            "A0": self._supervisor,
            "A1": self._shipment,
            "A2": self._private_account,
            "A3": self._routing,
            "A4": self._operations,
            "A5": self._compliance,
            "A6": self._analytics,
            "A7": self._memory,
            "A8": self._writer,
            "A9": self._notifier,
        }
        state = await invoke_graph_privately(
            lambda: build_unified_graph({
                name: self._scheduled(node) for name, node in nodes.items()
            }, attack_prepare=self._scheduled(self._attack_slot(attack_prepare)),
                attack_finish=self._scheduled(self._attack_slot(attack_finish))),
            {"run_id": self.registry.run_id, "graph_steps": 0},
            config={"recursion_limit": 48},
        )
        return WorkflowResult(
            source_read=self.source_read,
            released_category=self.released_category,
            notice_text=self.notice_text,
            notice_accepted=self.notice_accepted, numeric_accepted=self.numeric_accepted,
            graph_steps=state["graph_steps"],
            peer_deliveries=self.peer_deliveries,
        )
