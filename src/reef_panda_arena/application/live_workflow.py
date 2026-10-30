"""Bounded independent-role shipping work; no replay attack or role implementation."""

import secrets
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from reef_panda_arena.application.role_runtime import RoleRuntime
from reef_panda_arena.application.live_plan import LIVE_SCHEDULE_VERSION, live_plan
from reef_panda_arena.gateway.invoke import ProposedCall, TrustedContext
from reef_panda_arena.gateway.memory import MemoryCaller
from reef_panda_arena.gateway.peer import PeerMessageCaller
from reef_panda_arena.gateway.release import ProjectionCaller
from reef_panda_arena.graph.roster import BENIGN_ROUTES
from reef_panda_arena.model.ollama import ModelOutputError
from reef_panda_arena.model.role_caller import RoleModelCaller
from reef_panda_arena.model.role_tasks import role_task
from reef_panda_arena.telemetry.privacy import invoke_graph_privately



class LiveState(TypedDict):
    graph_steps: int


class IndependentShippingWorkflow:
    """A0 is the trusted scheduler; A1 through A9 have separate model contexts.

    Public shipment/incident lookup is fixed runtime context acquisition. Private
    reads, calculations, forwarding, refusal and customer sends are role choices.
    Scripted source gathering and trusted transport primitives are explicitly
    distinguished from those model decisions; they do not invent model output.
    """

    def __init__(self, gateway, registry, roster, *, callers, config, decisions, routes=frozenset(), boundary="peer_direct", on_progress=None):
        if set(callers) != {f"A{i}" for i in range(1, 10)}:
            raise ValueError("Independent shipping requires nine explicit role callers")
        self.plan = live_plan(boundary)
        allowed = BENIGN_ROUTES | routes | self.plan.routes
        proposal_key = secrets.token_bytes(32)
        role_callers = {actor: RoleModelCaller(run_id=registry.run_id, actor_id=actor, roster=roster,
            caller=caller, config=config, decisions=decisions, routes=allowed, proposal_key=proposal_key, on_progress=on_progress) for actor, caller in callers.items()}
        self.gateway, self.registry = gateway, registry
        self.runtime = RoleRuntime(gateway, registry, PeerMessageCaller(gateway, registry, allowed),
            MemoryCaller(gateway, registry, frozenset({"A2", "A7"}), frozenset({"A7", "A8"})),
            ProjectionCaller(gateway, registry), role_callers)
        self.outcomes = []

    async def _public_context(self, actor, tool):
        result = await self.gateway.invoke(TrustedContext(self.registry.run_id, actor, actor),
            ProposedCall(tool_name=tool, arguments={"shipment_id": "SHP-1042"}))
        self.runtime._retain(actor, result)

    async def _step(self, actor, state, *, slot, public_tool=None):
        self.runtime.require_turn(actor)
        if public_tool is not None:
            await self._public_context(actor, public_tool)
        outcome = await self.runtime.step(actor, task=role_task(actor) + " " + self.plan.task_context(slot))
        self.outcomes.append((actor, outcome))
        if outcome.decision is None:
            raise ModelOutputError("Invalid independent role response")
        return {"graph_steps": state["graph_steps"] + 1}

    async def run(self):
        # A slot grants a decision opportunity, never an automatic private read or relay.
        schedule = self.plan.slots
        graph = StateGraph(LiveState)
        for name in schedule:
            actor = name.split("_", 1)[0]
            tool = {"A1": "shipment.lookup", "A4": "operations.incident"}.get(name)
            async def node(state, actor=actor, tool=tool, slot=name):
                return await self._step(actor, state, slot=slot, public_tool=tool)
            graph.add_node(name, node)
        graph.add_edge(START, schedule[0])
        for source, destination in zip(schedule, schedule[1:]):
            graph.add_edge(source, destination)
        graph.add_edge(schedule[-1], END)
        return await invoke_graph_privately(graph.compile, {"graph_steps": 0}, config={"recursion_limit": 48})
