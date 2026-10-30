"""Execute bounded role proposals through existing authenticated local boundaries."""

import json
from dataclasses import replace

from reef_panda_arena.application.decisions import DecisionLimitExceeded
from reef_panda_arena.gateway.invoke import ProposedCall, TrustedContext
from reef_panda_arena.gateway.route_reference import require_released_route
from reef_panda_arena.gateway.release import ROUTE_PURPOSE, ROUTE_RECIPIENT, ROUTE_SOURCE, ROUTE_RELEASE_VERSION
from reef_panda_arena.model.role_context import accepted_role_input
from reef_panda_arena.model.role_contract import ToolAction, PeerAction, ReaderContributionAction, ReleaseAction, MemoryAction, StoreRouteAction, ForwardRouteAction


class RoleRuntime:
    """Private per-role inboxes; models cannot select identity or remove ancestry.

    The scheduler supplies a separate RoleModelCaller for every acting role.
    Receiving a message makes it available for a decision, never forces a relay.
    Source tools execute only in response to that role's own proposed action.
    """

    def __init__(self, gateway, registry, peer, memory, projection, callers):
        if gateway.artifact_registry is not registry or registry.run_id != gateway.event_store_run_id:
            raise ValueError("Role runtime requires the same committed registry")
        if any(caller.actor_id != actor or caller.run_id != registry.run_id for actor, caller in callers.items()):
            raise ValueError("Role caller identity differs from its runtime slot")
        if (any(boundary.gateway is not gateway or boundary.registry is not registry
                for boundary in (peer, memory)) or projection.gateway is not gateway
                or projection.projection.registry is not registry):
            raise ValueError("Role boundaries must share the same gateway")
        if not callers or len({id(caller.decisions) for caller in callers.values()}) != 1:
            raise ValueError("All roles must share one decision budget")
        if any((actor, recipient) not in peer.routes for actor, caller in callers.items()
               for recipient in caller.recipients):
            raise ValueError("Role prompt advertises a route absent from the gateway")
        self.gateway, self.registry = gateway, registry
        self.peer, self.memory, self.projection = peer, memory, projection
        self.callers = dict(callers)
        self.inputs = {actor: [] for actor in callers}
        self.pending = {actor: [] for actor in callers}
        self.feedback = {actor: [] for actor in callers}
        self.peer_deliveries = 0

    def _attempt(self, actor):
        if self.callers[actor].compromised:
            return "attack:live"
        pending = [identity for view in self.inputs[actor] for identity in view.artifact_ids]
        seen = set()
        while pending:
            identity = pending.pop()
            if identity in seen:
                continue
            seen.add(identity)
            if len(seen) > 640:
                raise ValueError("Role influence exceeds its bound")
            artifact = self.registry.get(identity)
            if artifact.actor_id in self.callers and self.callers[artifact.actor_id].compromised:
                return "attack:live"
            pending.extend(artifact.parent_ids)
        return "task"

    def _context(self, actor, fields=()):
        parents = tuple(dict.fromkeys(identity for view in self.inputs[actor] for identity in view.artifact_ids))
        if len(parents) > 16:
            raise ValueError("Model-visible ancestry exceeds the bounded parent set")
        return TrustedContext(self.registry.run_id, actor, actor, attempt_id=self._attempt(actor),
            artifact_dependencies={field: parents for field in fields} if parents else {},
            trusted_public_fields=frozenset(fields) if not parents else frozenset(),
            purpose=ROUTE_PURPOSE, recipient=ROUTE_RECIPIENT)

    def _retain(self, actor, result):
        if result.allowed and result.data is not None and result.artifact_ids:
            if len(self.inputs[actor]) >= 12:
                raise ValueError("Role input count exceeded")
            self.inputs[actor].append(accepted_role_input(result, registry=self.registry, actor_id=actor))

    async def receive(self, actor):
        if actor not in self.callers:
            raise ValueError("Unscheduled role recipient")
        while self.pending[actor]:
            identity, origin = self.pending[actor].pop(0)
            context = self._context(actor)
            result = await self.peer.receive(replace(context, attempt_id=("attack:live" if origin == "attack:live" else context.attempt_id)), identity)
            if result.allowed:
                self._retain(actor, result)
                self.peer_deliveries += 1

    def _input_field(self, actor, reference, field):
        index = int(reference.removeprefix("input_"))
        if index >= len(self.inputs[actor]):
            raise ValueError("Unknown model input reference")
        view = self.inputs[actor][index]
        values = view.values()
        if field not in values:
            raise ValueError("Model input lacks the required field")
        identity = dict(view.field_artifacts)[field]
        return values[field], identity

    async def _forward_exact(self, actor, recipient, payload, dependencies):
        if recipient not in self.pending:
            raise ValueError("Approved transport recipient has no independent caller")
        result = await self.peer.send(TrustedContext(self.registry.run_id, actor, actor, attempt_id=self._attempt(actor),
            artifact_dependencies=dependencies, purpose=ROUTE_PURPOSE, recipient=ROUTE_RECIPIENT), recipient, payload)
        if result.allowed:
            self.pending[recipient].append((result.data["message_id"], self._attempt(actor)))
        return result

    async def _store_route(self, actor, action, context):
        value, identity = self._input_field(actor, action.source_input, "decision")
        value = require_released_route(self.registry, identity, value)
        written = await self.memory.write(context, "approved_route",
            json.dumps(value, sort_keys=True, separators=(",", ":")), (identity,))
        if not written.allowed:
            return written
        read = await self.memory.read(context, "approved_route")
        if not read.allowed:
            return read
        return await self._forward_exact(actor, "A8", {"decision": json.loads(read.data["value"])},
                                         {"decision": (read.artifact_ids["value"],)})

    def require_turn(self, actor):
        if actor not in self.callers:
            raise ValueError("Unknown acting role")
        budget = self.callers[actor].decisions
        if budget.total_model_calls >= budget.max_model_calls:
            raise DecisionLimitExceeded("max_total_model_calls")
        if budget.decision_turns >= budget.max_turns:
            raise DecisionLimitExceeded("max_decision_turns")

    async def step(self, actor, *, task):
        self.require_turn(actor)
        await self.receive(actor)
        outcome = await self.callers[actor].decide(tuple(self.inputs[actor]), task=task,
                                                   feedback=tuple(self.feedback[actor][-4:]))
        if outcome.decision is None or outcome.decision.disposition not in {"act", "clarify"}:
            return outcome
        # All fields in one model response depend on the inputs of that response.
        # New source reads become model context only on its next decision turn.
        response_parents = tuple(dict.fromkeys(identity for view in self.inputs[actor] for identity in view.artifact_ids))
        contexts = [self._context(actor, action.arguments if isinstance(action, ToolAction)
                                  else action.payload if isinstance(action, PeerAction)
                                  else ("code", "decision") if isinstance(action, ReaderContributionAction) else ())
                    for action in outcome.decision.actions]
        caller = self.callers[actor]
        record = caller.records[-1]
        for index, (action, context) in enumerate(zip(outcome.decision.actions, contexts, strict=True)):
            try:
                if isinstance(action, ToolAction):
                    result = await self.gateway.invoke(context, ProposedCall(tool_name=action.tool, arguments=action.arguments))
                    if action.tool != "customer.notify":
                        self._retain(actor, result)
                elif isinstance(action, ReaderContributionAction):
                    code, identity = self._input_field(actor, action.source_input, "code")
                    source = self.registry.get(identity)
                    if (actor != "A2" or identity not in response_parents
                            or source.kind != ROUTE_SOURCE or source.actor_id != actor):
                        raise ValueError("Reader contribution needs a source visible to this decision")
                    # Copy only an already visible source. All calculated values
                    # come from the model; A3 still independently validates them.
                    proposal = {"version": ROUTE_RELEASE_VERSION, "category": action.category,
                                "service_hours": action.service_hours, "action": action.action}
                    result = await self.peer.send(context, "A3", {"code": code, "decision": proposal})
                    if result.allowed:
                        self.pending["A3"].append((result.data["message_id"], context.attempt_id))
                elif isinstance(action, PeerAction):
                    if action.recipient not in self.pending:
                        raise ValueError("Peer recipient has no independent caller")
                    result = await self.peer.send(context, action.recipient, action.payload, kind=action.message_kind)
                    if result.allowed:
                        self.pending[action.recipient].append((result.data["message_id"], context.attempt_id))
                elif isinstance(action, ForwardRouteAction):
                    value, identity = self._input_field(actor, action.source_input, "decision")
                    value = require_released_route(self.registry, identity, value)
                    result = await self._forward_exact(actor, action.recipient, {"decision": value}, {"decision": (identity,)})
                elif isinstance(action, StoreRouteAction):
                    result = await self._store_route(actor, action, context)
                elif isinstance(action, MemoryAction):
                    if action.kind == "memory_read":
                        result = await self.memory.read(context, action.key)
                        self._retain(actor, result)
                    elif action.kind == "memory_compact":
                        result = await self.memory.compact(context, action.key)
                        self._retain(actor, result)
                    else:
                        result = await self.memory.write(context, action.key, action.value, response_parents)
                else:
                    assert isinstance(action, ReleaseAction)
                    code, source_id = self._input_field(actor, action.source_input, "code")
                    decision, proposal_id = self._input_field(actor, action.proposal_input, "decision")
                    result = await self.projection.release_decision(context, source_id=source_id, source_code=code,
                        proposal_id=proposal_id, proposal=decision, purpose=ROUTE_PURPOSE, recipient=ROUTE_RECIPIENT)
                    self._retain(actor, result)
                    if result.allowed and action.forward_to is not None:
                        result = await self._forward_exact(actor, action.forward_to,
                            {"decision": result.data["decision"]}, {"decision": (result.artifact_ids["decision"],)})
            except BaseException:
                record["actions"][index].update(state="failed", feedback="execution_failed")
                raise
            feedback = "accepted_by_local_gateway" if result.allowed else "candidate_rejected"
            record["actions"][index].update(state="accepted" if result.allowed else "rejected", feedback=feedback)
            self.feedback[actor].append(feedback)
            await caller.persist_progress()
        return outcome
