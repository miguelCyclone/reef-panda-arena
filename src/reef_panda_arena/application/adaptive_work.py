"""Schedule authorized adaptive work around bounded attack rounds."""

from reef_panda_arena.adaptive.proposer import TASK_PROMPT_VERSION, OllamaProposer
from reef_panda_arena.adaptive.release import AdaptiveReleasePolicy
from reef_panda_arena.gateway.invoke import ProposedCall
from reef_panda_arena.oracle.adaptive_utility import ADAPTIVE_UTILITY_VERSION, AdaptiveUtilityOracle
from reef_panda_arena.oracle.benign_actions import ClassifiedBenignActions
from reef_panda_arena.oracle.utility_evidence import UtilityEvidence


class AdaptiveWorkRuntime:
    """Trusted execution/evidence coordinator; the utility oracle is separate."""

    def __init__(self, *, case, shipping, research, invoke, profile):
        self.case = case
        self.shipping = shipping
        self.research = research
        self.invoke = invoke
        self.profile = profile
        self.release = AdaptiveReleasePolicy()
        self.source = None
        self.completed = False
        self.benign_evaluated = 0
        self.legitimate_blocked = 0

    async def _send(self, work, operation, *, actor="customer_worker", derived_from=None):
        decision = await self.invoke(
            actor, work.call, operation_id=operation,
            derived_from=derived_from or {},
            public_fields=work.public_fields if self.profile == "declassify_strict" else frozenset(),
        )
        self.benign_evaluated += 1
        self.legitimate_blocked += int(not decision.allowed)
        return decision

    async def _notice(self, stage):
        work = self.research.validated_work
        if work is not None:
            await self._send(self.release.notice(self.case, self.source, work),
                             f"adaptive-{stage}-notice")

    async def support(self):
        work = self.research.validated_work
        if work is None:
            return
        if self.case.scenario_id in {"C23", "C26"}:
            await self._send(self.release.numeric_report(self.case, self.source, work),
                             "adaptive-benign-numeric")
        elif self.case.scenario_id == "C24":
            await self._send(self.release.attestation(self.case, self.source, work),
                             "adaptive-benign-attestation")
        elif self.case.scenario_id == "C25":
            handoff = await self._send(self.release.handoff(self.case, self.source, work),
                                       "adaptive-benign-handoff")
            if not handoff.allowed:
                return
            peer = await self.invoke(
                "response_writer", ProposedCall(tool_name="memory.read", arguments={
                    "key": "customer_update_context",
                }), operation_id="adaptive-benign-peer-read",
            )
            self.benign_evaluated += 1
            self.legitimate_blocked += int(not peer.allowed)
            if not peer.allowed:
                return
            try:
                acknowledgement = self.release.peer_notice(self.case, self.source, work, peer)
            except ValueError:
                return  # The independent oracle records the missing/corrupt handoff.
            await self._send(
                acknowledgement, "adaptive-benign-peer-notice", actor="response_writer",
                derived_from={"text": ("memory.read.message",)},
            )

    async def execute(self, source, rounds):
        self.source = source
        await self.research.prepare_work(self.shipping)
        await self._notice("initial")
        if rounds:
            await self.research.run(rounds, after_first_attack=self.support)
        else:
            await self.support()
        await self._notice("final")
        self.completed = True

    def evaluate(self):
        if not self.completed:
            return None
        gateway = self.research.gateway
        evidence = UtilityEvidence(gateway.evidence_registry, gateway.action_evidence,
                                   gateway.accepted_artifacts)
        source = evidence.source(self.source, actor_id="customer_worker",
                                 tool_name=self.case.source_tool, expected=self.case.source_record)
        return AdaptiveUtilityOracle().evaluate(
            self.case, self.shipping, source=source, evidence=evidence,
            contribution=(self.research.work_outcome.contribution
                          if self.research.work_outcome is not None else None),
        )

    def benign_contract(self, scenario):
        if self.source is None:
            return None
        gateway = self.research.gateway
        evidence = UtilityEvidence(gateway.evidence_registry, gateway.action_evidence,
                                   gateway.accepted_artifacts)
        proof = evidence.source(self.source, actor_id="customer_worker",
                                tool_name=self.case.source_tool, expected=self.case.source_record)
        return ClassifiedBenignActions(
            scenario, self.case, self.shipping, proof,
            contribution=(self.research.work_outcome.contribution
                          if self.research.work_outcome is not None else None),
        )

    def metadata(self, result=None):
        model = isinstance(self.research.proposer, OllamaProposer)
        return {
            "utility_version": ADAPTIVE_UTILITY_VERSION,
            "utility_scope": "same_reader_model_decision" if model else "same_reader_scripted",
            "utility_reason": result.reason_code if result is not None else "task_incomplete",
            "same_reader_utility": result.benign_task_success if result is not None else None,
            "task_actor": "customer_worker",
            "task_mechanism": "model_computation" if model else "scripted_computation",
            "task_prompt_version": TASK_PROMPT_VERSION if model else None,
            "task_model_calls": self.research.task_model_calls,
            "utility_required_components": list(result.required_components) if result else [],
            "utility_satisfied_components": list(result.satisfied_components) if result else [],
            "utility_evidence_event_seqs": list(result.evidence_event_seqs) if result else [],
        }
