"""Execution-specific model setup and retained evidence for the unified lifecycle."""

from dataclasses import dataclass
import re

from reef_panda_arena.application.live_workflow import IndependentShippingWorkflow, LIVE_SCHEDULE_VERSION
from reef_panda_arena.application.comparison_contract import source_revision
from reef_panda_arena.application.live_execution_contract import LiveExecutionEvidence
from reef_panda_arena.model.ollama import OllamaCaller
from reef_panda_arena.model.role_caller import ROLE_PROMPT_VERSION
from reef_panda_arena.telemetry.privacy import no_external_tracing


@dataclass(frozen=True)
class LiveWorkflowResult:
    graph_steps: int
    peer_deliveries: int


class LiveExecution:
    """No secret, receiver key, fixture or oracle is passed to the role callers."""
    def __init__(self, config, *, ollama_url, caller_factory=None):
        self.config, self.ollama_url = config, ollama_url
        self.caller_factory = caller_factory
        self.workflow = None
        self.model_digest = None
        self.source_digest = source_revision()
        self.status = "in_progress"

    def evidence(self):
        records = [] if self.workflow is None else sorted(
            (dict(record) for caller in self.workflow.runtime.callers.values() for record in caller.records),
            key=lambda record: record["decision_turn"])
        return LiveExecutionEvidence.model_validate({
            "version": "live-execution-v2", "proposal_identity": "run_local_hmac_sha256", "schedule": LIVE_SCHEDULE_VERSION,
            "model_backend": "ollama" if self.caller_factory is None else "injected_caller",
            "scheduler": "trusted_A0", "public_context_acquisition": "fixed_shipment_and_incident_lookup",
            "trusted_transport": "reader_submission_and_validated_route_copy",
            "attempt_attribution": "assigned_compromise_or_causal_input", "measurement_status": self.status,
            "requests": records, "total_model_calls": len(records),
            "invalid_model_outputs": sum(item["outcome"] == "invalid_role_proposal" for item in records),
            "model_refusals": sum(item["outcome"] == "refuse" for item in records),
            "model_clarifications": sum(item["outcome"] == "clarify" for item in records),
        }).model_dump(mode="json")

    def metadata(self):
        evidence = self.evidence()
        return {"live_execution": evidence, "model_digest": self.model_digest, "source_digest": self.source_digest,
                "model_top_p": self.config.top_p, "model_generation_seed": self.config.seed,
                "decision_accounting": "model_request_attempts", "task_prompt_version": ROLE_PROMPT_VERSION,
                "task_model_calls": evidence["total_model_calls"],
                "tokens_in": sum(item["tokens_in"] for item in evidence["requests"]),
                "tokens_out": sum(item["tokens_out"] for item in evidence["requests"])}

    def candidate_counts(self):
        records = [item for item in self.evidence()["requests"] if item["compromised"]]
        return {"valid_candidates": sum(item["outcome"] in {"act", "clarify"} for item in records),
                "invalid_candidates": sum(item["outcome"] == "invalid_role_proposal" for item in records),
                "duplicate_candidates": 0, "unsupported_candidates": 0}

    async def run(self, gateway, registry, roster, scenario, decisions, *, on_progress=None):
        try:
            if self.caller_factory is None:
                provider = OllamaCaller(self.ollama_url)
                with no_external_tracing():
                    digest = await provider.model_digest(self.config.model_name)
                if digest is not None and re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", digest):
                    self.model_digest = digest
                callers = {f"A{i}": provider for i in range(1, 10)}
            else:
                callers = {f"A{i}": self.caller_factory(f"A{i}") for i in range(1, 10)}
            self.workflow = IndependentShippingWorkflow(gateway, registry, roster, callers=callers,
                config=self.config, decisions=decisions, boundary=scenario.boundary, on_progress=on_progress)
            state = await self.workflow.run()
            self.status = "complete"
            return LiveWorkflowResult(state["graph_steps"], self.workflow.runtime.peer_deliveries)
        except BaseException:
            self.status = "partial_run"
            raise
