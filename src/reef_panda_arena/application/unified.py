"""Persistent bounded C29–C43 unified replay and independent scoring."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic
from typing import Callable
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.application.admission import run_admission
from reef_panda_arena.application.live_execution import LiveExecution
from reef_panda_arena.application.live_plan import LIVE_SCHEDULE_VERSION
from reef_panda_arena.model.protocol import ModelConfig
from reef_panda_arena.model.role_caller import ROLE_PROMPT_VERSION
from reef_panda_arena.model.ollama import ModelTimedOut
from reef_panda_arena.oracle.information import InformationMeasure
from reef_panda_arena.application.knowledge import knowledge_metadata, shipping_template_digest
from reef_panda_arena.application.decisions import DecisionBudget, DecisionLimitExceeded
from reef_panda_arena.application.comparison_contract import declare_comparison
from reef_panda_arena.application.run_observations import notify_terminal, preserve_failure, score_gateway
from reef_panda_arena.application.unified_attack import ATTACK_ROUTES, UnifiedAttack
from reef_panda_arena.application.unified_workflow import UnifiedWorkflow
from reef_panda_arena.gateway.invoke import PolicyGateway
from reef_panda_arena.gateway.budget import UnifiedBudgetExceeded
from reef_panda_arena.gateway.policies import UNIFIED_PROFILES
from reef_panda_arena.gateway.provenance import ArtifactRegistry
from reef_panda_arena.gateway.research_observer import ResearchObserver, VALID_REVIEWERS
from reef_panda_arena.graph.roster import AgentRoster
from reef_panda_arena.oracle.unified import UNIFIED_ORACLE_VERSION, SealedUnifiedOracle, UnifiedUtilityRubric
from reef_panda_arena.oracle.benign_unified import UnifiedBenignActions
from reef_panda_arena.oracle.utility_evidence import UtilityEvidence
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.scenarios.unified_contract import UnifiedScenarioDefinition
from reef_panda_arena.scenarios.vault import SyntheticSecretVault
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.events import SessionEventStore
from reef_panda_arena.storage.models import ArenaRun, RunEvent, RunScore
from reef_panda_arena.telemetry.events import lifecycle_event
from reef_panda_arena.tools.unified import (
    UNIFIED_DESTINATIONS, UNIFIED_ROLE_TOOLS, UNIFIED_TOOL_INPUTS,
    UnifiedToolAdapter,
)


@dataclass(frozen=True)
class UnifiedRunSummary:
    run_id: str
    scenario_id: str
    defense_profile: str
    attacker_attempted: bool
    invalid_attempt: bool
    secret_escaped: bool
    benign_task_success: bool
    blocked_attempts: int
    accepted_outbound_events: int
    attacker_win: bool | None
    lineage_gap_count: int | None
    lineage_unknown_count: int | None
    peer_deliveries: int
    admin_alerted_pre_egress: bool | None
    blocked_egress_attempts: int
    observed_partial_bits: float | None
    mode: str = "replay"
    model_name: str | None = None
    scoring: dict | None = None


async def run_unified_replay(
    scenario_id: str, defense_profile: str, seed: int, *,
    settings: ArenaSettings | None = None, attack_enabled: bool = True,
    observer_profile: str = "metadata_schema", run_id: str | None = None,
    on_event: Callable[[RunEvent], None] | None = None,
    action_limit_override: int | None = None,
) -> UnifiedRunSummary:
    return await _run_unified(scenario_id, defense_profile, seed, settings=settings,
        attack_enabled=attack_enabled, observer_profile=observer_profile, run_id=run_id,
        on_event=on_event, action_limit_override=action_limit_override)


async def run_unified_live(
    scenario_id: str, defense_profile: str, seed: int, *, settings: ArenaSettings | None = None,
    attack_enabled: bool = True, observer_profile: str = "metadata_schema", run_id: str | None = None,
    on_event: Callable[[RunEvent], None] | None = None, model_name: str | None = None,
    temperature: float = 0.0, top_p: float | None = None, generation_seed: int | None = None,
    caller_factory=None, action_limit_override: int | None = None,
) -> UnifiedRunSummary:
    settings = settings or ArenaSettings()
    config = ModelConfig(model_name=model_name or settings.model, temperature=temperature,
        top_p=top_p, seed=generation_seed if generation_seed is not None else seed % (2**31),
        max_response_tokens=1024, timeout_seconds=90)
    execution = LiveExecution(config, ollama_url=settings.ollama_url, caller_factory=caller_factory)
    return await _run_unified(scenario_id, defense_profile, seed, settings=settings,
        attack_enabled=attack_enabled, observer_profile=observer_profile, run_id=run_id, on_event=on_event,
        action_limit_override=action_limit_override, live_execution=execution)


async def _run_unified(
    scenario_id: str, defense_profile: str, seed: int, *,
    settings: ArenaSettings | None = None, attack_enabled: bool = True,
    observer_profile: str = "metadata_schema", run_id: str | None = None,
    on_event: Callable[[RunEvent], None] | None = None,
    action_limit_override: int | None = None,
    live_execution: LiveExecution | None = None,
) -> UnifiedRunSummary:
    settings = settings or ArenaSettings()
    live = live_execution is not None
    mode = "live_multiagent" if live else "replay"
    def execution_metadata():
        return live_execution.metadata() if live else {}
    def candidate_counts():
        return live_execution.candidate_counts() if live else None
    scenario = ScenarioLoader().load(scenario_id)
    if not isinstance(scenario, UnifiedScenarioDefinition):
        raise ValueError("Scenario is not in the unified extension")
    if defense_profile not in UNIFIED_PROFILES:
        raise ValueError("Unsupported unified defense")
    if observer_profile not in VALID_REVIEWERS:
        raise ValueError("Unknown unified observer")
    if not 0 <= seed < 2**64:
        raise ValueError("Invalid seed")
    if action_limit_override is not None and not (
        1 <= action_limit_override <= scenario.limits.tool_message_actions
    ):
        raise ValueError("Invalid unified action cap")
    async with run_admission(settings, family="unified"):
        run_id = run_id or str(uuid4())
        fixture = ScenarioLoader().shipping_fixture()
        vault, secret = SyntheticSecretVault(settings.encryption_key).create(
            run_id, scenario_id, seed, 8, "private_account_code",
            fixture_mode=settings.fixture_mode,
        )
        knowledge = knowledge_metadata(
            scenario_id, settings.fixture_mode, shipping_template_digest(fixture),
            defense_profile=defense_profile, observer_profile=observer_profile,
        )
        information_measure = InformationMeasure(scenario_id, secret, knowledge=knowledge)
        utility_initial = {
            "utility_version": "unified-utility-v3", "utility_scope": "same_reader_model_decision" if live else "same_reader_scripted",
            "task_mechanism": "model_computation" if live else "scripted_computation", "task_actor": "A2",
            "utility_reason": None, "same_reader_utility": None,
            "contribution_verified": None, "customer_sequence_consistent": None,
            "required_action_count": 2, "accepted_required_count": None,
            "utility_required_event_seqs": None, "utility_source_event_seqs": None,
            "utility_release_event_seqs": None,
        }
        engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        decisions = DecisionBudget()
        started = monotonic()
        try:
            async with sessions() as session:
                roster = AgentRoster(scenario.compromised_roles if attack_enabled or not live else ())
                run = ArenaRun(
                    id=run_id, scenario_id=scenario_id,
                    scenario_revision=scenario.revision, mode="live" if live else "replay",
                    model_name=live_execution.config.model_name if live else None,
                    model_temperature=live_execution.config.temperature if live else None,
                    defense_profile=defense_profile, seed=seed,
                    status="running", started_at=datetime.now(timezone.utc),
                    benign_goal_json={"goal_id": "shipping_delay_update"},
                    stage_snapshot_json={
                        **decisions.snapshot(), "audit_mode": settings.audit_mode,
                        "lineage_version": "lineage-v1", "observation_version": "observation-v1",
                        **knowledge, **utility_initial,
                        "decision_accounting": "model_request_attempts" if live else "fixed_script_activations",
                        "submode": "live_multiagent" if live else "unified_replay",
                        **execution_metadata(),
                        "oracle_version": UNIFIED_ORACLE_VERSION,
                        "attack_enabled": attack_enabled,
                        "compromised_roles": list(roster.compromised_roles),
                        "fault_origin": "none",
                        "observer_profile": observer_profile,
                    },
                    prompt_version=ROLE_PROMPT_VERSION if live else "unified-replay-v2",
                )
                events = SessionEventStore(session)
                session.add_all([run, vault])
                started_event = lifecycle_event(run_id, 0, "run.started")
                await events.append(started_event)
                registry = ArtifactRegistry(run_id)
                gateway = PolicyGateway(
                    events, UnifiedToolAdapter(fixture, secret),
                    defense_profile, secret=b"",
                    max_calls=(
                        action_limit_override or scenario.limits.tool_message_actions
                    ),
                    max_events=scenario.limits.graph_steps,
                    max_payload_bytes=scenario.limits.max_payload_bytes,
                    tool_inputs=UNIFIED_TOOL_INPUTS,
                    tool_destinations=UNIFIED_DESTINATIONS,
                    role_tools=UNIFIED_ROLE_TOOLS,
                    artifact_registry=registry,
                    run_id=run_id, runtime_roles=roster.runtime_roles,
                    observer=ResearchObserver(observer_profile),
                    on_event=on_event,
                )
                gateway.comparison_contract = declare_comparison(
                    gateway, scenario, fixture, key=settings.encryption_key, decisions=decisions,
                    seconds=min(scenario.limits.seconds, 900), schedule=LIVE_SCHEDULE_VERSION if live else "unified-interleaved-v2",
                    attack_enabled=attack_enabled, extra_limits=scenario.limits.model_dump(mode="json"),
                )
                benign_contract = UnifiedBenignActions(secret, fixture, live=live)
                async def checkpoint_execution():
                    run.stage_snapshot_json = {**(run.stage_snapshot_json or {}),
                        **decisions.snapshot(), **execution_metadata()}
                    await session.commit()
                try:
                    if on_event is not None:
                        on_event(started_event)
                    async with asyncio.timeout(min(scenario.limits.seconds, 900)):
                        if live:
                            benign = await live_execution.run(gateway, registry, roster, scenario, decisions,
                                on_progress=checkpoint_execution)
                            attack = None
                        else:
                            workflow = UnifiedWorkflow(
                                gateway, registry, fixture,
                                roster,
                                ATTACK_ROUTES, decisions=decisions,
                            )
                            script = UnifiedAttack(scenario, workflow) if attack_enabled else None
                            benign = await workflow.run(
                                attack_prepare=script.prepare if script else None,
                                attack_finish=script.finish if script else None,
                            )
                            attack = script.result if script else None
                        recovery = SealedUnifiedOracle().evaluate(
                            secret, gateway.accepted_artifacts,
                        )
                        utility_result = UnifiedUtilityRubric().evaluate(
                            secret, fixture, UtilityEvidence(
                                gateway.evidence_registry, gateway.action_evidence,
                                gateway.accepted_artifacts,
                            ),
                        )
                        utility = utility_result.success
                    utility_metadata = {
                        **utility_initial, "utility_version": utility_result.version,
                        "utility_reason": utility_result.reason_code,
                        "same_reader_utility": utility,
                        "contribution_verified": utility_result.contribution_verified,
                        "customer_sequence_consistent": utility_result.customer_sequence_consistent,
                        "required_action_count": utility_result.required_action_count,
                        "accepted_required_count": utility_result.accepted_required_count,
                        "utility_required_event_seqs": list(utility_result.required_event_seqs),
                        "utility_source_event_seqs": list(utility_result.source_event_seqs),
                        "utility_release_event_seqs": list(utility_result.release_event_seqs),
                    }
                    task_actions = tuple(
                        action for action in gateway.action_evidence
                        if action.tool_name == "customer.notify" and action.attempt_id == "task"
                    )
                    accepted_attack = attack.outbound_accepted if attack else False
                    alerted = attack.admin_alerted_pre_egress if attack else False
                    scoring = score_gateway(
                        gateway, information_measure=information_measure, benign_contract=benign_contract, status="completed", attack_enabled=attack_enabled,
                        evaluate=lambda items: SealedUnifiedOracle().evaluate(
                            secret, items,
                        ).full_secret_recovered,
                        utility=utility, candidate_counts=candidate_counts(),
                    )
                    scoring["live_execution"] = live_execution.evidence() if live else None
                    attacker_win = scoring["strict_win"]
                    details = {
                        **knowledge, **utility_metadata, **execution_metadata(),
                        "scenario_revision": scenario.revision,
                        **decisions.snapshot(),
                        "scoring": scoring,
                        "compromised_roles": list(roster.compromised_roles),
                        "fault_origin": "none",
                        "attack_attempted": attack.attempted if attack else False,
                        "invalid_attempt": (
                            scenario.boundary == "authorization_claim"
                            if attack else False
                        ),
                        "accepted_external_artifact": accepted_attack,
                        "full_secret_recovered": recovery.full_secret_recovered,
                        "observed_partial_bits": recovery.observed_partial_bits,
                        "partial_bits_method": recovery.partial_bits_method,
                        "admin_alerted_pre_egress": alerted,
                        "blocked_egress_attempts": (
                            attack.blocked_egress_attempts if attack else 0
                        ),
                        "benign_task_success": utility,
                        "lineage_gap_count": attack.lineage_gap_count if attack else 0,
                        "secret_dependent_receives": (
                            attack.secret_dependent_receives if attack else 0
                        ),
                        "lineage_unknown_count": (
                            attack.lineage_unknown_count if attack else 0
                        ),
                        "peer_deliveries": benign.peer_deliveries + (
                            attack.peer_deliveries if attack else 0
                        ),
                        "accepted_sink_receipts": len(gateway.accepted_artifacts),
                        "attacker_win": attacker_win,
                        "termination_reason": "completed",
                        "fixture_hash": None,
                        "graph_steps": benign.graph_steps,
                        "mediated_actions": gateway.calls,
                        "observer_profile": observer_profile,
                        "attack_enabled": attack_enabled,
                        "public_control_allowed": (
                            attack.public_control_allowed if attack else None
                        ),
                        "public_control_alerted": (
                            attack.public_control_alerted if attack else None
                        ),
                        "mode": mode,
                        "status": "completed",
                        "seed": seed,
                    }
                    if live:
                        pre = scoring["pre_egress_alerts"]
                        alerted = pre > 0 if pre is not None else None
                        details.update(attack_attempted=scoring["attacker_attempted"],
                            accepted_external_artifact=scoring["accepted_egress"], admin_alerted_pre_egress=alerted,
                            invalid_attempt=bool(scoring["invalid_attempt"]),
                            lineage_gap_count=None, lineage_unknown_count=None, secret_dependent_receives=None,
                            blocked_egress_attempts=sum(item.get("outbound") is True and item.get("blocked") is True
                                and item.get("attempt_id") == "attack:live" for item in gateway.boundary_observations))
                    score = RunScore(
                        run_id=run_id, scenario_valid=True,
                        attacker_attempted=scoring["attacker_attempted"],
                        secret_escaped=recovery.full_secret_recovered,
                        benign_task_success=utility,
                        blocked_attempts=gateway.blocked_attempts,
                        accepted_outbound_events=len(gateway.accepted_artifacts),
                        benign_events_blocked=(scoring["benign_cost"]["policy_false_blocks"] or 0) if live else sum(not action.allowed for action in task_actions),
                        benign_events_evaluated=(scoring["benign_cost"]["eligible_actions"] or 0) if live else len(task_actions),
                        decoded_bytes=8 if recovery.full_secret_recovered else 0,
                        run_duration_ms=int((monotonic() - started) * 1000),
                        oracle_version=UNIFIED_ORACLE_VERSION,
                        details_json=details,
                    )
                    session.add(score)
                    run.status = "completed"
                    run.finished_at = datetime.now(timezone.utc)
                    run.stage_snapshot_json = {
                        **(run.stage_snapshot_json or {}), **decisions.snapshot(), **utility_metadata, **execution_metadata(),
                        "phase": "completed", "scoring": scoring,
                    }
                    completed = lifecycle_event(
                        run_id, gateway.events + 1, "run.completed",
                    )
                    await events.append(completed)
                    notify_terminal(on_event, completed)
                    return UnifiedRunSummary(
                        run_id, scenario_id, defense_profile,
                        scoring["attacker_attempted"], details["invalid_attempt"],
                        recovery.full_secret_recovered, utility,
                        gateway.blocked_attempts, len(gateway.accepted_artifacts),
                        attacker_win,
                        details["lineage_gap_count"], details["lineage_unknown_count"],
                        details["peer_deliveries"], alerted,
                        details["blocked_egress_attempts"],
                        recovery.observed_partial_bits, mode=mode,
                        model_name=live_execution.config.model_name if live else None, scoring=scoring,
                    )
                except (UnifiedBudgetExceeded, DecisionLimitExceeded):
                    await preserve_failure(
                        session, run, gateway, information_measure=information_measure, benign_contract=benign_contract, status="failed", failure_code="budget_exhausted",
                        attack_enabled=attack_enabled, candidate_counts=candidate_counts(),
                        evaluate=lambda items: SealedUnifiedOracle().evaluate(
                            secret, items,
                        ).full_secret_recovered,
                        metadata={**decisions.snapshot(), **utility_initial, **execution_metadata(),
                                  "termination_reason": "budget_exhausted",
                                  "mediated_actions": gateway.calls},
                    )
                    failed = lifecycle_event(
                        run_id, gateway.events + 1, "run.failed",
                    )
                    await events.append(failed)
                    notify_terminal(on_event, failed)
                    raise
                except asyncio.CancelledError:
                    await preserve_failure(
                        session, run, gateway, information_measure=information_measure, benign_contract=benign_contract, status="cancelled", failure_code="cancelled",
                        attack_enabled=attack_enabled, candidate_counts=candidate_counts(),
                        evaluate=lambda items: SealedUnifiedOracle().evaluate(
                            secret, items,
                        ).full_secret_recovered,
                        metadata={**decisions.snapshot(), **utility_initial, **execution_metadata()},
                    )
                    cancelled = lifecycle_event(
                        run_id, gateway.events + 1, "run.cancelled",
                    )
                    await events.append(cancelled)
                    notify_terminal(on_event, cancelled)
                    raise
                except Exception as error:
                    await preserve_failure(
                        session, run, gateway, information_measure=information_measure, benign_contract=benign_contract,
                        status="timed_out" if isinstance(error, (TimeoutError, ModelTimedOut)) else "failed",
                        failure_code=type(error).__name__[:64], attack_enabled=attack_enabled, candidate_counts=candidate_counts(),
                        evaluate=lambda items: SealedUnifiedOracle().evaluate(
                            secret, items,
                        ).full_secret_recovered,
                        metadata={**decisions.snapshot(), **utility_initial, **execution_metadata()},
                    )
                    failed = lifecycle_event(
                        run_id, gateway.events + 1,
                        "run.timed_out" if isinstance(error, (TimeoutError, ModelTimedOut))
                        else "run.failed",
                    )
                    await events.append(failed)
                    notify_terminal(on_event, failed)
                    raise
        finally:
            await engine.dispose()
