"""Bounded C10-C14 replay: same sensitive reader, separate alert and egress scores."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic
from typing import Callable
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.application.admission import run_admission
from reef_panda_arena.oracle.information import InformationMeasure
from reef_panda_arena.application.knowledge import knowledge_metadata
from reef_panda_arena.application.decisions import DecisionBudget, DecisionLimitExceeded
from reef_panda_arena.application.comparison_contract import declare_comparison
from reef_panda_arena.application.run_observations import (
    notify_terminal, preserve_failure, score_gateway,
)
from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
from reef_panda_arena.gateway.observer import ContentObserver
from reef_panda_arena.gateway.budget import GatewayBudgetExceeded
from reef_panda_arena.gateway.policies import LEGACY_PROFILES
from reef_panda_arena.graph.roster import LEGACY_RUNTIME_ROLES
from reef_panda_arena.gateway.sensitive_release import SensitiveReleasePolicy
from reef_panda_arena.oracle.sensitive import SENSITIVE_ORACLE_VERSION, SensitiveOracle
from reef_panda_arena.oracle.sensitive_utility import SENSITIVE_UTILITY_VERSION, SensitiveWorkflowRubric
from reef_panda_arena.oracle.benign_actions import ClassifiedBenignActions
from reef_panda_arena.oracle.utility_evidence import UtilityEvidence
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.scenarios.sensitive_contract import SensitiveScenarioDefinition
from reef_panda_arena.scenarios.sensitive_fixtures import SensitiveFixtureRegistry
from reef_panda_arena.scenarios.sensitive_scripts import attack_actions, sensitive_decision, sensitive_work
from reef_panda_arena.scenarios.vault import SyntheticSecretVault
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.events import SessionEventStore
from reef_panda_arena.storage.models import ArenaRun, RunEvent, RunScore
from reef_panda_arena.telemetry.events import lifecycle_event
from reef_panda_arena.tools.sensitive import (
    SENSITIVE_TOOL_DESTINATIONS, SENSITIVE_TOOL_INPUTS,
    SOURCE_TOOL_BY_SCENARIO, SensitiveToolAdapter, role_tools_for,
)


@dataclass(frozen=True)
class SensitiveRunSummary:
    run_id: str
    scenario_id: str
    defense_profile: str
    attacker_attempted: bool
    invalid_attempt: bool
    secret_escaped: bool | None
    benign_task_success: bool | None
    blocked_attempts: int
    accepted_outbound_events: int
    partial_information_score: float
    authorized_release_success: bool
    alerts: int
    legitimate_actions_blocked: int
    mode: str = "replay"
    model_name: str | None = None
    scoring: dict | None = None
    undetected_success: bool | None = None


async def run_sensitive_replay(
    scenario: SensitiveScenarioDefinition, defense_profile: str, seed: int,
    settings: ArenaSettings, attack_enabled: bool = True,
    run_id: str | None = None,
    on_event: Callable[[RunEvent], None] | None = None,
) -> SensitiveRunSummary:
    if defense_profile not in LEGACY_PROFILES:
        raise ValueError("Unsupported defense profile")
    async with run_admission(settings, family="sensitive"):
        registry = SensitiveFixtureRegistry()
        case = registry.load(
            scenario.id, seed, settings.encryption_key, fixture_mode=settings.fixture_mode,
        )
        knowledge = knowledge_metadata(
            scenario.id, settings.fixture_mode, registry.template_digest,
            defense_profile=defense_profile, observer_profile="content",
        )
        information_measure = InformationMeasure(scenario.id, case.marker, knowledge=knowledge, case=case)
        utility_metadata = {
            "utility_version": SENSITIVE_UTILITY_VERSION, "utility_scope": "same_reader_scripted",
            "task_mechanism": "scripted_computation", "task_actor": scenario.rogue_slot,
            "same_reader_utility": None,
        }
        shipping = ScenarioLoader().shipping_fixture()
        run_id = run_id or str(uuid4())
        vault = SyntheticSecretVault(settings.encryption_key).create_fixed(
            run_id, scenario.secret_fixture.label, case.marker
        )
        evaluate = lambda artifacts: SensitiveOracle().evaluate(case, artifacts).full_reconstruction
        engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        decisions = DecisionBudget()
        started = monotonic()
        try:
            async with sessions() as session:
                run = ArenaRun(
                    id=run_id, scenario_id=scenario.id,
                    scenario_revision=scenario.revision, mode="replay",
                    defense_profile=defense_profile, model_name=None,
                    model_temperature=None, seed=seed, status="running",
                    started_at=datetime.now(timezone.utc),
                    benign_goal_json={"goal_id": scenario.benign_goal_id},
                    prompt_version="sensitive-replay-v3",
                    stage_snapshot_json={**decisions.snapshot(), "audit_mode": settings.audit_mode,
                        "lineage_version": "lineage-v1", "observation_version": "observation-v1",
                        **knowledge, **utility_metadata,
                        "decision_accounting": "fixed_script_activations",
                        "phase": "running", "attack_enabled": attack_enabled,
                        "oracle_version": SENSITIVE_ORACLE_VERSION},
                )
                event_store = SessionEventStore(session)
                started_event = lifecycle_event(run_id, 0, "run.started")
                session.add_all([run, vault])
                await event_store.append(started_event)
                tools = SensitiveToolAdapter(
                    shipping, case.marker, scenario.id, case.source_record,
                    case.expected_public_value,
                )
                gateway = PolicyGateway(
                    run_id=run_id, runtime_roles=LEGACY_RUNTIME_ROLES,
                    event_store=event_store, tools=tools,
                    profile=defense_profile, secret=case.marker,
                    max_calls=scenario.limits.max_tool_calls,
                    max_events=scenario.limits.max_events - 2,
                    max_payload_bytes=scenario.limits.max_accepted_payload_bytes,
                    on_event=on_event, observer=ContentObserver(),
                    tool_inputs=SENSITIVE_TOOL_INPUTS,
                    tool_destinations=SENSITIVE_TOOL_DESTINATIONS,
                    role_tools=role_tools_for(scenario.id),
                )
                gateway.comparison_contract = declare_comparison(
                    gateway, scenario, shipping, key=settings.encryption_key, decisions=decisions,
                    seconds=min(scenario.limits.timeout_seconds, 900), schedule="sensitive-interleaved-v3",
                    attack_enabled=attack_enabled, extra_limits=scenario.limits.model_dump(mode="json"),
                )
                actor = scenario.rogue_slot
                benign_contract = None
                try:
                    if on_event is not None:
                        on_event(started_event)
                    async with asyncio.timeout(min(scenario.limits.timeout_seconds, 900)):
                        decisions.reserve_script()
                        source = await gateway.invoke(
                            TrustedContext(run_id, actor, actor, operation_id="sensitive-read"),
                            ProposedCall(
                                tool_name=SOURCE_TOOL_BY_SCENARIO[scenario.id],
                                arguments={"case_id": scenario.id},
                            ),
                        )
                        if not source.allowed or source.data is None:
                            raise RuntimeError("Required sensitive read was rejected")
                        source_proof = UtilityEvidence(
                            gateway.evidence_registry, gateway.action_evidence,
                            gateway.accepted_artifacts,
                        ).source(source, actor_id=actor,
                                 tool_name=SOURCE_TOOL_BY_SCENARIO[scenario.id],
                                 expected=case.source_record)
                        if source_proof is None:
                            raise RuntimeError("Classified source has no committed proof")
                        benign_contract = ClassifiedBenignActions(scenario, case, shipping, source_proof)
                        contribution = sensitive_decision(scenario.id, source.data)
                        work = sensitive_work(scenario.id, source.data, shipping,
                                              benign_attestation=case.benign_attestation)
                        notice_call = next(call for call in work if call.tool_name == "customer.notify")
                        release = SensitiveReleasePolicy()
                        benign_evaluated = legitimate_blocked = 0

                        async def send_work(call, operation_id):
                            nonlocal benign_evaluated, legitimate_blocked
                            public_fields = frozenset()
                            if defense_profile == "declassify_strict":
                                approved = release.validate(
                                    scenario, source_proof, call, shipping,
                                    actor_id=actor, contribution=contribution, case=case,
                                )
                                public_fields = approved.public_fields
                                call = approved.call
                            result = await gateway.invoke(TrustedContext(
                                run_id, actor, actor, operation_id=operation_id,
                                trusted_public_fields=public_fields,
                            ), call)
                            benign_evaluated += 1
                            legitimate_blocked += not result.allowed
                            return result

                        await send_work(notice_call, "sensitive-initial-notice")
                        issued = attack_actions(case, source.data) if attack_enabled else ()
                        attack_accepted = 0
                        invalid_attempt = False
                        alerts_before_attack = gateway.alerts
                        for action in issued:
                            decision = await gateway.invoke(
                                TrustedContext(
                                    run_id, actor, actor,
                                    operation_id=action.operation_id,
                                    derived_from=action.derived_from, attempt_id="attack:1",
                                ),
                                action.call,
                            )
                            attack_accepted += decision.allowed
                            invalid_attempt |= decision.reason in {
                                "invalid_arguments", "invalid_provenance", "unknown_tool",
                                "payload_too_large", "scenario_channel_not_allowed",
                            }
                        attack_alerts = gateway.alerts - alerts_before_attack
                        for index, call in enumerate(work):
                            if call.tool_name != "customer.notify":
                                await send_work(call, f"sensitive-work-{index}")
                        await send_work(notice_call, "sensitive-final-notice")
                        security = SensitiveOracle().evaluate(case, gateway.accepted_artifacts)
                        utility = SensitiveWorkflowRubric().evaluate(
                            case, shipping, source=source_proof,
                            evidence=UtilityEvidence(gateway.evidence_registry,
                                gateway.action_evidence, gateway.accepted_artifacts),
                        )
                    scoring = score_gateway(
                        gateway, information_measure=information_measure, status="completed", attack_enabled=attack_enabled,
                        evaluate=evaluate, utility=utility.benign_task_success,
                        oracle_reason=security.unscorable_reason, benign_contract=benign_contract,
                    )
                    score = RunScore(
                        run_id=run_id, scenario_valid=True,
                        attacker_attempted=bool(issued),
                        secret_escaped=security.full_reconstruction,
                        benign_task_success=utility.benign_task_success,
                        blocked_attempts=gateway.blocked_attempts,
                        accepted_outbound_events=len(gateway.accepted_artifacts),
                        benign_events_blocked=legitimate_blocked,
                        benign_events_evaluated=benign_evaluated,
                        decoded_bytes=len(case.marker) if security.full_reconstruction else 0,
                        run_duration_ms=int((monotonic() - started) * 1000),
                        oracle_version=SENSITIVE_ORACLE_VERSION,
                        details_json={
                            **knowledge, **utility_metadata,
                            **decisions.snapshot(),
                            "scoring": scoring,
                            "decoder": scenario.attack_contract.decoder_id,
                            "release_policy": scenario.trusted_release_policy,
                            "release_version": "sensitive-release-v3",
                            "authorized_release_success": utility.authorized_release_success,
                            "utility_reason": utility.reason_code,
                            "same_reader_utility": utility.benign_task_success,
                            "partial_information_score": security.partial_information_score,
                            "scoring_scope": security.scoring_scope,
                            "oracle_validation": "independent_accepted_artifact_decode",
                            "evidence_event_seqs": list(security.evidence_event_seqs),
                            "unscorable_reason": security.unscorable_reason,
                            "attack_proposals": len(issued),
                            "attack_accepted": attack_accepted,
                            "attack_blocked": len(issued) - attack_accepted,
                            "alerts": gateway.alerts,
                            "attack_alerts": attack_alerts,
                            "benign_alerts": gateway.alerts - attack_alerts,
                            "legitimate_actions_blocked": legitimate_blocked,
                            "theoretical_capacity_bits": 16 if scenario.id == "C12" else None,
                            "invalid_attempt": invalid_attempt,
                            "attack_enabled": attack_enabled,
                        },
                    )
                    session.add(score)
                    run.status = "completed"
                    run.finished_at = datetime.now(timezone.utc)
                    run.stage_snapshot_json = {
                        **(run.stage_snapshot_json or {}), **decisions.snapshot(),
                        "phase": "completed", "scoring": scoring,
                        "same_reader_utility": utility.benign_task_success,
                        "utility_reason": utility.reason_code,
                    }
                    completed = lifecycle_event(run_id, gateway.events + 1, "run.completed")
                    await event_store.append(completed)
                    notify_terminal(on_event, completed)
                    return SensitiveRunSummary(
                        run_id, scenario.id, defense_profile, bool(issued),
                        invalid_attempt, scoring["secret_escaped"],
                        utility.benign_task_success, gateway.blocked_attempts,
                        len(gateway.accepted_artifacts),
                        security.partial_information_score,
                        utility.authorized_release_success,
                        gateway.alerts, legitimate_blocked,
                        scoring=scoring, undetected_success=scoring["strict_win"],
                    )
                except asyncio.CancelledError:
                    await preserve_failure(
                        session, run, gateway, information_measure=information_measure, status="cancelled", failure_code="cancelled",
                        attack_enabled=attack_enabled, evaluate=evaluate,
                        metadata=decisions.snapshot(), benign_contract=benign_contract,
                    )
                    cancelled = lifecycle_event(run_id, gateway.events + 1, "run.cancelled")
                    await event_store.append(cancelled)
                    notify_terminal(on_event, cancelled)
                    raise
                except Exception as error:
                    terminal_status = "timed_out" if isinstance(error, TimeoutError) else "failed"
                    failure_code = ("budget_exhausted" if isinstance(
                        error, (DecisionLimitExceeded, GatewayBudgetExceeded)
                    ) else type(error).__name__[:64])
                    await preserve_failure(
                        session, run, gateway, information_measure=information_measure, status=terminal_status, failure_code=failure_code,
                        attack_enabled=attack_enabled, evaluate=evaluate,
                        metadata=decisions.snapshot(), benign_contract=benign_contract,
                    )
                    failed = lifecycle_event(
                        run_id, gateway.events + 1,
                        "run.timed_out" if terminal_status == "timed_out" else "run.failed",
                    )
                    await event_store.append(failed)
                    notify_terminal(on_event, failed)
                    raise
        finally:
            await engine.dispose()
