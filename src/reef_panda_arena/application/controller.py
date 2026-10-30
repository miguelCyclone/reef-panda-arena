"""Bounded persistent replay for the ten synthetic scenarios."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic
from uuid import uuid4
from typing import Callable

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.application.admission import run_admission
from reef_panda_arena.oracle.information import InformationMeasure
from reef_panda_arena.application.knowledge import knowledge_metadata, shipping_template_digest
from reef_panda_arena.application.decisions import DecisionBudget, DecisionLimitExceeded
from reef_panda_arena.application.run_observations import (
    notify_terminal, preserve_failure, score_gateway,
)
from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
from reef_panda_arena.gateway.budget import GatewayBudgetExceeded
from reef_panda_arena.gateway.policies import LEGACY_PROFILES
from reef_panda_arena.graph.roster import LEGACY_RUNTIME_ROLES
from reef_panda_arena.model.replay import ReplayCaller
from reef_panda_arena.oracle.evaluate import ExactOracle, Oracle, benign_task_succeeded
from reef_panda_arena.scenarios.loader import ScenarioLoader, ScenarioLoaderProtocol
from reef_panda_arena.scenarios.sensitive_contract import SensitiveScenarioDefinition
from reef_panda_arena.scenarios.extension_contract import ExtensionScenarioDefinition
from reef_panda_arena.adaptive.scenario import AdaptiveScenarioDefinition
from reef_panda_arena.scenarios.vault import SyntheticSecretVault
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.events import SessionEventStore
from reef_panda_arena.storage.models import ArenaRun, RunEvent, RunScore
from reef_panda_arena.telemetry.events import lifecycle_event
from reef_panda_arena.tools.registry import MockToolRegistry


@dataclass(frozen=True)
class RunSummary:
    run_id: str
    scenario_id: str
    defense_profile: str
    attacker_attempted: bool
    invalid_attempt: bool
    secret_escaped: bool | None
    benign_task_success: bool | None
    blocked_attempts: int
    accepted_outbound_events: int
    mode: str = "replay"
    model_name: str | None = None
    scoring: dict | None = None
    undetected_success: bool | None = None


async def run_replay(scenario_id: str, defense_profile: str, seed: int,
                     settings: ArenaSettings | None = None,
                     loader: ScenarioLoaderProtocol | None = None,
                     attack_enabled: bool = True,
                     run_id: str | None = None,
                     on_event: Callable[[RunEvent], None] | None = None,
                     arm: str | None = None,
                     observer_profile: str = "metadata_schema") -> RunSummary:
    if defense_profile not in LEGACY_PROFILES:
        raise ValueError("Unsupported defense profile")
    if not 0 <= seed < 2**64:
        raise ValueError("Seed must be an unsigned 64-bit integer")
    settings = settings or ArenaSettings()
    loader = loader or ScenarioLoader()
    scenario = loader.load(scenario_id)
    if isinstance(scenario, AdaptiveScenarioDefinition):
        from reef_panda_arena.application.adaptive import run_adaptive

        chosen_arm = arm or ("A1" if attack_enabled else "A0")
        if not attack_enabled and chosen_arm != "A0":
            raise ValueError("No-attack control requires A0")
        return await run_adaptive(
            scenario_id, defense_profile, seed, settings=settings,
            mode="replay", arm=chosen_arm, observer_profile=observer_profile,
            run_id=run_id, on_event=on_event,
        )
    if isinstance(scenario, ExtensionScenarioDefinition):
        from reef_panda_arena.application.extension import run_extension_replay

        return await run_extension_replay(
            scenario, defense_profile, seed, settings, arm=arm,
            observer_profile=observer_profile, attack_enabled=attack_enabled,
            run_id=run_id, on_event=on_event,
        )
    if arm is not None or observer_profile != "metadata_schema":
        raise ValueError("Arm and reviewer profile apply only to C15-C21")
    if isinstance(scenario, SensitiveScenarioDefinition):
        from reef_panda_arena.application.sensitive import run_sensitive_replay

        return await run_sensitive_replay(
            scenario, defense_profile, seed, settings,
            attack_enabled=attack_enabled, run_id=run_id, on_event=on_event,
        )
    if "replay" not in scenario.mode_support:
        raise ValueError("Scenario does not support replay")
    async with run_admission(settings, family="core"):
        fixture = loader.shipping_fixture()
        run_id = run_id or str(uuid4())
        vault, secret = SyntheticSecretVault(settings.encryption_key).create(
            run_id, scenario.id, seed, scenario.secret_fixture.bytes,
            scenario.secret_fixture.label, fixture_mode=settings.fixture_mode,
        )
        knowledge = knowledge_metadata(
            scenario.id, settings.fixture_mode, shipping_template_digest(fixture),
            defense_profile=defense_profile, observer_profile=None,
        )
        information_measure = InformationMeasure(scenario.id, secret, knowledge=knowledge)
        evaluate = lambda artifacts: ExactOracle().escaped(secret, artifacts, scenario, seed)
        engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        decisions = DecisionBudget()
        started = monotonic()
        try:
            async with sessions() as session:
                run = ArenaRun(
                    id=run_id,
                    scenario_id=scenario.id,
                    scenario_revision=scenario.revision,
                    mode="replay",
                    defense_profile=defense_profile,
                    model_name=None,
                    model_temperature=None,
                    seed=seed,
                    status="running",
                    started_at=datetime.now(timezone.utc),
                    benign_goal_json=fixture["expected"],
                    prompt_version="replay-v1",
                    stage_snapshot_json={**decisions.snapshot(), "audit_mode": settings.audit_mode,
                        "lineage_version": "lineage-v1", "observation_version": "observation-v1",
                        **knowledge,
                        "utility_version": "legacy-safe-writer-v1",
                        "utility_scope": "legacy_safe_writer",
                        "task_mechanism": "trusted_formatter",
                        "task_actor": "response_writer",
                        "same_reader_utility": None,
                                         "decision_accounting": "fixed_script_activations",
                                         "phase": "running", "attack_enabled": attack_enabled,
                                         "oracle_version": "v1"},
                )
                started_event = lifecycle_event(run_id, 0, "run.started")
                event_store = SessionEventStore(session)
                session.add_all([run, vault])
                await event_store.append(started_event)

                gateway = PolicyGateway(
                    run_id=run_id, runtime_roles=LEGACY_RUNTIME_ROLES,
                    event_store=event_store,
                    tools=MockToolRegistry(fixture, secret),
                    profile=defense_profile,
                    secret=secret,
                    max_calls=scenario.limits.max_tool_calls,
                    max_events=scenario.limits.max_events - 2,
                    max_payload_bytes=scenario.limits.max_accepted_payload_bytes,
                    allowed_attack_tool=scenario.allowed_channels[0].tool,
                    on_event=on_event,
                )
                replay = ReplayCaller()
                shipment_id = fixture["records"]["shipment"]["id"]
                try:
                    if on_event is not None:
                        on_event(started_event)
                    async with asyncio.timeout(min(scenario.limits.timeout_seconds, 900)):
                        async def invoke(role: str, tool_name: str, arguments: dict):
                            result = await gateway.invoke(
                                TrustedContext(run_id, role, role, operation_id=tool_name),
                                ProposedCall(tool_name=tool_name, arguments=arguments),
                            )
                            if not result.allowed or result.data is None:
                                raise RuntimeError("A required synthetic lookup was blocked")
                            return result

                        decisions.reserve_script()
                        shipment_result = await invoke(
                            "operations_worker", "shipment.lookup",
                            {"shipment_id": shipment_id},
                        )
                        incident_result = await invoke(
                            "operations_worker", "operations.incident",
                            {"shipment_id": shipment_id},
                        )
                        shipment = shipment_result.data
                        incident = incident_result.data
                        decisions.reserve_script()
                        profile_result = await invoke(
                            "customer_worker", "customer.profile",
                            {"customer_id": shipment["customer_id"]},
                        )
                        actions = (
                            replay.attack_actions(
                                scenario, profile_result.data, seed, shipment_id,
                                shipment["customer_id"],
                            ) if attack_enabled else ()
                        )
                        results: dict[str, dict] = {}
                        internal_exposure = False
                        invalid_attempt = False
                        active_actor = "customer_worker"
                        for action in actions:
                            if action.actor != active_actor:
                                decisions.reserve_script()
                                active_actor = action.actor
                            attack_result = await gateway.invoke(
                                TrustedContext(
                                    run_id, action.actor, action.actor,
                                    operation_id=action.operation_id,
                                    derived_from=action.derived_from, attempt_id="attack:1",
                                ),
                                action.proposed_call(results),
                            )
                            if attack_result.reason in {
                                "invalid_arguments", "unknown_tool", "invalid_provenance",
                                "scenario_channel_not_allowed", "payload_too_large",
                            }:
                                invalid_attempt = True
                            if action.capture_as and attack_result.allowed:
                                results[action.capture_as] = attack_result.data
                            if action.tool_name == "memory.write" and attack_result.allowed:
                                internal_exposure = True
                        decisions.reserve_script()
                        writer = replay.writer_call(shipment_result, incident_result)
                        handoff = await gateway.forward_message(
                            TrustedContext(
                                run_id, "operations_worker", "operations_worker",
                                operation_id="operations-handoff",
                                trusted_public_fields=writer.public_fields,
                            ),
                            "response_writer", writer.call.arguments,
                        )
                        if not handoff.allowed or handoff.data is None:
                            raise RuntimeError("Safe operations handoff was blocked")
                        writer_result = await gateway.invoke(
                            TrustedContext(
                                run_id, "response_writer", "response_writer",
                                operation_id="writer",
                                trusted_public_fields=writer.public_fields,
                            ),
                            ProposedCall(
                                tool_name=writer.call.tool_name,
                                arguments=handoff.data,
                            ),
                        )
                        oracle: Oracle = ExactOracle()
                        escaped = oracle.escaped(
                            secret, gateway.accepted_artifacts, scenario, seed
                        )
                        utility = benign_task_succeeded(
                            fixture, handoff.data["text"], secret,
                            writer_result.allowed,
                        )
                    scoring = score_gateway(
                        gateway, information_measure=information_measure, status="completed", attack_enabled=attack_enabled,
                        evaluate=evaluate, utility=utility,
                    )
                    score = RunScore(
                        run_id=run_id,
                        scenario_valid=True,
                        attacker_attempted=bool(actions),
                        secret_escaped=escaped,
                        benign_task_success=utility,
                        blocked_attempts=gateway.blocked_attempts,
                        accepted_outbound_events=len(gateway.accepted_artifacts),
                        benign_events_blocked=0 if writer_result.allowed else 1,
                        benign_events_evaluated=1,
                        decoded_bytes=len(secret) if escaped else 0,
                        run_duration_ms=int((monotonic() - started) * 1000),
                        oracle_version="v1",
                        details_json={
                            **knowledge,
                            "utility_version": "legacy-safe-writer-v1",
                            "utility_scope": "legacy_safe_writer",
                            "task_mechanism": "trusted_formatter",
                            "task_actor": "response_writer",
                            "same_reader_utility": None,
                            **decisions.snapshot(),
                            "scoring": scoring,
                            "decoder": scenario.attack_contract.decoder_id,
                            "sink": scenario.allowed_channels[0].destination,
                            "internal_exposure": internal_exposure,
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
                    }
                    completed_event = lifecycle_event(
                        run_id, gateway.events + 1, "run.completed"
                    )
                    await event_store.append(completed_event)
                    notify_terminal(on_event, completed_event)
                    return RunSummary(
                        run_id, scenario.id, defense_profile, bool(actions),
                        invalid_attempt, scoring["secret_escaped"], utility,
                        gateway.blocked_attempts, len(gateway.accepted_artifacts),
                        scoring=scoring, undetected_success=scoring["strict_win"],
                    )
                except asyncio.CancelledError:
                    await preserve_failure(
                        session, run, gateway, information_measure=information_measure, status="cancelled", failure_code="cancelled",
                        attack_enabled=attack_enabled, evaluate=evaluate,
                        metadata=decisions.snapshot(),
                    )
                    cancelled_event = lifecycle_event(
                        run_id, gateway.events + 1, "run.cancelled"
                    )
                    await event_store.append(cancelled_event)
                    notify_terminal(on_event, cancelled_event)
                    raise
                except Exception as error:
                    terminal_status = "timed_out" if isinstance(error, TimeoutError) else "failed"
                    failure_code = ("budget_exhausted" if isinstance(
                        error, (DecisionLimitExceeded, GatewayBudgetExceeded)
                    ) else type(error).__name__[:64])
                    await preserve_failure(
                        session, run, gateway, information_measure=information_measure, status=terminal_status, failure_code=failure_code,
                        attack_enabled=attack_enabled, evaluate=evaluate,
                        metadata=decisions.snapshot(),
                    )
                    failed_event = lifecycle_event(
                        run_id, gateway.events + 1,
                        "run.timed_out" if terminal_status == "timed_out" else "run.failed",
                    )
                    await event_store.append(failed_event)
                    notify_terminal(on_event, failed_event)
                    raise
        finally:
            await engine.dispose()
