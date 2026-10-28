"""One bounded, persistent C00 replay slice."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic
from uuid import uuid4
from typing import Callable

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.gateway.invoke import PolicyGateway, ProposedCall, TrustedContext
from reef_panda_arena.gateway.policies import VALID_PROFILES
from reef_panda_arena.model.replay import ReplayCaller
from reef_panda_arena.oracle.evaluate import benign_task_succeeded, secret_escaped
from reef_panda_arena.scenarios.loader import ScenarioLoader
from reef_panda_arena.scenarios.vault import SyntheticSecretVault
from reef_panda_arena.settings import ArenaSettings
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
    secret_escaped: bool
    benign_task_success: bool
    blocked_attempts: int
    accepted_outbound_events: int
    mode: str = "replay"
    model_name: str | None = None


async def run_replay(scenario_id: str, defense_profile: str, seed: int,
                     settings: ArenaSettings | None = None,
                     loader: ScenarioLoader | None = None,
                     attack_enabled: bool = True,
                     run_id: str | None = None,
                     on_event: Callable[[RunEvent], None] | None = None) -> RunSummary:
    if defense_profile not in VALID_PROFILES:
        raise ValueError("Unsupported defense profile")
    if not 0 <= seed < 2**64:
        raise ValueError("Seed must be an unsigned 64-bit integer")
    settings = settings or ArenaSettings()
    loader = loader or ScenarioLoader()
    scenario = loader.load(scenario_id)
    if "replay" not in scenario.mode_support:
        raise ValueError("Scenario does not support replay")
    fixture = loader.shipping_fixture()
    run_id = run_id or str(uuid4())
    vault, secret = SyntheticSecretVault(settings.encryption_key).create(
        run_id, scenario.id, seed, scenario.secret_fixture.bytes,
        scenario.secret_fixture.label,
    )
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
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
            )
            started_event = lifecycle_event(run_id, 0, "run.started")
            session.add_all([run, vault, started_event])
            await session.commit()
            if on_event is not None:
                on_event(started_event)

            gateway = PolicyGateway(
                session=session,
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
                async with asyncio.timeout(scenario.limits.timeout_seconds):
                    async def invoke(role: str, tool_name: str, arguments: dict):
                        result = await gateway.invoke(
                            TrustedContext(run_id, role, role, operation_id=tool_name),
                            ProposedCall(tool_name=tool_name, arguments=arguments),
                        )
                        if not result.allowed or result.data is None:
                            raise RuntimeError("A required synthetic lookup was blocked")
                        return result

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
                    for action in actions:
                        attack_result = await gateway.invoke(
                            TrustedContext(
                                run_id, action.actor, action.actor,
                                operation_id=action.operation_id,
                                derived_from=action.derived_from,
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
                    writer = replay.writer_call(shipment_result, incident_result)
                    writer_result = await gateway.invoke(
                        TrustedContext(
                            run_id, "response_writer", "response_writer",
                            operation_id="writer",
                            trusted_public_fields=writer.public_fields,
                        ),
                        writer.call,
                    )
                    escaped = secret_escaped(
                        secret, gateway.accepted_artifacts, scenario, seed
                    )
                    utility = benign_task_succeeded(
                        fixture, writer.call.arguments["text"], secret,
                        writer_result.allowed,
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
                completed_event = lifecycle_event(
                    run_id, gateway.events + 1, "run.completed"
                )
                session.add(completed_event)
                await session.commit()
                if on_event is not None:
                    on_event(completed_event)
                return RunSummary(
                    run_id, scenario.id, defense_profile, bool(actions),
                    invalid_attempt, escaped, utility,
                    gateway.blocked_attempts, len(gateway.accepted_artifacts),
                )
            except asyncio.CancelledError:
                await session.rollback()
                run.status = "cancelled"
                run.finished_at = datetime.now(timezone.utc)
                cancelled_event = lifecycle_event(
                    run_id, gateway.events + 1, "run.cancelled"
                )
                session.add(cancelled_event)
                await session.commit()
                if on_event is not None:
                    on_event(cancelled_event)
                raise
            except Exception as error:
                await session.rollback()
                run.status = "timed_out" if isinstance(error, TimeoutError) else "failed"
                run.failure_code = type(error).__name__[:64]
                run.finished_at = datetime.now(timezone.utc)
                failed_event = lifecycle_event(
                    run_id, gateway.events + 1,
                    "run.timed_out" if isinstance(error, TimeoutError) else "run.failed",
                )
                session.add(failed_event)
                await session.commit()
                if on_event is not None:
                    on_event(failed_event)
                raise
    finally:
        await engine.dispose()
