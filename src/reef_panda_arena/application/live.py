"""Bounded local Ollama/LangGraph run lifecycle for the C00 live challenge."""

import asyncio
from datetime import datetime, timezone
from decimal import Decimal
from time import monotonic
from uuid import uuid4
from typing import Callable

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.agents.prompts import PROMPT_VERSION
from reef_panda_arena.application.admission import run_admission
from reef_panda_arena.oracle.information import InformationMeasure
from reef_panda_arena.application.knowledge import knowledge_metadata, shipping_template_digest
from reef_panda_arena.application.decisions import DecisionBudget, DecisionLimitExceeded
from reef_panda_arena.application.budgets import ModelBudget
from reef_panda_arena.application.controller import RunSummary
from reef_panda_arena.application.run_observations import (
    notify_terminal, preserve_failure, score_gateway,
)
from reef_panda_arena.gateway.invoke import PolicyGateway
from reef_panda_arena.gateway.budget import GatewayBudgetExceeded
from reef_panda_arena.gateway.policies import LEGACY_PROFILES
from reef_panda_arena.graph.roster import LEGACY_RUNTIME_ROLES
from reef_panda_arena.graph.nodes import LiveNodes
from reef_panda_arena.graph.topology import build_live_graph
from reef_panda_arena.model.ollama import ModelTimedOut, ModelUnavailable, OllamaCaller
from reef_panda_arena.model.protocol import ModelConfig
from reef_panda_arena.oracle.evaluate import ExactOracle, Oracle, benign_task_succeeded
from reef_panda_arena.scenarios.loader import ScenarioLoader, ScenarioLoaderProtocol
from reef_panda_arena.scenarios.vault import SyntheticSecretVault
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.events import SessionEventStore
from reef_panda_arena.storage.models import ArenaRun, RunEvent, RunScore
from reef_panda_arena.telemetry.events import lifecycle_event
from reef_panda_arena.telemetry.privacy import invoke_graph_privately
from reef_panda_arena.tools.registry import MockToolRegistry


async def run_live(
    scenario_id: str, defense_profile: str, seed: int, attack_enabled: bool,
    model_name: str | None = None, temperature: float = 0.0,
    settings: ArenaSettings | None = None,
    run_id: str | None = None,
    on_event: Callable[[RunEvent], None] | None = None,
) -> RunSummary:
    if scenario_id != "C00":
        raise ValueError("Live mode currently supports C00 only")
    if defense_profile not in LEGACY_PROFILES or not 0 <= seed < 2**64:
        raise ValueError("Invalid live run configuration")
    settings = settings or ArenaSettings()
    loader: ScenarioLoaderProtocol = ScenarioLoader()
    scenario = loader.load(scenario_id)
    config = ModelConfig(
        model_name=model_name or settings.model,
        temperature=temperature,
        max_response_tokens=512,
        timeout_seconds=120,
    )
    async with run_admission(settings, family="live"):
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
        decisions = DecisionBudget(max_turns=12, max_model_calls=12)
        started = monotonic()
        try:
            async with sessions() as session:
                run = ArenaRun(
                    id=run_id, scenario_id=scenario.id,
                    scenario_revision=scenario.revision, mode="live",
                    defense_profile=defense_profile, model_name=config.model_name,
                    model_temperature=Decimal(str(temperature)), seed=seed,
                    status="running", started_at=datetime.now(timezone.utc),
                    benign_goal_json=fixture["expected"],
                    prompt_version=PROMPT_VERSION,
                    stage_snapshot_json={**decisions.snapshot(), "audit_mode": settings.audit_mode,
                        "lineage_version": "lineage-v1", "observation_version": "observation-v1",
                        **knowledge,
                        "utility_version": "legacy-safe-writer-v1",
                        "utility_scope": "legacy_safe_writer",
                        "task_mechanism": "trusted_formatter",
                        "task_actor": "response_writer",
                        "same_reader_utility": None,
                                         "decision_accounting": "model_request_attempts",
                                         "phase": "running", "attack_enabled": attack_enabled,
                                         "oracle_version": "v1"},
                )
                started_event = lifecycle_event(run_id, 0, "run.started")
                event_store = SessionEventStore(session)
                session.add_all([run, vault])
                await event_store.append(started_event)
                gateway = None
                budget = None
                digest = None
                try:
                    if on_event is not None:
                        on_event(started_event)
                    async with asyncio.timeout(min(scenario.limits.timeout_seconds, 360)):
                        model = OllamaCaller(settings.ollama_url)
                        digest = await model.model_digest(config.model_name)
                        if digest is None:
                            raise ModelUnavailable("Selected local model is not installed")
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
                        budget = ModelBudget(model, max_calls=12, decisions=decisions)
                        nodes = LiveNodes(run_id, gateway, budget, config, attack_enabled)
                        initial = {
                            "shipment_id": fixture["records"]["shipment"]["id"],
                            "customer_id": fixture["records"]["shipment"]["customer_id"],
                        }
                        output = await invoke_graph_privately(
                            lambda: build_live_graph(nodes.operations_worker, nodes.customer_worker,
                                                     nodes.response_writer),
                            initial, config={"recursion_limit": 8},
                        )
                    oracle: Oracle = ExactOracle()
                    escaped = oracle.escaped(secret, gateway.accepted_artifacts, scenario, seed)
                    utility = benign_task_succeeded(
                        fixture, output.get("writer_text", ""), secret,
                        bool(output.get("writer_accepted")),
                    )
                    attempted = bool(output.get("attack_attempted"))
                    scoring = score_gateway(
                        gateway, information_measure=information_measure, status="completed", attack_enabled=attack_enabled,
                        evaluate=evaluate, utility=utility,
                    )
                    session.add(RunScore(
                        run_id=run_id, scenario_valid=True,
                        attacker_attempted=attempted,
                        secret_escaped=escaped,
                        benign_task_success=utility,
                        blocked_attempts=gateway.blocked_attempts,
                        accepted_outbound_events=len(gateway.accepted_artifacts),
                        benign_events_blocked=0 if output.get("writer_accepted") else 1,
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
                            "model_digest": digest,
                            "model_calls": budget.calls,
                            "invalid_attempt": False,
                            "attack_enabled": attack_enabled,
                        },
                    ))
                    run.status = "completed"
                    run.finished_at = datetime.now(timezone.utc)
                    run.stage_snapshot_json = {
                        **(run.stage_snapshot_json or {}), **decisions.snapshot(), "phase": "completed",
                        "writer_accepted": bool(output.get("writer_accepted")), "scoring": scoring,
                    }
                    completed_event = lifecycle_event(
                        run_id, gateway.events + 1, "run.completed"
                    )
                    await event_store.append(completed_event)
                    notify_terminal(on_event, completed_event)
                    return RunSummary(
                        run_id, scenario.id, defense_profile, attempted, False,
                        scoring["secret_escaped"], utility, gateway.blocked_attempts,
                        len(gateway.accepted_artifacts), mode="live",
                        model_name=config.model_name, scoring=scoring,
                        undetected_success=scoring["strict_win"],
                    )
                except asyncio.CancelledError:
                    await preserve_failure(
                        session, run, gateway, information_measure=information_measure, status="cancelled", failure_code="cancelled",
                        attack_enabled=attack_enabled, evaluate=evaluate,
                        metadata={**decisions.snapshot(), "model_calls": budget.calls if budget else 0,
                                  "model_digest": digest},
                    )
                    cancelled_event = lifecycle_event(
                        run_id, (gateway.events if gateway else 0) + 1,
                        "run.cancelled",
                    )
                    await event_store.append(cancelled_event)
                    notify_terminal(on_event, cancelled_event)
                    raise
                except Exception as error:
                    terminal_status = "timed_out" if isinstance(error, (ModelTimedOut, TimeoutError)) else "failed"
                    failure_code = (
                        "model_timeout" if isinstance(error, ModelTimedOut) else
                        "model_unavailable" if isinstance(error, ModelUnavailable) else
                        "budget_exhausted" if isinstance(error, (DecisionLimitExceeded, GatewayBudgetExceeded)) else
                        type(error).__name__[:64]
                    )
                    await preserve_failure(
                        session, run, gateway, information_measure=information_measure, status=terminal_status, failure_code=failure_code,
                        attack_enabled=attack_enabled, evaluate=evaluate,
                        metadata={**decisions.snapshot(), "model_calls": budget.calls if budget else 0,
                                  "model_digest": digest},
                    )
                    failed_event = lifecycle_event(
                        run_id, (gateway.events if gateway else 0) + 1,
                        "run.timed_out" if terminal_status == "timed_out" else "run.failed",
                    )
                    await event_store.append(failed_event)
                    notify_terminal(on_event, failed_event)
                    raise
        finally:
            await engine.dispose()
