"""Sanitized reports over every started run, with independent receipt counts."""

from collections.abc import AsyncIterator

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from reef_panda_arena.application.knowledge import KNOWLEDGE_FIELDS
from reef_panda_arena.application.utility_contract import UTILITY_FIELDS
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, RunEvent, RunScore, SinkReceipt
from reef_panda_arena.storage.report_projection import (
    EXECUTION_FIELDS, PERSISTED_FIELDS, SCORING_FIELDS, project_report,
)
from reef_panda_arena.tools.registry import OUTBOUND_TOOLS


REPORT_COLUMNS = (
    "run_id", "scenario_id", "scenario_revision", "mode", "defense_profile",
    "model_name", "model_temperature", "model_top_p", "model_generation_seed",
    "model_digest", "source_digest",
    "prompt_version", "seed", "status", "attacker_attempted",
    "invalid_attempt", "secret_escaped", "benign_task_success", "blocked_attempts",
    "accepted_outbound_events", "run_duration_ms", "oracle_version", "decoder",
    "authorized_release_success", "partial_information_score", "alerts",
    "attack_proposals", "attack_accepted", "attack_blocked",
    "legitimate_actions_blocked", "theoretical_capacity_bits",
    "unscorable_reason", "arm", "observer_profile", "verified_bits",
    "attack_alerts", "benign_alerts", "undetected_success", "scoring_scope",
    "split", "round_limit", "rounds_used", "valid_candidates", "invalid_candidates",
    "unsupported_proposals", "candidate_family_count", "first_success_round",
    "attacker_model_calls", "total_model_calls", "gateway_calls",
    "graph_supersteps", "accepted_sink_bytes",
    "tokens_in", "tokens_out", "stop_reason",
    "model_originated", "novelty_status", "novel_vs_catalog",
    "first_alert_round", "first_block_round", "limits",
    "novel_candidate_count", "distinct_candidate_count",
    "minimum_structural_edits", "canonical_candidate_hashes",
    "hypothesis_records",
    "transfer_from_run_id",
    "compromised_roles", "fault_origin", "accepted_external_artifact",
    "full_secret_recovered", "observed_partial_bits", "partial_bits_method",
    "admin_alerted_pre_egress", "blocked_egress_attempts",
    "lineage_gap_count", "lineage_unknown_count", "peer_deliveries",
    "accepted_sink_receipts", "attacker_win", "termination_reason",
    "fixture_hash", "mediated_actions", "public_control_allowed",
    "public_control_alerted", "secret_dependent_receives",
)
REPORT_COLUMNS = tuple(dict.fromkeys((*REPORT_COLUMNS, *SCORING_FIELDS, *PERSISTED_FIELDS, *EXECUTION_FIELDS, *KNOWLEDGE_FIELDS, *UTILITY_FIELDS)))


async def load_report_evidence(session: AsyncSession, run_ids: list[str]) -> dict[str, dict]:
    """Query only safe aggregate metadata; no payload or private vault reads."""
    if not run_ids:
        return {}
    counts = {run_id: dict.fromkeys(PERSISTED_FIELDS, 0) for run_id in run_ids}
    receipts = await session.execute(
        select(SinkReceipt.run_id, func.count())
        .where(SinkReceipt.run_id.in_(run_ids), SinkReceipt.accepted.is_(True))
        .group_by(SinkReceipt.run_id)
    )
    for run_id, count in receipts:
        counts[run_id]["persisted_accepted_sink_receipts"] = int(count)
    rejected = RunEvent.event_type == "candidate.rejected"
    event_counts = await session.execute(
        select(
            RunEvent.run_id,
            func.sum(case((and_(RunEvent.event_type == "tool.proposed",
                                RunEvent.tool_name.in_(OUTBOUND_TOOLS)), 1), else_=0)),
            func.sum(case((RunEvent.policy_decision == "block", 1), else_=0)),
            func.sum(case((RunEvent.event_type == "candidate.validated", 1), else_=0)),
            func.sum(case((rejected, 1), else_=0)),
            func.sum(case((and_(rejected, RunEvent.reason_code == "duplicate_candidate"), 1), else_=0)),
            func.sum(case((and_(rejected, RunEvent.reason_code == "unsupported_hypothesis"), 1), else_=0)),
        ).where(RunEvent.run_id.in_(run_ids)).group_by(RunEvent.run_id)
    )
    for run_id, *values in event_counts:
        for name, value in zip(PERSISTED_FIELDS[1:], values, strict=True):
            counts[run_id][name] = int(value or 0)
    return counts


def _query(run_id: str | None, limit: int):
    query = (
        select(ArenaRun, RunScore)
        .outerjoin(RunScore, ArenaRun.id == RunScore.run_id)
        .order_by(ArenaRun.created_at.desc(), ArenaRun.id.desc()).limit(limit)
    )
    return query.where(ArenaRun.id == run_id) if run_id is not None else query


async def _project_pairs(session: AsyncSession, pairs: list) -> list[dict]:
    evidence = await load_report_evidence(session, [run.id for run, _ in pairs])
    return [project_report(run, score, evidence[run.id]) for run, score in pairs]


async def list_reports(settings: ArenaSettings, run_id: str | None = None,
                       limit: int = 1000) -> list[dict]:
    """Preserve the bounded list API, including runs without a score row."""
    if not 1 <= limit <= 1000:
        raise ValueError("Report limit must be within 1..1000")
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    try:
        async with async_sessionmaker(engine)() as session:
            result = await session.execute(_query(run_id, limit))
            return await _project_pairs(session, result.all())
    finally:
        await engine.dispose()


async def iter_reports(settings: ArenaSettings, run_id: str | None = None,
                       page_size: int = 1000) -> AsyncIterator[dict]:
    """Export a finite database snapshot completely, using bounded pages.

    The initial count and keyset pages share one repeatable-read transaction.
    New runs cannot prolong the export. This is pagination, never polling.
    """
    if not 1 <= page_size <= 1000:
        raise ValueError("Report page size must be within 1..1000")
    engine = create_async_engine(
        settings.sqlalchemy_url, pool_pre_ping=True, isolation_level="REPEATABLE READ",
    )
    try:
        async with async_sessionmaker(engine)() as session, session.begin():
            count_query = select(func.count()).select_from(ArenaRun)
            if run_id is not None:
                count_query = count_query.where(ArenaRun.id == run_id)
            remaining = int(await session.scalar(count_query) or 0)
            cursor = None
            while remaining:
                query = _query(run_id, min(page_size, remaining))
                if cursor is not None:
                    created_at, identifier = cursor
                    query = query.where(or_(
                        ArenaRun.created_at < created_at,
                        and_(ArenaRun.created_at == created_at, ArenaRun.id < identifier),
                    ))
                pairs = (await session.execute(query)).all()
                if not pairs:
                    raise RuntimeError("Report snapshot ended before its recorded count")
                reports = await _project_pairs(session, pairs)
                last = pairs[-1][0]
                cursor = (last.created_at, last.id)
                remaining -= len(pairs)
                for report in reports:
                    yield report
    finally:
        await engine.dispose()


UNIFIED_REPORT_FIELDS = (
    "run_id", "scenario_id", "scenario_revision", "mode",
    "defense_profile", "seed", "status", "compromised_roles",
    "fault_origin", "attack_attempted", "accepted_external_artifact",
    "full_secret_recovered", "observed_partial_bits", "partial_bits_method",
    "admin_alerted_pre_egress", "blocked_egress_attempts",
    "benign_task_success", "lineage_gap_count", "lineage_unknown_count",
    "peer_deliveries", "accepted_sink_receipts", "attacker_win",
    "termination_reason", "fixture_hash", "model_digest",
    "run_duration_ms", "notes",
)
UNIFIED_REPORT_FIELDS = tuple(dict.fromkeys((
    *UNIFIED_REPORT_FIELDS, *SCORING_FIELDS, *PERSISTED_FIELDS, *EXECUTION_FIELDS, *KNOWLEDGE_FIELDS, *UTILITY_FIELDS, "report_contract_version",
)))


async def get_unified_report(settings: ArenaSettings, run_id: str) -> dict | None:
    """Project all persisted unified runs, including unscored terminal failures."""
    rows = await list_reports(settings, run_id, limit=1)
    if not rows or rows[0]["scenario_revision"] != "unified-v1":
        return None
    row = rows[0]
    projected = {name: row.get(name) for name in UNIFIED_REPORT_FIELDS}
    projected["attack_attempted"] = row["attacker_attempted"]
    projected["report_contract_version"] = "unified-v2"
    execution = row.get("live_execution")
    if row["mode"] == "live_multiagent":
        execution_note = (
            "Independent role requests through Ollama; synthetic data and local mock sinks."
            if execution and execution["model_backend"] == "ollama" else
            "Controlled injected role callers; not an Ollama experiment."
            if execution and execution["model_backend"] == "injected_caller" else
            "Live multiagent execution requested; model request evidence is unavailable."
        )
    else:
        execution_note = "Deterministic replay with synthetic data and local mock sinks."
    projected["notes"] = [
        execution_note,
        "Actor-local is an intentionally weak educational baseline.",
        "Null outcomes are unmeasured or ineligible; eligibility_reasons explains why.",
    ]
    return projected
