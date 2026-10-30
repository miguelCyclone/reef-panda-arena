"""Reconstruct bounded runtime provenance from the persisted journal alone."""

import asyncio
import logging
from collections import deque
from collections.abc import Mapping, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from reef_panda_arena.gateway.lineage_evidence import (
    SINKS, SOURCE_KINDS, SOURCE_FIELDS, validate_lineage_document,
)
from reef_panda_arena.gateway.observer_contract import safe_observation
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.models import ArenaRun, RunEvent, SinkReceipt


# Current manifests permit <=150 gateway events plus lifecycle events. A fixed
# larger ceiling permits one finite snapshot without consulting private fixtures.
MAX_JOURNAL_EVENTS = 256
MAX_GRAPH_ERRORS = 256
_QUERY_SECONDS = 15
_DISPOSE_SECONDS = 5
_LOG = logging.getLogger(__name__)
_TERMINAL = frozenset({"completed", "failed", "cancelled", "timed_out", "budget_exhausted"})
_LIFECYCLE = frozenset({"run.started", "run.completed", "run.failed", "run.cancelled", "run.timed_out"})
_DIAGNOSTICS = frozenset({"candidate.proposed", "candidate.validated", "candidate.rejected", "hypothesis.proposed"})
_PUBLIC_ROOTS = frozenset({"trusted_public_message", "trusted_public_argument"})


def _get(row, field, default=None):
    return row.get(field, default) if isinstance(row, Mapping) else getattr(row, field, default)


def _join(labels: list[str]) -> str:
    for label in ("secret", "unknown", "internal"):
        if label in labels:
            return label
    return "public" if labels else "unknown"


def reconstruct_lineage(
    run_id: str, events: Sequence, receipts: Sequence, *,
    truncated: bool = False, run_status: str | None = None,
) -> dict:
    """Validate detached event/receipt metadata; never infer missing ancestry.

    `complete` describes recorded graph consistency/coverage, not the absence of
    leakage, expected mathematical dependence, or successful execution. A failed
    run may still have a complete journal containing accepted receipts. It does
    not establish that no uncommitted operation was lost before persistence.
    """
    errors: set[tuple[str, int | None]] = set()

    def problem(code, seq=None):
        errors.add((code, seq if type(seq) is int and seq >= 0 else None))

    if truncated or len(events) > MAX_JOURNAL_EVENTS or len(receipts) > MAX_JOURNAL_EVENTS:
        problem("journal_truncated")
    ordered = []
    for row in events[:MAX_JOURNAL_EVENTS]:
        seq = _get(row, "event_seq")
        if _get(row, "run_id") != run_id or type(seq) is not int or seq < 0:
            problem("event_ownership_invalid")
        else:
            ordered.append(row)
    ordered.sort(key=lambda row: _get(row, "event_seq"))
    event_by_seq, documents, boundaries, nodes, positions = {}, {}, [], {}, {}
    invalid_nodes = set()
    missing_lineage = 0
    for event in ordered:
        seq = _get(event, "event_seq")
        if seq in event_by_seq:
            problem("duplicate_event_sequence", seq)
            continue
        event_by_seq[seq] = event
        summary = _get(event, "safe_summary_json", {})
        summary = summary if isinstance(summary, dict) else {}
        observation = safe_observation(summary.get("observation"))
        if observation is not None and observation["event_seq"] != seq:
            observation = None
            problem("observation_event_mismatch", seq)
        if summary.get("observation") is not None and observation is None:
            problem("invalid_observation", seq)
        raw = summary.get("lineage")
        document = None
        if raw is not None:
            try:
                document = validate_lineage_document(raw)
            except ValueError:
                problem("invalid_lineage_document", seq)
            if document is not None and (
                document["run_id"] != run_id or document["event_seq"] != seq
                or document["actor_id"] != _get(event, "actor_id")
            ):
                problem("lineage_event_mismatch", seq)
                document = None
        if observation is not None and (
            (document is not None and observation["attempt_id"] != document["attempt_id"])
            or ("attempt_id" in summary and observation["attempt_id"] != summary["attempt_id"])
        ):
            observation = None
            problem("observation_attempt_mismatch", seq)
        boundary_event = _get(event, "event_type") not in _LIFECYCLE | _DIAGNOSTICS
        if document is None:
            if boundary_event:
                missing_lineage += 1
                problem("lineage_not_instrumented", seq)
        else:
            documents[seq] = document
            if document["coverage"] != "complete":
                problem("partial_lineage_evidence", seq)
            for offset, node in enumerate(document["nodes"]):
                identifier = node["artifact_id"]
                if identifier in nodes:
                    invalid_nodes.add(identifier)
                    problem("duplicate_artifact_definition", seq)
                    continue
                nodes[identifier] = node
                positions[identifier] = (seq, offset)
        if boundary_event or document is not None or observation is not None:
            boundaries.append({
                "event_seq": seq,
                "boundary": document["boundary"] if document else None,
                "attempt_id": document["attempt_id"] if document else None,
                "coverage": document["coverage"] if document else "not_instrumented",
                "reasons": document["reasons"] if document else ["historical_evidence_unavailable"],
                "inputs": document["inputs"] if document else {},
                "outputs": document["outputs"] if document else {},
                "metadata": document["metadata"] if document else {},
                "observation": observation,
            })

    edges, children = [], {identifier: [] for identifier in nodes}
    indegrees = dict.fromkeys(nodes, 0)
    for identifier, node in nodes.items():
        seq = node["event_seq"]

        def node_problem(code, event_seq=None):
            invalid_nodes.add(identifier)
            problem(code, event_seq)

        parents = node["parent_ids"]
        resolved = []
        for parent_id in parents:
            parent = nodes.get(parent_id)
            if parent is None:
                node_problem("unresolved_parent", seq)
                continue
            edges.append({"parent_id": parent_id, "child_id": identifier})
            children[parent_id].append(identifier)
            indegrees[identifier] += 1
            if positions[parent_id] >= positions[identifier]:
                node_problem("parent_order_invalid", seq)
            resolved.append(parent)
        transform = node["transform"]
        event = event_by_seq[seq]
        labels = _get(event, "taint_labels_json", {})
        if not isinstance(labels, dict) or labels.get(node["field"]) != node["effective_label"]:
            node_problem("effective_label_event_mismatch", seq)
        if parents and transform in set(SOURCE_KINDS) | _PUBLIC_ROOTS | {"source_read"}:
            node_problem("source_root_has_parents", seq)
        if transform == "trusted_projection":
            if (len(resolved) != 1 or resolved[0]["stored_label"] != "secret"
                    or node["stored_label"] != "public"
                    or node["dependency_basis"] != "trusted_projection"
                    or node["release_purpose"] != "shipping_delay_notice"
                    or node["release_recipient"] != "CUS-008"
                    or documents[seq]["boundary"] != "projection.release"):
                node_problem("invalid_trusted_release", seq)
        elif parents:
            if len(resolved) == len(parents) and node["stored_label"] != _join([
                parent["stored_label"] for parent in resolved
            ]):
                node_problem("stored_label_join_mismatch", seq)
        elif transform in SOURCE_KINDS or transform == "source_read":
            if (documents[seq]["boundary"] != "tool.source"
                    or _get(event, "policy_decision") != "allow"
                    or _get(event, "tool_name") != node["source_type"]):
                node_problem("source_boundary_mismatch", seq)
            if transform in SOURCE_KINDS:
                source_type, source_field = SOURCE_KINDS[transform]
                if node["stored_label"] != SOURCE_FIELDS[source_type][source_field]:
                    node_problem("source_label_mismatch", seq)
            if node["dependency_basis"] != "trusted_source_contract":
                node_problem("source_contract_unavailable", seq)
        elif transform in _PUBLIC_ROOTS:
            if node["stored_label"] != "public" or node["dependency_basis"] != "trusted_public_contract":
                node_problem("invalid_public_root", seq)
        elif transform == "unknown_argument" and node["stored_label"] == "unknown":
            node_problem("unknown_provenance", seq)
        else:
            node_problem("undeclared_source_root", seq)
        if node["stored_label"] == "unknown":
            node_problem("unknown_provenance", seq)

    pending = deque(identifier for identifier, count in indegrees.items() if count == 0)
    visited = 0
    ancestry_complete = {}
    while pending:
        identifier = pending.popleft()
        visited += 1
        ancestry_complete[identifier] = identifier not in invalid_nodes and all(
            ancestry_complete.get(parent, False) for parent in nodes[identifier]["parent_ids"]
        )
        for child in children[identifier]:
            indegrees[child] -= 1
            if indegrees[child] == 0:
                pending.append(child)
    if visited != len(nodes):
        problem("lineage_cycle")

    for seq, document in documents.items():
        for parents in document["inputs"].values():
            for parent_id in parents:
                parent = nodes.get(parent_id)
                if parent is None:
                    problem("unresolved_input", seq)
                elif parent["event_seq"] > seq:
                    problem("input_order_invalid", seq)
        if _get(event_by_seq[seq], "policy_decision") == "block" and document["nodes"]:
            problem("denied_output_published", seq)

    durable_receipts, seen_receipts = [], set()
    for row in receipts[:MAX_JOURNAL_EVENTS]:
        seq = _get(row, "event_seq")
        if _get(row, "run_id") != run_id or type(seq) is not int or seq < 0:
            problem("receipt_ownership_invalid")
            continue
        if seq in seen_receipts:
            problem("duplicate_receipt_sequence", seq)
            continue
        seen_receipts.add(seq)
        accepted = _get(row, "accepted")
        sink = _get(row, "sink_name")
        event, document = event_by_seq.get(seq), documents.get(seq)
        link = document["receipt"] if document else None
        linked = True
        if type(accepted) is not bool or sink not in SINKS:
            problem("invalid_receipt_metadata", seq)
            linked = False
        if event is None:
            problem("receipt_event_missing", seq)
            linked = False
        elif accepted is True and _get(event, "policy_decision") != "allow":
            problem("accepted_receipt_on_denied_event", seq)
            linked = False
        if (link is None or link["accepted"] != accepted or link["sink"] != sink
                or document["boundary"] != "tool.outbound"):
            problem("receipt_lineage_mismatch", seq)
            linked = False
        elif (not link["argument_artifact_ids"]
              or set(link["argument_artifact_ids"]) != set(document["outputs"].values())
              or any(nodes.get(identifier, {}).get("event_seq") != seq
                     for identifier in link["argument_artifact_ids"])):
            problem("receipt_arguments_incomplete", seq)
            linked = False
        if link is not None and any(not ancestry_complete.get(identifier, False)
                                    for identifier in link["argument_artifact_ids"]):
            problem("receipt_ancestry_incomplete", seq)
            linked = False
        durable_receipts.append({
            "event_seq": seq, "accepted": accepted if type(accepted) is bool else None,
            "sink": sink if sink in SINKS else None,
            "argument_artifact_ids": link["argument_artifact_ids"] if link else [],
            "linked": linked,
        })
    for seq, document in documents.items():
        if document["receipt"] is not None and seq not in seen_receipts:
            problem("claimed_receipt_missing", seq)
    if not ordered:
        problem("journal_empty")
    if not documents:
        problem("lineage_not_instrumented")
    if run_status is not None and run_status not in _TERMINAL:
        problem("run_not_terminal")
    ordered_errors = sorted(errors, key=lambda item: (item[1] is None, item[1] or 0, item[0]))
    complete = not errors
    return {
        "version": "lineage-graph-v1", "run_id": run_id,
        "run_status": run_status if run_status in _TERMINAL | {"pending", "running"} else None,
        "coverage": "complete" if complete else "partial" if documents else "not_instrumented",
        "complete": complete, "truncated": bool(truncated or len(events) > MAX_JOURNAL_EVENTS
                                                  or len(receipts) > MAX_JOURNAL_EVENTS),
        "counts": {
            "events": len(event_by_seq), "boundaries": len(boundaries), "nodes": len(nodes),
            "edges": len(edges), "accepted_receipts": sum(row["accepted"] is True for row in durable_receipts),
            "linked_receipts": sum(row["accepted"] is True and row["linked"] for row in durable_receipts),
            "missing_lineage_events": missing_lineage, "validation_errors": len(errors),
        },
        "validation_errors": [{"code": code, "event_seq": seq}
                              for code, seq in ordered_errors[:MAX_GRAPH_ERRORS]],
        "errors_truncated": len(errors) > MAX_GRAPH_ERRORS,
        "nodes": list(nodes.values()), "edges": edges,
        "receipts": sorted(durable_receipts, key=lambda row: row["event_seq"]),
        "boundaries": boundaries,
    }


async def load_run_lineage(settings: ArenaSettings, run_id: str) -> dict | None:
    """Read one bounded repeatable-read snapshot with no secret/commitment columns."""
    engine = create_async_engine(
        settings.sqlalchemy_url, pool_pre_ping=True, isolation_level="REPEATABLE READ",
    )
    try:
        async with asyncio.timeout(_QUERY_SECONDS):
            async with async_sessionmaker(engine)() as session, session.begin():
                run = (await session.execute(select(ArenaRun.id, ArenaRun.status).where(
                    ArenaRun.id == run_id,
                ))).first()
                if run is None:
                    return None
                events = (await session.execute(select(
                    RunEvent.run_id, RunEvent.event_seq, RunEvent.event_type,
                    RunEvent.actor_id, RunEvent.policy_decision, RunEvent.tool_name,
                    RunEvent.taint_labels_json, RunEvent.safe_summary_json,
                ).where(RunEvent.run_id == run_id).order_by(RunEvent.event_seq)
                    .limit(MAX_JOURNAL_EVENTS + 1))).mappings().all()
                receipts = (await session.execute(select(
                    SinkReceipt.run_id, SinkReceipt.event_seq, SinkReceipt.accepted, SinkReceipt.sink_name,
                ).where(SinkReceipt.run_id == run_id).order_by(SinkReceipt.event_seq)
                    .limit(MAX_JOURNAL_EVENTS + 1))).mappings().all()
                return reconstruct_lineage(run_id, events, receipts, run_status=run.status)
    finally:
        try:
            async with asyncio.timeout(_DISPOSE_SECONDS):
                await engine.dispose()
        except TimeoutError:
            _LOG.warning("Lineage reader engine disposal timed out")
