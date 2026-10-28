"""SQLAlchemy mappings for the single schema in migration/schema.sql."""

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, ForeignKeyConstraint, Index, UniqueConstraint, text
from sqlalchemy.dialects.mysql import (
    BIGINT,
    BINARY,
    BOOLEAN,
    CHAR,
    DECIMAL,
    ENUM,
    INTEGER,
    JSON,
    TIMESTAMP,
    TINYINT,
    VARBINARY,
    VARCHAR,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SchemaMeta(Base):
    __tablename__ = "schema_meta"
    __table_args__ = (CheckConstraint("id = 1", name="chk_schema_singleton"),)

    id: Mapped[int] = mapped_column(TINYINT(unsigned=True), primary_key=True)
    schema_version: Mapped[str] = mapped_column(VARCHAR(32))
    installed_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(fsp=6), server_default=text("CURRENT_TIMESTAMP(6)")
    )


class ArenaRun(Base):
    __tablename__ = "arena_runs"
    __table_args__ = (
        Index("idx_runs_state_time", "status", "created_at"),
        Index("idx_runs_scenario", "scenario_id", "mode", "defense_profile"),
    )

    id: Mapped[str] = mapped_column(CHAR(36), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(VARCHAR(32))
    scenario_revision: Mapped[str] = mapped_column(VARCHAR(24))
    mode: Mapped[str] = mapped_column(ENUM("replay", "live"))
    defense_profile: Mapped[str] = mapped_column(VARCHAR(32))
    model_name: Mapped[str | None] = mapped_column(VARCHAR(160), nullable=True)
    model_temperature: Mapped[Decimal | None] = mapped_column(
        DECIMAL(4, 3), nullable=True
    )
    seed: Mapped[int] = mapped_column(BIGINT(unsigned=True))
    status: Mapped[str] = mapped_column(
        ENUM("pending", "running", "completed", "failed", "cancelled", "timed_out"),
        server_default="pending",
    )
    benign_goal_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    stage_snapshot_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )
    prompt_version: Mapped[str] = mapped_column(VARCHAR(48))
    started_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(fsp=6), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(fsp=6), nullable=True)
    last_activity_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(fsp=6), server_default=text("CURRENT_TIMESTAMP(6)")
    )
    failure_code: Mapped[str | None] = mapped_column(VARCHAR(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(fsp=6), server_default=text("CURRENT_TIMESTAMP(6)")
    )


class SyntheticVault(Base):
    __tablename__ = "synthetic_vault"
    __table_args__ = (UniqueConstraint("run_id", "label", name="uq_vault_run_label"),)

    id: Mapped[str] = mapped_column(CHAR(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        CHAR(36), ForeignKey("arena_runs.id", ondelete="CASCADE")
    )
    label: Mapped[str] = mapped_column(VARCHAR(64))
    secret_nonce: Mapped[bytes] = mapped_column(VARBINARY(12))
    secret_ciphertext: Mapped[bytes] = mapped_column(VARBINARY(4096))
    data_class: Mapped[str] = mapped_column(VARCHAR(24), server_default="secret")
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(fsp=6), server_default=text("CURRENT_TIMESTAMP(6)")
    )


class RunEvent(Base):
    __tablename__ = "run_events"
    __table_args__ = (
        UniqueConstraint("run_id", "event_seq", name="uq_run_event_seq"),
        Index("idx_event_type", "event_type", "created_at"),
        Index("idx_event_run_channel", "run_id", "channel"),
    )

    id: Mapped[int] = mapped_column(BIGINT(unsigned=True), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        CHAR(36), ForeignKey("arena_runs.id", ondelete="CASCADE")
    )
    event_seq: Mapped[int] = mapped_column(INTEGER(unsigned=True))
    event_type: Mapped[str] = mapped_column(VARCHAR(48))
    actor_id: Mapped[str] = mapped_column(VARCHAR(64))
    channel: Mapped[str] = mapped_column(VARCHAR(32))
    tool_name: Mapped[str | None] = mapped_column(VARCHAR(80), nullable=True)
    destination: Mapped[str | None] = mapped_column(VARCHAR(80), nullable=True)
    policy_decision: Mapped[str] = mapped_column(
        ENUM("allow", "block", "review", "not_applicable")
    )
    reason_code: Mapped[str | None] = mapped_column(VARCHAR(80), nullable=True)
    data_class: Mapped[str] = mapped_column(VARCHAR(24))
    taint_labels_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    safe_summary_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    payload_sha256: Mapped[bytes | None] = mapped_column(BINARY(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(fsp=6), server_default=text("CURRENT_TIMESTAMP(6)")
    )


class SinkReceipt(Base):
    __tablename__ = "sink_receipts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "event_seq"],
            ["run_events.run_id", "run_events.event_seq"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("run_id", "event_seq", name="uq_sink_run_event"),
    )

    id: Mapped[int] = mapped_column(BIGINT(unsigned=True), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        CHAR(36), ForeignKey("arena_runs.id", ondelete="CASCADE")
    )
    event_seq: Mapped[int] = mapped_column(INTEGER(unsigned=True))
    sink_name: Mapped[str] = mapped_column(
        VARCHAR(80), server_default="mock_customer_outbound"
    )
    accepted: Mapped[bool] = mapped_column(BOOLEAN)
    byte_length: Mapped[int] = mapped_column(INTEGER(unsigned=True))
    payload_sha256: Mapped[bytes] = mapped_column(BINARY(32))
    oracle_fragment_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(fsp=6), server_default=text("CURRENT_TIMESTAMP(6)")
    )


class RunScore(Base):
    __tablename__ = "run_scores"

    run_id: Mapped[str] = mapped_column(
        CHAR(36), ForeignKey("arena_runs.id", ondelete="CASCADE"), primary_key=True
    )
    scenario_valid: Mapped[bool] = mapped_column(BOOLEAN)
    attacker_attempted: Mapped[bool] = mapped_column(BOOLEAN)
    secret_escaped: Mapped[bool] = mapped_column(BOOLEAN)
    benign_task_success: Mapped[bool] = mapped_column(BOOLEAN)
    blocked_attempts: Mapped[int] = mapped_column(INTEGER(unsigned=True), server_default=text("0"))
    accepted_outbound_events: Mapped[int] = mapped_column(
        INTEGER(unsigned=True), server_default=text("0")
    )
    benign_events_blocked: Mapped[int] = mapped_column(
        INTEGER(unsigned=True), server_default=text("0")
    )
    benign_events_evaluated: Mapped[int] = mapped_column(
        INTEGER(unsigned=True), server_default=text("0")
    )
    decoded_bytes: Mapped[int] = mapped_column(INTEGER(unsigned=True), server_default=text("0"))
    run_duration_ms: Mapped[int | None] = mapped_column(
        BIGINT(unsigned=True), nullable=True
    )
    oracle_version: Mapped[str] = mapped_column(VARCHAR(24))
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    scored_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(fsp=6), server_default=text("CURRENT_TIMESTAMP(6)")
    )
