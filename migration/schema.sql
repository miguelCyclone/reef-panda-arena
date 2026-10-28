-- Reef Panda Covert Channel Arena - SINGLE AUTHORITATIVE SCHEMA
-- This is the entire desired schema for a NEW local dev volume.
-- Do not create numbered migration files. Edits require documented dev reset.
-- All IDs are application-generated UUID strings. All secrets are synthetic.
CREATE TABLE IF NOT EXISTS schema_meta (
  id TINYINT UNSIGNED PRIMARY KEY,
  schema_version VARCHAR(32) NOT NULL,
  installed_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT chk_schema_singleton CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
INSERT INTO schema_meta (id, schema_version) VALUES (1, '0.1.0')
  ON DUPLICATE KEY UPDATE schema_version=VALUES(schema_version);

CREATE TABLE IF NOT EXISTS arena_runs (
  id CHAR(36) PRIMARY KEY,
  scenario_id VARCHAR(32) NOT NULL,
  scenario_revision VARCHAR(24) NOT NULL,
  mode ENUM('replay','live') NOT NULL,
  defense_profile VARCHAR(32) NOT NULL,
  model_name VARCHAR(160) NULL,
  model_temperature DECIMAL(4,3) NULL,
  seed BIGINT UNSIGNED NOT NULL,
  status ENUM('pending','running','completed','failed','cancelled','timed_out') NOT NULL DEFAULT 'pending',
  benign_goal_json JSON NOT NULL,
  stage_snapshot_json JSON NULL,
  prompt_version VARCHAR(48) NOT NULL,
  started_at TIMESTAMP(6) NULL,
  finished_at TIMESTAMP(6) NULL,
  last_activity_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  failure_code VARCHAR(64) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX idx_runs_state_time (status, created_at),
  INDEX idx_runs_scenario (scenario_id, mode, defense_profile)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS synthetic_vault (
  id CHAR(36) PRIMARY KEY,
  run_id CHAR(36) NOT NULL,
  label VARCHAR(64) NOT NULL,
  secret_nonce VARBINARY(12) NOT NULL,
  secret_ciphertext VARBINARY(4096) NOT NULL,
  data_class VARCHAR(24) NOT NULL DEFAULT 'secret',
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_vault_run_label (run_id, label),
  CONSTRAINT fk_vault_run FOREIGN KEY (run_id) REFERENCES arena_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
-- Secrets are AES-GCM encrypted by application code using local environment key.
-- Never render decrypted values into trace, logs, public API, graph shared state.

CREATE TABLE IF NOT EXISTS run_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  run_id CHAR(36) NOT NULL,
  event_seq INT UNSIGNED NOT NULL,
  event_type VARCHAR(48) NOT NULL,
  actor_id VARCHAR(64) NOT NULL,
  channel VARCHAR(32) NOT NULL,
  tool_name VARCHAR(80) NULL,
  destination VARCHAR(80) NULL,
  policy_decision ENUM('allow','block','review','not_applicable') NOT NULL,
  reason_code VARCHAR(80) NULL,
  data_class VARCHAR(24) NOT NULL,
  taint_labels_json JSON NOT NULL,
  safe_summary_json JSON NOT NULL,
  payload_sha256 BINARY(32) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_run_event_seq (run_id, event_seq),
  INDEX idx_event_type (event_type, created_at),
  INDEX idx_event_run_channel (run_id, channel),
  CONSTRAINT fk_events_run FOREIGN KEY (run_id) REFERENCES arena_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS sink_receipts (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  run_id CHAR(36) NOT NULL,
  event_seq INT UNSIGNED NOT NULL,
  sink_name VARCHAR(80) NOT NULL DEFAULT 'mock_customer_outbound',
  accepted BOOLEAN NOT NULL,
  byte_length INT UNSIGNED NOT NULL,
  payload_sha256 BINARY(32) NOT NULL,
  oracle_fragment_json JSON NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_sink_run_event (run_id, event_seq),
  CONSTRAINT fk_sink_run FOREIGN KEY (run_id) REFERENCES arena_runs(id) ON DELETE CASCADE,
  CONSTRAINT fk_sink_event FOREIGN KEY (run_id, event_seq) REFERENCES run_events(run_id, event_seq) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
-- oracle_fragment_json stores only NON-SECRET aggregate metadata, never raw payload.
-- The oracle reconstructs from ephemeral accepted sink material before redaction.

CREATE TABLE IF NOT EXISTS run_scores (
  run_id CHAR(36) PRIMARY KEY,
  scenario_valid BOOLEAN NOT NULL,
  attacker_attempted BOOLEAN NOT NULL,
  secret_escaped BOOLEAN NOT NULL,
  benign_task_success BOOLEAN NOT NULL,
  blocked_attempts INT UNSIGNED NOT NULL DEFAULT 0,
  accepted_outbound_events INT UNSIGNED NOT NULL DEFAULT 0,
  benign_events_blocked INT UNSIGNED NOT NULL DEFAULT 0,
  benign_events_evaluated INT UNSIGNED NOT NULL DEFAULT 0,
  decoded_bytes INT UNSIGNED NOT NULL DEFAULT 0,
  run_duration_ms BIGINT UNSIGNED NULL,
  oracle_version VARCHAR(24) NOT NULL,
  details_json JSON NOT NULL,
  scored_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_score_run FOREIGN KEY (run_id) REFERENCES arena_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
