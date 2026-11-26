PRAGMA foreign_keys = ON;

-- Phase 3 navigation evidence (PREPARED ONLY — not active).
-- Durable, append-only attempt/verification/receipt facts for T1
-- navigation. No observations, window titles or UIA content are stored.
CREATE TABLE navigation_confirmations (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK (plan_revision >= 1),
    plan_hash TEXT NOT NULL CHECK (length(plan_hash) = 64),
    capability_id TEXT NOT NULL,
    arguments_sha256 TEXT NOT NULL CHECK (length(arguments_sha256) = 64),
    app_resource_id TEXT NOT NULL CHECK (app_resource_id LIKE 'app:%'),
    expected_app_version TEXT NOT NULL,
    integrity_evidence_sha256 TEXT NOT NULL CHECK (length(integrity_evidence_sha256) = 64),
    session_id TEXT NOT NULL,
    activation_scope TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    revoked_at TEXT,
    UNIQUE (task_id, step_id, plan_revision)
);

CREATE TABLE navigation_attempts (
    id TEXT PRIMARY KEY,
    confirmation_id TEXT NOT NULL REFERENCES navigation_confirmations(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    app_resource_id TEXT NOT NULL CHECK (app_resource_id LIKE 'app:%'),
    attempt_number INTEGER NOT NULL CHECK (attempt_number = 1),
    recorded_at TEXT NOT NULL,
    UNIQUE (confirmation_id),
    UNIQUE (task_id, step_id, attempt_number)
);

CREATE TABLE navigation_verifications (
    id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES navigation_attempts(id) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK (outcome IN (
        'verified_new_instance', 'verified_existing_instance',
        'verified_background', 'timeout_before_effect',
        'timeout_after_effect', 'unverified', 'failed'
    )),
    process_instance_token TEXT,
    window_version_token TEXT,
    verified_at TEXT NOT NULL,
    UNIQUE (attempt_id)
);

CREATE TABLE navigation_receipts (
    id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES navigation_attempts(id) ON DELETE RESTRICT,
    verification_id TEXT NOT NULL REFERENCES navigation_verifications(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('SUCCEEDED', 'FAILED', 'UNVERIFIED')),
    recovery_class TEXT NOT NULL CHECK (recovery_class = 'IRREVERSIBLE'),
    created_at TEXT NOT NULL,
    UNIQUE (attempt_id),
    UNIQUE (verification_id)
);

CREATE INDEX idx_navigation_attempts_task ON navigation_attempts(task_id, step_id);
CREATE INDEX idx_navigation_confirmations_task ON navigation_confirmations(task_id, expires_at);

CREATE TRIGGER navigation_confirmations_no_delete BEFORE DELETE ON navigation_confirmations
BEGIN SELECT RAISE(ABORT, 'navigation confirmations are append-only'); END;
CREATE TRIGGER navigation_attempts_no_update BEFORE UPDATE ON navigation_attempts
BEGIN SELECT RAISE(ABORT, 'navigation attempts are append-only'); END;
CREATE TRIGGER navigation_attempts_no_delete BEFORE DELETE ON navigation_attempts
BEGIN SELECT RAISE(ABORT, 'navigation attempts are append-only'); END;
CREATE TRIGGER navigation_verifications_no_update BEFORE UPDATE ON navigation_verifications
BEGIN SELECT RAISE(ABORT, 'navigation verifications are append-only'); END;
CREATE TRIGGER navigation_verifications_no_delete BEFORE DELETE ON navigation_verifications
BEGIN SELECT RAISE(ABORT, 'navigation verifications are append-only'); END;
CREATE TRIGGER navigation_receipts_no_update BEFORE UPDATE ON navigation_receipts
BEGIN SELECT RAISE(ABORT, 'navigation receipts are append-only'); END;
CREATE TRIGGER navigation_receipts_no_delete BEFORE DELETE ON navigation_receipts
BEGIN SELECT RAISE(ABORT, 'navigation receipts are append-only'); END;

PRAGMA user_version = 3;
