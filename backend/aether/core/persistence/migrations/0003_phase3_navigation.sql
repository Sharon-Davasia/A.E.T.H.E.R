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
    binding_sha256 TEXT NOT NULL CHECK (length(binding_sha256) = 64),
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
        'verified_background_no_window', 'accepted_unverified',
        'timeout_before_effect', 'timeout_after_effect',
        'unverified', 'failed'
    )),
    process_instance_token TEXT,
    window_version_token TEXT,
    verified_at TEXT NOT NULL,
    UNIQUE (attempt_id),
    -- Outcome-specific evidence requirements: a verified outcome must
    -- name the independently observed identity that supports it.
    CHECK (outcome NOT IN (
        'verified_new_instance', 'verified_existing_instance',
        'verified_background_no_window'
    ) OR process_instance_token IS NOT NULL),
    CHECK (outcome NOT IN (
        'verified_new_instance', 'verified_existing_instance'
    ) OR window_version_token IS NOT NULL),
    CHECK (outcome != 'verified_background_no_window' OR window_version_token IS NULL)
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
-- Binding fields are immutable after issuance; only the guarded
-- consumption/revocation state columns may ever change.
CREATE TRIGGER navigation_confirmations_binding_no_update
BEFORE UPDATE ON navigation_confirmations
WHEN NEW.id != OLD.id OR NEW.task_id != OLD.task_id OR NEW.step_id != OLD.step_id
  OR NEW.plan_revision != OLD.plan_revision OR NEW.plan_hash != OLD.plan_hash
  OR NEW.capability_id != OLD.capability_id
  OR NEW.arguments_sha256 != OLD.arguments_sha256
  OR NEW.binding_sha256 != OLD.binding_sha256
  OR NEW.app_resource_id != OLD.app_resource_id
  OR NEW.expected_app_version != OLD.expected_app_version
  OR NEW.integrity_evidence_sha256 != OLD.integrity_evidence_sha256
  OR NEW.session_id != OLD.session_id OR NEW.activation_scope != OLD.activation_scope
  OR NEW.issued_at != OLD.issued_at OR NEW.expires_at != OLD.expires_at
BEGIN SELECT RAISE(ABORT, 'navigation confirmation binding is immutable'); END;
-- A SUCCEEDED receipt requires an affirmative verified verification.
CREATE TRIGGER navigation_receipts_success_requires_verification
BEFORE INSERT ON navigation_receipts
WHEN NEW.status = 'SUCCEEDED' AND NOT EXISTS (
    SELECT 1 FROM navigation_verifications
    WHERE id = NEW.verification_id AND attempt_id = NEW.attempt_id
      AND outcome IN (
        'verified_new_instance', 'verified_existing_instance',
        'verified_background_no_window'
      )
)
BEGIN SELECT RAISE(ABORT, 'receipt success requires verified verification'); END;
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

-- Phase 3 CP5 exact UI-operation evidence (PREPARED ONLY — not active).
-- A separate evidence class from navigation: T1 navigation evidence can
-- never authorize a UI interaction, and UI evidence can never authorize
-- navigation or filesystem edits. No UIA content, names or values are
-- stored — only bound identities, digests and outcome tokens.
CREATE TABLE ui_operation_bindings (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK (plan_revision >= 1),
    plan_hash TEXT NOT NULL CHECK (length(plan_hash) = 64),
    capability_id TEXT NOT NULL,
    arguments_sha256 TEXT NOT NULL CHECK (length(arguments_sha256) = 64),
    binding_sha256 TEXT NOT NULL CHECK (length(binding_sha256) = 64),
    app_resource_id TEXT NOT NULL CHECK (app_resource_id LIKE 'app:%'),
    window_resource_id TEXT NOT NULL CHECK (window_resource_id LIKE 'window:%'),
    window_version_token TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    snapshot_generation INTEGER NOT NULL CHECK (snapshot_generation >= 0),
    element_ref TEXT NOT NULL,
    element_runtime_id TEXT NOT NULL,
    pattern TEXT NOT NULL CHECK (pattern IN ('invoke','value','selectionitem','toggle','expandcollapse')),
    intended_effect TEXT NOT NULL,
    session_id TEXT NOT NULL,
    activation_scope TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    revoked_at TEXT,
    UNIQUE (task_id, step_id, plan_revision)
);

CREATE TABLE ui_operation_attempts (
    id TEXT PRIMARY KEY,
    binding_id TEXT NOT NULL REFERENCES ui_operation_bindings(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    window_resource_id TEXT NOT NULL CHECK (window_resource_id LIKE 'window:%'),
    attempt_number INTEGER NOT NULL CHECK (attempt_number = 1),
    recorded_at TEXT NOT NULL,
    UNIQUE (binding_id),
    UNIQUE (task_id, step_id, attempt_number)
);

CREATE TABLE ui_operation_verifications (
    id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES ui_operation_attempts(id) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK (outcome IN (
        'verified_effect', 'no_effect', 'uncertain', 'failed', 'stale_target'
    )),
    observed_postcondition_token TEXT,
    verified_at TEXT NOT NULL,
    UNIQUE (attempt_id),
    CHECK (outcome != 'verified_effect' OR observed_postcondition_token IS NOT NULL)
);

CREATE TABLE ui_operation_receipts (
    id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES ui_operation_attempts(id) ON DELETE RESTRICT,
    verification_id TEXT NOT NULL REFERENCES ui_operation_verifications(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('SUCCEEDED', 'FAILED', 'UNVERIFIED')),
    recovery_class TEXT NOT NULL CHECK (recovery_class = 'IRREVERSIBLE'),
    created_at TEXT NOT NULL,
    UNIQUE (attempt_id),
    UNIQUE (verification_id)
);

CREATE INDEX idx_ui_operation_attempts_task ON ui_operation_attempts(task_id, step_id);
CREATE INDEX idx_ui_operation_bindings_task ON ui_operation_bindings(task_id, expires_at);

CREATE TRIGGER ui_operation_bindings_no_delete BEFORE DELETE ON ui_operation_bindings
BEGIN SELECT RAISE(ABORT, 'ui operation bindings are append-only'); END;
CREATE TRIGGER ui_operation_bindings_binding_no_update
BEFORE UPDATE ON ui_operation_bindings
WHEN NEW.id != OLD.id OR NEW.task_id != OLD.task_id OR NEW.step_id != OLD.step_id
  OR NEW.plan_revision != OLD.plan_revision OR NEW.plan_hash != OLD.plan_hash
  OR NEW.capability_id != OLD.capability_id
  OR NEW.arguments_sha256 != OLD.arguments_sha256
  OR NEW.binding_sha256 != OLD.binding_sha256
  OR NEW.app_resource_id != OLD.app_resource_id
  OR NEW.window_resource_id != OLD.window_resource_id
  OR NEW.window_version_token != OLD.window_version_token
  OR NEW.snapshot_id != OLD.snapshot_id
  OR NEW.snapshot_generation != OLD.snapshot_generation
  OR NEW.element_ref != OLD.element_ref
  OR NEW.element_runtime_id != OLD.element_runtime_id
  OR NEW.pattern != OLD.pattern OR NEW.intended_effect != OLD.intended_effect
  OR NEW.session_id != OLD.session_id OR NEW.activation_scope != OLD.activation_scope
  OR NEW.issued_at != OLD.issued_at OR NEW.expires_at != OLD.expires_at
BEGIN SELECT RAISE(ABORT, 'ui operation binding is immutable'); END;
CREATE TRIGGER ui_operation_receipts_success_requires_verification
BEFORE INSERT ON ui_operation_receipts
WHEN NEW.status = 'SUCCEEDED' AND NOT EXISTS (
    SELECT 1 FROM ui_operation_verifications
    WHERE id = NEW.verification_id AND attempt_id = NEW.attempt_id
      AND outcome = 'verified_effect'
)
BEGIN SELECT RAISE(ABORT, 'ui receipt success requires verified effect'); END;
CREATE TRIGGER ui_operation_attempts_no_update BEFORE UPDATE ON ui_operation_attempts
BEGIN SELECT RAISE(ABORT, 'ui operation attempts are append-only'); END;
CREATE TRIGGER ui_operation_attempts_no_delete BEFORE DELETE ON ui_operation_attempts
BEGIN SELECT RAISE(ABORT, 'ui operation attempts are append-only'); END;
CREATE TRIGGER ui_operation_verifications_no_update BEFORE UPDATE ON ui_operation_verifications
BEGIN SELECT RAISE(ABORT, 'ui operation verifications are append-only'); END;
CREATE TRIGGER ui_operation_verifications_no_delete BEFORE DELETE ON ui_operation_verifications
BEGIN SELECT RAISE(ABORT, 'ui operation verifications are append-only'); END;
CREATE TRIGGER ui_operation_receipts_no_update BEFORE UPDATE ON ui_operation_receipts
BEGIN SELECT RAISE(ABORT, 'ui operation receipts are append-only'); END;
CREATE TRIGGER ui_operation_receipts_no_delete BEFORE DELETE ON ui_operation_receipts
BEGIN SELECT RAISE(ABORT, 'ui operation receipts are append-only'); END;

PRAGMA user_version = 3;
