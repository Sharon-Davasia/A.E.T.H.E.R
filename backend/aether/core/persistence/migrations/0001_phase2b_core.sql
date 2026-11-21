PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    user_goal TEXT NOT NULL CHECK (length(user_goal) BETWEEN 1 AND 8000),
    state TEXT NOT NULL CHECK (state IN (
        'RECEIVED', 'RESOLVING_CONTEXT', 'PLANNING', 'VALIDATING',
        'PREVIEW_READY', 'AWAITING_APPROVAL', 'PRECHECK', 'EXECUTING',
        'POSTCHECK', 'COMPLETED', 'CLARIFICATION_REQUIRED', 'PAUSED',
        'DENIED', 'CANCELLED', 'FAILED', 'RECOVERING',
        'PARTIALLY_COMPLETED', 'UNVERIFIED'
    )),
    plan_revision INTEGER NOT NULL DEFAULT 0 CHECK (plan_revision >= 0),
    plan_hash TEXT,
    project_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    last_error_code TEXT,
    CHECK (plan_hash IS NULL OR length(plan_hash) = 64)
);

CREATE TABLE task_plans (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    plan_hash TEXT NOT NULL CHECK (length(plan_hash) = 64),
    canonical_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (task_id, revision),
    UNIQUE (task_id, revision, plan_hash)
);

CREATE TABLE task_steps (
    id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    capability_id TEXT NOT NULL,
    args_json TEXT NOT NULL,
    resources_json TEXT NOT NULL,
    expected_state_json TEXT NOT NULL,
    effect_json TEXT NOT NULL,
    deps_json TEXT NOT NULL,
    locks_json TEXT NOT NULL,
    risk_tier INTEGER NOT NULL CHECK (risk_tier BETWEEN 0 AND 3),
    approval_status TEXT NOT NULL CHECK (approval_status IN (
        'NOT_REQUIRED', 'REQUIRED', 'CONTRACT_ONLY'
    )),
    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 86400),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 5),
    idempotency_key TEXT NOT NULL,
    postconditions_json TEXT NOT NULL,
    recovery_class TEXT NOT NULL CHECK (recovery_class IN (
        'REVERSIBLE', 'SNAPSHOT_RESTORABLE', 'COMPENSATABLE', 'IRREVERSIBLE'
    )),
    order_index INTEGER NOT NULL CHECK (order_index >= 0),
    PRIMARY KEY (task_id, plan_revision, id),
    FOREIGN KEY (task_id, plan_revision)
        REFERENCES task_plans(task_id, revision) ON DELETE RESTRICT
);

CREATE TABLE task_events (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    seq INTEGER NOT NULL CHECK (seq >= 1),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    step_id TEXT,
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (task_id, seq)
);

-- These are immutable consent/audit records. There is intentionally no grant
-- status, issuer, use counter, or operation-execution interface in this PR.
CREATE TABLE approval_records (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    plan_hash TEXT NOT NULL CHECK (length(plan_hash) = 64),
    preview_id TEXT NOT NULL,
    preview_digest TEXT NOT NULL CHECK (length(preview_digest) = 64),
    decision TEXT NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
    authority TEXT NOT NULL CHECK (authority = 'NON_AUTHORIZING_AUDIT_RECORD'),
    decided_at TEXT NOT NULL,
    FOREIGN KEY (task_id, plan_revision, plan_hash)
        REFERENCES task_plans(task_id, revision, plan_hash) ON DELETE RESTRICT
);

CREATE INDEX idx_tasks_state ON tasks(state, updated_at);
CREATE INDEX idx_task_events_task ON task_events(task_id, seq);
CREATE INDEX idx_approval_records_task ON approval_records(task_id, plan_revision);

CREATE TRIGGER task_plans_no_update BEFORE UPDATE ON task_plans
BEGIN SELECT RAISE(ABORT, 'task plan revisions are immutable'); END;
CREATE TRIGGER task_plans_no_delete BEFORE DELETE ON task_plans
BEGIN SELECT RAISE(ABORT, 'task plan revisions are immutable'); END;
CREATE TRIGGER task_steps_no_update BEFORE UPDATE ON task_steps
BEGIN SELECT RAISE(ABORT, 'task plan steps are immutable'); END;
CREATE TRIGGER task_steps_no_delete BEFORE DELETE ON task_steps
BEGIN SELECT RAISE(ABORT, 'task plan steps are immutable'); END;
CREATE TRIGGER task_events_no_update BEFORE UPDATE ON task_events
BEGIN SELECT RAISE(ABORT, 'task events are append-only'); END;
CREATE TRIGGER task_events_no_delete BEFORE DELETE ON task_events
BEGIN SELECT RAISE(ABORT, 'task events are append-only'); END;
CREATE TRIGGER approval_records_no_update BEFORE UPDATE ON approval_records
BEGIN SELECT RAISE(ABORT, 'approval audit records are immutable'); END;
CREATE TRIGGER approval_records_no_delete BEFORE DELETE ON approval_records
BEGIN SELECT RAISE(ABORT, 'approval audit records are immutable'); END;

INSERT INTO schema_migrations(version, name, applied_at)
VALUES (1, '0001_phase2b_core', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
PRAGMA user_version = 1;
