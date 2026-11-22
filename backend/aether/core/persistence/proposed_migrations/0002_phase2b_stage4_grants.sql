-- PROPOSED Stage 4 migration — NOT applied, NOT registered, NOT fingerprinted
-- for production in this delivery. Applying or merging it requires separate
-- user approval (see docs/engineering/PHASE2B_STAGE4_GRANTS.md).
--
-- Adds the durable exact-approval-grant ledger on top of 0001_phase2b_core.
-- Grants bind task, plan revision/hash, step/capability/arguments/effect,
-- canonical resource versions, recovery class, risk-tier ceiling, bounded
-- uses, expiry, revocation and an HMAC-free scope digest. Issuance binds a
-- full immutable authorization intent digest (including issue/expiry times,
-- use bound and trusted issuer identity) and consumption binds a complete
-- immutable action digest so any replay with changed action terms fails
-- closed. Audit metadata is bounded machine-readable codes and hashes only —
-- never free-text that could carry secrets. Execution adapters are NOT
-- introduced here.

PRAGMA foreign_keys = ON;

CREATE TABLE exact_approval_grants (
    approval_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK (plan_revision >= 1),
    plan_hash TEXT NOT NULL CHECK (length(plan_hash) = 64),
    -- Digest of the immutable approved operations scope.
    scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
    scope_json TEXT NOT NULL,
    -- Digest of the full immutable authorization intent: scope digest, task,
    -- plan binding, tier ceiling, issued/expiry times, initial use bound and
    -- the trusted issuer identity. Replay under one issuance key must match.
    issuance_digest TEXT NOT NULL CHECK (length(issuance_digest) = 64),
    max_tier INTEGER NOT NULL CHECK (max_tier BETWEEN 0 AND 2),
    approval_origin TEXT NOT NULL CHECK (approval_origin = 'trusted-electron'),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    -- Bounded machine-readable code of the trusted authorizing source. Never
    -- renderer-supplied free text.
    issued_by TEXT NOT NULL CHECK (issued_by GLOB '[a-z]*' AND length(issued_by) BETWEEN 1 AND 64),
    issuance_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    CHECK (expires_at > issued_at),
    FOREIGN KEY (task_id, plan_revision, plan_hash)
        REFERENCES task_plans(task_id, revision, plan_hash) ON DELETE RESTRICT
);

-- Append-only ledger of grant lifecycle events. Never updated or deleted.
-- Only bounded codes, hashes and small integers are stored here.
CREATE TABLE exact_approval_grant_events (
    id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL REFERENCES exact_approval_grants(approval_id) ON DELETE RESTRICT,
    grant_seq INTEGER NOT NULL CHECK (grant_seq >= 1),
    event TEXT NOT NULL CHECK (event IN ('ISSUED', 'CONSUMED', 'REVOKED')),
    -- Machine-readable reason code for REVOKED events (e.g. SUPERSEDED_BY_PLAN).
    reason_code TEXT CHECK (reason_code IS NULL OR (
        reason_code GLOB '[A-Z]*' AND length(reason_code) BETWEEN 1 AND 64
    )),
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (approval_id, grant_seq)
);

-- Idempotency ledger for consumption. A retried consumption with the same
-- consumption_id returns the recorded result instead of double-spending only
-- when every action-defining field matches; otherwise it fails closed.
CREATE TABLE exact_approval_grant_consumptions (
    consumption_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL REFERENCES exact_approval_grants(approval_id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    plan_revision INTEGER NOT NULL,
    plan_hash TEXT NOT NULL CHECK (length(plan_hash) = 64),
    step_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    risk_tier INTEGER NOT NULL CHECK (risk_tier BETWEEN 0 AND 3),
    arguments_sha256 TEXT NOT NULL CHECK (length(arguments_sha256) = 64),
    expected_effect_sha256 TEXT NOT NULL CHECK (length(expected_effect_sha256) = 64),
    -- Canonical digest of the sorted (resource_id, observed_version) set.
    resource_versions_digest TEXT NOT NULL CHECK (length(resource_versions_digest) = 64),
    -- Digest of every field above that defines the action.
    action_digest TEXT NOT NULL CHECK (length(action_digest) = 64),
    consumed_by TEXT NOT NULL CHECK (
        consumed_by GLOB '[a-z]*' AND length(consumed_by) BETWEEN 1 AND 64
    ),
    consumed_at TEXT NOT NULL,
    uses_remaining_after INTEGER NOT NULL CHECK (uses_remaining_after >= 0)
);

CREATE INDEX idx_exact_approval_grants_task ON exact_approval_grants(task_id, plan_revision);
CREATE INDEX idx_exact_approval_grant_consumptions_grant ON exact_approval_grant_consumptions(approval_id);

-- Immutable audit/event history and no-op grant-content rewrites.
CREATE TRIGGER exact_approval_grant_events_no_update BEFORE UPDATE ON exact_approval_grant_events
BEGIN SELECT RAISE(ABORT, 'grant events are append-only'); END;
CREATE TRIGGER exact_approval_grant_events_no_delete BEFORE DELETE ON exact_approval_grant_events
BEGIN SELECT RAISE(ABORT, 'grant events are append-only'); END;
CREATE TRIGGER exact_approval_grant_consumptions_no_update BEFORE UPDATE ON exact_approval_grant_consumptions
BEGIN SELECT RAISE(ABORT, 'grant consumptions are append-only'); END;
CREATE TRIGGER exact_approval_grant_consumptions_no_delete BEFORE DELETE ON exact_approval_grant_consumptions
BEGIN SELECT RAISE(ABORT, 'grant consumptions are append-only'); END;

-- A grant may transition mutable lifecycle state only; the approved scope
-- (digests and JSON) and issuance identity are immutable after insert.
CREATE TRIGGER exact_approval_grants_scope_no_update BEFORE UPDATE ON exact_approval_grants
WHEN NEW.approval_id != OLD.approval_id
  OR NEW.task_id != OLD.task_id
  OR NEW.plan_revision != OLD.plan_revision
  OR NEW.plan_hash != OLD.plan_hash
  OR NEW.scope_digest != OLD.scope_digest
  OR NEW.scope_json != OLD.scope_json
  OR NEW.issuance_digest != OLD.issuance_digest
  OR NEW.max_tier != OLD.max_tier
  OR NEW.approval_origin != OLD.approval_origin
  OR NEW.issued_at != OLD.issued_at
  OR NEW.expires_at != OLD.expires_at
  OR NEW.issued_by != OLD.issued_by
  OR NEW.issuance_key != OLD.issuance_key
BEGIN SELECT RAISE(ABORT, 'grant scope is immutable'); END;

-- Mutable lifecycle counters live outside the immutable grant scope row so
-- that spending a use or revoking a grant can never rewrite approved scope.
CREATE TABLE exact_approval_grant_state (
    approval_id TEXT PRIMARY KEY REFERENCES exact_approval_grants(approval_id) ON DELETE RESTRICT,
    initial_uses_remaining INTEGER NOT NULL CHECK (initial_uses_remaining BETWEEN 1 AND 8),
    uses_remaining INTEGER NOT NULL CHECK (uses_remaining >= 0),
    consumed_count INTEGER NOT NULL DEFAULT 0 CHECK (consumed_count >= 0),
    revoked_at TEXT,
    -- Bounded machine-readable revocation reason; never free text.
    revocation_code TEXT CHECK (revocation_code IS NULL OR (
        revocation_code GLOB '[A-Z]*' AND length(revocation_code) BETWEEN 1 AND 64
    )),
    CHECK (uses_remaining + consumed_count = initial_uses_remaining),
    CHECK ((revoked_at IS NULL) = (revocation_code IS NULL))
);

CREATE TRIGGER exact_approval_grant_state_no_delete BEFORE DELETE ON exact_approval_grant_state
BEGIN SELECT RAISE(ABORT, 'grant state rows are never deleted'); END;

-- State may only move along the approved lifecycle: uses decrease by at most
-- one per transaction with a matching consumption increase, the initial bound
-- never changes, and revocation is a one-way transition.
CREATE TRIGGER exact_approval_grant_state_guarded_update
BEFORE UPDATE ON exact_approval_grant_state
WHEN NEW.approval_id != OLD.approval_id
  OR NEW.initial_uses_remaining != OLD.initial_uses_remaining
  OR OLD.revoked_at IS NOT NULL
  OR NEW.consumed_count NOT IN (OLD.consumed_count, OLD.consumed_count + 1)
  OR NEW.uses_remaining != NEW.initial_uses_remaining - NEW.consumed_count
BEGIN SELECT RAISE(ABORT, 'grant state transition is invalid'); END;

PRAGMA user_version = 2;
