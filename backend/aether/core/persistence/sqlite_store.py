"""Transactional SQLite persistence for task plans and audit history.

This store intentionally has no capability executor, grant loader, or mutation
API. Approval decisions written here are immutable audit records only.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path, PureWindowsPath
from typing import BinaryIO, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aether.core.contracts.task import TaskState
from aether.core.persistence.models import (
    DISABLED_EXECUTION_STATES,
    ApprovalDecisionRecord,
    ApprovalDecisionValue,
    DurableReceiptFacts,
    EventMetadata,
    ExecutionEvidence,
    PersistentTaskState,
    TaskPlan,
)
from aether.core.resources.path_safety import (
    PathSafetyError,
    VolumeKind,
    inspect_volume,
    reject_reparse_components,
    relative_parts,
)
from aether.core.security.redaction import redact_text


class PersistenceError(RuntimeError):
    """A storage operation failed closed."""


class PersistenceIntegrityError(PersistenceError):
    """The database failed integrity, schema, or canonical-record validation."""


class PersistenceBusyError(PersistenceError):
    """Another process already owns this database for the application's lifetime."""


class IllegalPersistentTransition(PersistenceError):
    """A requested persistent task-state transition is not allowed."""


class ReviewConflictError(PersistenceError):
    """An idempotency identity was replayed with different immutable review data."""


class StoredTask(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: UUID
    user_goal: str
    state: PersistentTaskState
    plan_revision: int = Field(ge=0)
    plan_hash: str | None
    project_id: str | None
    created_at: datetime
    updated_at: datetime
    finished_at: datetime | None
    last_error_code: str | None


class StoredTaskEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: UUID
    task_id: UUID
    sequence: int = Field(ge=1)
    event_type: str
    step_id: UUID | None
    metadata: EventMetadata
    created_at: datetime


@dataclass(frozen=True)
class Stage2ReviewWrite:
    """Internal outcome of one atomic Stage 2 audit write."""

    resolution: str
    requested_outcome: str
    task_id: UUID
    plan_revision: int
    plan_hash: str
    preview_id: UUID
    preview_digest: str
    review_request_id: UUID
    event_id: UUID | None
    decision_id: UUID | None
    idempotent_replay: bool


@dataclass(frozen=True)
class Stage2ReviewRevocation:
    """Internal result of one idempotent non-authorizing revocation event."""

    task_id: UUID
    plan_revision: int
    plan_hash: str
    preview_digest: str
    revocation_id: UUID
    event_id: UUID | None
    already_recorded: bool


# State vocabulary is Master Spec § Persistent state machine. The Phase 2B
# store deliberately blocks all entry into executor/recovery states.
_TRANSITIONS: dict[PersistentTaskState, frozenset[PersistentTaskState]] = {
    PersistentTaskState.RECEIVED: frozenset(
        {
            PersistentTaskState.RESOLVING_CONTEXT,
            PersistentTaskState.PLANNING,
            PersistentTaskState.CLARIFICATION_REQUIRED,
            PersistentTaskState.CANCELLED,
            PersistentTaskState.FAILED,
        }
    ),
    PersistentTaskState.RESOLVING_CONTEXT: frozenset(
        {
            PersistentTaskState.PLANNING,
            PersistentTaskState.CLARIFICATION_REQUIRED,
            PersistentTaskState.PAUSED,
            PersistentTaskState.CANCELLED,
            PersistentTaskState.FAILED,
        }
    ),
    PersistentTaskState.PLANNING: frozenset(
        {
            PersistentTaskState.VALIDATING,
            PersistentTaskState.PREVIEW_READY,
            PersistentTaskState.CLARIFICATION_REQUIRED,
            PersistentTaskState.PAUSED,
            PersistentTaskState.DENIED,
            PersistentTaskState.CANCELLED,
            PersistentTaskState.FAILED,
        }
    ),
    PersistentTaskState.VALIDATING: frozenset(
        {
            PersistentTaskState.PLANNING,
            PersistentTaskState.PREVIEW_READY,
            PersistentTaskState.AWAITING_APPROVAL,
            PersistentTaskState.CLARIFICATION_REQUIRED,
            PersistentTaskState.PAUSED,
            PersistentTaskState.DENIED,
            PersistentTaskState.CANCELLED,
            PersistentTaskState.FAILED,
        }
    ),
    PersistentTaskState.PREVIEW_READY: frozenset(
        {
            PersistentTaskState.AWAITING_APPROVAL,
            PersistentTaskState.PLANNING,
            PersistentTaskState.DENIED,
            PersistentTaskState.CANCELLED,
            PersistentTaskState.FAILED,
        }
    ),
    PersistentTaskState.AWAITING_APPROVAL: frozenset(
        {
            PersistentTaskState.PLANNING,
            PersistentTaskState.PAUSED,
            PersistentTaskState.DENIED,
            PersistentTaskState.CANCELLED,
            PersistentTaskState.FAILED,
        }
    ),
    PersistentTaskState.PRECHECK: frozenset(),
    PersistentTaskState.EXECUTING: frozenset(),
    PersistentTaskState.POSTCHECK: frozenset(),
    PersistentTaskState.COMPLETED: frozenset(),
    PersistentTaskState.CLARIFICATION_REQUIRED: frozenset(
        {
            PersistentTaskState.RESOLVING_CONTEXT,
            PersistentTaskState.PLANNING,
            PersistentTaskState.CANCELLED,
        }
    ),
    PersistentTaskState.PAUSED: frozenset(
        {
            PersistentTaskState.PLANNING,
            PersistentTaskState.CANCELLED,
            PersistentTaskState.FAILED,
        }
    ),
    PersistentTaskState.DENIED: frozenset(),
    PersistentTaskState.CANCELLED: frozenset(),
    PersistentTaskState.FAILED: frozenset(),
    PersistentTaskState.RECOVERING: frozenset(),
    PersistentTaskState.PARTIALLY_COMPLETED: frozenset(),
    PersistentTaskState.UNVERIFIED: frozenset(),
}

# Narrow execution/recovery transitions (Decision D). Reachable only through
# ``advance_execution_state``, never through the general ``transition_task``
# (which hard-refuses every ``DISABLED_EXECUTION_STATES`` target). Each edge
# names the minimum durable backend evidence the store re-reads from the
# schema-v2 grant ledger inside the transition transaction:
#
# * ``"grant"``       — an issued, unrevoked grant bound to the task's current
#                       plan revision and hash;
# * ``"consumption"`` — ``"grant"`` plus a recorded authoritative consumption
#                       of that grant for this exact task/plan;
# * ``"receipt"``     — ``"consumption"`` plus the executor's verified receipt
#                       identity, which is what makes a success claim honest.
#
# Renderer input, model output and audit-only review records can never create
# these rows, so they can never drive these states. On a schema-v1 database
# the ledger tables do not exist and every edge fails closed.
_EXECUTION_TRANSITIONS: dict[PersistentTaskState, dict[PersistentTaskState, str]] = {
    PersistentTaskState.AWAITING_APPROVAL: {
        PersistentTaskState.PRECHECK: "grant",
    },
    PersistentTaskState.PRECHECK: {
        PersistentTaskState.EXECUTING: "consumption",
        PersistentTaskState.CANCELLED: "grant",
        PersistentTaskState.FAILED: "grant",
        PersistentTaskState.RECOVERING: "grant",
    },
    PersistentTaskState.EXECUTING: {
        PersistentTaskState.POSTCHECK: "consumption",
        PersistentTaskState.RECOVERING: "consumption",
        PersistentTaskState.UNVERIFIED: "consumption",
    },
    PersistentTaskState.POSTCHECK: {
        PersistentTaskState.COMPLETED: "receipt",
        PersistentTaskState.UNVERIFIED: "consumption",
        PersistentTaskState.RECOVERING: "consumption",
    },
    PersistentTaskState.RECOVERING: {
        PersistentTaskState.COMPLETED: "receipt",
        PersistentTaskState.PARTIALLY_COMPLETED: "receipt",
        PersistentTaskState.UNVERIFIED: "consumption",
        PersistentTaskState.FAILED: "grant",
    },
}


# Narrow navigation (T1) execution transitions (CP3-B03). Reachable only
# through ``advance_navigation_state``, which re-reads the durable
# schema-v3 navigation evidence named by each edge's minimum class:
# ``"confirmation"`` (recorded confirmation bound to the current plan),
# ``"attempt"`` (confirmation consumed + durable attempt recorded),
# ``"verification"`` (independently loaded verification), and
# ``"receipt"`` (durable receipt; SUCCEEDED required for COMPLETED).
_NAVIGATION_TRANSITIONS: dict[PersistentTaskState, dict[PersistentTaskState, str]] = {
    PersistentTaskState.AWAITING_APPROVAL: {
        PersistentTaskState.PRECHECK: "confirmation",
    },
    PersistentTaskState.PRECHECK: {
        PersistentTaskState.EXECUTING: "attempt",
        PersistentTaskState.CANCELLED: "confirmation",
        PersistentTaskState.FAILED: "confirmation",
        PersistentTaskState.RECOVERING: "confirmation",
    },
    PersistentTaskState.EXECUTING: {
        PersistentTaskState.POSTCHECK: "attempt",
        PersistentTaskState.RECOVERING: "attempt",
        PersistentTaskState.UNVERIFIED: "attempt",
    },
    PersistentTaskState.POSTCHECK: {
        PersistentTaskState.COMPLETED: "receipt",
        PersistentTaskState.UNVERIFIED: "verification",
        PersistentTaskState.FAILED: "verification",
        PersistentTaskState.RECOVERING: "attempt",
    },
    PersistentTaskState.RECOVERING: {
        PersistentTaskState.COMPLETED: "receipt",
        # UNVERIFIED from recovery is the truthful outcome both when a
        # verification exists and when the attempt was interrupted
        # before verification; the recorded attempt is the minimum.
        PersistentTaskState.UNVERIFIED: "attempt",
        PersistentTaskState.FAILED: "confirmation",
    },
}

_PHASE1_TO_PERSISTENT: dict[TaskState, PersistentTaskState] = {
    TaskState.CREATED: PersistentTaskState.RECEIVED,
    TaskState.PLANNING: PersistentTaskState.PLANNING,
    TaskState.AWAITING_APPROVAL: PersistentTaskState.AWAITING_APPROVAL,
    TaskState.COMPLETED: PersistentTaskState.COMPLETED,
    TaskState.FAILED: PersistentTaskState.FAILED,
    TaskState.CANCELLED: PersistentTaskState.CANCELLED,
    TaskState.PAUSED: PersistentTaskState.PAUSED,
}
_PERSISTENT_TO_PHASE1 = {value: key for key, value in _PHASE1_TO_PERSISTENT.items()}
_ACTIVE_RESTART_STATES = frozenset(
    {
        PersistentTaskState.RECEIVED,
        PersistentTaskState.RESOLVING_CONTEXT,
        PersistentTaskState.PLANNING,
        PersistentTaskState.VALIDATING,
        PersistentTaskState.PREVIEW_READY,
        PersistentTaskState.AWAITING_APPROVAL,
        PersistentTaskState.PRECHECK,
        PersistentTaskState.EXECUTING,
        PersistentTaskState.POSTCHECK,
        PersistentTaskState.RECOVERING,
    }
)
_EVENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_LOWER_PREVIEW_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Migration registry: version -> (filename, SHA-256 of the packaged bytes).
#
# PR #14 (Phase 2B Stage 4) prepares version 2 here. Every entry is verified
# against the packaged bytes before any SQL runs, and the recorded ledger row
# is re-verified on every reopen, so a prepared-but-unauthorized migration
# cannot be applied by accident.
_EXPECTED_MIGRATIONS: dict[int, tuple[str, str]] = {
    1: (
        "0001_phase2b_core.sql",
        "709077298230c7065c6778b3149f93b679b6e678220e2d1a34d3540a348d741e",
    ),
    2: (
        "0002_phase2b_stage4_grants.sql",
        # Independently recomputed from the packaged bytes, not copied from
        # documentation (see docs/engineering/PHASE2B_STAGE4_MIGRATION.md).
        "d2a02f54bc2f0eaee19fe1fd29c58294efbb136565145866d3c4853b8d64571c",
    ),
    # Phase 3 navigation evidence: PREPARED ONLY. Activation requires a
    # separate owner decision; see docs/engineering/PHASE3_R1_DESIGN.md.
    3: (
        "0003_phase3_navigation.sql",
        "6d165d8a3f56634619b1340ca310aa7d0057c9b6438d461919f34d1a64dcd4dc",
    ),
}
_EXPECTED_SCHEMA_SHA256: dict[int, str] = {
    # v3 fingerprint computed from a synthetic isolated database after
    # applying 0001-0003; v3 remains PENDING (never the active target).
    3: "880a6a58b8ac1639f86b3a06dc21294a32608b9688c9b845183809732a762904",
    1: "02f3cac7e905dfb4d1f161621c789bd5c437530002dec36202e9b2dfaa5d2e30",
    2: "dec68c2c1ecdd6d7222b5dcff54b877c9895e5cee6329930148c5db97355b788",
}

# ---------------------------------------------------------------------------
# Migration activation (Phase 2B Stage 4, PR #14)
# ---------------------------------------------------------------------------
#
# Registering a migration is *preparation*; making it the schema this build
# creates and accepts is *activation*. They are deliberately separate:
#
# * ``_EXPECTED_MIGRATIONS`` / ``_EXPECTED_SCHEMA_SHA256`` list every known
#   version, so their packaged bytes and fingerprints are verified on every
#   single open — even while a version is inactive.
# * ``ACTIVE_SCHEMA_VERSION`` is the version this build creates and accepts.
#   It is one, so a prepared-but-unapproved version changes nothing about user
#   databases.
# * ``PENDING_MIGRATION_VERSIONS`` records versions that are prepared but must
#   never run until explicitly authorized. Activation refuses to target a
#   pending version, so bumping the active version alone cannot apply one.
#
# Activation record (Proposal A, PR #36): version 2 was activated by
# explicit user authorization for a controlled Windows acceptance
# candidate, after independent review of the FI-01..FI-08 corrections.
# This build therefore creates and accepts schema version 2 and applies
# migration 0002 through the verified migration path. Production grant
# issuance remains disabled (Proposal B is a separate, unapproved
# change); activation of the schema does not enable issuance.
# Existing real user databases are NOT migrated by this code change in
# the acceptance candidate: the acceptance configuration uses only
# disposable fixture storage (AETHER_FIXTURE_DB / AETHER_APP_DB inside
# an isolated fixture directory), and migrating any pre-existing real
# database still requires separate authorization and a verified backup.
ACTIVE_SCHEMA_VERSION = 2
PENDING_MIGRATION_VERSIONS: frozenset[int] = frozenset({3})


def _activation_error(version: int) -> str:
    return (
        f"migration {version} is registered but not authorized to apply; activating it "
        "requires explicit approval, and this build refuses to apply it"
    )


# Objects each schema version must contain. Version 2 is a strict superset of
# version 1: 0002 only adds the grant ledger, so an upgraded v1 database and a
# clean v2 install must be indistinguishable in what they guarantee.
_CRITICAL_TRIGGER_NAMES_V1 = frozenset(
    {
        "task_plans_no_update",
        "task_plans_no_delete",
        "task_steps_no_update",
        "task_steps_no_delete",
        "task_events_no_update",
        "task_events_no_delete",
        "approval_records_no_update",
        "approval_records_no_delete",
    }
)
_CRITICAL_TRIGGER_NAMES_V2 = _CRITICAL_TRIGGER_NAMES_V1 | {
    "exact_approval_grants_scope_no_update",
    "exact_approval_grant_events_no_update",
    "exact_approval_grant_events_no_delete",
    "exact_approval_grant_consumptions_no_update",
    "exact_approval_grant_consumptions_no_delete",
    "exact_approval_grant_state_guarded_update",
    "exact_approval_grant_state_no_delete",
}
_CRITICAL_TABLES_V1 = frozenset(
    {
        "schema_migrations",
        "tasks",
        "task_plans",
        "task_steps",
        "task_events",
        "approval_records",
    }
)
_CRITICAL_TABLES_V2 = _CRITICAL_TABLES_V1 | {
    "exact_approval_grants",
    "exact_approval_grant_state",
    "exact_approval_grant_events",
    "exact_approval_grant_consumptions",
}

_CRITICAL_TABLES_V3 = _CRITICAL_TABLES_V2 | {
    "navigation_confirmations",
    "navigation_attempts",
    "navigation_verifications",
    "navigation_receipts",
}
_CRITICAL_TRIGGER_NAMES_V3 = _CRITICAL_TRIGGER_NAMES_V2 | {
    "navigation_confirmations_no_delete",
    "navigation_confirmations_binding_no_update",
    "navigation_receipts_success_requires_verification",
    "navigation_attempts_no_update",
    "navigation_attempts_no_delete",
    "navigation_verifications_no_update",
    "navigation_verifications_no_delete",
    "navigation_receipts_no_update",
    "navigation_receipts_no_delete",
}
_SCHEMA_REQUIREMENTS: dict[int, tuple[frozenset[str], frozenset[str]]] = {
    1: (_CRITICAL_TABLES_V1, _CRITICAL_TRIGGER_NAMES_V1),
    2: (_CRITICAL_TABLES_V2, _CRITICAL_TRIGGER_NAMES_V2),
    3: (_CRITICAL_TABLES_V3, _CRITICAL_TRIGGER_NAMES_V3),
}

# Backwards-compatible alias: the highest version's trigger inventory.
_CRITICAL_TRIGGER_NAMES = _CRITICAL_TRIGGER_NAMES_V2


def persistent_state_from_phase1(state: TaskState) -> PersistentTaskState:
    """Explicitly map compatible Phase 1 states; never mutate its contract."""
    try:
        return _PHASE1_TO_PERSISTENT[state]
    except KeyError as exc:
        raise ValueError(f"Phase 1 state {state.value} has no Phase 2B mapping") from exc


def phase1_state_from_persistent(state: PersistentTaskState) -> TaskState:
    """Map only states representable by Phase 1; richer states are not coerced."""
    try:
        return _PERSISTENT_TO_PHASE1[state]
    except KeyError as exc:
        raise ValueError(f"persistent state {state.value} has no Phase 1 mapping") from exc


class SQLiteTaskStore:
    """Versioned SQLite task/plan/audit store with fail-closed startup recovery."""

    def __init__(
        self,
        database_path: Path | str,
        *,
        migrations_dir: Path | Traversable | None = None,
    ) -> None:
        try:
            raw_database_path = os.fspath(database_path)
        except TypeError as exc:
            raise PersistenceError("database path must be text or a path-like object") from exc
        if not isinstance(raw_database_path, str):
            raise PersistenceError("database path must be text or a path-like object")
        _validate_raw_database_path(raw_database_path)
        expanded_database_path = Path(raw_database_path).expanduser()
        _validate_raw_database_path(os.fspath(expanded_database_path))
        self.database_path = expanded_database_path
        self._lock = threading.RLock()
        self._owner_lock_file: BinaryIO | None = None
        self._closed = False
        # FI-03: loader for durable receipt facts (separate receipts
        # database), registered by the composition. Without it, no
        # receipt-gated transition (COMPLETED) can ever be satisfied.
        self._receipt_evidence_source: Callable[[UUID], DurableReceiptFacts | None] | None = None
        self._storage_volume_id = ""
        self._parent_identity: tuple[int, int] | None = None
        self._database_identity: tuple[int, int] | None = None
        self._migrations_dir = migrations_dir or files("aether.core.persistence").joinpath(
            "migrations"
        )
        try:
            self._verified_migrations = self._load_verified_migrations()
            self._prepare_private_path()
            self._acquire_owner_lock()
            self._secure_database_permissions()
            self._connection = sqlite3.connect(
                self.database_path,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA secure_delete = ON")
            self._verify_database_location()
            self._secure_database_permissions()
            self._check_integrity()
            self._apply_migrations()
            self._verify_schema()
            self._check_integrity()
            journal_mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if journal_mode.casefold() != "wal":
                raise PersistenceError("SQLite WAL mode is unavailable")
            self._verify_database_location()
            self.recover_on_startup()
        except (sqlite3.Error, OSError, PersistenceError, PathSafetyError) as exc:
            if hasattr(self, "_connection"):
                self._connection.close()
            self._release_owner_lock()
            if isinstance(exc, PersistenceError):
                raise
            raise PersistenceError("database initialization failed closed") from exc

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._connection.close()
            finally:
                self._release_owner_lock()
                self._closed = True

    def __enter__(self) -> SQLiteTaskStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def create_task(
        self,
        user_goal: str,
        *,
        task_id: UUID | None = None,
        project_id: str | None = None,
        now: datetime | None = None,
    ) -> StoredTask:
        if not user_goal.strip() or len(user_goal) > 8000:
            raise ValueError("task goal must contain 1 to 8000 characters")
        if project_id is not None and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", project_id):
            raise ValueError("project ID must be an opaque identifier, not a path")
        safe_goal = redact_text(user_goal)
        created = _timestamp(now)
        identifier = task_id or uuid4()
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO tasks(id, user_goal, state, project_id, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(identifier),
                    safe_goal,
                    PersistentTaskState.RECEIVED.value,
                    project_id,
                    created,
                    created,
                ),
            )
            self._append_event(
                connection,
                identifier,
                "TASK_CREATED",
                EventMetadata(values={"state": PersistentTaskState.RECEIVED.value}),
                now=created,
            )
        return self.get_task(identifier)

    def get_task(self, task_id: UUID) -> StoredTask:
        with self._lock:
            self._verify_database_location()
            row = self._connection.execute(
                "SELECT * FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
        if row is None:
            raise KeyError("unknown task id")
        return self._task_from_row(row)

    def transition_task(
        self,
        task_id: UUID,
        to_state: PersistentTaskState,
        *,
        event_type: str | None = None,
        metadata: EventMetadata | None = None,
        error_code: str | None = None,
        now: datetime | None = None,
    ) -> StoredTask:
        if to_state in DISABLED_EXECUTION_STATES:
            raise IllegalPersistentTransition(
                "Phase 2B does not permit execution or recovery states"
            )
        if error_code is not None and not _ERROR_CODE.fullmatch(error_code):
            raise ValueError("error code must be a redacted lowercase code")
        event = event_type or f"TASK_{to_state.value}"
        self._validate_event_name(event)
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            row = connection.execute("SELECT * FROM tasks WHERE id = ?", (str(task_id),)).fetchone()
            if row is None:
                raise KeyError("unknown task id")
            current = PersistentTaskState(row["state"])
            if to_state not in _TRANSITIONS[current]:
                raise IllegalPersistentTransition(
                    f"illegal task transition: {current} -> {to_state}"
                )
            values = dict((metadata or EventMetadata()).values)
            self._commit_transition_unlocked(
                connection,
                task_id,
                current,
                to_state,
                event_type=event,
                metadata_values=values,
                now=timestamp,
                error_code=error_code,
            )
        return self.get_task(task_id)

    def set_receipt_evidence_source(
        self, source: Callable[[UUID], DurableReceiptFacts | None] | None
    ) -> None:
        """Register the durable-receipt loader used for FI-03 verification.

        The composition registers the real ``ReceiptStore`` loader once the
        sibling receipts database exists. Registration is deliberately not
        a constructor concern: the store is opened by the review surface
        before the trusted tier is composed, and receipt-gated transitions
        must fail closed until a real source is registered.
        """

        self._receipt_evidence_source = source

    def advance_execution_state(
        self,
        task_id: UUID,
        to_state: PersistentTaskState,
        *,
        evidence: ExecutionEvidence,
        now: datetime | None = None,
    ) -> StoredTask:
        """Advance a task through one narrow execution/recovery transition.

        This is the *only* way to enter ``PRECHECK``, ``EXECUTING``,
        ``POSTCHECK``, ``RECOVERING``, ``PARTIALLY_COMPLETED`` or
        ``UNVERIFIED`` (and to leave them for ``COMPLETED``/``FAILED``/
        ``CANCELLED``); the general :meth:`transition_task` hard-refuses those
        targets. The transition is granted only when the store itself, inside
        this transaction, re-reads the durable backend evidence the edge
        requires from the schema-v2 grant ledger (see
        ``_EXECUTION_TRANSITIONS``): the authoritative grant bound to the
        task's *current* plan revision/hash, a recorded consumption of it, and
        — for any success claim — the executor's verified receipt identity.

        Renderer input, model output and audit-only review records cannot
        create those rows and therefore can never drive these states. On a
        schema-v1 database the ledger tables do not exist and this method
        fails closed, so the shipped configuration (schema v1) keeps every
        execution state unreachable until schema activation is separately
        approved.
        """
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            if int(connection.execute("PRAGMA user_version").fetchone()[0]) < 2:
                raise IllegalPersistentTransition(
                    "execution/recovery states require the schema version 2 grant ledger"
                )
            row = connection.execute(
                "SELECT state, plan_revision, plan_hash FROM tasks WHERE id = ?",
                (str(task_id),),
            ).fetchone()
            if row is None:
                raise KeyError("unknown task id")
            current = PersistentTaskState(row["state"])
            required = _EXECUTION_TRANSITIONS.get(current, {}).get(to_state)
            if required is None:
                raise IllegalPersistentTransition(
                    f"illegal execution transition: {current} -> {to_state}"
                )
            if (
                to_state is PersistentTaskState.UNVERIFIED
                and not evidence.mutation_may_have_happened
            ):
                raise IllegalPersistentTransition(
                    "an UNVERIFIED claim requires evidence the mutation may have happened"
                )
            plan_revision = int(row["plan_revision"])
            plan_hash = row["plan_hash"]
            grant = connection.execute(
                "SELECT g.approval_id AS approval_id, s.revoked_at AS revoked_at "
                "FROM exact_approval_grants AS g "
                "JOIN exact_approval_grant_state AS s ON s.approval_id = g.approval_id "
                "WHERE g.approval_id = ? AND g.task_id = ? AND g.plan_revision = ? "
                "AND g.plan_hash = ?",
                (str(evidence.approval_id), str(task_id), plan_revision, plan_hash),
            ).fetchone()
            if grant is None or grant["revoked_at"] is not None:
                raise IllegalPersistentTransition(
                    "execution evidence names no live grant for the task's current plan"
                )
            if required in ("consumption", "receipt"):
                consumed = connection.execute(
                    "SELECT 1 FROM exact_approval_grant_consumptions "
                    "WHERE approval_id = ? AND task_id = ? AND plan_revision = ? "
                    "AND plan_hash = ? LIMIT 1",
                    (str(evidence.approval_id), str(task_id), plan_revision, plan_hash),
                ).fetchone()
                if consumed is None:
                    raise IllegalPersistentTransition(
                        "execution evidence names no recorded grant consumption for this task"
                    )
            if required == "receipt":
                self._verify_receipt_evidence(
                    connection,
                    task_id=task_id,
                    plan_revision=plan_revision,
                    evidence=evidence,
                )
            values: dict[str, str | int | float | bool | None] = {
                "approval_id": str(evidence.approval_id),
                "authority": "BACKEND_EXECUTION_EVIDENCE",
            }
            if evidence.receipt_id is not None:
                values["receipt_id"] = str(evidence.receipt_id)
            if evidence.mutation_may_have_happened:
                values["mutation_may_have_happened"] = True
            self._commit_transition_unlocked(
                connection,
                task_id,
                current,
                to_state,
                event_type=f"TASK_{to_state.value}",
                metadata_values=values,
                now=timestamp,
                error_code=None,
            )
        return self.get_task(task_id)

    # -- Phase 3 navigation evidence integration (CP3-B03) -----------------
    # One authoritative task-state machine: navigation (T1) execution
    # states are entered only through ``advance_navigation_state``,
    # which derives the evidence class from the *persisted* plan step's
    # registered capability and re-reads the durable navigation
    # evidence (schema v3, prepared-only) inside the transition
    # transaction. T1 navigation evidence can never satisfy the T2
    # grant/consumption/receipt edges in ``advance_execution_state``,
    # and this path refuses tasks whose persisted capability is not a
    # trusted navigation capability. On a pre-v3 database every method
    # here fails closed.

    @staticmethod
    def _navigation_capability_ids() -> frozenset[str]:
        from aether.core.contracts.policy import RiskTier
        from aether.core.policy.capabilities import CapabilityRegistry

        registry = CapabilityRegistry.phase3_with_uia()
        return frozenset(
            definition.capability_id
            for definition in registry.definitions()
            if definition.risk_tier == RiskTier.NAVIGATE
        )

    def _require_navigation_schema(self, connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version < 3:
            raise IllegalPersistentTransition(
                "navigation evidence requires the prepared schema v3 (not activated)"
            )

    def _persisted_step_capability(
        self, connection: sqlite3.Connection, task_id: UUID, step_id: UUID, plan_revision: int
    ) -> str:
        row = connection.execute(
            "SELECT capability_id FROM task_steps WHERE task_id = ? AND plan_revision = ? AND id = ?",
            (str(task_id), plan_revision, str(step_id)),
        ).fetchone()
        if row is None:
            raise IllegalPersistentTransition("navigation evidence names no persisted plan step")
        return str(row["capability_id"])

    def _check_navigation_binding(
        self,
        connection: sqlite3.Connection,
        *,
        task_id: UUID,
        step_id: UUID,
        confirmation_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT state, plan_revision, plan_hash FROM tasks WHERE id = ?", (str(task_id),)
        ).fetchone()
        if row is None:
            raise KeyError("unknown task id")
        confirmation = connection.execute(
            "SELECT * FROM navigation_confirmations WHERE id = ?", (confirmation_id,)
        ).fetchone()
        if confirmation is None:
            raise IllegalPersistentTransition("navigation confirmation is not recorded")
        capability = self._persisted_step_capability(
            connection, task_id, step_id, int(row["plan_revision"])
        )
        if capability not in self._navigation_capability_ids():
            raise IllegalPersistentTransition(
                "persisted capability is not a navigation capability; "
                "navigation evidence cannot drive this task"
            )
        if (
            confirmation["task_id"] != str(task_id)
            or confirmation["step_id"] != str(step_id)
            or int(confirmation["plan_revision"]) != int(row["plan_revision"])
            or confirmation["plan_hash"] != row["plan_hash"]
            or confirmation["capability_id"] != capability
        ):
            raise IllegalPersistentTransition(
                "navigation confirmation does not bind the task's current plan and step"
            )
        return cast(sqlite3.Row, confirmation)

    def record_navigation_confirmation(
        self,
        *,
        confirmation_id: str,
        task_id: UUID,
        step_id: UUID,
        capability_id: str,
        arguments_sha256: str,
        binding_sha256: str,
        app_resource_id: str,
        expected_app_version: str,
        integrity_evidence_sha256: str,
        session_id: str,
        activation_scope: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> None:
        """Persist a trusted confirmation bound to the current plan.

        Actual issuance/expiry from the trusted confirmer are stored;
        nothing is manufactured at execution time.
        """
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            row = connection.execute(
                "SELECT plan_revision, plan_hash FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
            if row is None:
                raise KeyError("unknown task id")
            capability = self._persisted_step_capability(
                connection, task_id, step_id, int(row["plan_revision"])
            )
            if capability != capability_id or capability not in self._navigation_capability_ids():
                raise IllegalPersistentTransition(
                    "confirmation capability does not match the persisted navigation step"
                )
            try:
                connection.execute(
                    "INSERT INTO navigation_confirmations(id, task_id, step_id, plan_revision,"
                    " plan_hash, capability_id, arguments_sha256, binding_sha256, app_resource_id,"
                    " expected_app_version, integrity_evidence_sha256, session_id,"
                    " activation_scope, issued_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        confirmation_id,
                        str(task_id),
                        str(step_id),
                        int(row["plan_revision"]),
                        row["plan_hash"],
                        capability_id,
                        arguments_sha256,
                        binding_sha256,
                        app_resource_id,
                        expected_app_version,
                        integrity_evidence_sha256,
                        session_id,
                        activation_scope,
                        _timestamp(issued_at),
                        _timestamp(expires_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise IllegalPersistentTransition(
                    "navigation confirmation could not be recorded for this plan"
                ) from exc

    def revoke_navigation_confirmation(self, confirmation_id: str, *, now: datetime) -> None:
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            cursor = connection.execute(
                "UPDATE navigation_confirmations SET revoked_at = ?"
                " WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL",
                (_timestamp(now), confirmation_id),
            )
            if cursor.rowcount != 1:
                raise IllegalPersistentTransition("confirmation is not revocable")

    def _begin_attempt_unlocked(
        self,
        connection: sqlite3.Connection,
        *,
        task_id: UUID,
        step_id: UUID,
        confirmation_id: str,
        timestamp: str,
    ) -> str:
        confirmation = self._check_navigation_binding(
            connection, task_id=task_id, step_id=step_id, confirmation_id=confirmation_id
        )
        if confirmation["revoked_at"] is not None:
            raise IllegalPersistentTransition("navigation confirmation is revoked")
        if confirmation["consumed_at"] is not None:
            raise IllegalPersistentTransition("navigation confirmation was already consumed")
        if str(confirmation["expires_at"]) <= timestamp:
            raise IllegalPersistentTransition("navigation confirmation has expired")
        cursor = connection.execute(
            "UPDATE navigation_confirmations SET consumed_at = ?"
            " WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL",
            (timestamp, confirmation_id),
        )
        if cursor.rowcount != 1:
            raise IllegalPersistentTransition("navigation confirmation consumption raced")
        attempt_id = str(uuid4())
        connection.execute(
            "INSERT INTO navigation_attempts(id, confirmation_id, task_id, step_id,"
            " capability_id, app_resource_id, attempt_number, recorded_at)"
            " VALUES (?,?,?,?,?,?,1,?)",
            (
                attempt_id,
                confirmation_id,
                str(task_id),
                str(step_id),
                confirmation["capability_id"],
                confirmation["app_resource_id"],
                timestamp,
            ),
        )
        return attempt_id

    def begin_navigation_attempt(
        self, *, task_id: UUID, step_id: UUID, confirmation_id: str, now: datetime
    ) -> str:
        """Atomically consume the confirmation and record the attempt.

        This durable commit happens *before* any external effect; if
        it fails, no launch may occur. Consumption is a guarded
        update: concurrent or replayed consumption matches no row.
        """
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            return self._begin_attempt_unlocked(
                connection,
                task_id=task_id,
                step_id=step_id,
                confirmation_id=confirmation_id,
                timestamp=timestamp,
            )

    def commit_navigation_attempt(
        self, *, task_id: UUID, step_id: UUID, confirmation_id: str, now: datetime
    ) -> str:
        """Execution commitment boundary (CP3-R01/R02), one transaction.

        Consumes the confirmation, records the durable attempt and
        transitions PRECHECK -> EXECUTING atomically. A crash before
        this commit leaves the task in PRECHECK with an unconsumed
        confirmation (distinguishable, cancellable); a crash after it
        leaves an EXECUTING task with a committed attempt that
        reconciliation resolves truthfully. No external effect may be
        attempted before this method returns.
        """
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            row = connection.execute(
                "SELECT state FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
            if row is None:
                raise KeyError("unknown task id")
            current = PersistentTaskState(row["state"])
            if current is not PersistentTaskState.PRECHECK:
                raise IllegalPersistentTransition(
                    "execution commitment requires the task to be in PRECHECK"
                )
            attempt_id = self._begin_attempt_unlocked(
                connection,
                task_id=task_id,
                step_id=step_id,
                confirmation_id=confirmation_id,
                timestamp=timestamp,
            )
            self._commit_transition_unlocked(
                connection,
                task_id,
                current,
                PersistentTaskState.EXECUTING,
                event_type="TASK_EXECUTING",
                metadata_values={
                    "confirmation_id": confirmation_id,
                    "attempt_id": attempt_id,
                    "authority": "BACKEND_NAVIGATION_EVIDENCE",
                },
                now=timestamp,
                error_code=None,
            )
        return attempt_id

    def record_navigation_verification(
        self,
        *,
        attempt_id: str,
        outcome: str,
        process_token: str | None,
        window_token: str | None,
        now: datetime,
    ) -> str:
        from aether.core.apps.navigation_outcomes import VERIFIED_OUTCOMES, NavigationOutcome

        parsed = NavigationOutcome(outcome)
        if parsed in VERIFIED_OUTCOMES and process_token is None:
            raise IllegalPersistentTransition(
                "a verified outcome requires observed process identity"
            )
        if (
            parsed
            in (
                NavigationOutcome.VERIFIED_NEW_INSTANCE,
                NavigationOutcome.VERIFIED_EXISTING_INSTANCE,
            )
            and window_token is None
        ):
            raise IllegalPersistentTransition(
                "this verified outcome requires observed window identity"
            )
        verification_id = str(uuid4())
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            if (
                connection.execute(
                    "SELECT 1 FROM navigation_attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                is None
            ):
                raise IllegalPersistentTransition("verification names no recorded attempt")
            try:
                connection.execute(
                    "INSERT INTO navigation_verifications(id, attempt_id, outcome,"
                    " process_instance_token, window_version_token, verified_at)"
                    " VALUES (?,?,?,?,?,?)",
                    (
                        verification_id,
                        attempt_id,
                        parsed.value,
                        process_token,
                        window_token,
                        _timestamp(now),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise IllegalPersistentTransition("navigation verification was rejected") from exc
        return verification_id

    def record_navigation_receipt(
        self, *, attempt_id: str, verification_id: str, now: datetime
    ) -> str:
        """Record the receipt whose status derives from the verification."""
        from aether.core.apps.navigation_outcomes import NavigationOutcome, receipt_status_for

        receipt_id = str(uuid4())
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            row = connection.execute(
                "SELECT attempt_id, outcome FROM navigation_verifications WHERE id = ?",
                (verification_id,),
            ).fetchone()
            if row is None or row["attempt_id"] != attempt_id:
                raise IllegalPersistentTransition("receipt does not match its verification")
            status = receipt_status_for(NavigationOutcome(row["outcome"]))
            try:
                connection.execute(
                    "INSERT INTO navigation_receipts(id, attempt_id, verification_id, status,"
                    " recovery_class, created_at) VALUES (?,?,?,?,?,?)",
                    (
                        receipt_id,
                        attempt_id,
                        verification_id,
                        status,
                        "IRREVERSIBLE",
                        _timestamp(now),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise IllegalPersistentTransition("navigation receipt was rejected") from exc
        return receipt_id

    def advance_navigation_state(
        self,
        task_id: UUID,
        to_state: PersistentTaskState,
        *,
        step_id: UUID,
        confirmation_id: str,
        attempt_id: str | None = None,
        now: datetime | None = None,
    ) -> StoredTask:
        """Advance a navigation task on durable navigation evidence only.

        The evidence class is derived from the persisted plan step's
        capability; there is no caller-controlled override. A task
        whose persisted capability is a T2 mutation capability can
        never be advanced here.
        """
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            confirmation = self._check_navigation_binding(
                connection, task_id=task_id, step_id=step_id, confirmation_id=confirmation_id
            )
            row = connection.execute(
                "SELECT state FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
            current = PersistentTaskState(row["state"])
            required = _NAVIGATION_TRANSITIONS.get(current, {}).get(to_state)
            if required is None:
                raise IllegalPersistentTransition(
                    f"illegal navigation transition: {current} -> {to_state}"
                )
            attempt_row = None
            if attempt_id is not None:
                attempt_row = connection.execute(
                    "SELECT * FROM navigation_attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
            if required in ("attempt", "verification", "receipt"):
                if attempt_row is None or attempt_row["confirmation_id"] != confirmation_id:
                    raise IllegalPersistentTransition(
                        "navigation transition requires the recorded attempt for this confirmation"
                    )
                if confirmation["consumed_at"] is None:
                    raise IllegalPersistentTransition(
                        "navigation attempt exists without confirmation consumption"
                    )
            verification_row = None
            if required in ("verification", "receipt"):
                verification_row = connection.execute(
                    "SELECT * FROM navigation_verifications WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if verification_row is None:
                    raise IllegalPersistentTransition(
                        "navigation transition requires recorded verification evidence"
                    )
            if required == "receipt":
                receipt_row = connection.execute(
                    "SELECT * FROM navigation_receipts WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
                if receipt_row is None:
                    raise IllegalPersistentTransition(
                        "navigation completion requires the durable receipt"
                    )
                if (
                    to_state is PersistentTaskState.COMPLETED
                    and receipt_row["status"] != "SUCCEEDED"
                ):
                    raise IllegalPersistentTransition(
                        "only a SUCCEEDED navigation receipt can complete a task"
                    )
            values: dict[str, str | int | float | bool | None] = {
                "confirmation_id": confirmation_id,
                "authority": "BACKEND_NAVIGATION_EVIDENCE",
            }
            if attempt_id is not None:
                values["attempt_id"] = attempt_id
            self._commit_transition_unlocked(
                connection,
                task_id,
                current,
                to_state,
                event_type=f"TASK_{to_state.value}",
                metadata_values=values,
                now=timestamp,
                error_code=None,
            )
        return self.get_task(task_id)

    def reconcile_navigation_tasks(self, *, now: datetime | None = None) -> list[tuple[UUID, str]]:
        """Durably reconcile interrupted navigation attempts; never replay.

        Crash after attempt (no verification) -> UNVERIFIED. Crash
        after verification (no receipt) -> the receipt is derived from
        the recorded verification, then COMPLETED only when the
        verification is affirmative, else UNVERIFIED. Crash after
        receipt -> COMPLETED/UNVERIFIED per the receipt. No launch is
        ever re-attempted here.
        """
        timestamp = _timestamp(now)
        outcomes: list[tuple[UUID, str]] = []
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            rows = connection.execute(
                "SELECT t.id AS task_id, t.state AS state, a.id AS attempt_id,"
                " a.step_id AS step_id, a.confirmation_id AS confirmation_id,"
                " v.id AS verification_id, v.outcome AS outcome,"
                " r.id AS receipt_id, r.status AS receipt_status"
                " FROM tasks t"
                " JOIN navigation_attempts a ON a.task_id = t.id"
                " LEFT JOIN navigation_verifications v ON v.attempt_id = a.id"
                " LEFT JOIN navigation_receipts r ON r.attempt_id = a.id"
                " WHERE t.state IN ('PRECHECK', 'EXECUTING', 'POSTCHECK', 'RECOVERING')"
            ).fetchall()
        for row in rows:
            task_id = UUID(row["task_id"])
            step_id = UUID(row["step_id"])
            try:
                if row["state"] == "PRECHECK":
                    # Attempt committed but EXECUTING never reached:
                    # within this architecture the adapter is gated on
                    # EXECUTING, so no external effect occurred. The
                    # consumed confirmation is never replayed.
                    self.advance_navigation_state(
                        task_id,
                        PersistentTaskState.FAILED,
                        step_id=step_id,
                        confirmation_id=row["confirmation_id"],
                        now=now,
                    )
                    outcomes.append((task_id, PersistentTaskState.FAILED.value))
                    continue
                if row["verification_id"] is not None and row["receipt_id"] is None:
                    self.record_navigation_receipt(
                        attempt_id=row["attempt_id"],
                        verification_id=row["verification_id"],
                        now=now or datetime.now(UTC),
                    )
                if row["verification_id"] is None:
                    target = PersistentTaskState.UNVERIFIED
                else:
                    from aether.core.apps.navigation_outcomes import (
                        VERIFIED_OUTCOMES,
                        NavigationOutcome,
                    )

                    target = (
                        PersistentTaskState.COMPLETED
                        if NavigationOutcome(row["outcome"]) in VERIFIED_OUTCOMES
                        else PersistentTaskState.UNVERIFIED
                    )
                # Drive through RECOVERING when the task was mid-flight.
                state = PersistentTaskState(row["state"])
                if state is not PersistentTaskState.RECOVERING:
                    self.advance_navigation_state(
                        task_id,
                        PersistentTaskState.RECOVERING,
                        step_id=step_id,
                        confirmation_id=row["confirmation_id"],
                        attempt_id=row["attempt_id"],
                        now=now,
                    )
                self.advance_navigation_state(
                    task_id,
                    target,
                    step_id=step_id,
                    confirmation_id=row["confirmation_id"],
                    attempt_id=row["attempt_id"],
                    now=now,
                )
                outcomes.append((task_id, target.value))
            except IllegalPersistentTransition:
                continue
        _ = timestamp
        return outcomes

    # -- exact UI-operation evidence (CP5, schema v3 prepared only) ------
    # A separate evidence class: T1 navigation evidence never authorizes
    # a UI interaction and UI evidence never authorizes navigation or
    # filesystem edits. Only bound identities/digests/outcome tokens are
    # stored — never UIA content, names or values.

    # F09: explicit capability-specific execution-evidence
    # classification. Only the specifically approved fixture
    # interaction may use the T2 UI-operation evidence class;
    # read-only UIA inspection capabilities never enter it.
    _UI_EFFECTFUL_CAPABILITY_IDS: frozenset[str] = frozenset({"uia.invoke_fixture"})

    @classmethod
    def _ui_capability_ids(cls) -> frozenset[str]:
        return cls._UI_EFFECTFUL_CAPABILITY_IDS

    def _check_ui_binding(
        self,
        connection: sqlite3.Connection,
        *,
        task_id: UUID,
        step_id: UUID,
        binding_id: str,
        expected_session_id: str | None = None,
        expected_activation_scope: str | None = None,
    ) -> sqlite3.Row:
        """F09: exact authoritative comparison of every binding field.

        All values are derived from the authoritative persisted plan
        (task row, plan revision/hash, persisted step arguments and
        digests) — caller-provided binding fields are never trusted.
        """
        row = connection.execute(
            "SELECT state, plan_revision, plan_hash FROM tasks WHERE id = ?", (str(task_id),)
        ).fetchone()
        if row is None:
            raise KeyError("unknown task id")
        binding = connection.execute(
            "SELECT * FROM ui_operation_bindings WHERE id = ?", (binding_id,)
        ).fetchone()
        if binding is None:
            raise IllegalPersistentTransition("ui operation binding is not recorded")
        capability = self._persisted_step_capability(
            connection, task_id, step_id, int(row["plan_revision"])
        )
        if capability not in self._UI_EFFECTFUL_CAPABILITY_IDS:
            raise IllegalPersistentTransition(
                "persisted capability is not approved for the UI-operation evidence class"
            )
        step_row = connection.execute(
            "SELECT args_json, expected_state_json FROM task_steps"
            " WHERE task_id = ? AND plan_revision = ? AND id = ?",
            (str(task_id), int(row["plan_revision"]), str(step_id)),
        ).fetchone()
        if step_row is None:
            raise IllegalPersistentTransition("ui binding names no persisted plan step")
        import json as _json

        from aether.core.apps.ui_binding import arguments_digest

        persisted_arguments = _json.loads(step_row["args_json"])
        persisted_state = _json.loads(step_row["expected_state_json"])
        mismatches: list[str] = []
        if binding["task_id"] != str(task_id):
            mismatches.append("task")
        if binding["step_id"] != str(step_id):
            mismatches.append("step")
        if int(binding["plan_revision"]) != int(row["plan_revision"]):
            mismatches.append("plan_revision")
        if binding["plan_hash"] != row["plan_hash"]:
            mismatches.append("plan_hash")
        if binding["capability_id"] != capability:
            mismatches.append("capability")
        if binding["arguments_sha256"] != arguments_digest(persisted_arguments):
            mismatches.append("arguments")
        if binding["window_resource_id"] != persisted_arguments.get("resource_id"):
            mismatches.append("window_resource")
        if binding["snapshot_id"] != persisted_arguments.get("snapshot_id"):
            mismatches.append("snapshot")
        if binding["element_ref"] != persisted_arguments.get("element_ref"):
            mismatches.append("element")
        expected_effect = persisted_state.get("intended_effect")
        if expected_effect is not None and binding["intended_effect"] != expected_effect:
            mismatches.append("intended_effect")
        if expected_session_id is not None and binding["session_id"] != expected_session_id:
            mismatches.append("session")
        if (
            expected_activation_scope is not None
            and binding["activation_scope"] != expected_activation_scope
        ):
            mismatches.append("activation_scope")
        if mismatches:
            raise IllegalPersistentTransition(
                "ui operation binding mismatch: " + ",".join(mismatches)
            )
        return cast(sqlite3.Row, binding)

    def record_ui_binding(
        self,
        *,
        binding_id: str,
        task_id: UUID,
        step_id: UUID,
        capability_id: str,
        arguments_sha256: str,
        binding_sha256: str,
        app_resource_id: str,
        window_resource_id: str,
        window_version_token: str,
        snapshot_id: str,
        snapshot_generation: int,
        element_ref: str,
        element_runtime_id: str,
        pattern: str,
        intended_effect: str,
        expected_precondition: str = "",
        expected_postcondition: str = "",
        session_id: str,
        activation_scope: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> None:
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            row = connection.execute(
                "SELECT plan_revision, plan_hash FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
            if row is None:
                raise KeyError("unknown task id")
            capability = self._persisted_step_capability(
                connection, task_id, step_id, int(row["plan_revision"])
            )
            if capability != capability_id or capability not in self._ui_capability_ids():
                raise IllegalPersistentTransition(
                    "ui binding capability does not match the persisted UI step"
                )
            try:
                connection.execute(
                    "INSERT INTO ui_operation_bindings(id, task_id, step_id, plan_revision,"
                    " plan_hash, capability_id, arguments_sha256, binding_sha256,"
                    " app_resource_id, window_resource_id, window_version_token, snapshot_id,"
                    " snapshot_generation, element_ref, element_runtime_id, pattern,"
                    " intended_effect, expected_precondition, expected_postcondition,"
                    " session_id, activation_scope, issued_at, expires_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        binding_id,
                        str(task_id),
                        str(step_id),
                        int(row["plan_revision"]),
                        row["plan_hash"],
                        capability_id,
                        arguments_sha256,
                        binding_sha256,
                        app_resource_id,
                        window_resource_id,
                        window_version_token,
                        snapshot_id,
                        snapshot_generation,
                        element_ref,
                        element_runtime_id,
                        pattern,
                        intended_effect,
                        expected_precondition,
                        expected_postcondition,
                        session_id,
                        activation_scope,
                        _timestamp(issued_at),
                        _timestamp(expires_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise IllegalPersistentTransition(
                    "ui operation binding could not be recorded for this plan"
                ) from exc

    def revoke_ui_binding(self, binding_id: str, *, now: datetime) -> None:
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            cursor = connection.execute(
                "UPDATE ui_operation_bindings SET revoked_at = ?"
                " WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL",
                (_timestamp(now), binding_id),
            )
            if cursor.rowcount != 1:
                raise IllegalPersistentTransition("ui binding is not revocable")

    def commit_ui_attempt(
        self,
        *,
        task_id: UUID,
        step_id: UUID,
        binding_id: str,
        now: datetime,
        expected_session_id: str | None = None,
        expected_activation_scope: str | None = None,
    ) -> str:
        """Execution commitment for one exact UI operation (one transaction)."""
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            row = connection.execute(
                "SELECT state FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
            if row is None:
                raise KeyError("unknown task id")
            if PersistentTaskState(row["state"]) is not PersistentTaskState.PRECHECK:
                raise IllegalPersistentTransition(
                    "ui execution commitment requires the task to be in PRECHECK"
                )
            binding = self._check_ui_binding(
                connection,
                task_id=task_id,
                step_id=step_id,
                binding_id=binding_id,
                expected_session_id=expected_session_id,
                expected_activation_scope=expected_activation_scope,
            )
            if binding["revoked_at"] is not None:
                raise IllegalPersistentTransition("ui operation binding is revoked")
            if binding["consumed_at"] is not None:
                raise IllegalPersistentTransition("ui operation binding was already consumed")
            if str(binding["expires_at"]) <= timestamp:
                raise IllegalPersistentTransition("ui operation binding has expired")
            cursor = connection.execute(
                "UPDATE ui_operation_bindings SET consumed_at = ?"
                " WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL",
                (timestamp, binding_id),
            )
            if cursor.rowcount != 1:
                raise IllegalPersistentTransition("ui operation binding consumption raced")
            attempt_id = str(uuid4())
            connection.execute(
                "INSERT INTO ui_operation_attempts(id, binding_id, task_id, step_id,"
                " capability_id, window_resource_id, attempt_number, recorded_at)"
                " VALUES (?,?,?,?,?,?,1,?)",
                (
                    attempt_id,
                    binding_id,
                    str(task_id),
                    str(step_id),
                    binding["capability_id"],
                    binding["window_resource_id"],
                    timestamp,
                ),
            )
            self._commit_transition_unlocked(
                connection,
                task_id,
                PersistentTaskState.PRECHECK,
                PersistentTaskState.EXECUTING,
                event_type="TASK_EXECUTING",
                metadata_values={
                    "confirmation_id": binding_id,
                    "attempt_id": attempt_id,
                    "authority": "BACKEND_UI_OPERATION_EVIDENCE",
                },
                now=timestamp,
                error_code=None,
            )
        return attempt_id

    def advance_ui_state(
        self,
        task_id: UUID,
        to_state: PersistentTaskState,
        *,
        step_id: UUID,
        binding_id: str,
        attempt_id: str | None = None,
        now: datetime | None = None,
        expected_session_id: str | None = None,
        expected_activation_scope: str | None = None,
    ) -> StoredTask:
        """Advance a UI-operation task on durable UI evidence only."""
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            binding = self._check_ui_binding(
                connection,
                task_id=task_id,
                step_id=step_id,
                binding_id=binding_id,
                expected_session_id=expected_session_id,
                expected_activation_scope=expected_activation_scope,
            )
            row = connection.execute(
                "SELECT state FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
            if row is None:
                raise KeyError("unknown task id")
            current = PersistentTaskState(row["state"])
            required = _NAVIGATION_TRANSITIONS.get(current, {}).get(to_state)
            if required is None:
                raise IllegalPersistentTransition(
                    f"illegal ui transition: {current.value} -> {to_state.value}"
                )
            if binding["consumed_at"] is None and required != "confirmation":
                raise IllegalPersistentTransition("ui transition lacks a consumed binding")
            attempt = None
            if attempt_id is not None:
                attempt = connection.execute(
                    "SELECT * FROM ui_operation_attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                if attempt is None or attempt["binding_id"] != binding_id:
                    raise IllegalPersistentTransition("ui attempt does not match its binding")
            if required in ("attempt", "verification", "receipt") and attempt is None:
                raise IllegalPersistentTransition("ui transition requires a recorded attempt")
            verification = None
            if attempt is not None:
                verification = connection.execute(
                    "SELECT * FROM ui_operation_verifications WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
            if required == "verification" and verification is None:
                raise IllegalPersistentTransition("ui transition requires a verification")
            if required == "receipt":
                receipt = (
                    connection.execute(
                        "SELECT * FROM ui_operation_receipts WHERE attempt_id = ?",
                        (attempt["id"],),
                    ).fetchone()
                    if attempt is not None
                    else None
                )
                if receipt is None:
                    raise IllegalPersistentTransition("ui transition requires a receipt")
                if to_state is PersistentTaskState.COMPLETED and receipt["status"] != "SUCCEEDED":
                    raise IllegalPersistentTransition("ui completion requires a SUCCEEDED receipt")
            self._commit_transition_unlocked(
                connection,
                task_id,
                current,
                to_state,
                event_type=f"TASK_{to_state.value}",
                metadata_values={
                    "confirmation_id": binding_id,
                    "attempt_id": attempt_id or "",
                    "authority": "BACKEND_UI_OPERATION_EVIDENCE",
                },
                now=timestamp,
                error_code=None,
            )
        return self.get_task(task_id)

    def record_ui_verification(
        self,
        *,
        attempt_id: str,
        outcome: str,
        observed_postcondition_token: str | None,
        now: datetime,
    ) -> str:
        if outcome == "verified_effect" and not observed_postcondition_token:
            raise IllegalPersistentTransition(
                "a verified ui outcome requires an observed postcondition token"
            )
        verification_id = str(uuid4())
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            if (
                connection.execute(
                    "SELECT 1 FROM ui_operation_attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                is None
            ):
                raise IllegalPersistentTransition("ui verification names no recorded attempt")
            try:
                connection.execute(
                    "INSERT INTO ui_operation_verifications(id, attempt_id, outcome,"
                    " observed_postcondition_token, verified_at) VALUES (?,?,?,?,?)",
                    (
                        verification_id,
                        attempt_id,
                        outcome,
                        observed_postcondition_token,
                        _timestamp(now),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise IllegalPersistentTransition("ui verification was rejected") from exc
        return verification_id

    def record_ui_receipt(self, *, attempt_id: str, verification_id: str, now: datetime) -> str:
        status_by_outcome = {
            "verified_effect": "SUCCEEDED",
            "no_effect": "FAILED",
            "stale_target": "FAILED",
            "failed": "FAILED",
            "uncertain": "UNVERIFIED",
        }
        receipt_id = str(uuid4())
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            row = connection.execute(
                "SELECT attempt_id, outcome FROM ui_operation_verifications WHERE id = ?",
                (verification_id,),
            ).fetchone()
            if row is None or row["attempt_id"] != attempt_id:
                raise IllegalPersistentTransition("ui receipt does not match its verification")
            status = status_by_outcome.get(str(row["outcome"]))
            if status is None:
                raise IllegalPersistentTransition("unknown ui verification outcome")
            try:
                connection.execute(
                    "INSERT INTO ui_operation_receipts(id, attempt_id, verification_id, status,"
                    " recovery_class, created_at) VALUES (?,?,?,?,?,?)",
                    (
                        receipt_id,
                        attempt_id,
                        verification_id,
                        status,
                        "IRREVERSIBLE",
                        _timestamp(now),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise IllegalPersistentTransition("ui receipt was rejected") from exc
        return receipt_id

    def get_ui_binding(self, binding_id: str) -> dict[str, object]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM ui_operation_bindings WHERE id = ?", (binding_id,)
            ).fetchone()
        if row is None:
            raise KeyError("unknown ui operation binding")
        return dict(row)

    def ui_attempts_for_task(self, task_id: UUID) -> list[dict[str, object]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT a.id AS attempt_id, a.binding_id AS binding_id,"
                " v.outcome AS outcome, r.status AS receipt_status"
                " FROM ui_operation_attempts a"
                " LEFT JOIN ui_operation_verifications v ON v.attempt_id = a.id"
                " LEFT JOIN ui_operation_receipts r ON r.attempt_id = a.id"
                " WHERE a.task_id = ?",
                (str(task_id),),
            ).fetchall()
        return [dict(row) for row in rows]

    def reconcile_ui_tasks(self, *, now: datetime | None = None) -> list[tuple[UUID, str]]:
        """Reconcile interrupted UI operations; never replay an operation."""
        outcomes: list[tuple[UUID, str]] = []
        with self._transaction() as connection:
            self._require_navigation_schema(connection)
            rows = connection.execute(
                "SELECT t.id AS task_id, t.state AS state, a.id AS attempt_id,"
                " a.step_id AS step_id, a.binding_id AS binding_id,"
                " v.id AS verification_id, v.outcome AS outcome, r.id AS receipt_id"
                " FROM tasks t JOIN ui_operation_attempts a ON a.task_id = t.id"
                " LEFT JOIN ui_operation_verifications v ON v.attempt_id = a.id"
                " LEFT JOIN ui_operation_receipts r ON r.attempt_id = a.id"
                " WHERE t.state IN ('PRECHECK', 'EXECUTING', 'POSTCHECK', 'RECOVERING')"
            ).fetchall()
        for row in rows:
            task_id = UUID(row["task_id"])
            step_id = UUID(row["step_id"])
            try:
                if row["state"] == "PRECHECK":
                    self.advance_ui_state(
                        task_id,
                        PersistentTaskState.FAILED,
                        step_id=step_id,
                        binding_id=row["binding_id"],
                        now=now,
                    )
                    outcomes.append((task_id, "FAILED"))
                    continue
                if row["verification_id"] is not None and row["receipt_id"] is None:
                    self.record_ui_receipt(
                        attempt_id=row["attempt_id"],
                        verification_id=row["verification_id"],
                        now=now or datetime.now(UTC),
                    )
                target = (
                    PersistentTaskState.COMPLETED
                    if row["outcome"] == "verified_effect"
                    else PersistentTaskState.UNVERIFIED
                )
                if PersistentTaskState(row["state"]) is not PersistentTaskState.RECOVERING:
                    self.advance_ui_state(
                        task_id,
                        PersistentTaskState.RECOVERING,
                        step_id=step_id,
                        binding_id=row["binding_id"],
                        attempt_id=row["attempt_id"],
                        now=now,
                    )
                self.advance_ui_state(
                    task_id,
                    target,
                    step_id=step_id,
                    binding_id=row["binding_id"],
                    attempt_id=row["attempt_id"],
                    now=now,
                )
                outcomes.append((task_id, target.value))
            except IllegalPersistentTransition:
                continue
        return outcomes

    def navigation_attempts_for_task(self, task_id: UUID) -> list[dict[str, object]]:
        """Read durable navigation evidence for one task (audit/tests)."""
        with self._lock:
            self._verify_database_location()
            rows = self._connection.execute(
                "SELECT a.id AS attempt_id, a.confirmation_id AS confirmation_id,"
                " v.outcome AS outcome, r.status AS receipt_status"
                " FROM navigation_attempts a"
                " LEFT JOIN navigation_verifications v ON v.attempt_id = a.id"
                " LEFT JOIN navigation_receipts r ON r.attempt_id = a.id"
                " WHERE a.task_id = ?",
                (str(task_id),),
            ).fetchall()
        return [dict(row) for row in rows]

    def _verify_receipt_evidence(
        self,
        connection: sqlite3.Connection,
        *,
        task_id: UUID,
        plan_revision: int,
        evidence: ExecutionEvidence,
    ) -> None:
        """Independently verify the durable receipt behind a COMPLETED claim.

        FI-03: a caller-supplied receipt UUID is an identity, never proof.
        The durable record is loaded through the registered evidence source
        (the real receipts database, a separate persistence boundary — this
        re-read is point-in-time under the store lock, not cross-database
        atomicity) and must belong to this exact task, plan step, grant and
        consumption, name the step's resource, and record a successfully
        verified outcome whose resulting hash matches the approved effect.
        """

        if evidence.receipt_id is None:
            raise IllegalPersistentTransition(
                "a verified receipt is required before this state may be recorded"
            )
        source = self._receipt_evidence_source
        if source is None:
            raise IllegalPersistentTransition(
                "no durable receipt evidence source is registered; completion cannot be verified"
            )
        try:
            facts = source(evidence.receipt_id)
        except Exception as exc:
            raise IllegalPersistentTransition(
                "the durable receipt could not be loaded; completion cannot be verified"
            ) from exc
        if facts is None:
            raise IllegalPersistentTransition("execution evidence names no durable receipt")
        if facts.task_id != str(task_id):
            raise IllegalPersistentTransition("the durable receipt belongs to a different task")
        if facts.approval_id != str(evidence.approval_id):
            raise IllegalPersistentTransition("the durable receipt belongs to a different grant")
        if facts.status != "SUCCEEDED" or not facts.verified or not facts.post_sha256:
            raise IllegalPersistentTransition(
                "the durable receipt does not record a successfully verified outcome"
            )
        step = connection.execute(
            "SELECT capability_id, resources_json, effect_json FROM task_steps "
            "WHERE task_id = ? AND plan_revision = ? AND id = ?",
            (str(task_id), plan_revision, facts.step_id),
        ).fetchone()
        if step is None:
            raise IllegalPersistentTransition(
                "the durable receipt names no step of the task's current plan"
            )
        if step["capability_id"] != facts.capability_id:
            raise IllegalPersistentTransition(
                "the durable receipt records a different operation than the plan step"
            )
        resource_ids = {
            str(resource.get("resource_id"))
            for resource in json.loads(step["resources_json"])
            if isinstance(resource, dict)
        }
        if facts.resource_id not in resource_ids:
            raise IllegalPersistentTransition(
                "the durable receipt names a different resource than the plan step"
            )
        consumed_step = connection.execute(
            "SELECT 1 FROM exact_approval_grant_consumptions "
            "WHERE approval_id = ? AND task_id = ? AND plan_revision = ? AND step_id = ? "
            "LIMIT 1",
            (str(evidence.approval_id), str(task_id), plan_revision, facts.step_id),
        ).fetchone()
        if consumed_step is None:
            raise IllegalPersistentTransition(
                "no recorded grant consumption binds this receipt's step"
            )
        effect = json.loads(step["effect_json"])
        # The approved *resulting content* hash (the post-image the user
        # approved), distinct from the effect descriptor digest.
        result_digest = effect.get("approved_result_digest") if isinstance(effect, dict) else None
        if (
            isinstance(result_digest, str)
            and result_digest
            and facts.post_sha256.casefold() != result_digest.casefold()
        ):
            raise IllegalPersistentTransition(
                "the durable receipt's resulting content does not match the approved effect"
            )

    def save_plan(self, plan: TaskPlan) -> str:
        """Append the next immutable plan revision and update the task pointer."""
        canonical = plan.canonical_json()
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        timestamp = _timestamp(plan.created_at)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT state, plan_revision FROM tasks WHERE id = ?", (str(plan.task_id),)
            ).fetchone()
            if row is None:
                raise KeyError("unknown task id")
            state = PersistentTaskState(row["state"])
            if state != PersistentTaskState.PLANNING:
                raise IllegalPersistentTransition("a plan may be saved only while task is PLANNING")
            expected_revision = int(row["plan_revision"]) + 1
            if plan.revision != expected_revision:
                raise PersistenceError("plan revision is not the next immutable revision")
            connection.execute(
                "INSERT INTO task_plans(task_id, revision, plan_hash, canonical_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(plan.task_id), plan.revision, digest, canonical, timestamp),
            )
            for order, step in enumerate(plan.steps):
                step_data = step.model_dump(mode="json")
                connection.execute(
                    "INSERT INTO task_steps("
                    "id, task_id, plan_revision, capability_id, args_json, resources_json, "
                    "expected_state_json, effect_json, deps_json, locks_json, risk_tier, "
                    "approval_status, timeout_seconds, max_attempts, idempotency_key, "
                    "postconditions_json, recovery_class, order_index) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(step.step_id),
                        str(plan.task_id),
                        plan.revision,
                        step.capability_id,
                        _canonical_json(step_data["arguments"]),
                        _canonical_json(step_data["resources"]),
                        _canonical_json(step_data["expected_state"]),
                        _canonical_json(step_data["expected_effect"]),
                        _canonical_json(step_data["dependencies"]),
                        _canonical_json(step_data["resource_locks"]),
                        int(step.risk_tier),
                        step.approval_status.value,
                        step.timeout_seconds,
                        step.max_attempts,
                        str(step.idempotency_key),
                        _canonical_json(step_data["postconditions"]),
                        step.recovery_class,
                        order,
                    ),
                )
            connection.execute(
                "UPDATE tasks SET plan_revision = ?, plan_hash = ?, updated_at = ? WHERE id = ?",
                (plan.revision, digest, timestamp, str(plan.task_id)),
            )
            self._append_event(
                connection,
                plan.task_id,
                "PLAN_REVISION_SAVED",
                EventMetadata(values={"plan_revision": plan.revision, "plan_hash": digest}),
                now=timestamp,
            )
        return digest

    def get_plan(self, task_id: UUID, revision: int | None = None) -> TaskPlan:
        current_hash: str | None = None
        current_revision: int | None = None
        with self._lock:
            self._verify_database_location()
            task = self._connection.execute(
                "SELECT plan_revision, plan_hash FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
            if task is None:
                raise KeyError("unknown task id")
            current_revision = int(task["plan_revision"])
            current_hash = task["plan_hash"]
            if revision is None:
                revision = current_revision
            if revision < 1:
                raise KeyError("task has no persisted plan")
            row = self._connection.execute(
                "SELECT canonical_json, plan_hash FROM task_plans WHERE task_id = ? AND revision = ?",
                (str(task_id), revision),
            ).fetchone()
            if row is None:
                raise KeyError("unknown plan revision")
            steps = self._connection.execute(
                "SELECT * FROM task_steps WHERE task_id = ? AND plan_revision = ? ORDER BY order_index",
                (str(task_id), revision),
            ).fetchall()
        try:
            plan = TaskPlan.model_validate_json(row["canonical_json"])
        except (ValidationError, ValueError) as exc:
            raise PersistenceIntegrityError("stored plan failed typed validation") from exc
        actual_hash = hashlib.sha256(plan.canonical_json().encode("utf-8")).hexdigest()
        if (
            plan.task_id != task_id
            or plan.revision != revision
            or actual_hash != row["plan_hash"]
            or plan.plan_hash != row["plan_hash"]
            or (revision == current_revision and current_hash != row["plan_hash"])
        ):
            raise PersistenceIntegrityError("stored plan identity or digest mismatch")
        self._verify_normalized_steps(plan, steps)
        return plan

    def record_approval_decision(self, record: ApprovalDecisionRecord) -> None:
        """Persist a decision as immutable audit only; it never creates a grant."""
        timestamp = _timestamp(record.decided_at)
        with self._transaction() as connection:
            task = connection.execute(
                "SELECT plan_revision, plan_hash, state FROM tasks WHERE id = ?",
                (str(record.task_id),),
            ).fetchone()
            if task is None:
                raise KeyError("unknown task id")
            if (
                int(task["plan_revision"]) != record.plan_revision
                or task["plan_hash"] != record.plan_hash
                or PersistentTaskState(task["state"])
                not in {PersistentTaskState.PREVIEW_READY, PersistentTaskState.AWAITING_APPROVAL}
            ):
                raise PersistenceError("decision does not match the current preview plan")
            self._insert_approval_decision_unlocked(connection, record, now=timestamp)

    def _insert_approval_decision_unlocked(
        self,
        connection: sqlite3.Connection,
        record: ApprovalDecisionRecord,
        *,
        now: str,
    ) -> tuple[UUID, UUID]:
        connection.execute(
            "INSERT INTO approval_records("
            "id, task_id, plan_revision, plan_hash, preview_id, preview_digest, decision, "
            "authority, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(record.approval_id),
                str(record.task_id),
                record.plan_revision,
                record.plan_hash,
                str(record.preview_id),
                record.preview_digest,
                record.decision.value,
                "NON_AUTHORIZING_AUDIT_RECORD",
                now,
            ),
        )
        event_id = self._append_event(
            connection,
            record.task_id,
            "APPROVAL_DECISION_RECORDED",
            EventMetadata(
                values={
                    "approval_id": str(record.approval_id),
                    "decision": record.decision.value,
                    "authority": "NON_AUTHORIZING_AUDIT_RECORD",
                    "plan_revision": record.plan_revision,
                    "plan_hash": record.plan_hash,
                    "preview_digest": record.preview_digest,
                    "preview_id": str(record.preview_id),
                    "requested_outcome": record.decision.value,
                }
            ),
            now=now,
        )
        return record.approval_id, event_id

    def record_stage2_review_outcome(
        self,
        task_id: UUID,
        *,
        review_request_id: UUID,
        plan_revision: int,
        plan_hash: str,
        preview_id: UUID,
        preview_digest: str,
        requested_outcome: str,
        preview_matches_current: bool,
        decided_at: datetime | None = None,
    ) -> Stage2ReviewWrite:
        """Atomically record a non-authorizing Stage 2 review outcome.

        A replay with the same immutable request identity returns the original
        audit outcome. Reusing that identity for different review data fails
        closed. No path here issues, stores, or consumes an approval grant.
        """

        if requested_outcome not in {"APPROVE", "REVISE", "REJECT", "CANCELLED"}:
            raise ValueError("Stage 2 requested outcome is invalid")
        if not isinstance(preview_matches_current, bool):
            raise ValueError("preview_matches_current must be a boolean")
        if _LOWER_PREVIEW_SHA256.fullmatch(preview_digest) is None:
            raise ValueError("preview digest must be a lowercase SHA-256 digest")
        timestamp = _timestamp(decided_at)
        with self._transaction() as connection:
            existing = self._existing_stage2_review(
                connection,
                task_id,
                review_request_id=review_request_id,
                requested_outcome=requested_outcome,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                preview_id=preview_id,
                preview_digest=preview_digest,
            )
            if existing is not None:
                return existing

            task = connection.execute(
                "SELECT state, plan_revision, plan_hash FROM tasks WHERE id = ?",
                (str(task_id),),
            ).fetchone()
            if task is None:
                raise KeyError("unknown task id")
            current_state = PersistentTaskState(task["state"])
            current_revision = int(task["plan_revision"])
            current_hash = task["plan_hash"]
            latest_plan_sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(seq), 0) FROM task_events "
                    "WHERE task_id = ? AND event_type = 'PLAN_REVISION_SAVED'",
                    (str(task_id),),
                ).fetchone()[0]
            )
            fresh_consent_blocked = self._has_fresh_consent_blocker(
                connection,
                task_id,
                latest_plan_sequence,
            )

            if not preview_matches_current:
                event_id = self._append_stage2_event(
                    connection,
                    task_id,
                    "APPROVAL_REVIEW_STALE",
                    review_request_id=review_request_id,
                    plan_revision=plan_revision,
                    plan_hash=plan_hash,
                    preview_id=preview_id,
                    preview_digest=preview_digest,
                    now=timestamp,
                    requested_outcome=requested_outcome,
                    error_code="preview_stale",
                )
                return Stage2ReviewWrite(
                    resolution="STALE",
                    requested_outcome=requested_outcome,
                    task_id=task_id,
                    plan_revision=plan_revision,
                    plan_hash=plan_hash,
                    preview_id=preview_id,
                    preview_digest=preview_digest,
                    review_request_id=review_request_id,
                    event_id=event_id,
                    decision_id=None,
                    idempotent_replay=False,
                )
            if (
                current_state
                not in {
                    PersistentTaskState.PREVIEW_READY,
                    PersistentTaskState.AWAITING_APPROVAL,
                }
                or fresh_consent_blocked
            ):
                event_id = self._append_stage2_event(
                    connection,
                    task_id,
                    "APPROVAL_REVIEW_UNAVAILABLE",
                    review_request_id=review_request_id,
                    plan_revision=current_revision,
                    plan_hash=current_hash or plan_hash,
                    preview_id=preview_id,
                    preview_digest=preview_digest,
                    now=timestamp,
                    requested_outcome=requested_outcome,
                    error_code="review_unavailable",
                )
                return Stage2ReviewWrite(
                    resolution="UNAVAILABLE",
                    requested_outcome=requested_outcome,
                    task_id=task_id,
                    plan_revision=current_revision,
                    plan_hash=current_hash or plan_hash,
                    preview_id=preview_id,
                    preview_digest=preview_digest,
                    review_request_id=review_request_id,
                    event_id=event_id,
                    decision_id=None,
                    idempotent_replay=False,
                )

            if requested_outcome in {"APPROVE", "REJECT"}:
                if requested_outcome == "REJECT":
                    self._stage2_transition_unlocked(
                        connection,
                        task_id,
                        current_state,
                        PersistentTaskState.DENIED,
                        now=timestamp,
                        plan_revision=current_revision,
                        plan_hash=current_hash,
                    )
                decision = ApprovalDecisionRecord(
                    approval_id=review_request_id,
                    task_id=task_id,
                    plan_revision=current_revision,
                    plan_hash=current_hash or plan_hash,
                    preview_id=preview_id,
                    preview_digest=preview_digest,
                    decision=ApprovalDecisionValue(requested_outcome),
                    authority="NON_AUTHORIZING_AUDIT_RECORD",
                    decided_at=_parse_timestamp(timestamp),
                )
                decision_id, event_id = self._insert_approval_decision_unlocked(
                    connection,
                    decision,
                    now=timestamp,
                )
                resolution = requested_outcome
            elif requested_outcome == "REVISE":
                self._stage2_transition_unlocked(
                    connection,
                    task_id,
                    current_state,
                    PersistentTaskState.PLANNING,
                    now=timestamp,
                    plan_revision=current_revision,
                    plan_hash=current_hash,
                )
                event_id = self._append_stage2_event(
                    connection,
                    task_id,
                    "APPROVAL_REVIEW_REVISION_REQUESTED",
                    review_request_id=review_request_id,
                    plan_revision=current_revision,
                    plan_hash=current_hash or plan_hash,
                    preview_id=preview_id,
                    preview_digest=preview_digest,
                    now=timestamp,
                    requested_outcome=requested_outcome,
                    requires_fresh_plan_and_consent=True,
                )
                decision_id = None
                resolution = "REVISE"
            else:  # CANCELLED
                self._stage2_transition_unlocked(
                    connection,
                    task_id,
                    current_state,
                    PersistentTaskState.CANCELLED,
                    now=timestamp,
                    plan_revision=current_revision,
                    plan_hash=current_hash,
                )
                event_id = self._append_stage2_event(
                    connection,
                    task_id,
                    "APPROVAL_REVIEW_CANCELLED",
                    review_request_id=review_request_id,
                    plan_revision=current_revision,
                    plan_hash=current_hash or plan_hash,
                    preview_id=preview_id,
                    preview_digest=preview_digest,
                    now=timestamp,
                    requested_outcome=requested_outcome,
                )
                decision_id = None
                resolution = "CANCELLED"
            return Stage2ReviewWrite(
                resolution=resolution,
                requested_outcome=requested_outcome,
                task_id=task_id,
                plan_revision=current_revision,
                plan_hash=current_hash or plan_hash,
                preview_id=preview_id,
                preview_digest=preview_digest,
                review_request_id=review_request_id,
                event_id=event_id,
                decision_id=decision_id,
                idempotent_replay=False,
            )

    def record_preview_revocation(
        self,
        task_id: UUID,
        *,
        plan_revision: int,
        plan_hash: str,
        preview_id: UUID,
        preview_digest: str,
        revocation_id: UUID,
        reason_code: str = "review_revoked",
        now: datetime | None = None,
    ) -> Stage2ReviewRevocation:
        """Idempotently append a non-authorizing invalidation event."""

        if _ERROR_CODE.fullmatch(reason_code) is None:
            raise ValueError("revocation reason must be a redacted lowercase code")
        if _LOWER_PREVIEW_SHA256.fullmatch(preview_digest) is None:
            raise ValueError("preview digest must be a lowercase SHA-256 digest")
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            existing = self._find_stage2_revocation(
                connection,
                task_id,
                revocation_id=revocation_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                preview_id=preview_id,
                preview_digest=preview_digest,
            )
            if existing is not None:
                return Stage2ReviewRevocation(
                    task_id=task_id,
                    plan_revision=plan_revision,
                    plan_hash=plan_hash,
                    preview_digest=preview_digest,
                    revocation_id=revocation_id,
                    event_id=existing,
                    already_recorded=True,
                )
            task = connection.execute(
                "SELECT state, plan_revision, plan_hash FROM tasks WHERE id = ?",
                (str(task_id),),
            ).fetchone()
            if task is None:
                raise KeyError("unknown task id")
            current_state = PersistentTaskState(task["state"])
            if (
                int(task["plan_revision"]) != plan_revision
                or task["plan_hash"] != plan_hash
                or current_state
                not in {
                    PersistentTaskState.PREVIEW_READY,
                    PersistentTaskState.AWAITING_APPROVAL,
                }
            ):
                raise PersistenceError("revocation does not match the current reviewable preview")
            event_id = self._append_stage2_event(
                connection,
                task_id,
                "APPROVAL_PREVIEW_REVOKED",
                review_request_id=revocation_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                preview_id=preview_id,
                preview_digest=preview_digest,
                now=timestamp,
                error_code=reason_code,
                requires_fresh_plan_and_consent=True,
            )
            return Stage2ReviewRevocation(
                task_id=task_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                preview_digest=preview_digest,
                revocation_id=revocation_id,
                event_id=event_id,
                already_recorded=False,
            )

    def is_stage2_preview_blocked(self, task_id: UUID) -> bool:
        """Return whether fresh plan/consent is required before a new review."""

        with self._lock:
            self._verify_database_location()
            task = self._connection.execute(
                "SELECT state, plan_revision FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
            if task is None:
                return True
            if PersistentTaskState(task["state"]) not in {
                PersistentTaskState.PREVIEW_READY,
                PersistentTaskState.AWAITING_APPROVAL,
            }:
                return True
            return self._has_fresh_consent_blocker(
                self._connection,
                task_id,
                self._latest_plan_sequence(self._connection, task_id),
            )

    def _latest_plan_sequence(self, connection: sqlite3.Connection, task_id: UUID) -> int:
        return int(
            connection.execute(
                "SELECT COALESCE(MAX(seq), 0) FROM task_events "
                "WHERE task_id = ? AND event_type = 'PLAN_REVISION_SAVED'",
                (str(task_id),),
            ).fetchone()[0]
        )

    def is_execution_consent_active(self, task_id: UUID) -> bool:
        """Whether live consent covers spending during recorded execution.

        FI-04: execution states are now recorded at the real checkpoints,
        so by the time the executor spends the grant the task legitimately
        sits in PRECHECK — a state reachable only through
        ``advance_execution_state`` against a live grant bound to the
        current plan. Consumption-time consent therefore accepts PRECHECK
        in addition to the consent-bearing states, with the identical
        fresh-consent blocker checks. Issuance-time gates are unchanged:
        a grant may still only be *created* from PREVIEW_READY /
        AWAITING_APPROVAL (see ``is_stage2_preview_blocked``).
        """

        with self._lock:
            self._verify_database_location()
            task = self._connection.execute(
                "SELECT state, plan_revision FROM tasks WHERE id = ?", (str(task_id),)
            ).fetchone()
            if task is None:
                return False
            state = PersistentTaskState(task["state"])
            if state is PersistentTaskState.PRECHECK:
                # Only the state gate widens (see docstring); the
                # fresh-consent blocker logic stays the shared one.
                return not self._has_fresh_consent_blocker(
                    self._connection,
                    task_id,
                    self._latest_plan_sequence(self._connection, task_id),
                )
            if state not in {
                PersistentTaskState.PREVIEW_READY,
                PersistentTaskState.AWAITING_APPROVAL,
            }:
                return False
            return not self.is_stage2_preview_blocked(task_id)

    def find_stage2_review_outcome(
        self,
        task_id: UUID,
        *,
        review_request_id: UUID,
        requested_outcome: str,
        plan_revision: int,
        plan_hash: str,
        preview_id: UUID,
        preview_digest: str,
    ) -> Stage2ReviewWrite | None:
        """Read-only lookup of a persisted Stage 2 review outcome.

        Returns the persisted write for one exact immutable request identity
        (idempotent_replay is True), or None when nothing was ever recorded.
        Unlike ``record_stage2_review_outcome`` this never writes, never
        transitions state and never appends an audit event: it exists so an
        audit-only reconciliation can confirm a previously persisted decision
        whose acknowledgement was lost. Identity replayed with different data
        or a different outcome raises ReviewConflictError; a stored audit
        record or event that fails integrity validation raises
        PersistenceIntegrityError. No grant is issued, stored or consumed.
        """

        if requested_outcome not in {"APPROVE", "REVISE", "REJECT", "CANCELLED"}:
            raise ValueError("Stage 2 requested outcome is invalid")
        with self._lock:
            self._verify_database_location()
            return self._existing_stage2_review(
                self._connection,
                task_id,
                review_request_id=review_request_id,
                requested_outcome=requested_outcome,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                preview_id=preview_id,
                preview_digest=preview_digest,
            )

    def _existing_stage2_review(
        self,
        connection: sqlite3.Connection,
        task_id: UUID,
        *,
        review_request_id: UUID,
        requested_outcome: str,
        plan_revision: int,
        plan_hash: str,
        preview_id: UUID,
        preview_digest: str,
    ) -> Stage2ReviewWrite | None:
        row = connection.execute(
            "SELECT * FROM approval_records WHERE id = ? AND task_id = ?",
            (str(review_request_id), str(task_id)),
        ).fetchone()
        if row is not None:
            try:
                record = ApprovalDecisionRecord(
                    approval_id=UUID(row["id"]),
                    task_id=UUID(row["task_id"]),
                    plan_revision=row["plan_revision"],
                    plan_hash=row["plan_hash"],
                    preview_id=UUID(row["preview_id"]),
                    preview_digest=row["preview_digest"],
                    decision=ApprovalDecisionValue(row["decision"]),
                    authority=row["authority"],
                    decided_at=_parse_timestamp(row["decided_at"]),
                )
            except (ValidationError, ValueError) as exc:
                raise PersistenceIntegrityError("stored approval audit record is invalid") from exc
            resolution = record.decision.value
            if (
                record.plan_revision != plan_revision
                or record.plan_hash != plan_hash
                or record.preview_id != preview_id
                or record.preview_digest != preview_digest
            ):
                raise ReviewConflictError(
                    "review request identity was replayed with different data"
                )
            if requested_outcome != resolution:
                raise ReviewConflictError(
                    "review request identity was replayed with a different outcome"
                )
            return Stage2ReviewWrite(
                resolution=resolution,
                requested_outcome=requested_outcome,
                task_id=task_id,
                plan_revision=record.plan_revision,
                plan_hash=record.plan_hash,
                preview_id=record.preview_id,
                preview_digest=record.preview_digest,
                review_request_id=review_request_id,
                event_id=None,
                decision_id=record.approval_id,
                idempotent_replay=True,
            )

        resolutions = {
            "APPROVAL_REVIEW_REVISION_REQUESTED": "REVISE",
            "APPROVAL_REVIEW_CANCELLED": "CANCELLED",
            "APPROVAL_REVIEW_STALE": "STALE",
            "APPROVAL_REVIEW_UNAVAILABLE": "UNAVAILABLE",
        }
        rows = connection.execute(
            "SELECT * FROM task_events WHERE task_id = ? ORDER BY seq",
            (str(task_id),),
        ).fetchall()
        for event in rows:
            if event["event_type"] not in resolutions:
                continue
            metadata = self._stage2_event_metadata(event)
            if metadata.get("approval_id") != str(review_request_id):
                continue
            resolution = resolutions[event["event_type"]]
            if (
                metadata.get("authority") != "NON_AUTHORIZING_AUDIT_RECORD"
                or metadata.get("plan_revision") != plan_revision
                or metadata.get("plan_hash") != plan_hash
                or metadata.get("preview_id") != str(preview_id)
                or metadata.get("preview_digest") != preview_digest
            ):
                raise ReviewConflictError(
                    "review request identity was replayed with different data"
                )
            stored_outcome = metadata.get("requested_outcome")
            if stored_outcome is None:
                raise PersistenceIntegrityError(
                    "stored Stage 2 audit event is missing its requested outcome"
                )
            if stored_outcome != requested_outcome:
                raise ReviewConflictError(
                    "review request identity was replayed with a different outcome"
                )
            return Stage2ReviewWrite(
                resolution=resolution,
                requested_outcome=requested_outcome,
                task_id=task_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                preview_id=preview_id,
                preview_digest=preview_digest,
                review_request_id=review_request_id,
                event_id=UUID(event["id"]),
                decision_id=None,
                idempotent_replay=True,
            )
        return None

    def _find_stage2_revocation(
        self,
        connection: sqlite3.Connection,
        task_id: UUID,
        *,
        revocation_id: UUID,
        plan_revision: int,
        plan_hash: str,
        preview_id: UUID,
        preview_digest: str,
    ) -> UUID | None:
        rows = connection.execute(
            "SELECT * FROM task_events WHERE task_id = ? AND event_type = 'APPROVAL_PREVIEW_REVOKED' ORDER BY seq",
            (str(task_id),),
        ).fetchall()
        for event in rows:
            metadata = self._stage2_event_metadata(event)
            if metadata.get("approval_id") != str(revocation_id):
                continue
            if (
                metadata.get("authority") != "NON_AUTHORIZING_AUDIT_RECORD"
                or metadata.get("plan_revision") != plan_revision
                or metadata.get("plan_hash") != plan_hash
                or metadata.get("preview_id") != str(preview_id)
                or metadata.get("preview_digest") != preview_digest
                or metadata.get("requires_fresh_plan_and_consent") is not True
            ):
                raise ReviewConflictError("revocation identity was replayed with different data")
            return UUID(event["id"])
        return None

    @staticmethod
    def _stage2_event_metadata(row: sqlite3.Row) -> dict[str, object]:
        try:
            raw_metadata = json.loads(row["data_json"])
            metadata = EventMetadata(values=raw_metadata)
            if _canonical_json(metadata.values) != row["data_json"]:
                raise ValueError("event metadata is not canonical")
        except (TypeError, ValueError, ValidationError) as exc:
            raise PersistenceIntegrityError("stored Stage 2 audit event is invalid") from exc
        return dict(metadata.values)

    def _has_fresh_consent_blocker(
        self,
        connection: sqlite3.Connection,
        task_id: UUID,
        after_sequence: int,
    ) -> bool:
        rows = connection.execute(
            "SELECT * FROM task_events WHERE task_id = ? AND seq > ? ORDER BY seq",
            (str(task_id), after_sequence),
        ).fetchall()
        for row in rows:
            metadata = self._stage2_event_metadata(row)
            if metadata.get("requires_fresh_plan_and_consent") is True:
                return True
        return False

    def _append_stage2_event(
        self,
        connection: sqlite3.Connection,
        task_id: UUID,
        event_type: str,
        *,
        review_request_id: UUID,
        plan_revision: int,
        plan_hash: str,
        preview_id: UUID,
        preview_digest: str,
        now: str,
        requested_outcome: str | None = None,
        error_code: str | None = None,
        requires_fresh_plan_and_consent: bool = False,
    ) -> UUID:
        values: dict[str, str | int | float | bool | None] = {
            "approval_id": str(review_request_id),
            "authority": "NON_AUTHORIZING_AUDIT_RECORD",
            "plan_revision": plan_revision,
            "plan_hash": plan_hash,
            "preview_digest": preview_digest,
            "preview_id": str(preview_id),
        }
        if requested_outcome is not None:
            if requested_outcome not in {"APPROVE", "REVISE", "REJECT", "CANCELLED"}:
                raise ValueError("Stage 2 requested outcome is invalid")
            values["requested_outcome"] = requested_outcome
        if requires_fresh_plan_and_consent:
            values["requires_fresh_plan_and_consent"] = True
        if error_code is not None:
            if _ERROR_CODE.fullmatch(error_code) is None:
                raise ValueError("Stage 2 event error code is invalid")
            values["error_code"] = error_code
        return self._append_event(
            connection,
            task_id,
            event_type,
            EventMetadata(values=values),
            now=now,
        )

    def _commit_transition_unlocked(
        self,
        connection: sqlite3.Connection,
        task_id: UUID,
        current_state: PersistentTaskState,
        to_state: PersistentTaskState,
        *,
        event_type: str,
        metadata_values: dict[str, str | int | float | bool | None],
        now: str,
        error_code: str | None,
    ) -> None:
        """Apply a validated task transition inside an open transaction.

        Shared by ``transition_task`` and the Stage 2 review writes so both
        paths emit the identical ``TASK_<state>`` event shape with merged
        from/to metadata, identical terminal-state bookkeeping, and identical
        ``last_error_code`` semantics.
        """

        finished_at = (
            now
            if to_state
            in {
                PersistentTaskState.COMPLETED,
                PersistentTaskState.CANCELLED,
                PersistentTaskState.DENIED,
                PersistentTaskState.FAILED,
            }
            else None
        )
        connection.execute(
            "UPDATE tasks SET state = ?, updated_at = ?, finished_at = ?, last_error_code = ? "
            "WHERE id = ?",
            (to_state.value, now, finished_at, error_code, str(task_id)),
        )
        values = dict(metadata_values)
        values["from_state"] = current_state.value
        values["to_state"] = to_state.value
        self._append_event(
            connection,
            task_id,
            event_type,
            EventMetadata(values=values),
            now=now,
        )

    def _stage2_transition_unlocked(
        self,
        connection: sqlite3.Connection,
        task_id: UUID,
        current_state: PersistentTaskState,
        to_state: PersistentTaskState,
        *,
        now: str,
        plan_revision: int,
        plan_hash: str | None,
    ) -> None:
        if to_state not in _TRANSITIONS[current_state]:
            raise IllegalPersistentTransition(
                f"illegal Stage 2 review transition: {current_state} -> {to_state}"
            )
        metadata_values: dict[str, str | int | float | bool | None] = {
            "plan_revision": plan_revision,
        }
        if plan_hash is not None:
            metadata_values["plan_hash"] = plan_hash
        self._commit_transition_unlocked(
            connection,
            task_id,
            current_state,
            to_state,
            event_type=f"TASK_{to_state.value}",
            metadata_values=metadata_values,
            now=now,
            error_code=None,
        )

    def get_approval_record(self, approval_id: UUID) -> ApprovalDecisionRecord:
        with self._lock:
            self._verify_database_location()
            row = self._connection.execute(
                "SELECT * FROM approval_records WHERE id = ?", (str(approval_id),)
            ).fetchone()
        if row is None:
            raise KeyError("unknown approval record")
        try:
            record = ApprovalDecisionRecord(
                approval_id=UUID(row["id"]),
                task_id=UUID(row["task_id"]),
                plan_revision=row["plan_revision"],
                plan_hash=row["plan_hash"],
                preview_id=UUID(row["preview_id"]),
                preview_digest=row["preview_digest"],
                decision=ApprovalDecisionValue(row["decision"]),
                authority=row["authority"],
                decided_at=_parse_timestamp(row["decided_at"]),
            )
        except (ValidationError, ValueError) as exc:
            raise PersistenceIntegrityError("stored approval audit record is invalid") from exc
        return record

    def record_observation_event(
        self,
        task_id: UUID,
        event_type: str,
        *,
        values: dict[str, str | int | float | bool | None] | None = None,
        step_id: UUID | None = None,
        now: datetime | None = None,
    ) -> UUID:
        """Append one non-state-changing audit event for a capability action.

        Read-tier capabilities (inspect/read/search/open) do not transition the
        task, but they must still be auditable. This is the narrow, validated
        entry point for that: it never changes task state, it rejects unknown
        event names through the same ``_EVENT_NAME`` rule as every other event,
        and it runs inside the store's transaction and lock.
        """

        timestamp = _timestamp(now)
        with self._transaction() as connection:
            event_id = self._append_event(
                connection,
                task_id,
                event_type,
                EventMetadata(values=dict(values or {})),
                now=timestamp,
                step_id=step_id,
            )
        return event_id

    def list_events(self, task_id: UUID, *, after_sequence: int = 0) -> tuple[StoredTaskEvent, ...]:
        with self._lock:
            self._verify_database_location()
            rows = self._connection.execute(
                "SELECT * FROM task_events WHERE task_id = ? AND seq > ? ORDER BY seq",
                (str(task_id), after_sequence),
            ).fetchall()
        result: list[StoredTaskEvent] = []
        for row in rows:
            try:
                result.append(
                    StoredTaskEvent(
                        event_id=UUID(row["id"]),
                        task_id=UUID(row["task_id"]),
                        sequence=row["seq"],
                        event_type=row["event_type"],
                        step_id=UUID(row["step_id"]) if row["step_id"] else None,
                        metadata=EventMetadata(values=json.loads(row["data_json"])),
                        created_at=_parse_timestamp(row["created_at"]),
                    )
                )
            except (ValidationError, ValueError, TypeError) as exc:
                raise PersistenceIntegrityError("stored audit event is invalid") from exc
        return tuple(result)

    def recover_on_startup(self, *, now: datetime | None = None) -> int:
        """Pause every nonterminal in-flight task and force replanning/consent."""
        timestamp = _timestamp(now)
        count = 0
        with self._transaction() as connection:
            placeholders = ",".join("?" for _ in _ACTIVE_RESTART_STATES)
            states = sorted(state.value for state in _ACTIVE_RESTART_STATES)
            rows = connection.execute(
                f"SELECT id, state FROM tasks WHERE state IN ({placeholders})", states
            ).fetchall()
            for row in rows:
                task_id = UUID(row["id"])
                previous = PersistentTaskState(row["state"])
                connection.execute(
                    "UPDATE tasks SET state = ?, updated_at = ?, finished_at = NULL WHERE id = ?",
                    (PersistentTaskState.PAUSED.value, timestamp, str(task_id)),
                )
                self._append_event(
                    connection,
                    task_id,
                    "RESTART_RECOVERY_PAUSED",
                    EventMetadata(
                        values={
                            "from_state": previous.value,
                            "to_state": PersistentTaskState.PAUSED.value,
                            "requires_fresh_plan_and_consent": True,
                        }
                    ),
                    now=timestamp,
                )
                count += 1
        return count

    def check_integrity(self) -> None:
        with self._lock:
            self._verify_database_location()
            self._check_integrity()

    def _prepare_private_path(self) -> None:
        path = self.database_path
        if not path.is_absolute() or ".." in path.parts:
            raise PersistenceError("database path must be absolute and traversal-free")
        path = Path(os.path.abspath(path))
        _check_safe_storage_path(path)
        initial_volume = _inspect_storage_volume(path)
        parent = path.parent
        parent_was_present = parent.exists()
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not parent.is_dir():
            raise PersistenceError("database parent is not a directory")
        _check_safe_storage_path(path)
        volume_id = _inspect_storage_volume(path)
        if volume_id != initial_volume:
            raise PersistenceError("database storage volume changed during path preparation")
        if os.name != "nt":
            if not parent_was_present:
                parent.chmod(0o700)
            elif stat.S_IMODE(parent.stat().st_mode) & 0o077:
                raise PersistenceError("database directory permissions must be owner-only")
        resolved_parent = parent.resolve(strict=True)
        if not _same_path(resolved_parent, parent):
            raise PersistenceError("database parent was redirected during preparation")
        self.database_path = resolved_parent / path.name
        if self.database_path.exists():
            metadata = self.database_path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink > 1:
                raise PersistenceError("database path must be a non-hardlinked regular file")
            if not _same_path(self.database_path.resolve(strict=True), self.database_path):
                raise PersistenceError("database file was redirected during preparation")
            self._database_identity = (metadata.st_dev, metadata.st_ino)
        self._storage_volume_id = volume_id
        parent_stat = self.database_path.parent.stat()
        self._parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
        _check_safe_storage_path(self.database_path)

    def _secure_database_permissions(self) -> None:
        if os.name != "nt" and self.database_path.exists():
            self.database_path.chmod(0o600)

    def _verify_database_location(self) -> None:
        _check_safe_storage_path(self.database_path)
        parent_stat = self.database_path.parent.stat()
        if self._parent_identity != (parent_stat.st_dev, parent_stat.st_ino):
            raise PersistenceError("database parent identity changed")
        if _inspect_storage_volume(self.database_path) != self._storage_volume_id:
            raise PersistenceError("database storage volume changed")
        metadata = self.database_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink > 1:
            raise PersistenceError("database target is not a non-hardlinked regular file")
        if not _same_path(self.database_path.resolve(strict=True), self.database_path):
            raise PersistenceError("database target was redirected")
        identity = (metadata.st_dev, metadata.st_ino)
        if self._database_identity is not None and identity != self._database_identity:
            raise PersistenceError("database file identity changed")
        self._database_identity = identity

    def _acquire_owner_lock(self) -> None:
        # On POSIX, lock the database inode itself. A sidecar pathname can be
        # unlinked while flock remains attached to its old inode, allowing a
        # second process to lock a newly-created sidecar inode. Windows keeps
        # the dedicated sidecar because its CRT locking/sharing semantics need
        # target-platform validation before changing that mechanism.
        lock_path = (
            self.database_path
            if os.name != "nt"
            else self.database_path.with_name(self.database_path.name + ".owner.lock")
        )
        _check_safe_storage_path(lock_path)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise PersistenceError("database owner lock could not be opened safely") from exc
        try:
            _check_safe_storage_path(lock_path)
            metadata = os.fstat(descriptor)
            path_metadata = lock_path.lstat() if os.name != "nt" else metadata
            parent_stat = lock_path.parent.stat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink > 1
                or (
                    os.name != "nt"
                    and (metadata.st_dev, metadata.st_ino)
                    != (path_metadata.st_dev, path_metadata.st_ino)
                )
                or metadata.st_dev != parent_stat.st_dev
                or _inspect_storage_volume(lock_path) != self._storage_volume_id
            ):
                raise PersistenceError("database owner lock is redirected or not a regular file")
            if os.name != "nt":
                posix_fchmod = getattr(os, "fchmod", None)
                if posix_fchmod is None:
                    raise PersistenceError("owner-only database lock permissions are unavailable")
                posix_fchmod(descriptor, 0o600)
            if os.name == "nt" and metadata.st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                windows_locking = importlib.import_module("msvcrt")
                windows_locking.locking(descriptor, windows_locking.LK_NBLCK, 1)
            else:
                posix_locking = importlib.import_module("fcntl")
                posix_locking.flock(descriptor, posix_locking.LOCK_EX | posix_locking.LOCK_NB)
            if os.name != "nt":
                # Recheck after acquiring flock to close the open/stat race:
                # the pathname must still identify the locked inode.
                locked_metadata = os.fstat(descriptor)
                current_path_metadata = lock_path.lstat()
                if (locked_metadata.st_dev, locked_metadata.st_ino) != (
                    current_path_metadata.st_dev,
                    current_path_metadata.st_ino,
                ):
                    raise PersistenceError("database owner lock path changed during acquisition")
            self._owner_lock_file = os.fdopen(descriptor, "r+b", buffering=0)
        except OSError as exc:
            os.close(descriptor)
            raise PersistenceBusyError("another process owns this database") from exc
        except Exception:
            os.close(descriptor)
            raise

    def _release_owner_lock(self) -> None:
        lock_file = self._owner_lock_file
        if lock_file is None:
            return
        self._owner_lock_file = None
        try:
            if os.name == "nt":
                windows_locking = importlib.import_module("msvcrt")
                lock_file.seek(0)
                windows_locking.locking(lock_file.fileno(), windows_locking.LK_UNLCK, 1)
            else:
                posix_locking = importlib.import_module("fcntl")
                posix_locking.flock(lock_file.fileno(), posix_locking.LOCK_UN)
        except OSError:
            pass
        finally:
            lock_file.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._verify_database_location()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield self._connection
                self._connection.execute("COMMIT")
                self._verify_database_location()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def _load_verified_migrations(self) -> dict[int, tuple[str, str, str]]:
        expected_names = {filename for filename, _ in _EXPECTED_MIGRATIONS.values()}
        try:
            files_by_name = {
                item.name: item
                for item in self._migrations_dir.iterdir()
                if item.name.endswith(".sql") and item.is_file()
            }
        except (OSError, FileNotFoundError) as exc:
            raise PersistenceIntegrityError("packaged migrations are unavailable") from exc
        if set(files_by_name) != expected_names:
            raise PersistenceIntegrityError("packaged migration set is missing or unexpected")
        verified: dict[int, tuple[str, str, str]] = {}
        for version, (filename, expected_sha256) in _EXPECTED_MIGRATIONS.items():
            try:
                migration_bytes = files_by_name[filename].read_bytes()
                migration_sql = migration_bytes.decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise PersistenceIntegrityError("packaged migration cannot be read") from exc
            actual_sha256 = hashlib.sha256(migration_bytes).hexdigest()
            if actual_sha256 != expected_sha256:
                raise PersistenceIntegrityError("packaged migration checksum mismatch")
            if re.search(r"(?i)\b(?:INSERT|REPLACE)\s+INTO\s+schema_migrations\b", migration_sql):
                raise PersistenceIntegrityError("migration ledger writes must be external to SQL")
            verified[version] = (filename, actual_sha256, migration_sql)
        return verified

    def _apply_migrations(self) -> None:
        current = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        target_version = ACTIVE_SCHEMA_VERSION
        if target_version not in _EXPECTED_MIGRATIONS:
            raise PersistenceIntegrityError("active schema version is not registered")
        # Activation gate (PR #14): a prepared migration must never run before it
        # is explicitly authorized, even if the active version was bumped.
        if target_version in PENDING_MIGRATION_VERSIONS:
            raise PersistenceIntegrityError(_activation_error(target_version))
        # Compare against the *active* version, not the registry maximum: a build
        # that has only activated version 1 must refuse a version-2 database
        # rather than open schema it does not implement.
        if current > target_version:
            raise PersistenceIntegrityError("database schema is newer than this application")
        if current > 0:
            try:
                ledger = self._connection.execute(
                    "SELECT version, name, sha256 FROM schema_migrations ORDER BY version"
                ).fetchall()
            except sqlite3.Error as exc:
                raise PersistenceIntegrityError(
                    "applied migration checksums are unavailable"
                ) from exc
            if len(ledger) != current:
                raise PersistenceIntegrityError("applied migration ledger is incomplete")
            for expected_version, row in enumerate(ledger, start=1):
                expected_name, expected_sha256 = _EXPECTED_MIGRATIONS[expected_version]
                if (
                    row["version"] != expected_version
                    or row["name"] != expected_name.removesuffix(".sql")
                    or row["sha256"] != expected_sha256
                ):
                    raise PersistenceIntegrityError("applied migration checksum mismatch")
        for version in range(current + 1, target_version + 1):
            migration_name, checksum, script = self._verified_migrations[version]
            try:
                self._connection.executescript(f"BEGIN IMMEDIATE;\n{script}")
                self._connection.execute(
                    "INSERT INTO schema_migrations(version, name, sha256, applied_at) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        version,
                        migration_name.removesuffix(".sql"),
                        checksum,
                        _timestamp(None),
                    ),
                )
                # Verify the version bump *before* committing. A migration whose
                # script completes but does not advance ``user_version`` (for
                # example a truncated or interrupted file) would otherwise leave
                # a committed partial schema behind while the database still
                # reports the old version.
                applied = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
                if applied != version:
                    raise PersistenceIntegrityError(
                        f"migration {migration_name} did not advance schema version"
                    )
                self._connection.execute("COMMIT")
            except sqlite3.Error as exc:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise PersistenceIntegrityError(f"migration {migration_name} failed") from exc
            except PersistenceIntegrityError:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def _verify_schema(self) -> None:
        user_version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        requirements = _SCHEMA_REQUIREMENTS.get(user_version)
        if requirements is None:
            raise PersistenceIntegrityError("database schema version is not supported")
        required_tables, required_triggers = requirements
        rows = self._connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE type IN ('table', 'index', 'trigger') "
            "AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%' "
            "ORDER BY type, name"
        ).fetchall()
        present_tables = {row["name"] for row in rows if row["type"] == "table"}
        present_triggers = {row["name"] for row in rows if row["type"] == "trigger"}
        if not required_tables.issubset(present_tables) or not required_triggers.issubset(
            present_triggers
        ):
            raise PersistenceIntegrityError("database schema objects are missing")
        schema_descriptor = [
            (row["type"], row["name"], _normalize_schema_sql(row["sql"])) for row in rows
        ]
        schema_hash = hashlib.sha256(_canonical_json(schema_descriptor).encode("utf-8")).hexdigest()
        if schema_hash != _EXPECTED_SCHEMA_SHA256.get(user_version):
            raise PersistenceIntegrityError("database schema integrity fingerprint mismatch")
        expected_name, expected_sha256 = _EXPECTED_MIGRATIONS[user_version]
        migration = self._connection.execute(
            "SELECT name, sha256 FROM schema_migrations WHERE version = ?", (user_version,)
        ).fetchone()
        if (
            migration is None
            or migration["name"] != expected_name.removesuffix(".sql")
            or migration["sha256"] != expected_sha256
        ):
            raise PersistenceIntegrityError("database migration ledger is inconsistent")

    def _check_integrity(self) -> None:
        try:
            quick = self._connection.execute("PRAGMA quick_check").fetchone()[0]
            if quick != "ok":
                raise PersistenceIntegrityError("SQLite quick_check failed")
            foreign = self._connection.execute("PRAGMA foreign_key_check").fetchone()
            if foreign is not None:
                raise PersistenceIntegrityError("SQLite foreign_key_check failed")
        except sqlite3.Error as exc:
            raise PersistenceIntegrityError("SQLite integrity verification failed") from exc

    def _append_event(
        self,
        connection: sqlite3.Connection,
        task_id: UUID,
        event_type: str,
        metadata: EventMetadata,
        *,
        now: str,
        step_id: UUID | None = None,
    ) -> UUID:
        self._validate_event_name(event_type)
        sequence = int(
            connection.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM task_events WHERE task_id = ?",
                (str(task_id),),
            ).fetchone()[0]
        )
        event_id = uuid4()
        connection.execute(
            "INSERT INTO task_events(id, task_id, seq, event_type, step_id, data_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(event_id),
                str(task_id),
                sequence,
                event_type,
                str(step_id) if step_id else None,
                _canonical_json(metadata.values),
                now,
            ),
        )
        return event_id

    @staticmethod
    def _validate_event_name(event_type: str) -> None:
        if not _EVENT_NAME.fullmatch(event_type):
            raise ValueError("event type must be an uppercase code")

    @staticmethod
    def _task_from_row(row: sqlite3.Row) -> StoredTask:
        try:
            return StoredTask(
                task_id=UUID(row["id"]),
                user_goal=row["user_goal"],
                state=PersistentTaskState(row["state"]),
                plan_revision=row["plan_revision"],
                plan_hash=row["plan_hash"],
                project_id=row["project_id"],
                created_at=_parse_timestamp(row["created_at"]),
                updated_at=_parse_timestamp(row["updated_at"]),
                finished_at=_parse_timestamp(row["finished_at"]) if row["finished_at"] else None,
                last_error_code=row["last_error_code"],
            )
        except (ValidationError, ValueError) as exc:
            raise PersistenceIntegrityError("stored task record is invalid") from exc

    @staticmethod
    def _verify_normalized_steps(plan: TaskPlan, rows: list[sqlite3.Row]) -> None:
        if len(rows) != len(plan.steps):
            raise PersistenceIntegrityError("normalized plan step count does not match plan")
        for index, (row, step) in enumerate(zip(rows, plan.steps, strict=True)):
            step_data = step.model_dump(mode="json")
            expected = (
                str(step.step_id),
                step.capability_id,
                _canonical_json(step_data["arguments"]),
                _canonical_json(step_data["resources"]),
                _canonical_json(step_data["expected_state"]),
                _canonical_json(step_data["expected_effect"]),
                _canonical_json(step_data["dependencies"]),
                _canonical_json(step_data["resource_locks"]),
                int(step.risk_tier),
                step.approval_status.value,
                step.timeout_seconds,
                step.max_attempts,
                str(step.idempotency_key),
                _canonical_json(step_data["postconditions"]),
                step.recovery_class,
                index,
            )
            actual = (
                row["id"],
                row["capability_id"],
                row["args_json"],
                row["resources_json"],
                row["expected_state_json"],
                row["effect_json"],
                row["deps_json"],
                row["locks_json"],
                row["risk_tier"],
                row["approval_status"],
                row["timeout_seconds"],
                row["max_attempts"],
                row["idempotency_key"],
                row["postconditions_json"],
                row["recovery_class"],
                row["order_index"],
            )
            if actual != expected:
                raise PersistenceIntegrityError(
                    f"normalized plan step {index} does not match canonical plan"
                )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _timestamp(value: datetime | str | None) -> str:
    if value is None:
        parsed = datetime.now(UTC)
    elif isinstance(value, str):
        parsed = _parse_timestamp(value)
    else:
        parsed = value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamps must include an explicit timezone")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PersistenceIntegrityError("stored timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PersistenceIntegrityError("stored timestamp lacks timezone")
    return parsed.astimezone(UTC)


def _validate_raw_database_path(raw_path: str) -> None:
    """Validate original path components before pathlib/Win32 can normalize them."""
    if not raw_path or "\x00" in raw_path:
        raise PersistenceError("database path is empty or contains a NUL character")
    windows_drive = PureWindowsPath(raw_path).drive
    components = re.split(r"[\\/]", raw_path)
    first_component = True
    for component in components:
        if not component or component == ".":
            continue
        if component == "..":
            raise PersistenceError("database path contains an unsafe component")
        if first_component and windows_drive and component.casefold() == windows_drive.casefold():
            first_component = False
            continue
        first_component = False
        try:
            relative_parts(component)
        except PathSafetyError as exc:
            raise PersistenceError("database path contains an unsafe component") from exc


def _check_safe_storage_path(path: Path) -> None:
    """Reject redirection and unsafe Windows components without user-file policy."""
    try:
        reject_reparse_components(path)
        for component in path.parts:
            if component != path.anchor:
                relative_parts(component)
    except PathSafetyError as exc:
        raise PersistenceError(
            "database path contains a symlink or reparse point or unsafe component"
        ) from exc


def _inspect_storage_volume(path: Path) -> str:
    """Require every existing component to stay on one supported fixed volume."""
    components = list(reversed(path.parents))
    if path.exists() or path.is_symlink():
        components.append(path)
    volume_id: str | None = None
    for component in components:
        if not component.exists() and not component.is_symlink():
            continue
        try:
            metadata = component.lstat()
            inspected_path = component if stat.S_ISDIR(metadata.st_mode) else component.parent
            info = inspect_volume(inspected_path)
        except (OSError, PathSafetyError) as exc:
            raise PersistenceError("database path volume identity is unavailable") from exc
        if info.kind != VolumeKind.FIXED or not info.volume_id or info.volume_id == "unknown":
            raise PersistenceError("database requires a known fixed storage volume")
        if volume_id is not None and info.volume_id != volume_id:
            raise PersistenceError("database path crosses a storage-volume boundary")
        volume_id = info.volume_id
    if volume_id is None:
        raise PersistenceError("database path has no verifiable existing ancestor")
    return volume_id


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def _normalize_schema_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", sql.strip())
