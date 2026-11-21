"""Transactional SQLite persistence for task plans and audit history.

This store intentionally has no capability executor, grant loader, or mutation
API. Approval decisions written here are immutable audit records only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aether.core.contracts.task import TaskState
from aether.core.persistence.models import (
    DISABLED_EXECUTION_STATES,
    ApprovalDecisionRecord,
    ApprovalDecisionValue,
    EventMetadata,
    PersistentTaskState,
    TaskPlan,
)
from aether.core.security.redaction import redact_text


class PersistenceError(RuntimeError):
    """A storage operation failed closed."""


class PersistenceIntegrityError(PersistenceError):
    """The database failed integrity, schema, or canonical-record validation."""


class IllegalPersistentTransition(PersistenceError):
    """A requested persistent task-state transition is not allowed."""


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

    def __init__(self, database_path: Path | str) -> None:
        self.database_path = Path(database_path).expanduser()
        self._lock = threading.RLock()
        self._prepare_private_path()
        try:
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
            self._check_integrity()
            self._apply_migrations()
            self._verify_schema()
            self._check_integrity()
            journal_mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if journal_mode.casefold() != "wal":
                raise PersistenceError("SQLite WAL mode is unavailable")
            self.recover_on_startup()
        except (sqlite3.Error, OSError, PersistenceError) as exc:
            if hasattr(self, "_connection"):
                self._connection.close()
            if isinstance(exc, PersistenceError):
                raise
            raise PersistenceError("database initialization failed closed") from exc

    def close(self) -> None:
        with self._lock:
            self._connection.close()

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
            finished_at = (
                timestamp
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
                (to_state.value, timestamp, finished_at, error_code, str(task_id)),
            )
            values = dict((metadata or EventMetadata()).values)
            values["from_state"] = current.value
            values["to_state"] = to_state.value
            self._append_event(
                connection,
                task_id,
                event,
                EventMetadata(values=values),
                now=timestamp,
            )
        return self.get_task(task_id)

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
                    timestamp,
                ),
            )
            self._append_event(
                connection,
                record.task_id,
                "APPROVAL_DECISION_RECORDED",
                EventMetadata(
                    values={
                        "approval_id": str(record.approval_id),
                        "decision": record.decision.value,
                        "authority": "NON_AUTHORIZING_AUDIT_RECORD",
                        "plan_revision": record.plan_revision,
                    }
                ),
                now=timestamp,
            )

    def get_approval_record(self, approval_id: UUID) -> ApprovalDecisionRecord:
        with self._lock:
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

    def list_events(self, task_id: UUID, *, after_sequence: int = 0) -> tuple[StoredTaskEvent, ...]:
        with self._lock:
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
            self._check_integrity()

    def _prepare_private_path(self) -> None:
        if self.database_path.is_symlink():
            raise PersistenceError("database symlinks are not accepted")
        parent = self.database_path.parent
        was_present = parent.exists()
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not parent.is_dir():
            raise PersistenceError("database parent is not a directory")
        if os.name != "nt":
            if not was_present:
                parent.chmod(0o700)
            elif stat.S_IMODE(parent.stat().st_mode) & 0o077:
                raise PersistenceError("database directory permissions must be owner-only")
        if self.database_path.exists():
            metadata = self.database_path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise PersistenceError("database path must be a regular file")
            if os.name != "nt":
                self.database_path.chmod(0o600)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield self._connection
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            finally:
                if os.name != "nt" and self.database_path.exists():
                    self.database_path.chmod(0o600)

    def _apply_migrations(self) -> None:
        current = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        migration_dir = files("aether.core.persistence").joinpath("migrations")
        migration_paths = sorted(migration_dir.iterdir(), key=lambda item: item.name)
        available: dict[int, tuple[str, str]] = {}
        for migration in migration_paths:
            match = re.fullmatch(r"(\d{4})_[a-z0-9_]+\.sql", migration.name)
            if match is None:
                continue
            version = int(match.group(1))
            available[version] = (migration.name, migration.read_text(encoding="utf-8"))
        if current > max(available, default=0):
            raise PersistenceIntegrityError("database schema is newer than this application")
        for version in range(current + 1, max(available, default=0) + 1):
            migration_entry = available.get(version)
            if migration_entry is None:
                raise PersistenceIntegrityError("database migration sequence has a gap")
            migration_name, script = migration_entry
            try:
                self._connection.executescript(f"BEGIN IMMEDIATE;\n{script}\nCOMMIT;")
            except sqlite3.Error as exc:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise PersistenceIntegrityError(f"migration {migration_name} failed") from exc
            applied = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            if applied != version:
                raise PersistenceIntegrityError("migration did not advance schema version")

    def _verify_schema(self) -> None:
        required_tables = {
            "schema_migrations",
            "tasks",
            "task_plans",
            "task_steps",
            "task_events",
            "approval_records",
        }
        required_triggers = {
            "task_plans_no_update",
            "task_plans_no_delete",
            "task_steps_no_update",
            "task_steps_no_delete",
            "task_events_no_update",
            "task_events_no_delete",
            "approval_records_no_update",
            "approval_records_no_delete",
        }
        rows = self._connection.execute(
            "SELECT type, name FROM sqlite_master WHERE type IN ('table', 'trigger')"
        ).fetchall()
        present = {row["name"] for row in rows}
        missing = (required_tables | required_triggers) - present
        if missing:
            raise PersistenceIntegrityError("database schema objects are missing")
        migration = self._connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 1"
        ).fetchone()
        user_version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if migration is None or migration["name"] != "0001_phase2b_core" or user_version != 1:
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
    ) -> None:
        self._validate_event_name(event_type)
        sequence = int(
            connection.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM task_events WHERE task_id = ?",
                (str(task_id),),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO task_events(id, task_id, seq, event_type, step_id, data_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid4()),
                str(task_id),
                sequence,
                event_type,
                str(step_id) if step_id else None,
                _canonical_json(metadata.values),
                now,
            ),
        )

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
