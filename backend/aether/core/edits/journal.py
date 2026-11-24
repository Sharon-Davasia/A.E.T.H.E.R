"""Durable pre-mutation intent and restart reconciliation (S14-4).

The gap this closes: the executor captured a snapshot, replaced the file and only
then wrote a receipt. A process kill in that window left a changed file with no
durable record of *why* — either invisible (no receipt at all) or, worse, a
retry could produce a second effect for one approval.

The journal is written **before** anything is replaced and resolved afterwards,
so after a crash the state is always recoverable from disk:

  journal intent + snapshot + consumption  ──replace──▶  receipt + resolution

Reconciliation compares those four sources and reports one of a small set of
outcomes. It never infers success: an intent whose receipt cannot be found is
``NEEDS_REVIEW``, and an intent whose consumption was never resolved is reported
as such even if the file happens to look right.

Ordering guarantees:

* ``begin`` is durable before the first byte is written. If it cannot be written,
  the mutation does not happen (the executor refuses).
* ``resolve`` records the *observed* outcome, not the intended one.
* Both live in one SQLite database with one transaction each, so a crash leaves
  either the intent alone or the intent plus its resolution.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

JournalState = Literal[
    "INTENT_RECORDED",
    "REPLACED_UNVERIFIED",
    "VERIFIED",
    "FAILED",
    "ABANDONED",
]

_JOURNAL_STATES = frozenset(
    {"INTENT_RECORDED", "REPLACED_UNVERIFIED", "VERIFIED", "FAILED", "ABANDONED"}
)

ReconciliationVerdict = Literal[
    "COMPLETED_VERIFIED",
    "COMPLETED_UNVERIFIED",
    "NOT_APPLIED",
    "NEEDS_REVIEW",
    "INCONSISTENT",
]

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS mutation_intents (
        intent_id TEXT PRIMARY KEY,
        consumption_id TEXT,
        task_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        approval_id TEXT NOT NULL,
        capability_id TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        target_path TEXT,
        resource_version TEXT NOT NULL,
        pre_sha256 TEXT NOT NULL,
        intended_post_sha256 TEXT NOT NULL,
        expected_effect_sha256 TEXT NOT NULL,
        snapshot_id TEXT,
        state TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '',
        attempted_at TEXT NOT NULL,
        resolved_at TEXT
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS mutation_intents_open
        ON mutation_intents(state, attempted_at)
    """,
)


class JournalError(Exception):
    """The journal could not record the truth; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise JournalError("journal_timestamp_naive", "timestamps must be aware")
    return value.astimezone(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class MutationIntent:
    intent_id: UUID
    consumption_id: UUID | None
    task_id: UUID
    step_id: UUID
    approval_id: UUID
    capability_id: str
    resource_id: str
    target_path: str | None
    pre_sha256: str
    intended_post_sha256: str
    expected_effect_sha256: str
    snapshot_id: UUID | None
    state: JournalState
    attempted_at: datetime


@dataclass(frozen=True, slots=True)
class Reconciliation:
    """What reconciliation concluded about one unaccounted mutation.

    ``intent_id`` identifies the journal intent when there is one. An orphaned
    grant consumption has no intent, so ``intent_id`` is ``None`` and
    ``consumption_id`` carries the identity that was actually found. Keeping the
    two separate means a report can never imply an intent existed when it did not.
    """

    intent_id: UUID | None
    verdict: ReconciliationVerdict
    reason_code: str
    detail: str
    consumption_id: UUID | None = None


class MutationJournal:
    """Durable pre-mutation intent storage for one process' write path."""

    def __init__(self, database: Path | str, *, clock: object | None = None) -> None:
        self._lock = threading.RLock()
        self._clock = clock or (lambda: datetime.now(UTC))
        connection = sqlite3.connect(str(database), isolation_level=None, check_same_thread=False)
        try:
            connection.row_factory = sqlite3.Row
            with self._lock:
                connection.execute("PRAGMA journal_mode=WAL")
                for statement in _SCHEMA:
                    connection.execute(statement)
        except BaseException:
            # W-A3: deterministic constructor cleanup (see ReceiptStore):
            # a partially constructed journal is owned by no one, so its
            # connection must be closed here, preserving the failure.
            connection.close()
            raise
        self._connection = connection

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> MutationJournal:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- write path --------------------------------------------------------

    def begin(
        self,
        *,
        task_id: UUID,
        step_id: UUID,
        approval_id: UUID,
        capability_id: str,
        resource_id: str,
        target_path: str | Path | None = None,
        resource_version: str,
        pre_sha256: str,
        intended_post_sha256: str,
        expected_effect_sha256: str,
        consumption_id: UUID | None = None,
        snapshot_id: UUID | None = None,
        intent_id: UUID | None = None,
        now: datetime | None = None,
    ) -> MutationIntent:
        """Record the intent to mutate, before any byte is replaced.

        Called exactly once per attempted mutation. A second ``begin`` for the
        same step is refused: one approved step produces one intent, so a retry
        cannot create a second invisible effect.
        """

        identity = intent_id or uuid4()
        timestamp = _timestamp(now or self._clock())  # type: ignore[operator]
        with self._lock, self._transaction() as connection:
            existing = connection.execute(
                "SELECT intent_id FROM mutation_intents WHERE step_id = ? AND state != 'ABANDONED'",
                (str(step_id),),
            ).fetchone()
            if existing is not None:
                raise JournalError(
                    "journal_intent_already_recorded",
                    "this step already has a recorded mutation intent",
                )
            connection.execute(
                "INSERT INTO mutation_intents (intent_id, consumption_id, task_id, step_id,"
                " approval_id, capability_id, resource_id, target_path, resource_version,"
                " pre_sha256, intended_post_sha256, expected_effect_sha256, snapshot_id,"
                " state, attempted_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'INTENT_RECORDED',?)",
                (
                    str(identity),
                    str(consumption_id) if consumption_id else None,
                    str(task_id),
                    str(step_id),
                    str(approval_id),
                    capability_id,
                    resource_id,
                    str(target_path) if target_path is not None else None,
                    resource_version,
                    pre_sha256,
                    intended_post_sha256,
                    expected_effect_sha256,
                    str(snapshot_id) if snapshot_id else None,
                    timestamp,
                ),
            )
            return self._intent(connection, identity)

    def attach_snapshot(self, intent_id: UUID, snapshot_id: UUID) -> None:
        """Record the snapshot reference once it exists.

        The snapshot is captured after the intent (both precede the replace), so
        this fills in the reference the recovery path needs.
        """

        with self._lock, self._transaction() as connection:
            updated = connection.execute(
                "UPDATE mutation_intents SET snapshot_id = ? WHERE intent_id = ?",
                (str(snapshot_id), str(intent_id)),
            )
            if updated.rowcount != 1:
                raise JournalError("journal_intent_missing", "no such mutation intent")

    def resolve(
        self,
        intent_id: UUID,
        *,
        state: JournalState,
        detail: str = "",
        now: datetime | None = None,
    ) -> MutationIntent:
        """Record the observed outcome of an intent."""

        if state not in _JOURNAL_STATES or state == "INTENT_RECORDED":
            raise JournalError(
                "journal_state_invalid", "an intent must resolve to a terminal-ish state"
            )
        timestamp = _timestamp(now or self._clock())  # type: ignore[operator]
        with self._lock, self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM mutation_intents WHERE intent_id = ?", (str(intent_id),)
            ).fetchone()
            if row is None:
                raise JournalError("journal_intent_missing", "no such mutation intent")
            if row["state"] not in {"INTENT_RECORDED", "REPLACED_UNVERIFIED"}:
                raise JournalError(
                    "journal_intent_already_resolved",
                    "this intent was already resolved",
                )
            connection.execute(
                "UPDATE mutation_intents SET state = ?, detail = ?, resolved_at = ?"
                " WHERE intent_id = ?",
                (state, detail[:512], timestamp, str(intent_id)),
            )
            return self._intent(connection, intent_id)

    def record_replaced_unverified(self, intent_id: UUID, detail: str) -> MutationIntent:
        """The replace happened but verification has not completed.

        This is the crash window. Recording it means a subsequent kill leaves an
        intent that reconciliation will find instead of a silently changed file.
        """

        with self._lock, self._transaction() as connection:
            updated = connection.execute(
                "UPDATE mutation_intents SET state = 'REPLACED_UNVERIFIED', detail = ?"
                " WHERE intent_id = ? AND state = 'INTENT_RECORDED'",
                (detail[:512], str(intent_id)),
            )
            if updated.rowcount != 1:
                raise JournalError(
                    "journal_intent_missing", "no unresolved intent to mark as replaced"
                )
            return self._intent(connection, intent_id)

    # -- recovery ----------------------------------------------------------

    def open_intents(self) -> tuple[MutationIntent, ...]:
        """Intents whose outcome is unknown: the reconciliation work list."""

        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM mutation_intents"
                " WHERE state IN ('INTENT_RECORDED', 'REPLACED_UNVERIFIED')"
                " ORDER BY attempted_at"
            ).fetchall()
        return tuple(_intent_from_row(row) for row in rows)

    def get(self, intent_id: UUID) -> MutationIntent:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM mutation_intents WHERE intent_id = ?", (str(intent_id),)
            ).fetchone()
        if row is None:
            raise JournalError("journal_intent_missing", "no such mutation intent")
        return _intent_from_row(row)

    # -- internals ---------------------------------------------------------

    def _intent(self, connection: sqlite3.Connection, intent_id: UUID) -> MutationIntent:
        row = connection.execute(
            "SELECT * FROM mutation_intents WHERE intent_id = ?", (str(intent_id),)
        ).fetchone()
        if row is None:  # pragma: no cover - defensive
            raise JournalError("journal_intent_missing", "intent vanished after write")
        return _intent_from_row(row)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield self._connection
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        self._connection.execute("COMMIT")


def _intent_from_row(row: sqlite3.Row) -> MutationIntent:
    state = str(row["state"])
    if state not in _JOURNAL_STATES:
        raise JournalError("journal_state_invalid", "stored intent state is invalid")
    return MutationIntent(
        intent_id=UUID(row["intent_id"]),
        consumption_id=UUID(row["consumption_id"]) if row["consumption_id"] else None,
        task_id=UUID(row["task_id"]),
        step_id=UUID(row["step_id"]),
        approval_id=UUID(row["approval_id"]),
        capability_id=str(row["capability_id"]),
        resource_id=str(row["resource_id"]),
        target_path=str(row["target_path"]) if row["target_path"] else None,
        pre_sha256=str(row["pre_sha256"]),
        intended_post_sha256=str(row["intended_post_sha256"]),
        expected_effect_sha256=str(row["expected_effect_sha256"]),
        snapshot_id=UUID(row["snapshot_id"]) if row["snapshot_id"] else None,
        state=state,  # type: ignore[arg-type]
        attempted_at=datetime.fromisoformat(str(row["attempted_at"])),
    )


__all__ = [
    "JournalError",
    "JournalState",
    "MutationIntent",
    "MutationJournal",
    "Reconciliation",
    "ReconciliationVerdict",
]
