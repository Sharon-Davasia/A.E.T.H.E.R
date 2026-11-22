"""Durable action receipts for verified mutations.

A receipt is the only artifact that may claim an edit happened. It records what
was attempted, what was actually observed, the hashes on both sides, the
snapshot that makes recovery possible, and any uncertainty. A receipt is
persisted *after* verification, and its status can never be upgraded later.

Receipts are append-only: `record` refuses to overwrite an existing receipt id,
so a retry cannot rewrite history. Reconciliation after a crash reads the
receipt table to decide what, if anything, still needs compensating.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

ReceiptStatus = Literal["SUCCEEDED", "FAILED", "UNVERIFIED", "PARTIAL"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS action_receipts (
    receipt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    approval_id TEXT,
    capability_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SUCCEEDED','FAILED','UNVERIFIED','PARTIAL')),
    recovery_class TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    attempted_path TEXT NOT NULL,
    pre_sha256 TEXT,
    post_sha256 TEXT,
    snapshot_id TEXT,
    warnings_json TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    verified_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_action_receipts_task ON action_receipts(task_id, created_at);
"""


class ReceiptError(Exception):
    """A receipt could not be recorded or is inconsistent."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True, slots=True)
class ActionReceiptRecord:
    """One immutable record of an attempted mutation."""

    receipt_id: UUID
    task_id: str
    step_id: str
    approval_id: str | None
    capability_id: str
    status: ReceiptStatus
    recovery_class: str
    resource_id: str
    attempted_path: str
    pre_sha256: str | None
    post_sha256: str | None
    snapshot_id: str | None
    warnings: tuple[str, ...] = ()
    detail: dict[str, object] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    verified_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.status == "SUCCEEDED" and self.verified_at is None:
            raise ReceiptError(
                "receipt_success_requires_verification",
                "a SUCCEEDED receipt must record when the effect was verified",
            )
        if self.status == "SUCCEEDED" and self.post_sha256 is None:
            raise ReceiptError(
                "receipt_success_requires_post_hash",
                "a SUCCEEDED receipt must record the verified resulting hash",
            )


class ReceiptStore:
    """Append-only receipt persistence on its own SQLite database."""

    def __init__(self, database: Path) -> None:
        self._database = Path(database)
        self._connection = sqlite3.connect(
            self._database, timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.executescript(_SCHEMA)
        if os.name != "nt":
            self._database.chmod(0o600)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> ReceiptStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def record(self, receipt: ActionReceiptRecord) -> ActionReceiptRecord:
        """Append one receipt; refuses to rewrite an existing id."""

        try:
            self._connection.execute("BEGIN IMMEDIATE")
            existing = self._connection.execute(
                "SELECT receipt_id FROM action_receipts WHERE receipt_id = ?",
                (str(receipt.receipt_id),),
            ).fetchone()
            if existing is not None:
                raise ReceiptError(
                    "receipt_already_recorded", "receipts are append-only and never rewritten"
                )
            self._connection.execute(
                "INSERT INTO action_receipts("
                "receipt_id, task_id, step_id, approval_id, capability_id, status, "
                "recovery_class, resource_id, attempted_path, pre_sha256, post_sha256, "
                "snapshot_id, warnings_json, detail_json, created_at, verified_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(receipt.receipt_id),
                    receipt.task_id,
                    receipt.step_id,
                    receipt.approval_id,
                    receipt.capability_id,
                    receipt.status,
                    receipt.recovery_class,
                    receipt.resource_id,
                    receipt.attempted_path,
                    receipt.pre_sha256,
                    receipt.post_sha256,
                    receipt.snapshot_id,
                    json.dumps(list(receipt.warnings), separators=(",", ":")),
                    json.dumps(receipt.detail, sort_keys=True, separators=(",", ":")),
                    receipt.created_at.isoformat(),
                    receipt.verified_at.isoformat() if receipt.verified_at else None,
                ),
            )
            self._connection.execute("COMMIT")
        except ReceiptError:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise ReceiptError(
                "receipt_write_failed", "the receipt could not be persisted"
            ) from exc
        return receipt

    def get(self, receipt_id: UUID) -> ActionReceiptRecord:
        row = self._connection.execute(
            "SELECT * FROM action_receipts WHERE receipt_id = ?", (str(receipt_id),)
        ).fetchone()
        if row is None:
            raise ReceiptError("receipt_not_found", "no such receipt")
        return _from_row(row)

    def for_task(self, task_id: str) -> tuple[ActionReceiptRecord, ...]:
        rows = self._connection.execute(
            "SELECT * FROM action_receipts WHERE task_id = ? ORDER BY created_at, rowid",
            (task_id,),
        ).fetchall()
        return tuple(_from_row(row) for row in rows)

    def unresolved(self) -> tuple[ActionReceiptRecord, ...]:
        """Receipts that did not reach a verified success.

        Used at startup to decide what still needs reconciliation. A crash
        between replace and verification leaves a row that is *not* SUCCEEDED,
        so recovery never assumes an unverified write completed.
        """

        rows = self._connection.execute(
            "SELECT * FROM action_receipts WHERE status IN ('UNVERIFIED','PARTIAL') "
            "ORDER BY created_at, rowid"
        ).fetchall()
        return tuple(_from_row(row) for row in rows)


def _from_row(row: sqlite3.Row) -> ActionReceiptRecord:
    return ActionReceiptRecord(
        receipt_id=UUID(row["receipt_id"]),
        task_id=row["task_id"],
        step_id=row["step_id"],
        approval_id=row["approval_id"],
        capability_id=row["capability_id"],
        status=row["status"],
        recovery_class=row["recovery_class"],
        resource_id=row["resource_id"],
        attempted_path=row["attempted_path"],
        pre_sha256=row["pre_sha256"],
        post_sha256=row["post_sha256"],
        snapshot_id=row["snapshot_id"],
        warnings=tuple(json.loads(row["warnings_json"])),
        detail=json.loads(row["detail_json"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        verified_at=(datetime.fromisoformat(row["verified_at"]) if row["verified_at"] else None),
    )


def new_receipt_id() -> UUID:
    return uuid4()


__all__ = [
    "ActionReceiptRecord",
    "ReceiptError",
    "ReceiptStatus",
    "ReceiptStore",
    "new_receipt_id",
]
