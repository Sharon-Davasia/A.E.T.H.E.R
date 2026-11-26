"""Durable navigation evidence store — PREPARED schema v3 only.

Operates on an explicit SQLite connection whose schema was created
from the prepared 0003 migration on an *isolated synthetic* database
(the test mechanism), or — after a future separate activation
decision — the migrated task store. This module never opens or
migrates a real-user database and is not wired into production.

Evidence is append-only at the schema level; bindings are checked in
code before insertion: cross-task or cross-capability evidence is
rejected, an attempt requires its confirmation, and a receipt
requires the matching verification. Interrupted attempts (attempt
recorded, no verification) reconcile as UNVERIFIED — never replayed.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from uuid import uuid4


class NavigationEvidenceError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ConfirmationBinding:
    confirmation_id: str
    task_id: str
    step_id: str
    plan_revision: int
    plan_hash: str
    capability_id: str
    arguments_sha256: str
    app_resource_id: str
    expected_app_version: str
    integrity_sha256: str
    session_id: str
    activation_scope: str
    issued_at: str
    expires_at: str


class NavigationEvidenceStore:
    """Append-only navigation evidence over a prepared v3 schema."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        self._db = connection

    @classmethod
    def on_memory(cls) -> NavigationEvidenceStore:
        """Isolated synthetic in-memory v3 database (tests only)."""
        from pathlib import Path

        connection = sqlite3.connect(":memory:")
        migration = (
            Path(__file__).resolve().parent.parent
            / "persistence"
            / "migrations"
            / "0003_phase3_navigation.sql"
        )
        # Apply only the navigation tables (the migration's PRAGMA
        # user_version is inert on this synthetic connection).
        connection.executescript(migration.read_text(encoding="utf-8"))
        return cls(connection)

    def record_confirmation(self, binding: ConfirmationBinding) -> None:
        try:
            self._db.execute(
                "INSERT INTO navigation_confirmations(id, task_id, step_id, plan_revision,"
                " plan_hash, capability_id, arguments_sha256, app_resource_id,"
                " expected_app_version, integrity_evidence_sha256, session_id,"
                " activation_scope, issued_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    binding.confirmation_id, binding.task_id, binding.step_id,
                    binding.plan_revision, binding.plan_hash, binding.capability_id,
                    binding.arguments_sha256, binding.app_resource_id,
                    binding.expected_app_version, binding.integrity_sha256,
                    binding.session_id, binding.activation_scope,
                    binding.issued_at, binding.expires_at,
                ),
            )
            self._db.commit()
        except sqlite3.IntegrityError as exc:
            raise NavigationEvidenceError("confirmation_record_rejected") from exc

    def record_attempt(
        self, *, confirmation_id: str, task_id: str, step_id: str,
        capability_id: str, app_resource_id: str, recorded_at: str,
    ) -> str:
        row = self._db.execute(
            "SELECT task_id, step_id, capability_id, app_resource_id"
            " FROM navigation_confirmations WHERE id = ?",
            (confirmation_id,),
        ).fetchone()
        if row is None:
            raise NavigationEvidenceError("attempt_without_confirmation")
        if (
            row["task_id"] != task_id or row["step_id"] != step_id
            or row["capability_id"] != capability_id or row["app_resource_id"] != app_resource_id
        ):
            raise NavigationEvidenceError("attempt_binding_mismatch")
        attempt_id = str(uuid4())
        try:
            self._db.execute(
                "INSERT INTO navigation_attempts(id, confirmation_id, task_id, step_id,"
                " capability_id, app_resource_id, attempt_number, recorded_at)"
                " VALUES (?,?,?,?,?,?,1,?)",
                (attempt_id, confirmation_id, task_id, step_id, capability_id, app_resource_id, recorded_at),
            )
            self._db.commit()
        except sqlite3.IntegrityError as exc:
            raise NavigationEvidenceError("attempt_replay_rejected") from exc
        return attempt_id

    def record_verification(
        self, *, attempt_id: str, outcome: str, process_token: str | None,
        window_token: str | None, verified_at: str,
    ) -> str:
        if self._db.execute(
            "SELECT id FROM navigation_attempts WHERE id = ?", (attempt_id,)
        ).fetchone() is None:
            raise NavigationEvidenceError("verification_without_attempt")
        verification_id = str(uuid4())
        try:
            self._db.execute(
                "INSERT INTO navigation_verifications(id, attempt_id, outcome,"
                " process_instance_token, window_version_token, verified_at)"
                " VALUES (?,?,?,?,?,?)",
                (verification_id, attempt_id, outcome, process_token, window_token, verified_at),
            )
            self._db.commit()
        except sqlite3.IntegrityError as exc:
            raise NavigationEvidenceError("verification_rejected") from exc
        return verification_id

    def record_receipt(
        self, *, attempt_id: str, verification_id: str, status: str, created_at: str
    ) -> str:
        row = self._db.execute(
            "SELECT attempt_id FROM navigation_verifications WHERE id = ?", (verification_id,)
        ).fetchone()
        if row is None or row["attempt_id"] != attempt_id:
            raise NavigationEvidenceError("receipt_verification_mismatch")
        if status == "SUCCEEDED":
            outcome = self._db.execute(
                "SELECT outcome FROM navigation_verifications WHERE id = ?", (verification_id,)
            ).fetchone()["outcome"]
            if not str(outcome).startswith("verified_"):
                raise NavigationEvidenceError("receipt_success_without_verification")
        receipt_id = str(uuid4())
        try:
            self._db.execute(
                "INSERT INTO navigation_receipts(id, attempt_id, verification_id, status,"
                " recovery_class, created_at) VALUES (?,?,?,?,?,?)",
                (receipt_id, attempt_id, verification_id, status, "IRREVERSIBLE", created_at),
            )
            self._db.commit()
        except sqlite3.IntegrityError as exc:
            raise NavigationEvidenceError("receipt_rejected") from exc
        return receipt_id

    def reconcile_interrupted(self) -> list[str]:
        """Attempt ids with no verification: UNVERIFIED, never replayed."""
        rows = self._db.execute(
            "SELECT a.id FROM navigation_attempts a"
            " LEFT JOIN navigation_verifications v ON v.attempt_id = a.id"
            " WHERE v.id IS NULL"
        ).fetchall()
        return [str(row["id"]) for row in rows]
