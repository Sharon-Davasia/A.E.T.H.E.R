"""Durable, transactional exact-approval-grant ledger (schema version 2).

Security posture mirrors ``SQLiteTaskStore``: raw-path validation, private
file permissions, fixed WAL/synchronous/secure_delete pragmas, integrity
checks, and fail-closed schema verification by exact SHA-256 fingerprint.
The ledger **never applies or registers migrations** — production databases
at schema version 1 fail closed with :class:`GrantUnavailableError` until
the proposed ``0002_phase2b_stage4_grants.sql`` migration is separately
approved, merged and applied.

Consumption is a compare-and-decrement inside ``BEGIN IMMEDIATE``: a grant
can never be spent below zero, a revoked/expired/exhausted grant can never
be spent, and a retried consumption with the same idempotency identity
returns the recorded outcome without double-spending. Crash behavior is
all-or-nothing per transaction; committed effects survive restart, and an
uncommitted consumption leaves no trace.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import ValidationError

from aether.core.contracts.approval import ExactApprovalGrant, exact_approval_scope_digest
from aether.core.contracts.policy import RiskTier
from aether.core.grants.errors import (
    GrantConflictError,
    GrantDeniedError,
    GrantIntegrityError,
    GrantNotFoundError,
    GrantUnavailableError,
)
from aether.core.grants.models import GrantConsumption, GrantIssuanceOutcome, GrantStatus
from aether.core.grants.validation import check_grant_scope
from aether.core.persistence.sqlite_store import (
    PersistenceError,
    _check_safe_storage_path,
    _validate_raw_database_path,
)

_EXPECTED_SCHEMA_SHA256_V2 = "f68447f63fe0c61313a8df30d09b572f74352f6860bcaf1678f06bf6565283f2"
_PROPOSED_MIGRATION_SHA256 = "a91b431cd84ced700b443df8ed0ecce45316f5f9737d768d8f313cc59d1c18cb"
_MIGRATION_NAME_V2 = "0002_phase2b_stage4_grants"
_REQUIRED_V2_TABLES = frozenset(
    {
        "schema_migrations",
        "tasks",
        "task_plans",
        "task_steps",
        "task_events",
        "approval_records",
        "exact_approval_grants",
        "exact_approval_grant_state",
        "exact_approval_grant_events",
        "exact_approval_grant_consumptions",
    }
)
_REQUIRED_V2_TRIGGERS = frozenset(
    {
        "task_plans_no_update",
        "task_plans_no_delete",
        "task_steps_no_update",
        "task_steps_no_delete",
        "task_events_no_update",
        "task_events_no_delete",
        "approval_records_no_update",
        "approval_records_no_delete",
        "exact_approval_grant_events_no_update",
        "exact_approval_grant_events_no_delete",
        "exact_approval_grant_consumptions_no_update",
        "exact_approval_grant_consumptions_no_delete",
        "exact_approval_grants_scope_no_update",
        "exact_approval_grant_state_no_delete",
        "exact_approval_grant_state_guarded_update",
    }
)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise GrantIntegrityError("grant persistence requires timezone-aware timestamps")
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GrantIntegrityError("persisted grant timestamp lacks an explicit timezone")
    return parsed


class GrantLedger:
    """Schema-v2 grant store. Fails closed on any verification mismatch."""

    def __init__(self, database_path: Path | str) -> None:
        try:
            raw_database_path = os.fspath(database_path)
        except TypeError as exc:
            raise GrantIntegrityError("database path must be text or a path-like object") from exc
        if not isinstance(raw_database_path, str):
            raise GrantIntegrityError("database path must be text or a path-like object")
        self.database_path = Path(raw_database_path).expanduser()
        # Path safety is the same fail-closed validation the task store uses;
        # any rejection is reported as a grant-ledger integrity failure so the
        # ledger never degrades into "probably fine" behavior.
        try:
            _validate_raw_database_path(raw_database_path)
            _validate_raw_database_path(os.fspath(self.database_path))
        except PersistenceError as exc:
            raise GrantIntegrityError(
                "grant ledger database path failed safety validation"
            ) from exc
        if not self.database_path.exists():
            raise GrantUnavailableError(
                "grant ledger requires an existing schema version 2 database; "
                "production migration has not been approved or applied"
            )
        try:
            _check_safe_storage_path(self.database_path)
        except PersistenceError as exc:
            raise GrantIntegrityError("grant ledger storage path is redirected or unsafe") from exc
        if os.name != "nt" and self.database_path.exists():
            self.database_path.chmod(0o600)
        self._lock = threading.RLock()
        self._closed = False
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
            self._verify_v2_schema()
            self._check_integrity()
        except (sqlite3.Error, OSError) as exc:
            self._release_quietly()
            raise GrantIntegrityError("grant ledger initialization failed closed") from exc
        except GrantUnavailableError:
            self._release_quietly()
            raise
        except GrantIntegrityError:
            self._release_quietly()
            raise

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._connection.close()
            finally:
                self._closed = True

    def __enter__(self) -> GrantLedger:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Schema verification (never applies migrations)
    # ------------------------------------------------------------------

    def _check_integrity(self) -> None:
        try:
            quick = self._connection.execute("PRAGMA quick_check").fetchone()[0]
            if quick != "ok":
                raise GrantIntegrityError("SQLite quick_check failed")
            foreign = self._connection.execute("PRAGMA foreign_key_check").fetchone()
            if foreign is not None:
                raise GrantIntegrityError("SQLite foreign_key_check failed")
        except sqlite3.Error as exc:
            raise GrantIntegrityError("SQLite integrity verification failed") from exc

    def _verify_v2_schema(self) -> None:
        try:
            user_version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        except sqlite3.Error as exc:
            raise GrantIntegrityError("database schema version is unavailable") from exc
        if user_version != 2:
            raise GrantUnavailableError(
                f"grant ledger requires schema version 2 (found {user_version}); "
                "the Stage 4 migration is proposed but not approved or applied"
            )
        rows = self._connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE type IN ('table', 'index', 'trigger') "
            "AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%' "
            "ORDER BY type, name"
        ).fetchall()
        tables = {row["name"] for row in rows if row["type"] == "table"}
        triggers = {row["name"] for row in rows if row["type"] == "trigger"}
        if not _REQUIRED_V2_TABLES.issubset(tables) or not _REQUIRED_V2_TRIGGERS.issubset(triggers):
            raise GrantIntegrityError("database schema objects are missing for schema version 2")
        descriptor = [(row["type"], row["name"], _normalize_schema_sql(row["sql"])) for row in rows]
        schema_hash = hashlib.sha256(_canonical_json(descriptor).encode("utf-8")).hexdigest()
        if schema_hash != _EXPECTED_SCHEMA_SHA256_V2:
            raise GrantIntegrityError("database schema integrity fingerprint mismatch")
        migration = self._connection.execute(
            "SELECT name, sha256 FROM schema_migrations WHERE version = 2"
        ).fetchone()
        if migration is None or migration["name"] != _MIGRATION_NAME_V2:
            raise GrantIntegrityError("schema migration ledger is missing the Stage 4 entry")
        if migration["sha256"] != _PROPOSED_MIGRATION_SHA256:
            raise GrantIntegrityError("schema migration ledger checksum mismatch")

    def _release_quietly(self) -> None:
        with contextlib.suppress(sqlite3.Error, AttributeError):
            self._connection.close()

    # ------------------------------------------------------------------
    # Issuance (transactional, idempotent on the issuance identity)
    # ------------------------------------------------------------------

    def issue(
        self,
        grant: ExactApprovalGrant,
        *,
        scope_digest: str,
        issuance_key: UUID,
        issued_by: str,
    ) -> GrantIssuanceOutcome:
        with self._lock, self._transaction():
            existing = self._connection.execute(
                "SELECT approval_id, scope_digest FROM exact_approval_grants "
                "WHERE issuance_key = ?",
                (str(issuance_key),),
            ).fetchone()
            if existing is not None:
                if existing["scope_digest"] != scope_digest:
                    raise GrantConflictError(
                        "issuance identity was replayed with a different grant scope"
                    )
                return GrantIssuanceOutcome(
                    approval_id=UUID(existing["approval_id"]),
                    scope_digest=scope_digest,
                    replayed=True,
                )
            scope_json = _canonical_json(grant.model_dump(mode="json"))
            self._connection.execute(
                "INSERT INTO exact_approval_grants ("
                "approval_id, task_id, plan_revision, plan_hash, scope_digest, scope_json,"
                " max_tier, approval_origin, issued_at, expires_at, issued_by,"
                " issuance_key, created_at"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(grant.approval_id),
                    str(grant.task_id),
                    grant.plan_revision,
                    grant.plan_hash.casefold(),
                    scope_digest,
                    scope_json,
                    int(grant.max_tier),
                    grant.approval_origin,
                    _timestamp(grant.issued_at),
                    _timestamp(grant.expires_at),
                    issued_by,
                    str(issuance_key),
                    _timestamp(datetime.now(UTC)),
                ),
            )
            self._connection.execute(
                "INSERT INTO exact_approval_grant_state ("
                "approval_id, initial_uses_remaining, uses_remaining, consumed_count,"
                " revoked_at, revocation_reason"
                ") VALUES (?,?,?,0,NULL,NULL)",
                (str(grant.approval_id), grant.uses_remaining, grant.uses_remaining),
            )
            self._append_event_unlocked(
                str(grant.approval_id),
                "ISSUED",
                {
                    "approval_id": str(grant.approval_id),
                    "scope_digest": scope_digest,
                    "issued_by": issued_by,
                    "uses_remaining": grant.uses_remaining,
                },
            )
            return GrantIssuanceOutcome(
                approval_id=grant.approval_id,
                scope_digest=scope_digest,
                replayed=False,
            )

    # ------------------------------------------------------------------
    # Reads (scope verification is always re-done)
    # ------------------------------------------------------------------

    def load(self, approval_id: UUID) -> ExactApprovalGrant:
        with self._lock:
            row = self._grant_row(approval_id)
            grant, _state = self._grant_view(approval_id, row)
            return grant

    def status(self, approval_id: UUID, *, now: datetime | None = None) -> GrantStatus:
        now = now or datetime.now(UTC)
        with self._lock:
            row = self._grant_row(approval_id)
            grant, state = self._grant_view(approval_id, row)
            grant_state: Literal["ACTIVE", "NOT_YET_VALID", "EXPIRED", "REVOKED", "EXHAUSTED"]
            if grant.revoked_at is not None:
                grant_state = "REVOKED"
            elif now < grant.issued_at:
                grant_state = "NOT_YET_VALID"
            elif now >= grant.expires_at:
                grant_state = "EXPIRED"
            elif grant.uses_remaining < 1:
                grant_state = "EXHAUSTED"
            else:
                grant_state = "ACTIVE"
            return GrantStatus(
                approval_id=grant.approval_id,
                task_id=grant.task_id,
                plan_revision=grant.plan_revision,
                plan_hash=grant.plan_hash,
                scope_digest=row["scope_digest"],
                max_tier=grant.max_tier,
                approval_origin=grant.approval_origin,
                issued_at=grant.issued_at,
                expires_at=grant.expires_at,
                uses_remaining=grant.uses_remaining,
                consumed_count=state["consumed_count"],
                revoked_at=grant.revoked_at,
                revocation_reason=state["revocation_reason"],
                state=grant_state,
            )

    def get_consumption(self, consumption_id: UUID) -> GrantConsumption:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM exact_approval_grant_consumptions WHERE consumption_id = ?",
                (str(consumption_id),),
            ).fetchone()
            if row is None:
                raise GrantNotFoundError("no persisted consumption exists for the given identity")
            return self._consumption_from_row(row)

    def list_consumptions(self, approval_id: UUID) -> tuple[GrantConsumption, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM exact_approval_grant_consumptions "
                "WHERE approval_id = ? ORDER BY consumed_at, consumption_id",
                (str(approval_id),),
            ).fetchall()
            return tuple(self._consumption_from_row(row) for row in rows)

    # ------------------------------------------------------------------
    # Revocation (idempotent; appends an event only on transition)
    # ------------------------------------------------------------------

    def revoke(
        self,
        approval_id: UUID,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> GrantStatus:
        now = now or datetime.now(UTC)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 256:
            raise GrantDeniedError(
                "REVOCATION_REASON_INVALID", "revocation reason must be 1..256 chars"
            )
        with self._lock, self._transaction():
            row = self._connection.execute(
                "SELECT revoked_at FROM exact_approval_grant_state WHERE approval_id = ?",
                (str(approval_id),),
            ).fetchone()
            if row is None:
                raise GrantNotFoundError("no persisted grant exists for the given approval id")
            if row["revoked_at"] is None:
                updated = self._connection.execute(
                    "UPDATE exact_approval_grant_state SET revoked_at = ?, revocation_reason = ? "
                    "WHERE approval_id = ? AND revoked_at IS NULL",
                    (_timestamp(now), reason, str(approval_id)),
                )
                if updated.rowcount != 1:
                    raise GrantIntegrityError("grant revocation lost its compare-and-set")
                self._append_event_unlocked(
                    str(approval_id),
                    "REVOKED",
                    {"reason": reason, "revoked_at": _timestamp(now)},
                )
            # Idempotent: revoking an already-revoked grant returns current state.
        return self.status(approval_id, now=now)

    # ------------------------------------------------------------------
    # Consumption (transactional compare-and-decrement)
    # ------------------------------------------------------------------

    def consume(
        self,
        *,
        consumption_id: UUID,
        approval_id: UUID,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        step_id: UUID,
        capability_id: str,
        risk_tier: RiskTier,
        arguments_sha256: str,
        expected_effect_sha256: str,
        resource_versions: dict[str, str],
        now: datetime | None = None,
    ) -> GrantConsumption:
        now = now or datetime.now(UTC)
        with self._lock, self._transaction():
            existing = self._connection.execute(
                "SELECT * FROM exact_approval_grant_consumptions WHERE consumption_id = ?",
                (str(consumption_id),),
            ).fetchone()
            if existing is not None:
                if (
                    existing["approval_id"] != str(approval_id)
                    or existing["task_id"] != str(task_id)
                    or int(existing["plan_revision"]) != plan_revision
                    or existing["plan_hash"].casefold() != plan_hash.casefold()
                    or existing["step_id"] != str(step_id)
                    or existing["capability_id"] != capability_id
                ):
                    raise GrantConflictError(
                        "consumption identity was replayed with different action data"
                    )
                replayed = self._consumption_from_row(existing)
                return replayed.model_copy(update={"replayed": True})
            row = self._connection.execute(
                "SELECT * FROM exact_approval_grants WHERE approval_id = ?",
                (str(approval_id),),
            ).fetchone()
            if row is None:
                raise GrantNotFoundError("no persisted grant exists for the given approval id")
            grant, state = self._grant_view(approval_id, row)
            check = check_grant_scope(
                grant,
                now=now,
                task_id=task_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                step_id=step_id,
                capability_id=capability_id,
                risk_tier=risk_tier,
                arguments_sha256=arguments_sha256,
                expected_effect_sha256=expected_effect_sha256,
                resource_versions=resource_versions,
            )
            if not check.ok:
                raise GrantDeniedError(check.reason_code, "grant does not authorize this action")
            decremented = self._connection.execute(
                "UPDATE exact_approval_grant_state "
                "SET uses_remaining = uses_remaining - 1, consumed_count = consumed_count + 1 "
                "WHERE approval_id = ? AND uses_remaining > 0 AND revoked_at IS NULL",
                (str(approval_id),),
            )
            if decremented.rowcount != 1:
                raise GrantDeniedError(
                    "GRANT_EXHAUSTED", "grant use was lost to a concurrent transition"
                )
            after = state["uses_remaining"] - 1
            self._connection.execute(
                "INSERT INTO exact_approval_grant_consumptions ("
                "consumption_id, approval_id, task_id, plan_revision, plan_hash,"
                " step_id, capability_id, consumed_at, uses_remaining_after"
                ") VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    str(consumption_id),
                    str(approval_id),
                    str(task_id),
                    plan_revision,
                    plan_hash.casefold(),
                    str(step_id),
                    capability_id,
                    _timestamp(now),
                    after,
                ),
            )
            self._append_event_unlocked(
                str(approval_id),
                "CONSUMED",
                {
                    "consumption_id": str(consumption_id),
                    "step_id": str(step_id),
                    "capability_id": capability_id,
                    "uses_remaining_after": after,
                },
            )
            return GrantConsumption(
                consumption_id=consumption_id,
                approval_id=approval_id,
                task_id=task_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash.casefold(),
                step_id=step_id,
                capability_id=capability_id,
                consumed_at=now,
                uses_remaining_after=after,
                replayed=False,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _grant_view(
        self, approval_id: UUID, row: sqlite3.Row
    ) -> tuple[ExactApprovalGrant, sqlite3.Row]:
        """Load the immutable scope and its mutable state, cross-verified."""
        state_row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM exact_approval_grant_state WHERE approval_id = ?",
            (str(approval_id),),
        ).fetchone()
        if state_row is None:
            raise GrantIntegrityError("persisted grant has no state row")
        grant = self._grant_from_row(row, state_row)
        count_row = self._connection.execute(
            "SELECT COUNT(*) AS consumptions, "
            "(SELECT COUNT(*) FROM exact_approval_grant_events "
            "WHERE approval_id = ? AND event = 'CONSUMED') AS consumed_events "
            "FROM exact_approval_grant_consumptions WHERE approval_id = ?",
            (str(approval_id), str(approval_id)),
        ).fetchone()
        if (
            int(count_row["consumptions"]) != state_row["consumed_count"]
            or int(count_row["consumed_events"]) != state_row["consumed_count"]
        ):
            raise GrantIntegrityError("persisted grant consumption accounting mismatch")
        return grant, state_row

    def _grant_row(self, approval_id: UUID) -> sqlite3.Row:
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM exact_approval_grants WHERE approval_id = ?",
            (str(approval_id),),
        ).fetchone()
        if row is None:
            raise GrantNotFoundError("no persisted grant exists for the given approval id")
        return row

    def _grant_from_row(self, row: sqlite3.Row, state: sqlite3.Row) -> ExactApprovalGrant:
        """Rebuild the grant from verified evidence.

        The persisted scope JSON is the *immutable approved scope*: its digest
        is recomputed and compared, and every scope-bearing column is
        cross-checked. Mutable lifecycle state (uses and revocation) comes
        from the separate state row, so spending a use never rewrites the
        hashed scope; instead the reconstructed grant is rebuilt from both and
        the two must agree on the approval binding.
        """

        try:
            scope = json.loads(row["scope_json"])
            scoped = ExactApprovalGrant.model_validate(scope)
        except (ValidationError, ValueError, TypeError) as exc:
            raise GrantIntegrityError("persisted grant scope failed typed validation") from exc
        digest = exact_approval_scope_digest(scoped)
        if digest != row["scope_digest"]:
            raise GrantIntegrityError("persisted grant scope digest mismatch")
        if str(scoped.approval_id) != row["approval_id"]:
            raise GrantIntegrityError("persisted grant id mismatch")
        if str(scoped.task_id) != row["task_id"]:
            raise GrantIntegrityError("persisted grant task mismatch")
        if (
            scoped.plan_revision != int(row["plan_revision"])
            or scoped.plan_hash.casefold() != str(row["plan_hash"]).casefold()
        ):
            raise GrantIntegrityError("persisted grant plan binding mismatch")
        if int(scoped.max_tier) != int(row["max_tier"]):
            raise GrantIntegrityError("persisted grant tier mismatch")
        if scoped.approval_origin != row["approval_origin"]:
            raise GrantIntegrityError("persisted grant approval origin mismatch")
        if row["approval_origin"] != "trusted-electron":
            raise GrantIntegrityError("persisted grant approval origin is not trusted")
        if str(state["approval_id"]) != row["approval_id"]:
            raise GrantIntegrityError("persisted grant state row mismatch")
        initial = int(state["initial_uses_remaining"])
        uses_remaining = int(state["uses_remaining"])
        consumed = int(state["consumed_count"])
        if uses_remaining + consumed != initial:
            raise GrantIntegrityError("persisted grant use accounting mismatch")
        if consumed < 0 or uses_remaining < 0:
            raise GrantIntegrityError("persisted grant use accounting is negative")
        if int(scoped.uses_remaining) != initial:
            raise GrantIntegrityError("persisted grant approved use bound mismatch")
        revoked_at = None if state["revoked_at"] is None else _parse_timestamp(state["revoked_at"])
        if scoped.revoked_at is not None and scoped.revoked_at != revoked_at:
            raise GrantIntegrityError("persisted grant revocation state mismatch")
        return scoped.model_copy(
            update={"uses_remaining": uses_remaining, "revoked_at": revoked_at}
        )

    def _consumption_from_row(self, row: sqlite3.Row) -> GrantConsumption:
        return GrantConsumption(
            consumption_id=UUID(row["consumption_id"]),
            approval_id=UUID(row["approval_id"]),
            task_id=UUID(row["task_id"]),
            plan_revision=int(row["plan_revision"]),
            plan_hash=row["plan_hash"],
            step_id=UUID(row["step_id"]),
            capability_id=row["capability_id"],
            consumed_at=_parse_timestamp(row["consumed_at"]),
            uses_remaining_after=int(row["uses_remaining_after"]),
            replayed=False,
        )

    def _append_event_unlocked(self, approval_id: str, event: str, detail: dict[str, Any]) -> None:
        seq_row = self._connection.execute(
            "SELECT COALESCE(MAX(grant_seq), 0) + 1 AS next_seq "
            "FROM exact_approval_grant_events WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        self._connection.execute(
            "INSERT INTO exact_approval_grant_events ("
            "id, approval_id, grant_seq, event, detail_json, created_at"
            ") VALUES (?,?,?,?,?,?)",
            (
                str(uuid4()),
                approval_id,
                int(seq_row["next_seq"]),
                event,
                _canonical_json(detail),
                _timestamp(datetime.now(UTC)),
            ),
        )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._require_open()
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise GrantUnavailableError("grant ledger transaction could not begin") from exc
        try:
            yield self._connection
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    def _require_open(self) -> None:
        if self._closed:
            raise GrantUnavailableError("grant ledger is closed")

    def events(self, approval_id: UUID) -> tuple[tuple[int, str, dict[str, Any]], ...]:
        """Read-only audit view used by tests and recovery verification."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT grant_seq, event, detail_json, created_at "
                "FROM exact_approval_grant_events WHERE approval_id = ? ORDER BY grant_seq",
                (str(approval_id),),
            ).fetchall()
            return tuple(
                (int(row["grant_seq"]), row["event"], json.loads(row["detail_json"]))
                for row in rows
            )


_WHITESPACE = re.compile(r"\s+")


def _normalize_schema_sql(sql: str) -> str:
    return _WHITESPACE.sub(" ", sql.strip())
