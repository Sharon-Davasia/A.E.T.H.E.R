"""Durable, transactional exact-approval-grant ledger (schema version 2).

Security posture mirrors ``SQLiteTaskStore``: raw-path validation, private
file permissions, fixed pragmas, integrity checks, and fail-closed schema
verification by exact SHA-256 fingerprint. The ledger **never applies or
registers migrations** — databases below version 2 fail closed with
:class:`GrantUnavailableError` until the proposed
``0002_phase2b_stage4_grants.sql`` migration is separately approved, merged
and applied.

Ownership and transaction design (independent review S4-5)
-----------------------------------------------------------
The task store owns one database at a time; its single-owner lock and
storage-identity checks are never weakened.

* :meth:`GrantLedger.open` requires a live :class:`SQLiteTaskStore` for the
  same absolute database path and **shares** its already-held owner lock and
  connection. The ledger never opens a second lock, never opens a second
  connection to the same file, and never takes ownership away from the store.
* The store's location verification, its ``BEGIN IMMEDIATE`` transaction (with
  rollback and post-commit re-verification), and its lock release order are
  reused unchanged, so grant writes cannot interleave with task writes inside
  one transaction and crash recovery stays all-or-nothing.
* :meth:`GrantLedger.read_only` exists for read-only verification (no owner
  lock, no transaction) and is documented as not an authorization path.
* :meth:`GrantLedger` (path-only construction) is retained **only** for tests
  and for read-only diagnostics against a database no store has open. It is
  not used for production issuance and takes its own lock when available.

Authorization is established **before** storage. :meth:`GrantLedger.issue` is
private-by-convention (`GrantLedger._persist_verified_grant`) and accepts only
the single-use :class:`IssuancePermit` that ``GrantIssuer`` obtains *after* the
attestation verifier and the authoritative preview source both succeed. No
public ledger entry point can persist a grant, so no production-capable path
can bypass the trusted authorization decision.

Consumption is a compare-and-decrement inside the store's transaction: a
grant can never be spent below zero, a revoked/expired/exhausted grant can
never be spent, and a retried consumption with the same idempotency identity
returns the recorded outcome without double-spending — but only when *every*
action-defining field matches.
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
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID, uuid4

from pydantic import ValidationError

from aether.core.contracts.approval import ExactApprovalGrant, exact_approval_scope_digest
from aether.core.contracts.policy import RiskTier
from aether.core.grants.errors import (
    GrantConflictError,
    GrantDeniedError,
    GrantIntegrityError,
    GrantIssuanceDenied,
    GrantNotFoundError,
    GrantUnavailableError,
)
from aether.core.grants.models import GrantConsumption, GrantIssuanceOutcome, GrantStatus
from aether.core.grants.validation import check_grant_scope
from aether.core.persistence.sqlite_store import (
    PersistenceError,
    _check_safe_storage_path,
    _inspect_storage_volume,
    _validate_raw_database_path,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aether.core.persistence.sqlite_store import SQLiteTaskStore

_EXPECTED_SCHEMA_SHA256_V2 = "dec68c2c1ecdd6d7222b5dcff54b877c9895e5cee6329930148c5db97355b788"
_PROPOSED_MIGRATION_SHA256 = "d2a02f54bc2f0eaee19fe1fd29c58294efbb136565145866d3c4853b8d64571c"
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

# Revocation and consumption sources are bounded machine-readable codes, never
# free text: nothing secret-bearing can be persisted into grant metadata.
REVOCATION_CODES = frozenset(
    {
        "SUPERSEDED_BY_PLAN",
        "TASK_TERMINATED",
        "CONSENT_REVOKED",
        "USER_CANCELLED",
        "SCOPE_INVALIDATED",
        "ADMINISTRATIVE",
    }
)
CONSUMED_BY_CODES = frozenset({"policy_check", "execution_adapter", "test_simulation"})
_ISSUER_CODE = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")

# S4-9: trust sources a permit may record (see aether.core.grants.authorization).
# ``trusted_verifier`` records the central decision's outcome for future
# integration; it is *not* accepted by the production-configured ledger, which
# denies all new issuance (see ``_check_permit_trust``).
_TRUSTED_TRUST_SOURCE = "trusted_verifier"
_TEST_TRUST_SOURCE = "test_simulation"

# S4-9: the only modules allowed to request or spend test-only persistence.
# Both spellings are listed because pytest may import the Stage 4 test modules
# either package-rooted (``tests.…``) or top-level (prepend/rootdir import).
# The canonical set lives here; ``authorization`` imports it rather than
# keeping a second copy that could drift.
TEST_AUTHORIZATION_MODULES = frozenset(
    {
        "tests.stage4_support",
        "tests.test_phase2b_stage4_grants",
        "stage4_support",
        "test_phase2b_stage4_grants",
    }
)


assert not any(name.startswith("aether.") for name in TEST_AUTHORIZATION_MODULES), (
    "test-only authorization must never be reachable from the shipped package"
)


def _caller_module_name(depth: int = 1) -> str:
    import sys

    name = sys._getframe(depth).f_globals.get("__name__", "")
    return name if isinstance(name, str) else ""


def _is_permitted_test_authorizer(module_name: str) -> bool:
    return module_name in TEST_AUTHORIZATION_MODULES


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise GrantIntegrityError("grant persistence requires timezone-aware timestamps")
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GrantIntegrityError("persisted grant timestamp lacks an explicit timezone")
    return parsed


def _resource_versions_digest(resource_versions: dict[str, str]) -> str:
    """Canonical digest of the sorted (resource_id, observed_version) set."""

    return _sha256_text(
        _canonical_json(
            [[resource_id, version] for resource_id, version in sorted(resource_versions.items())]
        )
    )


def issuance_intent_digest(
    *,
    scope_digest: str,
    task_id: UUID,
    plan_revision: int,
    plan_hash: str,
    max_tier: int,
    issued_at: datetime,
    expires_at: datetime,
    uses_remaining: int,
    issued_by: str,
) -> str:
    """Digest of the full immutable authorization intent (S4-2).

    ``exact_approval_scope_digest`` covers the approved operations only. The
    issuance identity must additionally bind the tier ceiling, the issue and
    expiry times, the initial use bound and the trusted issuer identity, so a
    replay under one issuance key with changed terms can never be accepted as
    the same authorization.
    """

    return _sha256_text(
        _canonical_json(
            {
                "scope_digest": scope_digest,
                "task_id": str(task_id),
                "plan_revision": plan_revision,
                "plan_hash": plan_hash.casefold(),
                "max_tier": int(max_tier),
                "issued_at": _timestamp(issued_at),
                "expires_at": _timestamp(expires_at),
                "uses_remaining": int(uses_remaining),
                "issued_by": issued_by,
            }
        )
    )


def consumption_action_digest(
    *,
    approval_id: UUID,
    task_id: UUID,
    plan_revision: int,
    plan_hash: str,
    step_id: UUID,
    capability_id: str,
    risk_tier: RiskTier,
    arguments_sha256: str,
    expected_effect_sha256: str,
    resource_versions_digest: str,
    consumed_by: str,
) -> str:
    """Digest of every action-defining field of one consumption (S4-3).

    ``consumed_by`` is included so one consumer cannot adopt another
    consumer's committed consumption identity.
    """

    return _sha256_text(
        _canonical_json(
            {
                "approval_id": str(approval_id),
                "task_id": str(task_id),
                "plan_revision": int(plan_revision),
                "plan_hash": plan_hash.casefold(),
                "step_id": str(step_id),
                "capability_id": capability_id,
                "risk_tier": int(risk_tier),
                "arguments_sha256": arguments_sha256.casefold(),
                "expected_effect_sha256": expected_effect_sha256.casefold(),
                "resource_versions_digest": resource_versions_digest,
                "consumed_by": consumed_by,
            }
        )
    )


class IssuancePermit:
    """Proof that a trust decision was made, plus which kind of decision it was.

    The permit is *not* itself authentication (independent review S4-9). It
    records the outcome of the central decision in
    :mod:`aether.core.grants.authorization`:

    * ``trust_source="trusted_verifier"`` — minted by
      :func:`aether.core.grants.authorization.authorize_issuance` after the
      injected attestation verifier and the authoritative preview source both
      accepted this exact grant. Reserved for the future authenticated
      authorizing boundary; it is accepted only by a test-scoped ledger today.
    * ``trust_source="test_simulation"`` — minted by
      :func:`aether.core.grants.authorization.authorize_test_persistence` for
      low-level persistence tests.

    The default, production-configured :meth:`GrantLedger.open` accepts
    **neither**: it refuses all new grant issuance until the authenticated
    authorizing boundary exists (see ``_check_permit_trust``). The trust source
    is a record of which decision ran, not a credential.

    Permits are single-use, bound to one scope digest plus issuer identity, and
    never persisted.
    """

    _scope_digest: str
    _issuer: str
    _trust_source: str
    _test_requester: str | None
    _binding: dict[str, object]
    _consumed: bool

    def __init__(self, *, scope_digest: str, issued_by: str) -> None:
        raise TypeError(
            "IssuancePermit is minted only by aether.core.grants.authorization; "
            "constructing a permit is not authorization"
        )

    @classmethod
    def _mint(
        cls,
        *,
        scope_digest: str,
        issued_by: str,
        trust_source: str,
        test_requester: str | None,
        binding: dict[str, object],
    ) -> IssuancePermit:
        permit = object.__new__(cls)
        permit._scope_digest = scope_digest
        permit._issuer = issued_by
        permit._trust_source = trust_source
        permit._test_requester = test_requester
        permit._binding = dict(binding)
        permit._consumed = False
        return permit

    @property
    def trust_source(self) -> str:
        return self._trust_source

    @property
    def test_requester(self) -> str | None:
        return self._test_requester

    @property
    def binding(self) -> dict[str, object]:
        return dict(self._binding)

    def _claim(self, *, scope_digest: str, issued_by: str) -> None:
        if self._consumed:
            raise GrantIssuanceDenied(
                "ISSUANCE_PERMIT_ALREADY_USED", "an issuance permit authorizes exactly one write"
            )
        if scope_digest != self._scope_digest or issued_by != self._issuer:
            raise GrantIssuanceDenied(
                "ISSUANCE_PERMIT_MISMATCH", "issuance permit does not cover this grant"
            )
        self._consumed = True


class GrantLedger:
    """Schema-v2 grant store. Fails closed on any verification mismatch."""

    # S4-8: the synchronization mechanism is an attribute of the ledger so a
    # reader can prove it took the writer's lock. In shared mode it *is* the
    # owning task store's lock, so ledger reads and store writes/fresh-consent
    # reads are mutually exclusive on the one shared connection.
    _lock: threading.RLock

    def __init__(
        self,
        database_path: Path | str,
        *,
        _connection: sqlite3.Connection | None = None,
        _shared_transaction: Any = None,
    ) -> None:
        try:
            raw_database_path = os.fspath(database_path)
        except TypeError as exc:
            raise GrantIntegrityError("database path must be text or a path-like object") from exc
        if not isinstance(raw_database_path, str):
            raise GrantIntegrityError("database path must be text or a path-like object")
        self.database_path = Path(raw_database_path).expanduser()
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
        self._lock = threading.RLock()
        self._closed = False
        self._owns_connection = _connection is None
        self._owns_lock = False
        self._owner_lock_file: Any = None
        self._store: SQLiteTaskStore | None = None
        # S4-9: "production" accepts only permits from the trusted authorization
        # decision. Only ``open_tests_scoped`` relaxes this, and only for
        # allow-listed test modules.
        self._trust_source_policy: str = "production"
        if _connection is not None:
            # Shared mode: the store owns the only connection and owner lock.
            self._connection = _connection
            self._shared_transaction = _shared_transaction
        else:
            # Standalone mode: tests and read-only diagnostics only.
            if os.name != "nt" and self.database_path.exists():
                self.database_path.chmod(0o600)
            try:
                self._acquire_owner_lock()
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
                self._shared_transaction = None
            except (sqlite3.Error, OSError) as exc:
                self._release_quietly()
                raise GrantIntegrityError("grant ledger initialization failed closed") from exc
        try:
            self._check_integrity()
            self._verify_v2_schema()
            self._check_integrity()
        except (GrantUnavailableError, GrantIntegrityError):
            self._release_quietly()
            raise
        except sqlite3.Error as exc:
            self._release_quietly()
            raise GrantIntegrityError("grant ledger initialization failed closed") from exc

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def open(cls, store: SQLiteTaskStore) -> GrantLedger:
        """Open the ledger for a live store, **sharing** its lock and connection.

        This is the only supported path for operations that write grants. It
        requires the store to be open, verifies that this ledger targets the
        very same database file, and reuses the store's own transaction, which
        already verifies storage location before and after every commit.
        """

        database_path = getattr(store, "database_path", None)
        if database_path is None:
            raise GrantUnavailableError("grant ledger requires an open task store")
        if getattr(store, "_closed", True):
            raise GrantUnavailableError("grant ledger requires an open task store")
        connection = getattr(store, "_connection", None)
        if connection is None:
            raise GrantUnavailableError("grant ledger requires the store's own connection")
        previous = getattr(store, "_stage4_grant_ledger", None)
        if previous is not None and not previous._closed:
            raise GrantUnavailableError(
                "a grant ledger is already open for this store; close it before opening another"
            )
        # S4-9: hold the store's own lock for construction *and* the initial
        # integrity/schema reads, not only afterwards. Those reads use the
        # store's single connection, so without the lock another thread could be
        # mid-transaction on it and the ledger would validate uncommitted state.
        with store._lock:
            ledger = cls(
                database_path,
                _connection=connection,
                _shared_transaction=store._transaction,
            )
            ledger._store = store
            # One shared connection means one synchronization mechanism: adopt
            # the store's lock so grant reads and grant writes serialize with
            # every task/plan/audit operation on that connection (S4-8).
            ledger._lock = store._lock
            try:
                store._stage4_grant_ledger = ledger  # type: ignore[attr-defined]
            except AttributeError:  # pragma: no cover - unexpected store shape
                raise GrantUnavailableError("task store cannot host a grant ledger") from None
        return ledger

    @classmethod
    def open_tests_scoped(cls, store: SQLiteTaskStore) -> GrantLedger:
        """Open a **test-only** ledger that also accepts simulated persistence.

        Isolated from every production-capable configuration: the extra
        acceptance applies to this instance only, is reachable solely through
        allow-listed test modules, and the default :meth:`open` never sets it.
        Used for low-level ledger semantics (replay, rollback, immutability)
        that must not require fabricating an attestation.
        """

        requester = _caller_module_name(2)  # skip this classmethod frame
        if not _is_permitted_test_authorizer(requester):
            raise GrantUnavailableError(
                "test-only grant-ledger configuration is not available to core modules"
            )
        ledger = cls.open(store)
        ledger._trust_source_policy = "test_scoped"
        return ledger

    @classmethod
    def read_only(cls, database_path: Path | str) -> GrantLedger:
        """Read-only verification handle. Never authorizes and never writes.

        Uses ``mode=ro`` so SQLite itself refuses writes. Requires exclusive
        access, so callers must not hold a store open on the same database.
        """

        instance = cls.__new__(cls)
        instance.database_path = Path(os.fspath(database_path)).expanduser()
        try:
            _validate_raw_database_path(os.fspath(instance.database_path))
            _check_safe_storage_path(instance.database_path)
        except PersistenceError as exc:
            raise GrantIntegrityError(
                "grant ledger database path failed safety validation"
            ) from exc
        if not instance.database_path.exists():
            raise GrantUnavailableError("grant ledger database does not exist")
        instance._lock = threading.RLock()
        instance._closed = False
        instance._owns_connection = True
        instance._owns_lock = False
        instance._owner_lock_file = None
        instance._store = None
        instance._shared_transaction = None
        # Read-only handles never write, so the policy is irrelevant; set it
        # explicitly so the attribute always exists.
        instance._trust_source_policy = "production"
        try:
            instance._connection = sqlite3.connect(
                f"file:{instance.database_path}?mode=ro",
                uri=True,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            instance._connection.row_factory = sqlite3.Row
            instance._check_integrity()
            instance._verify_v2_schema()
        except (sqlite3.Error, OSError) as exc:
            instance._release_quietly()
            raise GrantIntegrityError("grant ledger read-only open failed closed") from exc
        return instance

    # ------------------------------------------------------------------
    # Owner lock (standalone mode only)
    # ------------------------------------------------------------------

    def _acquire_owner_lock(self) -> None:
        lock_path = (
            self.database_path
            if os.name != "nt"
            else self.database_path.with_name(self.database_path.name + ".owner.lock")
        )
        _check_safe_storage_path(lock_path)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        import importlib

        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise GrantUnavailableError(
                "another process owns this database (standalone grant ledger lock unavailable)"
            ) from exc
        try:
            volume = _inspect_storage_volume(self.database_path)
            if os.name != "nt":
                fchmod = getattr(os, "fchmod", None)
                if fchmod is not None:
                    fchmod(descriptor, 0o600)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                windows_locking = importlib.import_module("msvcrt")
                windows_locking.locking(descriptor, windows_locking.LK_NBLCK, 1)
            else:
                posix_locking = importlib.import_module("fcntl")
                posix_locking.flock(descriptor, posix_locking.LOCK_EX | posix_locking.LOCK_NB)
            if _inspect_storage_volume(lock_path) != volume:
                raise OSError("lock volume changed")
            self._owner_lock_file = os.fdopen(descriptor, "r+b", buffering=0)
            self._owns_lock = True
        except OSError as exc:
            os.close(descriptor)
            raise GrantUnavailableError("another process owns this database") from exc
        except Exception:
            os.close(descriptor)
            raise

    def _release_owner_lock(self) -> None:
        lock_file = self._owner_lock_file
        if lock_file is None:
            return
        self._owner_lock_file = None
        self._owns_lock = False

        def unlock() -> None:
            if os.name == "nt":
                import importlib

                windows_locking = importlib.import_module("msvcrt")
                windows_locking.locking(lock_file.fileno(), windows_locking.LK_UNLCK, 1)
            else:
                import importlib

                posix_locking = importlib.import_module("fcntl")
                posix_locking.flock(lock_file.fileno(), posix_locking.LOCK_UN)

        with contextlib.suppress(OSError, ValueError):
            unlock()
        with contextlib.suppress(OSError):
            lock_file.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                if self._owns_connection:
                    self._connection.close()
            finally:
                self._release_owner_lock()
                store = self._store
                if store is not None and getattr(store, "_stage4_grant_ledger", None) is self:
                    store._stage4_grant_ledger = None  # type: ignore[attr-defined]
                self._store = None
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
        schema_hash = _sha256_text(_canonical_json(descriptor))
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
        with contextlib.suppress(sqlite3.Error, AttributeError, OSError):
            if getattr(self, "_owns_connection", True) and hasattr(self, "_connection"):
                self._connection.close()
        if getattr(self, "_owns_lock", False):
            self._release_owner_lock()

    # ------------------------------------------------------------------
    # Issuance (transactional, idempotent on the full authorization intent)
    # ------------------------------------------------------------------

    def _persist_verified_grant(
        self,
        grant: ExactApprovalGrant,
        *,
        permit: IssuancePermit,
        scope_digest: str,
        issuance_key: UUID,
        issued_by: str,
    ) -> GrantIssuanceOutcome:
        """Store one already-authorized grant.

        Private by design (S4-6): the only caller is :meth:`GrantIssuer.issue`,
        which obtains the permit from the trusted authorization decision. A
        direct call without a valid single-use permit is refused before any
        database interaction.
        """

        # S4-9: the gate is the *decision* that produced the permit, not the
        # object. The base implementation is called explicitly so a subclass
        # cannot inherit into authorization or override the claim.
        if type(permit) is not IssuancePermit:
            raise GrantIssuanceDenied(
                "AUTHORIZATION_EVIDENCE_REQUIRED",
                "grant storage requires a permit from the trusted authorization decision; "
                "direct issuance is not an authorization path",
            )
        # Configuration policy first: the production ledger denies every grant
        # before the permit is even inspected or spent (S4-9).
        self._check_permit_trust(permit, grant=grant, issuance_key=issuance_key)
        IssuancePermit._claim(permit, scope_digest=scope_digest, issued_by=issued_by)
        # S4-2: the supplied digest is verified independently, never trusted.
        actual_digest = exact_approval_scope_digest(grant)
        if not isinstance(scope_digest, str) or scope_digest != actual_digest:
            raise GrantIntegrityError(
                "supplied scope digest does not match the grant's computed scope digest"
            )
        if not isinstance(issued_by, str) or not _ISSUER_CODE.fullmatch(issued_by):
            raise GrantIntegrityError("issued_by must be a bounded machine-readable code")
        normalized_issuer = issued_by.lower()
        intent_digest = issuance_intent_digest(
            scope_digest=actual_digest,
            task_id=grant.task_id,
            plan_revision=grant.plan_revision,
            plan_hash=grant.plan_hash,
            max_tier=int(grant.max_tier),
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            uses_remaining=grant.uses_remaining,
            issued_by=normalized_issuer,
        )
        with self._lock, self._transaction() as connection:
            existing = connection.execute(
                "SELECT approval_id, scope_digest, issuance_digest FROM exact_approval_grants "
                "WHERE issuance_key = ?",
                (str(issuance_key),),
            ).fetchone()
            if existing is not None:
                if existing["issuance_digest"] != intent_digest:
                    raise GrantConflictError(
                        "issuance identity was replayed with different authorization terms"
                    )
                return GrantIssuanceOutcome(
                    approval_id=UUID(existing["approval_id"]),
                    scope_digest=actual_digest,
                    replayed=True,
                )
            duplicate = connection.execute(
                "SELECT 1 FROM exact_approval_grants WHERE approval_id = ?",
                (str(grant.approval_id),),
            ).fetchone()
            if duplicate is not None:
                raise GrantConflictError("approval id already identifies a persisted grant")
            # S4-4: re-verify the task's *current* plan pointer and consent
            # state inside the issuing transaction, so a plan change that
            # raced the pre-check cannot be persisted as a live grant.
            task_row = connection.execute(
                "SELECT state, plan_revision, plan_hash FROM tasks WHERE id = ?",
                (str(grant.task_id),),
            ).fetchone()
            if task_row is None:
                raise GrantDeniedError(
                    "TASK_NOT_AVAILABLE", "the authorization target task does not exist"
                )
            if (
                int(task_row["plan_revision"]) != grant.plan_revision
                or task_row["plan_hash"] != grant.plan_hash.casefold()
            ):
                raise GrantDeniedError(
                    "GRANT_PLAN_SUPERSEDED",
                    "the task's current plan changed while issuing this grant",
                )
            if task_row["state"] not in ("PREVIEW_READY", "AWAITING_APPROVAL"):
                raise GrantDeniedError(
                    "TASK_STATE_NOT_AUTHORIZABLE",
                    "the task left a consent-bearing state while issuing this grant",
                )
            self._check_fresh_consent(connection, grant.task_id)
            scope_json = _canonical_json(grant.model_dump(mode="json"))
            connection.execute(
                "INSERT INTO exact_approval_grants ("
                "approval_id, task_id, plan_revision, plan_hash, scope_digest, scope_json,"
                " issuance_digest, max_tier, approval_origin, issued_at, expires_at, issued_by,"
                " issuance_key, created_at"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(grant.approval_id),
                    str(grant.task_id),
                    grant.plan_revision,
                    grant.plan_hash.casefold(),
                    actual_digest,
                    scope_json,
                    intent_digest,
                    int(grant.max_tier),
                    grant.approval_origin,
                    _timestamp(grant.issued_at),
                    _timestamp(grant.expires_at),
                    normalized_issuer,
                    str(issuance_key),
                    _timestamp(datetime.now(UTC)),
                ),
            )
            connection.execute(
                "INSERT INTO exact_approval_grant_state ("
                "approval_id, initial_uses_remaining, uses_remaining, consumed_count,"
                " revoked_at, revocation_code"
                ") VALUES (?,?,?,0,NULL,NULL)",
                (str(grant.approval_id), grant.uses_remaining, grant.uses_remaining),
            )
            self._append_event_unlocked(
                connection,
                str(grant.approval_id),
                "ISSUED",
                reason_code=None,
                detail={
                    "approval_id": str(grant.approval_id),
                    "scope_digest": actual_digest,
                    "issuance_digest": intent_digest,
                    "issued_by": normalized_issuer,
                    "uses_remaining": grant.uses_remaining,
                },
            )
            return GrantIssuanceOutcome(
                approval_id=grant.approval_id,
                scope_digest=actual_digest,
                replayed=False,
            )

    # ------------------------------------------------------------------
    # Reads (scope verification is always re-done)
    # ------------------------------------------------------------------

    def load(self, approval_id: UUID) -> ExactApprovalGrant:
        with self._lock, self._read():
            row = self._grant_row(approval_id)
            grant, _state = self._grant_view(approval_id, row)
            return grant

    def status(self, approval_id: UUID, *, now: datetime | None = None) -> GrantStatus:
        now = now or datetime.now(UTC)
        with self._lock, self._read():
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
                revocation_code=state["revocation_code"],
                state=grant_state,
            )

    def get_consumption(self, consumption_id: UUID) -> GrantConsumption:
        with self._lock, self._read():
            row = self._connection.execute(
                "SELECT * FROM exact_approval_grant_consumptions WHERE consumption_id = ?",
                (str(consumption_id),),
            ).fetchone()
            if row is None:
                raise GrantNotFoundError("no persisted consumption exists for the given identity")
            return self._consumption_from_row(row)

    def list_consumptions(self, approval_id: UUID) -> tuple[GrantConsumption, ...]:
        with self._lock, self._read():
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
        reason_code: str,
        now: datetime | None = None,
    ) -> GrantStatus:
        now = now or datetime.now(UTC)
        if not isinstance(reason_code, str) or reason_code not in REVOCATION_CODES:
            raise GrantDeniedError(
                "REVOCATION_CODE_INVALID",
                "revocation reason must be one of the bounded machine-readable codes",
            )
        with self._lock, self._transaction() as connection:
            row = connection.execute(
                "SELECT revoked_at FROM exact_approval_grant_state WHERE approval_id = ?",
                (str(approval_id),),
            ).fetchone()
            if row is None:
                raise GrantNotFoundError("no persisted grant exists for the given approval id")
            if row["revoked_at"] is None:
                updated = connection.execute(
                    "UPDATE exact_approval_grant_state SET revoked_at = ?, revocation_code = ? "
                    "WHERE approval_id = ? AND revoked_at IS NULL",
                    (_timestamp(now), reason_code, str(approval_id)),
                )
                if updated.rowcount != 1:
                    raise GrantIntegrityError("grant revocation lost its compare-and-set")
                self._append_event_unlocked(
                    connection,
                    str(approval_id),
                    "REVOKED",
                    reason_code=reason_code,
                    detail={"revoked_at": _timestamp(now)},
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
        consumed_by: str,
        now: datetime | None = None,
    ) -> GrantConsumption:
        now = now or datetime.now(UTC)
        if consumed_by not in CONSUMED_BY_CODES:
            raise GrantDeniedError(
                "CONSUMER_CODE_INVALID", "consumed_by must be a bounded machine-readable code"
            )
        resources_digest = _resource_versions_digest(resource_versions)
        action_digest = consumption_action_digest(
            approval_id=approval_id,
            task_id=task_id,
            plan_revision=plan_revision,
            plan_hash=plan_hash,
            step_id=step_id,
            capability_id=capability_id,
            risk_tier=risk_tier,
            arguments_sha256=arguments_sha256,
            expected_effect_sha256=expected_effect_sha256,
            resource_versions_digest=resources_digest,
            consumed_by=consumed_by,
        )
        with self._lock, self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM exact_approval_grant_consumptions WHERE consumption_id = ?",
                (str(consumption_id),),
            ).fetchone()
            if existing is not None:
                if existing["action_digest"] != action_digest:
                    raise GrantConflictError(
                        "consumption identity was replayed with different action terms"
                    )
                replayed = self._consumption_from_row(existing)
                return replayed.model_copy(update={"replayed": True})
            row = connection.execute(
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
            self._check_current_task_binding(
                connection,
                grant=grant,
                task_id=task_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                executing=True,
            )
            self._check_fresh_consent(connection, task_id, executing=True)
            decremented = connection.execute(
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
            connection.execute(
                "INSERT INTO exact_approval_grant_consumptions ("
                "consumption_id, approval_id, task_id, plan_revision, plan_hash,"
                " step_id, capability_id, risk_tier, arguments_sha256,"
                " expected_effect_sha256, resource_versions_digest, action_digest,"
                " consumed_by, consumed_at, uses_remaining_after"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(consumption_id),
                    str(approval_id),
                    str(task_id),
                    plan_revision,
                    plan_hash.casefold(),
                    str(step_id),
                    capability_id,
                    int(risk_tier),
                    arguments_sha256.casefold(),
                    expected_effect_sha256.casefold(),
                    resources_digest,
                    action_digest,
                    consumed_by,
                    _timestamp(now),
                    after,
                ),
            )
            self._append_event_unlocked(
                connection,
                str(approval_id),
                "CONSUMED",
                reason_code=None,
                detail={
                    "consumption_id": str(consumption_id),
                    "step_id": str(step_id),
                    "capability_id": capability_id,
                    "action_digest": action_digest,
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
                risk_tier=risk_tier,
                arguments_sha256=arguments_sha256.casefold(),
                expected_effect_sha256=expected_effect_sha256.casefold(),
                consumed_by=consumed_by,
                consumed_at=now,
                uses_remaining_after=after,
                replayed=False,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check_current_task_binding(
        self,
        connection: sqlite3.Connection,
        *,
        grant: ExactApprovalGrant,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        executing: bool = False,
    ) -> None:
        """S4-4: a grant cannot be spent once the task's current plan moved.

        Caller-supplied historical plan identities are not sufficient: the
        task's *current* pointer must still be the plan revision/hash the
        grant was issued for, and the task must still be in a consent-bearing
        state. Both reads happen inside the same transaction as the decrement.
        """

        if grant.task_id != task_id:
            raise GrantDeniedError("GRANT_TASK_MISMATCH", "grant task does not match the use")
        row = connection.execute(
            "SELECT state, plan_revision, plan_hash FROM tasks WHERE id = ?", (str(task_id),)
        ).fetchone()
        if row is None:
            raise GrantDeniedError("TASK_NOT_AVAILABLE", "the granted task no longer exists")
        if int(row["plan_revision"]) != plan_revision or row["plan_hash"] != plan_hash.casefold():
            raise GrantDeniedError(
                "GRANT_PLAN_SUPERSEDED",
                "the task's current plan revision no longer matches this grant",
            )
        # FI-04: at spend time the task may legitimately be in PRECHECK —
        # recorded execution progress against this very grant. Issuance
        # (executing=False) keeps the original consent-bearing states.
        allowed_states = (
            ("PREVIEW_READY", "AWAITING_APPROVAL", "PRECHECK")
            if executing
            else ("PREVIEW_READY", "AWAITING_APPROVAL")
        )
        if row["state"] not in allowed_states:
            raise GrantDeniedError(
                "TASK_STATE_NOT_AUTHORIZABLE",
                "the task is no longer in a state that carries live user consent",
            )

    def _check_permit_trust(
        self,
        permit: IssuancePermit,
        *,
        grant: ExactApprovalGrant,
        issuance_key: UUID,
    ) -> None:
        """S4-9: default-deny. New grant issuance is disabled by configuration.

        The production-configured ledger — ``GrantLedger.open(store)`` — refuses
        **every** new grant, whatever permit the caller supplies. A permit is an
        ordinary Python object, so its fields cannot prove that a trusted
        verifier or an authoritative preview source ever ran; checking more
        fields would only make forgery slightly longer to type.

        Production issuance therefore stays switched off until the separately
        reviewed authenticated authorizing boundary exists (see
        :mod:`aether.core.grants.authorization`). Enabling it is a deliberate
        code change to this gate, not something a caller can supply at runtime.

        :meth:`open_tests_scoped` — reachable solely from allow-listed test
        modules — accepts the central decision's ``trusted_verifier`` permit and
        the isolated ``test_simulation`` permit, so the real issuance path and
        synthetic ledger semantics stay testable without weakening the
        production configuration.
        """

        # 1. Default-deny, decided by configuration and checked before the
        #    permit is inspected at all: no caller-supplied object changes this.
        if self._trust_source_policy != "test_scoped":
            raise GrantIssuanceDenied(
                "GRANT_ISSUANCE_DISABLED",
                "production grant issuance is disabled: the authenticated authorizing "
                "boundary does not exist yet, and no caller-supplied permit can enable it",
            )
        # 2. Test-scoped configuration (reachable only from allow-listed test
        #    modules): accept the central decision's permit so the real issuance
        #    path stays exercised end-to-end, or the isolated test seam.
        source = permit.trust_source
        if source == _TRUSTED_TRUST_SOURCE:
            binding = permit.binding
            if (
                binding.get("task_id") != str(grant.task_id)
                or binding.get("plan_revision") != grant.plan_revision
                or str(binding.get("plan_hash", "")).casefold() != grant.plan_hash.casefold()
                or binding.get("issuance_key") != str(issuance_key)
            ):
                raise GrantIssuanceDenied(
                    "ISSUANCE_PERMIT_MISMATCH",
                    "the authorization decision does not cover this exact grant",
                )
            return
        if source != _TEST_TRUST_SOURCE:
            raise GrantIssuanceDenied(
                "AUTHORIZATION_EVIDENCE_REQUIRED",
                "grant storage requires a permit from a recognized authorization decision",
            )
        requester = permit.test_requester
        if not isinstance(requester, str) or not _is_permitted_test_authorizer(requester):
            raise GrantIssuanceDenied(
                "AUTHORIZATION_EVIDENCE_REQUIRED",
                "test-only persistence was requested by a module that is not allow-listed",
            )
        binding = permit.binding
        if (
            binding.get("task_id") != str(grant.task_id)
            or binding.get("plan_revision") != grant.plan_revision
            or str(binding.get("plan_hash", "")).casefold() != grant.plan_hash.casefold()
        ):
            raise GrantIssuanceDenied(
                "ISSUANCE_PERMIT_MISMATCH", "the test permit does not cover this exact grant"
            )

    def _check_fresh_consent(
        self, connection: sqlite3.Connection, task_id: UUID, *, executing: bool = False
    ) -> None:
        """S4-7: the store's own fresh-consent predicate, inside this transaction.

        Called inside the same transaction as the grant write or the use
        decrement. It delegates to ``SQLiteTaskStore.is_stage2_preview_blocked``
        — the existing Stage 2 semantics that read ``task_events`` for an
        ``APPROVAL_PREVIEW_REVOKED`` (or any event marked
        ``requires_fresh_plan_and_consent``) after the latest saved plan. That
        predicate reads through the store's connection, which in shared mode is
        the transaction's connection, so an uncommitted revocation/REVISE is
        visible here and a revocation that lands later is caught by the next
        write. No second consent system is implemented.
        """

        store = self._store
        if store is None:
            raise GrantDeniedError(
                "CONSENT_AUTHORITY_UNAVAILABLE",
                "fresh-consent state is only verifiable through the owning task store",
            )
        if store._connection is not connection:
            raise GrantDeniedError(
                "CONSENT_AUTHORITY_UNAVAILABLE",
                "fresh-consent state must be read inside the grant transaction",
            )
        try:
            # FI-04: spend-time consent accepts the recorded PRECHECK
            # execution state; issuance-time consent is unchanged.
            blocked = (
                not store.is_execution_consent_active(task_id)
                if executing
                else store.is_stage2_preview_blocked(task_id)
            )
        except Exception as exc:  # fail closed on unreadable audit state
            raise GrantDeniedError(
                "CONSENT_AUTHORITY_UNAVAILABLE", "fresh-consent state could not be verified"
            ) from exc
        if blocked:
            raise GrantDeniedError(
                "CONSENT_INVALIDATED",
                "fresh plan and consent are required before this grant can be written or used",
            )

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
        is recomputed and compared, every scope-bearing column is cross-checked,
        and the stored issuance-intent digest is recomputed from the persisted
        columns. Mutable lifecycle state comes from the separate state row, so
        spending a use never rewrites the hashed scope.
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
        expected_intent = issuance_intent_digest(
            scope_digest=digest,
            task_id=scoped.task_id,
            plan_revision=scoped.plan_revision,
            plan_hash=scoped.plan_hash,
            max_tier=int(scoped.max_tier),
            issued_at=_parse_timestamp(row["issued_at"]),
            expires_at=_parse_timestamp(row["expires_at"]),
            uses_remaining=int(state["initial_uses_remaining"]),
            issued_by=str(row["issued_by"]),
        )
        if expected_intent != row["issuance_digest"]:
            raise GrantIntegrityError("persisted issuance intent digest mismatch")
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
            risk_tier=RiskTier(int(row["risk_tier"])),
            arguments_sha256=row["arguments_sha256"],
            expected_effect_sha256=row["expected_effect_sha256"],
            consumed_by=row["consumed_by"],
            consumed_at=_parse_timestamp(row["consumed_at"]),
            uses_remaining_after=int(row["uses_remaining_after"]),
            replayed=False,
        )

    def _append_event_unlocked(
        self,
        connection: sqlite3.Connection,
        approval_id: str,
        event: str,
        *,
        reason_code: str | None,
        detail: dict[str, Any],
    ) -> None:
        """Append one audit event with bounded, non-secret metadata.

        ``detail`` values are restricted to booleans, integers, bounded codes
        and lowercase hex digests/UUIDs. Free text never reaches the database,
        and any value that looks like a secret aborts the write.
        """

        for key, value in detail.items():
            if not _SAFE_DETAIL_KEY.fullmatch(key):
                raise GrantIntegrityError("grant event detail key is not allow-listed")
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                continue
            if isinstance(value, str):
                if _SAFE_DETAIL_VALUE.fullmatch(value):
                    continue
                raise GrantIntegrityError(
                    f"grant event detail {key!r} is not a bounded code, hash or identifier"
                )
            raise GrantIntegrityError(f"grant event detail {key!r} has an unsupported type")
        seq_row = connection.execute(
            "SELECT COALESCE(MAX(grant_seq), 0) + 1 AS next_seq "
            "FROM exact_approval_grant_events WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        connection.execute(
            "INSERT INTO exact_approval_grant_events ("
            "id, approval_id, grant_seq, event, reason_code, detail_json, created_at"
            ") VALUES (?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                approval_id,
                int(seq_row["next_seq"]),
                event,
                reason_code,
                _canonical_json(detail),
                _timestamp(datetime.now(UTC)),
            ),
        )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._require_open()
        if self._shared_transaction is not None:
            # Shared mode reuses the store's transaction: its lock, its
            # BEGIN IMMEDIATE, its rollback and its before/after location
            # verification. The ledger never opens its own transaction on a
            # database another component owns.
            with self._shared_transaction() as connection:
                original = self._connection
                self._connection = connection
                try:
                    yield connection
                finally:
                    self._connection = original
            return
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise GrantUnavailableError("grant ledger transaction could not begin") from exc
        try:
            yield self._connection
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        """Read guard for every public read path (S4-8).

        Reads refuse a closed ledger, and on the shared connection they must
        serialize with the store's writes. In shared mode ``self._lock`` *is* the
        store's lock (adopted in :meth:`open`), so the caller's surrounding
        ``with self._lock`` already excludes an uncommitted task/grant write
        performed by another thread inside the store's transaction.
        """

        self._require_open()
        yield self._connection

    def _require_open(self) -> None:
        if self._closed:
            raise GrantUnavailableError("grant ledger is closed")

    def events(self, approval_id: UUID) -> tuple[tuple[int, str, str | None, dict[str, Any]], ...]:
        """Read-only audit view used by tests and recovery verification."""

        with self._lock, self._read():
            rows = self._connection.execute(
                "SELECT grant_seq, event, reason_code, detail_json, created_at "
                "FROM exact_approval_grant_events WHERE approval_id = ? ORDER BY grant_seq",
                (str(approval_id),),
            ).fetchall()
            return tuple(
                (
                    int(row["grant_seq"]),
                    row["event"],
                    row["reason_code"],
                    json.loads(row["detail_json"]),
                )
                for row in rows
            )


_WHITESPACE = re.compile(r"\s+")
_SAFE_DETAIL_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# Lowercase hex digests, UUIDs, bounded uppercase codes and small integers only.
_SAFE_DETAIL_VALUE = re.compile(
    r"^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|[0-9a-f]{64}"
    r"|[A-Z][A-Z0-9_]{0,63}"
    r"|[a-z][a-z0-9_.:-]{0,63}"
    r"|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2}))$"
)


def _normalize_schema_sql(sql: str) -> str:
    return _WHITESPACE.sub(" ", sql.strip())
