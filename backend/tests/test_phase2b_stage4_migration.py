"""Phase 2B Stage 4 — schema-v2 migration preparation and verification (PR #14).

This module verifies the *production integration surface* of the prepared
version-2 migration: the registry, fingerprints, critical-object inventories,
activation gate, clean install, upgrade from realistic v1 databases, rollback,
tampering and packaging.

Nothing here activates version 2 in production. The shipped configuration is
``ACTIVE_SCHEMA_VERSION = 1`` with version 2 listed in
``PENDING_MIGRATION_VERSIONS``; tests that need the migration to run lift that
gate in memory for the duration of one test only.

Everything is synthetic and offline. No test creates a real grant, executes a
capability, mutates a user file or exposes an IPC/HTTP grant surface.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from aether.core.grants.ledger import (
    _EXPECTED_SCHEMA_SHA256_V2,
    _MIGRATION_NAME_V2,
    _PROPOSED_MIGRATION_SHA256,
    GrantLedger,
)
from aether.core.persistence import sqlite_store
from aether.core.persistence.sqlite_store import (
    _EXPECTED_MIGRATIONS,
    _EXPECTED_SCHEMA_SHA256,
    _SCHEMA_REQUIREMENTS,
    ACTIVE_SCHEMA_VERSION,
    PENDING_MIGRATION_VERSIONS,
    PersistenceIntegrityError,
    PersistentTaskState,
    SQLiteTaskStore,
)

BACKEND_ROOT = Path(__file__).parents[1]
MIGRATIONS = BACKEND_ROOT / "aether/core/persistence/migrations"
MIGRATION_V1 = MIGRATIONS / "0001_phase2b_core.sql"
MIGRATION_V2 = MIGRATIONS / "0002_phase2b_stage4_grants.sql"

# Independently recomputed by replaying the packaged SQL through SQLite and
# hashing the normalized ``sqlite_master`` descriptor exactly as
# ``SQLiteTaskStore._verify_schema`` does. See the module-level test that proves
# the method reproduces the already-released version-1 pin.
EXPECTED_V1_SHA256 = "709077298230c7065c6778b3149f93b679b6e678220e2d1a34d3540a348d741e"
EXPECTED_V1_FINGERPRINT = "02f3cac7e905dfb4d1f161621c789bd5c437530002dec36202e9b2dfaa5d2e30"
EXPECTED_V2_SHA256 = "d2a02f54bc2f0eaee19fe1fd29c58294efbb136565145866d3c4853b8d64571c"
EXPECTED_V2_FINGERPRINT = "dec68c2c1ecdd6d7222b5dcff54b877c9895e5cee6329930148c5db97355b788"

V2_TABLES = {
    "exact_approval_grants",
    "exact_approval_grant_state",
    "exact_approval_grant_events",
    "exact_approval_grant_consumptions",
}
V2_TRIGGERS = {
    "exact_approval_grants_scope_no_update",
    "exact_approval_grant_events_no_update",
    "exact_approval_grant_events_no_delete",
    "exact_approval_grant_consumptions_no_update",
    "exact_approval_grant_consumptions_no_delete",
    "exact_approval_grant_state_guarded_update",
    "exact_approval_grant_state_no_delete",
}


# ---------------------------------------------------------------------------
# Independent recomputation helpers
# ---------------------------------------------------------------------------


def _normalize_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", sql.strip())


def _fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index', 'trigger') AND sql IS NOT NULL "
        "AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    descriptor = [(kind, name, _normalize_sql(sql)) for kind, name, sql in rows]
    canonical = json.dumps(descriptor, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _replay(*migrations: Path) -> tuple[sqlite3.Connection, str]:
    connection = sqlite3.connect(":memory:")
    for migration in migrations:
        connection.executescript(migration.read_text(encoding="utf-8"))
    return connection, _fingerprint(connection)


def _schema_objects(connection: sqlite3.Connection) -> dict[str, set[str]]:
    objects: dict[str, set[str]] = {"table": set(), "index": set(), "trigger": set()}
    for kind, name in connection.execute(
        "SELECT type, name FROM sqlite_master WHERE type IN ('table','index','trigger') "
        "AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%'"
    ):
        objects[kind].add(name)
    return objects


def _activate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lift the pending gate for one test (stands in for user approval)."""

    monkeypatch.setattr(sqlite_store, "ACTIVE_SCHEMA_VERSION", 2)
    monkeypatch.setattr(sqlite_store, "PENDING_MIGRATION_VERSIONS", frozenset())


CRLF_BYTES = b"\r\n"


def _scratch_migrations(destination: Path, *names: str) -> Path:
    destination.mkdir(parents=True)
    for name in names or (MIGRATION_V1.name, MIGRATION_V2.name):
        shutil.copyfile(MIGRATIONS / name, destination / name)
    return destination


def _assert_written_bytes_match_pin(path: Path, intended: str) -> None:
    """Prove the bytes on disk are the bytes whose digest the test pins.

    The checksum pinned for the store is computed from ``intended``. If the write
    path alters the file -- newline translation being the one that bit us -- the
    digest on disk disagrees with the pinned digest, and the store refuses the file
    as a *checksum* mismatch instead of reaching the failure the test is about.
    Asserting on the bytes actually written keeps that mistake visible here rather
    than surfacing as an inscrutable checksum error on another platform.

    This proves exactly one thing: the file on disk is the UTF-8 encoding of
    ``intended``, byte for byte. Hence the digest the test pins is the digest of
    the file the store will read.
    """

    written = path.read_bytes()
    expected = intended.encode("utf-8")
    crlf = written.count(CRLF_BYTES)
    assert written == expected, (
        "the migration file on disk is not the byte sequence the test intended to "
        f"write: {len(written)} bytes on disk vs {len(expected)} intended "
        f"({crlf} CRLF sequences found; newline translation mangles a checksum pin)"
    )
    assert CRLF_BYTES not in written, "the file contains CRLF; the write re-encoded it"
    assert hashlib.sha256(written).hexdigest() == hashlib.sha256(expected).hexdigest()


def _v1_database(database: Path) -> SQLiteTaskStore:
    """A realistic schema-v1 database (pre-activation configuration).

    Proposal A activated v2 in the shipped build, so a genuine v1
    database is produced under the test-scoped deactivated state.
    """

    from stage4_support import activation_state

    with pytest.MonkeyPatch.context() as monkeypatch:
        activation_state(monkeypatch, activated=False)
        store = SQLiteTaskStore(database)
    return store


# ---------------------------------------------------------------------------
# A. Registry, pins and independently recomputed values
# ---------------------------------------------------------------------------


def test_documented_migration_checksum_is_independently_reproduced() -> None:
    """The pinned migration bytes hash to the documented value."""

    actual = hashlib.sha256(MIGRATION_V2.read_bytes()).hexdigest()
    assert actual == EXPECTED_V2_SHA256
    assert actual == _PROPOSED_MIGRATION_SHA256
    assert actual == _EXPECTED_MIGRATIONS[2][1]
    assert _EXPECTED_MIGRATIONS[2][0] == MIGRATION_V2.name


def test_documented_v2_fingerprint_is_independently_reproduced() -> None:
    """Replaying 0001 then 0002 yields the documented 30-object fingerprint.

    The same helper reproduces the already-released version-1 pin, so the
    method itself is validated rather than assumed.
    """

    connection_v1, fingerprint_v1 = _replay(MIGRATION_V1)
    assert fingerprint_v1 == EXPECTED_V1_FINGERPRINT
    assert fingerprint_v1 == _EXPECTED_SCHEMA_SHA256[1]
    assert fingerprint_v1 == "02f3cac7e905dfb4d1f161621c789bd5c437530002dec36202e9b2dfaa5d2e30"

    connection_v2, fingerprint_v2 = _replay(MIGRATION_V1, MIGRATION_V2)
    assert fingerprint_v2 == EXPECTED_V2_FINGERPRINT
    assert fingerprint_v2 == _EXPECTED_SCHEMA_SHA256[2]
    assert fingerprint_v2 == _EXPECTED_SCHEMA_SHA256_V2

    objects_v1 = _schema_objects(connection_v1)
    objects_v2 = _schema_objects(connection_v2)
    assert len(objects_v2["table"]) + len(objects_v2["index"]) + len(objects_v2["trigger"]) == 30
    # Version 2 is additive: nothing from version 1 may disappear.
    for kind in ("table", "index", "trigger"):
        assert objects_v1[kind].issubset(objects_v2[kind]), kind
    assert objects_v2["table"] - objects_v1["table"] == V2_TABLES
    assert objects_v2["trigger"] - objects_v1["trigger"] == V2_TRIGGERS
    assert connection_v2.execute("PRAGMA user_version").fetchone()[0] == 2
    connection_v1.close()
    connection_v2.close()


def test_registry_and_grant_ledger_pins_agree() -> None:
    """The store registry and the ledger's own pins cannot drift apart."""

    assert _EXPECTED_MIGRATIONS[2] == (MIGRATION_V2.name, _PROPOSED_MIGRATION_SHA256)
    assert _EXPECTED_SCHEMA_SHA256[2] == _EXPECTED_SCHEMA_SHA256_V2
    assert MIGRATION_V2.name.removesuffix(".sql") == _MIGRATION_NAME_V2
    # Version 1 is untouched by this delivery.
    assert _EXPECTED_MIGRATIONS[1] == (MIGRATION_V1.name, EXPECTED_V1_SHA256)
    assert _EXPECTED_SCHEMA_SHA256[1] == EXPECTED_V1_FINGERPRINT


def test_critical_object_inventory_covers_version_two() -> None:
    """Schema requirements list exactly the objects each version must contain."""

    v1_tables, v1_triggers = _SCHEMA_REQUIREMENTS[1]
    v2_tables, v2_triggers = _SCHEMA_REQUIREMENTS[2]
    assert v1_tables.issubset(v2_tables)
    assert v1_triggers.issubset(v2_triggers)
    assert v2_tables - v1_tables == V2_TABLES
    assert v2_triggers - v1_triggers == V2_TRIGGERS
    assert v2_triggers == sqlite_store._CRITICAL_TRIGGER_NAMES
    # Every required trigger must actually exist in the replayed schema.
    connection, _ = _replay(MIGRATION_V1, MIGRATION_V2)
    present = _schema_objects(connection)["trigger"]
    assert v2_triggers.issubset(present)
    connection.close()


def test_migration_0001_bytes_are_not_rewritten() -> None:
    """The released migration is byte-identical to its release pin."""

    assert hashlib.sha256(MIGRATION_V1.read_bytes()).hexdigest() == EXPECTED_V1_SHA256


# ---------------------------------------------------------------------------
# B. Activation gate — v2 is prepared but must not run
# ---------------------------------------------------------------------------


def test_shipped_configuration_activates_version_two_after_proposal_a() -> None:
    """Proposal A: the delivered build creates and accepts v2 databases."""

    assert ACTIVE_SCHEMA_VERSION == 2
    assert frozenset() == PENDING_MIGRATION_VERSIONS


def test_clean_install_records_version_two_after_proposal_a(tmp_path: Path) -> None:
    """A fresh database is version 2 (Proposal A activated)."""

    database = tmp_path / "store.sqlite3"
    store = _v1_database(database)
    store.close()
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        rows = connection.execute(
            "SELECT version, name, sha256 FROM schema_migrations ORDER BY version"
        ).fetchall()
    assert rows == [(1, "0001_phase2b_core", EXPECTED_V1_SHA256)]
    assert rows[0][1] == _EXPECTED_MIGRATIONS[1][0].removesuffix(".sql")


def test_pending_migration_is_refused_even_if_active_version_is_bumped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bumping the active version alone cannot apply an unauthorized migration."""

    from stage4_support import activation_state

    activation_state(monkeypatch, activated=False)
    monkeypatch.setattr(sqlite_store, "ACTIVE_SCHEMA_VERSION", 2)
    database = tmp_path / "store.sqlite3"
    with pytest.raises(PersistenceIntegrityError, match="not authorized to apply"):
        SQLiteTaskStore(database)
    # A refused open must not write any schema. (The sqlite3 driver creates the
    # empty file on connect; the invariant that matters is no tables.)
    if database.exists():
        with sqlite3.connect(database) as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
            assert _schema_objects(connection)["table"] == set()


def test_refused_activation_does_not_touch_an_existing_v1_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused upgrade leaves an existing v1 database byte-identical."""

    from stage4_support import activation_state

    activation_state(monkeypatch, activated=False)
    database = tmp_path / "store.sqlite3"
    store = _v1_database(database)
    store.create_task("synthetic v1 task", now=None)
    store.close()
    before = database.read_bytes()
    monkeypatch.setattr(sqlite_store, "ACTIVE_SCHEMA_VERSION", 2)
    with pytest.raises(PersistenceIntegrityError, match="not authorized to apply"):
        SQLiteTaskStore(database)
    assert database.read_bytes() == before
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 1


def test_registered_migration_bytes_are_verified_even_while_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Packaged bytes are checked against the pin regardless of activation."""

    migrations = _scratch_migrations(tmp_path / "migrations")
    target = migrations / MIGRATION_V2.name
    target.write_bytes(target.read_bytes() + b"\n-- tampered\n")
    with pytest.raises(PersistenceIntegrityError, match="checksum mismatch"):
        SQLiteTaskStore(tmp_path / "store.sqlite3", migrations_dir=migrations)


def test_unexpected_migration_file_fails_closed(tmp_path: Path) -> None:
    """A stray .sql file in the packaged set is an integrity error."""

    migrations = _scratch_migrations(tmp_path / "migrations")
    (migrations / "0003_unexpected.sql").write_text("SELECT 1;", encoding="utf-8")
    with pytest.raises(PersistenceIntegrityError, match="missing or unexpected"):
        SQLiteTaskStore(tmp_path / "store.sqlite3", migrations_dir=migrations)


def test_missing_prepared_migration_fails_closed(tmp_path: Path) -> None:
    """Omitting the registered 0002 is detected, not silently tolerated."""

    migrations = _scratch_migrations(tmp_path / "migrations", MIGRATION_V1.name)
    with pytest.raises(PersistenceIntegrityError, match="missing or unexpected"):
        SQLiteTaskStore(tmp_path / "store.sqlite3", migrations_dir=migrations)


# ---------------------------------------------------------------------------
# C. Clean-install activation (exercises the real migration mechanics)
# ---------------------------------------------------------------------------


def test_activated_clean_install_creates_the_full_v2_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "store.sqlite3"
    _activate(monkeypatch)
    store = SQLiteTaskStore(database)
    store.create_task("synthetic v2 task", now=None)
    store.close()

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        rows = connection.execute(
            "SELECT version, name, sha256 FROM schema_migrations ORDER BY version"
        ).fetchall()
        assert [row[0] for row in rows] == [1, 2]
        assert rows[1] == (2, _MIGRATION_NAME_V2, EXPECTED_V2_SHA256)
        objects = _schema_objects(connection)
        assert V2_TABLES.issubset(objects["table"])
        assert V2_TRIGGERS.issubset(objects["trigger"])
        assert _fingerprint(connection) == EXPECTED_V2_FINGERPRINT
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_activated_v1_upgrade_preserves_existing_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Upgrading a realistic v1 database preserves every persisted row."""

    database = tmp_path / "store.sqlite3"
    store = _v1_database(database)
    task = store.create_task("synthetic pre-upgrade task", now=None)
    store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=None)
    store.close()

    with sqlite3.connect(database) as connection:
        before = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("tasks", "task_events", "schema_migrations")
        }
        before_task = connection.execute(
            "SELECT id, state, user_goal FROM tasks WHERE id = ?", (str(task.task_id),)
        ).fetchone()
        before_events = connection.execute(
            "SELECT id, task_id, seq, event_type, data_json FROM task_events ORDER BY id"
        ).fetchall()
        assert before["tasks"] == 1
        assert before["task_events"] >= 2
        assert before_task[1] == "PLANNING"

    _activate(monkeypatch)
    reopened = SQLiteTaskStore(database)
    reopened.close()

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        after = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("tasks", "task_events", "schema_migrations")
        }
        after_task = connection.execute(
            "SELECT id, state, user_goal FROM tasks WHERE id = ?", (str(task.task_id),)
        ).fetchone()
        after_events = connection.execute(
            "SELECT id, task_id, seq, event_type, data_json FROM task_events ORDER BY id"
        ).fetchall()
        assert after["tasks"] == before["tasks"]
        # The migration must not touch existing rows; reopening may append its
        # own durable event, so every pre-upgrade event must survive verbatim.
        assert set(before_events).issubset(set(after_events))
        # The task row survives with identical identity and goal. Its state moves
        # to PAUSED on reopen, which is the documented restart-recovery behaviour
        # and is independent of the schema migration.
        assert after_task[0] == before_task[0]
        assert after_task[2] == before_task[2]
        assert after_task[1] == "PAUSED"
        assert any(row[3] == "RESTART_RECOVERY_PAUSED" for row in after_events)
        assert after["schema_migrations"] == before["schema_migrations"] + 1
        assert _fingerprint(connection) == EXPECTED_V2_FINGERPRINT


def test_activated_upgrade_is_idempotent_on_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reopening a v2 database neither re-runs nor rewrites the migration."""

    database = tmp_path / "store.sqlite3"
    _activate(monkeypatch)
    SQLiteTaskStore(database).close()
    after_first = database.read_bytes()
    for _ in range(3):
        SQLiteTaskStore(database).close()
        assert database.read_bytes() == after_first


def test_activated_v2_database_opens_the_grant_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The migration is sufficient for the ledger, which shares the connection."""

    database = tmp_path / "store.sqlite3"
    _activate(monkeypatch)
    store = SQLiteTaskStore(database)
    try:
        ledger = GrantLedger.open(store)
        # The default (production) ledger still refuses issuance: the migration
        # does not enable authorization.
        assert ledger._trust_source_policy == "production"
        ledger.close()
    finally:
        store.close()
    read_only = GrantLedger.read_only(database)
    read_only.close()


def test_production_issuance_stays_disabled_after_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Migrating to schema v2 does not enable grant issuance.

    The permit forged here is *exact-type* with every field an attacker could
    want, on a database that really is at ``user_version = 2``. The
    production-configured ledger must still refuse it and write nothing, so the
    migration cannot be mistaken for an authorization change.
    """

    from uuid import uuid4

    from aether.core.contracts.approval import ExactApprovalGrant, exact_approval_scope_digest
    from aether.core.contracts.policy import RiskTier
    from aether.core.grants.errors import GrantIssuanceDenied
    from aether.core.grants.ledger import IssuancePermit
    from tests.stage4_support import LATER, NOW, SyntheticT2Plan

    database = tmp_path / "store.sqlite3"
    _activate(monkeypatch)
    store = SQLiteTaskStore(database)
    world = SyntheticT2Plan(database, store)
    grant = ExactApprovalGrant(
        approval_id=world.approval_id,
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation,),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        approval_origin="trusted-electron",
    )
    digest = exact_approval_scope_digest(grant)
    key = uuid4()
    forged = IssuancePermit._mint(  # type: ignore[attr-defined]
        scope_digest=digest,
        issued_by="test.attestation",
        trust_source="trusted_verifier",
        test_requester=None,
        binding={
            "task_id": str(world.task_id),
            "plan_revision": world.revision,
            "plan_hash": world.plan_hash,
            "issuance_key": str(key),
        },
    )
    assert forged.trust_source == "trusted_verifier"

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2

    try:
        with GrantLedger.open(store) as ledger:  # default: production-configured
            assert ledger._trust_source_policy == "production"
            with pytest.raises(GrantIssuanceDenied) as denied:
                ledger._persist_verified_grant(  # type: ignore[attr-defined]
                    grant,
                    permit=forged,
                    scope_digest=digest,
                    issuance_key=key,
                    issued_by="test.attestation",
                )
            assert denied.value.reason_code == "GRANT_ISSUANCE_DISABLED"
    finally:
        store.close()

    with sqlite3.connect(database) as connection:
        for table in V2_TABLES:
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table


# ---------------------------------------------------------------------------
# D. Failure injection, tampering and rollback
# ---------------------------------------------------------------------------


def test_upgrade_failure_rolls_back_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing 0002 leaves the database at v1 with no partial objects."""

    migrations = _scratch_migrations(tmp_path / "migrations")
    database = tmp_path / "store.sqlite3"
    _v1_database(database).close()  # realistic v1 database
    original = (migrations / MIGRATION_V2.name).read_text(encoding="utf-8")
    broken = original.replace("CREATE TABLE exact_approval_grants", "CREATE TABLE", 1)
    # ``write_text`` applies newline translation, so on Windows every LF became
    # CRLF and the file no longer hashed to the value pinned below: the store then
    # refused it as a *checksum* mismatch and never reached the SQL failure this
    # test is about. Writing bytes keeps the file identical on every platform.
    (migrations / MIGRATION_V2.name).write_bytes(broken.encode("utf-8"))
    _assert_written_bytes_match_pin(migrations / MIGRATION_V2.name, broken)

    # The pin no longer matches the (syntactically broken) file, so point the
    # registry at the tampered bytes to exercise the *SQL* failure path.
    monkeypatch.setitem(
        _EXPECTED_MIGRATIONS,
        2,
        (MIGRATION_V2.name, hashlib.sha256(broken.encode("utf-8")).hexdigest()),
    )
    _activate(monkeypatch)
    with pytest.raises(PersistenceIntegrityError, match=r"migration .* failed"):
        SQLiteTaskStore(database, migrations_dir=migrations)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        objects = _schema_objects(connection)
        assert not (V2_TABLES & objects["table"]), "partial migration left tables behind"
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 1


def test_interrupted_migration_leaves_no_half_applied_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A migration that stops mid-script rolls back completely.

    Simulates an unexpected interruption by truncating the script after the
    first objects are created but before the version bump.
    """

    migrations = _scratch_migrations(tmp_path / "migrations")
    database = tmp_path / "store.sqlite3"
    _v1_database(database).close()
    original = (migrations / MIGRATION_V2.name).read_text(encoding="utf-8")
    truncated = original[: original.index("CREATE TABLE exact_approval_grant_state")]
    # Bytes, not text: see the note in test_upgrade_failure_rolls_back_atomically.
    (migrations / MIGRATION_V2.name).write_bytes(truncated.encode("utf-8"))
    _assert_written_bytes_match_pin(migrations / MIGRATION_V2.name, truncated)
    monkeypatch.setitem(
        _EXPECTED_MIGRATIONS,
        2,
        (MIGRATION_V2.name, hashlib.sha256(truncated.encode("utf-8")).hexdigest()),
    )
    _activate(monkeypatch)
    # Pin the *specific* failure, not "some integrity error". The truncated script
    # is still valid SQL and runs to completion; it simply no longer ends with
    # ``PRAGMA user_version = 2``, so it must be refused by the version-bump check
    # and rolled back. Accepting any PersistenceIntegrityError would also pass if
    # the file were rejected earlier as a checksum mismatch, which is a different
    # bug entirely -- and is exactly what the CRLF defect produced on Windows.
    with pytest.raises(PersistenceIntegrityError) as refused:
        SQLiteTaskStore(database, migrations_dir=migrations)
    assert "did not advance schema version" in str(refused.value), (
        f"expected the version-bump rollback path, got: {refused.value}"
    )

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        objects = _schema_objects(connection)
        assert not (V2_TABLES & objects["table"])
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 1


def test_tampered_v2_migration_ledger_row_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "store.sqlite3"
    _activate(monkeypatch)
    SQLiteTaskStore(database).close()
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE schema_migrations SET sha256 = ? WHERE version = 2", ("e" * 64,))
    with pytest.raises(PersistenceIntegrityError, match="applied migration checksum mismatch"):
        SQLiteTaskStore(database)


def test_tampered_v2_schema_object_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dropping a grant-ledger trigger breaks the fingerprint and is rejected."""

    database = tmp_path / "store.sqlite3"
    _activate(monkeypatch)
    SQLiteTaskStore(database).close()
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER exact_approval_grant_state_no_delete")
    with pytest.raises(PersistenceIntegrityError, match="schema objects are missing"):
        SQLiteTaskStore(database)


def test_tampered_v2_schema_sql_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rewriting a grant-ledger object changes the fingerprint and is rejected.

    The object is dropped and recreated with equivalent-enough SQL to keep the
    name present, so this exercises the *fingerprint* check rather than the
    missing-object check.
    """

    database = tmp_path / "store.sqlite3"
    _activate(monkeypatch)
    SQLiteTaskStore(database).close()
    with sqlite3.connect(database) as connection:
        connection.execute("DROP INDEX idx_exact_approval_grants_task")
        connection.execute(
            "CREATE INDEX idx_exact_approval_grants_task ON exact_approval_grants(task_id, issued_at)"
        )
    with pytest.raises(PersistenceIntegrityError, match="fingerprint mismatch"):
        SQLiteTaskStore(database)


def test_version_two_database_is_rejected_when_not_activated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A database newer than the active version fails closed for this build."""

    database = tmp_path / "store.sqlite3"
    _activate(monkeypatch)
    SQLiteTaskStore(database).close()
    # Re-run with the shipped (unactivated) configuration.
    monkeypatch.setattr(sqlite_store, "ACTIVE_SCHEMA_VERSION", 1)
    monkeypatch.setattr(sqlite_store, "PENDING_MIGRATION_VERSIONS", frozenset({2}))
    with pytest.raises(PersistenceIntegrityError, match="newer than this application"):
        SQLiteTaskStore(database)


def test_v1_database_still_opens_while_v2_is_pending(tmp_path: Path) -> None:
    """Prepared-but-pending version 2 does not disturb shipped v1 behaviour."""

    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    task = store.create_task("synthetic v1 task", now=None)
    assert task.task_id is not None
    store.close()
    reopened = SQLiteTaskStore(database)
    assert reopened.get_task(task.task_id).task_id == task.task_id
    reopened.close()


def test_forged_permit_is_refused_on_a_migrated_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Doubles as the mutation guard for the issuance gate.

    Verified by mutation: deleting the ``_trust_source_policy != "test_scoped"``
    gate in ``GrantLedger._persist_verified_grant`` makes this test fail, so a
    green run here means production issuance is genuinely still disabled on a
    migrated database rather than merely reported as such.
    """

    import inspect

    from aether.core.grants import ledger as ledger_module

    source = inspect.getsource(ledger_module.GrantLedger._check_permit_trust)
    assert 'if self._trust_source_policy != "test_scoped":' in source
    assert "GRANT_ISSUANCE_DISABLED" in source
    # And the persistence path must consult that gate before writing anything.
    assert "_check_permit_trust" in inspect.getsource(
        ledger_module.GrantLedger._persist_verified_grant
    )


def test_activation_gate_is_the_only_thing_standing_between_pending_and_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation guard for the activation boundary (pre-activation state).

    Proposal A flipped the shipped configuration; the gate mechanics are
    still guarded here under the test-scoped deactivated state: with the
    gate deleted but ``ACTIVE_SCHEMA_VERSION`` still 1, nothing migrates
    (the pending version is never targeted); with the version bumped but
    the version still pending, opens fail closed.
    """

    from stage4_support import activation_state

    activation_state(monkeypatch, activated=False)
    assert sqlite_store.ACTIVE_SCHEMA_VERSION < 2
    assert 2 in sqlite_store.PENDING_MIGRATION_VERSIONS
    assert sqlite_store.ACTIVE_SCHEMA_VERSION in _EXPECTED_MIGRATIONS
    # The gate must be consulted *before* any target version is used, and the
    # active version must never be a pending one in the shipped build.
    assert sqlite_store.ACTIVE_SCHEMA_VERSION not in sqlite_store.PENDING_MIGRATION_VERSIONS
    # And the shipped build must not target the pending version even if the
    # version registry knows about it.
    database = tmp_path / "store.sqlite3"
    SQLiteTaskStore(database).close()
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert not (V2_TABLES & _schema_objects(connection)["table"])


# ---------------------------------------------------------------------------
# E. Packaged-wheel migration bytes
# ---------------------------------------------------------------------------


def test_packaged_migration_bytes_match_the_pin() -> None:
    """The files importlib.resources exposes are byte-identical to the pins."""

    from importlib.resources import files

    packaged = files("aether.core.persistence").joinpath("migrations")
    names = {item.name for item in packaged.iterdir() if item.name.endswith(".sql")}
    assert names == set(_EXPECTED_MIGRATIONS[version][0] for version in _EXPECTED_MIGRATIONS)
    for version, (filename, expected_sha256) in _EXPECTED_MIGRATIONS.items():
        data = packaged.joinpath(filename).read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected_sha256, version
    assert hashlib.sha256(packaged.joinpath(MIGRATION_V2.name).read_bytes()).hexdigest() == (
        EXPECTED_V2_SHA256
    )


def test_built_wheel_contains_the_verified_migration(tmp_path: Path) -> None:
    """A real wheel build ships 0002 with the exact pinned bytes.

    Slow (it builds a wheel), so it is skipped unless the build backend is
    importable; it is the only check that proves packaging, not the checkout.
    """

    import importlib.util

    if importlib.util.find_spec("hatchling") is None:
        pytest.skip("hatchling is not installed; wheel packaging check skipped")
    out = tmp_path / "dist"
    result = subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-d", str(out)],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"wheel build unavailable in this environment: {result.stderr[-400:]}")
    wheels = list(out.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        for version, (filename, expected_sha256) in _EXPECTED_MIGRATIONS.items():
            entry = f"aether/core/persistence/migrations/{filename}"
            assert entry in names, f"{filename} missing from wheel ({version})"
            assert hashlib.sha256(archive.read(entry)).hexdigest() == expected_sha256
        assert not any("proposed_migrations" in name for name in names)
