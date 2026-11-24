"""Migration-safety validation on disposable v1 database copies.

Decision E: schema v2 is required for the authoritative GrantLedger, but
activation is a separate, not-yet-authorized gate. These tests therefore
validate the migration only against *disposable copies* of a v1 database:

* the original v1 database fingerprint is byte-identical after every run;
* a backup of the v1 database can be restored and opens as v1;
* migration applies cleanly to the copy with all v1 records preserved;
* a failed/interrupted migration leaves the copy at v1 with no partial v2;
* the shipped build refuses a v2 database rather than downgrading or
  silently resetting it;
* concurrent ownership is refused while a store holds the database.

Shipped activation is unchanged: ``ACTIVE_SCHEMA_VERSION == 1`` and
``PENDING_MIGRATION_VERSIONS == {2}`` are asserted directly.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from aether.core.contracts.policy import RiskTier
from aether.core.persistence import (
    PersistenceIntegrityError,
    PersistentTaskState,
    SQLiteTaskStore,
)
from aether.core.persistence import sqlite_store
from aether.core.persistence.models import PlanStep, TaskPlan, TaskPlanResource
from stage4_support import NOW, activation_state, copy_migrations

RESOURCE_ID = "file:00000000-0000-0000-0000-000000000001"


def _fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _v1_populated(tmp_path: Path) -> tuple[Path, str]:
    """Create a genuine v1 database (shipped config) with representative data."""
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    task = store.create_task("pre-migration safety task", now=NOW)
    store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=NOW)
    plan = TaskPlan(
        task_id=task.task_id,
        revision=1,
        summary="synthetic plan",
        steps=(
            PlanStep(
                step_id=uuid4(),
                capability_id="fs.read_file",
                arguments={"resource_id": RESOURCE_ID},
                resources=(
                    TaskPlanResource(
                        resource_id=RESOURCE_ID,
                        expected_version="v1",
                        display_name="sample.txt",
                    ),
                ),
                resource_locks=(RESOURCE_ID,),
                expected_state={"resource": "present"},
                expected_effect={"effect": "read"},
                risk_tier=RiskTier.OBSERVE,
                approval_status="NOT_REQUIRED",
                idempotency_key=uuid4(),
                postconditions=({"condition": "read"},),
                recovery_class="IRREVERSIBLE",
            ),
        ),
        created_at=NOW,
    )
    store.save_plan(plan)
    store.close()
    return database, _fingerprint(database)


def _counts(database: Path) -> dict[str, int]:
    with sqlite3.connect(database) as connection:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in tables
        }


@pytest.fixture()
def v1(tmp_path: Path):
    database, fingerprint = _v1_populated(tmp_path)
    return database, fingerprint


def test_shipped_activation_configuration_is_unchanged() -> None:
    assert sqlite_store.ACTIVE_SCHEMA_VERSION == 1
    assert sqlite_store.PENDING_MIGRATION_VERSIONS == frozenset({2})


def test_backup_of_v1_database_restores_and_opens_as_v1(tmp_path: Path, v1) -> None:
    database, _ = v1
    backup = tmp_path / "backup.sqlite3"
    shutil.copyfile(database, backup)
    assert _fingerprint(backup) == _fingerprint(database)

    restored = tmp_path / "restored.sqlite3"
    shutil.copyfile(backup, restored)
    store = SQLiteTaskStore(restored)  # must open without error
    store.close()
    with sqlite3.connect(restored) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1


def test_migration_on_disposable_copy_preserves_records_and_original(
    v1, tmp_path, monkeypatch
) -> None:
    database, fingerprint = v1
    before = _counts(database)
    copy = tmp_path / "copy.sqlite3"
    shutil.copyfile(database, copy)

    migrations = copy_migrations(tmp_path / "migrations", include_proposed=True)
    activation_state(monkeypatch, activated=True)
    store = SQLiteTaskStore(copy, migrations_dir=migrations)
    store.close()

    assert _fingerprint(database) == fingerprint, "original v1 database was modified"
    after = _counts(copy)
    for table in ("tasks", "task_plans", "task_steps", "task_events", "schema_migrations"):
        if table == "schema_migrations":
            assert after[table] == before[table] + 1
        else:
            assert after[table] >= before[table], table
    with sqlite3.connect(copy) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='exact_approval_grants'"
        ).fetchone() is not None


def test_failed_migration_on_copy_leaves_v1_intact(tmp_path: Path, v1, monkeypatch) -> None:
    database, fingerprint = v1
    copy = tmp_path / "copy.sqlite3"
    shutil.copyfile(database, copy)

    # Corrupt the 0002 migration bytes in a disposable migrations dir: the
    # checksum verification must refuse before any SQL runs.
    migrations = copy_migrations(tmp_path / "migrations", include_proposed=True)
    (migrations / "0002_phase2b_stage4_grants.sql").write_text(
        "-- deliberately corrupted bytes for the disposable copy\n", encoding="utf-8"
    )
    activation_state(monkeypatch, activated=True)
    with pytest.raises(PersistenceIntegrityError):
        SQLiteTaskStore(copy, migrations_dir=migrations)

    assert _fingerprint(database) == fingerprint
    with sqlite3.connect(copy) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name='exact_approval_grants'"
        ).fetchone() is None


def test_shipped_build_refuses_v2_database_without_modifying_it(
    tmp_path: Path, v1, monkeypatch
) -> None:
    database, _ = v1
    copy = tmp_path / "copy.sqlite3"
    shutil.copyfile(database, copy)
    migrations = copy_migrations(tmp_path / "migrations", include_proposed=True)
    activation_state(monkeypatch, activated=True)
    SQLiteTaskStore(copy, migrations_dir=migrations).close()
    v2_fingerprint = _fingerprint(copy)

    monkeypatch.undo()  # restore shipped v1 configuration
    with pytest.raises(PersistenceIntegrityError):
        SQLiteTaskStore(copy)
    assert _fingerprint(copy) == v2_fingerprint, "v2 database was downgraded or reset"


def test_concurrent_ownership_is_refused(tmp_path: Path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    try:
        with pytest.raises(sqlite_store.PersistenceBusyError):
            SQLiteTaskStore(database)
    finally:
        store.close()
