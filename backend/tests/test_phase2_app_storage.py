"""FI-02A: supported application storage initialization.

The shipped path (`AETHER_APP_DB`, passed by Electron main for every
build) opens the application store independently of the development
review seed, preserving owner locking, private permissions,
active-schema-only migration and fail-closed behaviour. The fixture
configuration is simply an isolated path under a fixture directory —
no real user data is ever touched.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from aether.channel.app_storage import open_application_store
from aether.channel.live_bridge import LiveBridge
from aether.core.composition import TrustedComposition
from aether.core.persistence.sqlite_store import ACTIVE_SCHEMA_VERSION, SQLiteTaskStore

GESTURE_KEY = b"a" * 32


def test_app_store_opens_without_any_review_seed(tmp_path) -> None:
    db_path = tmp_path / "fixture-storage" / "aether" / "tasks.sqlite3"
    store = open_application_store({"AETHER_APP_DB": str(db_path)})
    assert store is not None
    try:
        assert db_path.is_file()
        version = int(store._connection.execute("PRAGMA user_version").fetchone()[0])
        # Only the shipped active schema is applied — opening the
        # supported store never implicitly activates pending migrations.
        assert version == ACTIVE_SCHEMA_VERSION == 2
    finally:
        store.close()


def test_app_store_serves_the_live_bridge_on_shipped_schema(tmp_path) -> None:
    store = open_application_store({"AETHER_APP_DB": str(tmp_path / "app.sqlite3")})
    assert store is not None
    composition = TrustedComposition.build(store=store, gesture_key=GESTURE_KEY)
    bridge = LiveBridge(composition)
    try:
        # No review seed anywhere: project registration and planning work,
        # while mutation execution fails closed on the shipped schema.
        project = tmp_path / "project"
        project.mkdir()
        (project / "sample.txt").write_bytes(b"hello world\n")
        registered = bridge.register_project({"alias": "proj", "path": str(project)})
        assert "rootId" in registered, registered
        task = bridge.create_task({"goal": "replace one token"})
        executed = bridge.execute_edit({"taskId": task["taskId"]})
        assert executed["status"] == "unavailable", executed
    finally:
        composition.close()
        store.close()


def test_app_store_owner_lock_excludes_a_second_store(tmp_path) -> None:
    db_path = tmp_path / "app.sqlite3"
    store = open_application_store({"AETHER_APP_DB": str(db_path)})
    assert store is not None
    try:
        from aether.core.persistence.sqlite_store import PersistenceError

        with pytest.raises(PersistenceError):
            SQLiteTaskStore(db_path)
    finally:
        store.close()
    # After a clean close the store can be reopened (restart lifecycle).
    reopened = open_application_store({"AETHER_APP_DB": str(db_path)})
    assert reopened is not None
    reopened.close()


def test_app_store_misconfiguration_fails_closed(tmp_path) -> None:
    assert open_application_store({}) is None
    assert open_application_store({"AETHER_APP_DB": "relative/path.sqlite3"}) is None
    assert (
        open_application_store({"AETHER_APP_DB": str(tmp_path / "a" / ".." / "x.sqlite3")}) is None
    )
    # A directory where the database file should be is unusable.
    blocker = tmp_path / "blocked.sqlite3"
    blocker.mkdir()
    assert open_application_store({"AETHER_APP_DB": str(blocker)}) is None


def test_fixture_storage_configuration_is_isolated(tmp_path) -> None:
    """Windows-acceptance shape: storage entirely inside the fixture."""
    fixture = tmp_path / "AETHER-Phase2-Fixture-test"
    store = open_application_store({"AETHER_APP_DB": str(fixture / "storage" / "tasks.sqlite3")})
    assert store is not None
    try:
        task = store.create_task("fixture task", task_id=uuid4())
        assert store.get_task(task.task_id).user_goal == "fixture task"
        assert (fixture / "storage").is_dir()
    finally:
        store.close()
