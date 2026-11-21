"""Adversarial persistence tests for Phase 2B-1 (no execution authority)."""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

import aether.core.persistence.sqlite_store as persistence_store
from aether.core.contracts.policy import RiskTier
from aether.core.contracts.task import TaskState
from aether.core.persistence.models import (
    ApprovalDecisionRecord,
    ApprovalDecisionValue,
    EventMetadata,
    PersistentTaskState,
    PlanStep,
    TaskPlan,
    TaskPlanResource,
)
from aether.core.persistence.sqlite_store import (
    IllegalPersistentTransition,
    PersistenceBusyError,
    PersistenceError,
    PersistenceIntegrityError,
    SQLiteTaskStore,
    persistent_state_from_phase1,
    phase1_state_from_persistent,
)
from aether.core.resources.path_safety import PathSafetyError, VolumeInfo, VolumeKind

_NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


def _skip_if_symlink_unavailable(exc: OSError | NotImplementedError) -> None:
    """Skip only when the host explicitly cannot create the test symlink."""
    if isinstance(exc, NotImplementedError) or os.name != "nt":
        pytest.skip("symlink creation is unavailable on this host")
    if getattr(exc, "winerror", None) in {5, 1314}:
        pytest.skip(f"Windows denied symlink creation (WinError {exc.winerror})")
    raise exc


def _plan(task_id: UUID, *, revision: int = 1) -> TaskPlan:
    first = uuid4()
    second = uuid4()
    return TaskPlan(
        task_id=task_id,
        revision=revision,
        summary="Inspect a synthetic project and prepare a review-only proposal.",
        steps=(
            PlanStep(
                step_id=first,
                capability_id="fs.inspect_file",
                arguments={"resource_id": "file:synthetic-1"},
                resources=(
                    TaskPlanResource(
                        resource_id="file:synthetic-1",
                        expected_version="version-1",
                        display_name="example.py",
                    ),
                ),
                resource_locks=("file:synthetic-1",),
                expected_state={"resource": "unchanged"},
                expected_effect={"effect": "metadata-only"},
                risk_tier=RiskTier.OBSERVE,
                approval_status="NOT_REQUIRED",
                idempotency_key=uuid4(),
                postconditions=({"condition": "no mutation"},),
            ),
            PlanStep(
                step_id=second,
                dependencies=(first,),
                capability_id="proposal.review_only",
                arguments={"proposal": "review only"},
                expected_state={"task": "unmodified"},
                expected_effect={"effect": "none"},
                risk_tier=RiskTier.NAVIGATE,
                approval_status="CONTRACT_ONLY",
                idempotency_key=uuid4(),
                postconditions=({"condition": "no executor"},),
            ),
        ),
        created_at=_NOW + timedelta(seconds=revision),
    )


def _ready_for_plan(store: SQLiteTaskStore, task_id: UUID) -> None:
    store.transition_task(task_id, PersistentTaskState.PLANNING, now=_NOW)


def test_versioned_migration_and_private_file_permissions(tmp_path) -> None:
    database = tmp_path / "private" / "aether.sqlite3"
    store = SQLiteTaskStore(database)
    with store._lock:
        version = store._connection.execute("PRAGMA user_version").fetchone()[0]
        applied = store._connection.execute(
            "SELECT version, name, sha256 FROM schema_migrations"
        ).fetchall()
    assert version == 1
    assert [(row["version"], row["name"], row["sha256"]) for row in applied] == [
        (
            1,
            "0001_phase2b_core",
            persistence_store._EXPECTED_MIGRATIONS[1][1],
        )
    ]
    if os.name != "nt":
        assert database.stat().st_mode & 0o777 == 0o600
    store.close()
    reopened = SQLiteTaskStore(database)
    with reopened._lock:
        assert reopened._connection.execute("PRAGMA user_version").fetchone()[0] == 1
    reopened.close()


def _copy_migration_directory(destination: Path) -> Path:
    destination.mkdir()
    source = Path(__file__).parents[1] / "aether/core/persistence/migrations/0001_phase2b_core.sql"
    shutil.copyfile(source, destination / source.name)
    return destination


def test_changed_applied_migration_bytes_are_rejected(tmp_path) -> None:
    migrations = _copy_migration_directory(tmp_path / "migrations")
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database, migrations_dir=migrations)
    store.close()
    migration_file = migrations / "0001_phase2b_core.sql"
    migration_file.write_bytes(migration_file.read_bytes() + b"\n-- tampered after release\n")
    with pytest.raises(PersistenceIntegrityError, match="checksum mismatch"):
        SQLiteTaskStore(database, migrations_dir=migrations)


def test_missing_migration_fails_before_opening_database(tmp_path) -> None:
    missing = tmp_path / "empty-migrations"
    missing.mkdir()
    database = tmp_path / "store.sqlite3"
    with pytest.raises(PersistenceIntegrityError, match="missing or unexpected"):
        SQLiteTaskStore(database, migrations_dir=missing)
    assert not database.exists()


def test_missing_applied_migration_file_fails_on_repeat_startup(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    store.close()
    missing = tmp_path / "empty-migrations"
    missing.mkdir()
    with pytest.raises(PersistenceIntegrityError, match="missing or unexpected"):
        SQLiteTaskStore(database, migrations_dir=missing)


def test_migration_ledger_checksum_tampering_fails_on_startup(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    store.close()
    connection = sqlite3.connect(database)
    connection.execute("UPDATE schema_migrations SET sha256 = ? WHERE version = 1", ("0" * 64,))
    connection.commit()
    connection.close()
    with pytest.raises(PersistenceIntegrityError, match="applied migration checksum mismatch"):
        SQLiteTaskStore(database)


def test_migration_failure_rolls_back_schema_and_ledger_atomically(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY)")
    connection.close()
    migrations = _copy_migration_directory(tmp_path / "migrations")
    with pytest.raises(PersistenceIntegrityError, match=r"migration .* failed"):
        SQLiteTaskStore(database, migrations_dir=migrations)
    connection = sqlite3.connect(database)
    names = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    assert names == {"tasks"}
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    connection.close()


def test_changed_critical_trigger_definition_fails_schema_fingerprint(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    store.close()
    connection = sqlite3.connect(database)
    connection.executescript(
        "DROP TRIGGER task_plans_no_update; "
        "CREATE TRIGGER task_plans_no_update BEFORE UPDATE ON task_plans "
        "BEGIN SELECT 1; END;"
    )
    connection.close()
    with pytest.raises(PersistenceIntegrityError, match="schema integrity fingerprint"):
        SQLiteTaskStore(database)


def test_persistence_redacts_common_credentials_and_rejects_sensitive_plan_fields(tmp_path) -> None:
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task = store.create_task("Inspect api_key=synthetic-secret-value", now=_NOW)
    assert "synthetic-secret-value" not in task.user_goal
    assert "[REDACTED]" in task.user_goal
    store.close()

    with pytest.raises(ValidationError, match="sensitive or document-content keys"):
        PlanStep(
            step_id=uuid4(),
            capability_id="proposal.review_only",
            arguments={"document_content": "private body"},
            idempotency_key=uuid4(),
            risk_tier=RiskTier.NAVIGATE,
        )
    with pytest.raises(ValidationError, match="resource display name"):
        TaskPlanResource(
            resource_id="file:synthetic-1",
            expected_version="version-1",
            display_name="C:/private/example.txt",
        )


def test_task_plan_is_canonical_versioned_and_normalized_consistently(tmp_path) -> None:
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task = store.create_task("Review this synthetic project", now=_NOW)
    _ready_for_plan(store, task.task_id)
    plan = _plan(task.task_id)
    digest = store.save_plan(plan)
    loaded = store.get_plan(task.task_id)
    assert digest == plan.plan_hash
    assert loaded == plan
    assert loaded.plan_hash == digest
    assert store.get_task(task.task_id).plan_revision == 1
    store.close()


def test_plan_save_rolls_back_as_one_transaction_on_step_failure(tmp_path) -> None:
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task = store.create_task("Synthetic goal", now=_NOW)
    _ready_for_plan(store, task.task_id)
    store._connection.execute(
        "CREATE TRIGGER injected_step_failure BEFORE INSERT ON task_steps "
        "BEGIN SELECT RAISE(ABORT, 'injected'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        store.save_plan(_plan(task.task_id))
    assert store.get_task(task.task_id).plan_revision == 0
    with pytest.raises(KeyError, match="no persisted plan"):
        store.get_plan(task.task_id)
    store.close()


def test_plan_revision_is_append_only_and_must_be_next_revision(tmp_path) -> None:
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task = store.create_task("Synthetic goal", now=_NOW)
    _ready_for_plan(store, task.task_id)
    store.save_plan(_plan(task.task_id))
    with pytest.raises(PersistenceError, match="next immutable"):
        store.save_plan(_plan(task.task_id, revision=1))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._connection.execute(
            "UPDATE task_plans SET canonical_json = '{}' WHERE task_id = ?",
            (str(task.task_id),),
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._connection.execute("DELETE FROM task_steps WHERE task_id = ?", (str(task.task_id),))
    store.close()


def test_plan_nested_json_fields_are_deeply_immutable() -> None:
    plan = _plan(uuid4())
    with pytest.raises(TypeError):
        plan.steps[0].arguments["resource_id"] = "forged"  # type: ignore[index]
    with pytest.raises(TypeError):
        plan.steps[0].postconditions[0]["condition"] = "forged"  # type: ignore[index]
    round_tripped = TaskPlan.model_validate_json(plan.canonical_json())
    assert round_tripped == plan
    assert round_tripped.plan_hash == plan.plan_hash


def test_plan_validation_rejects_dangling_or_cyclic_dependencies() -> None:
    task_id = uuid4()
    left = uuid4()
    right = uuid4()
    with pytest.raises(ValidationError, match="must reference this plan"):
        TaskPlan(
            task_id=task_id,
            revision=1,
            summary="invalid graph",
            steps=(
                PlanStep(
                    step_id=left,
                    dependencies=(right,),
                    capability_id="test.step",
                    idempotency_key=uuid4(),
                    risk_tier=RiskTier.OBSERVE,
                ),
            ),
            created_at=_NOW,
        )
    with pytest.raises(ValidationError, match="acyclic"):
        TaskPlan(
            task_id=task_id,
            revision=1,
            summary="cycle",
            steps=(
                PlanStep(
                    step_id=left,
                    dependencies=(right,),
                    capability_id="test.step",
                    idempotency_key=uuid4(),
                    risk_tier=RiskTier.OBSERVE,
                ),
                PlanStep(
                    step_id=right,
                    dependencies=(left,),
                    capability_id="test.step",
                    idempotency_key=uuid4(),
                    risk_tier=RiskTier.OBSERVE,
                ),
            ),
            created_at=_NOW,
        )


def test_tampered_normalized_plan_rows_fail_closed(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    task = store.create_task("Synthetic goal", now=_NOW)
    _ready_for_plan(store, task.task_id)
    store.save_plan(_plan(task.task_id))
    store._connection.execute("DROP TRIGGER task_steps_no_update")
    store._connection.execute(
        "UPDATE task_steps SET args_json = '{\"forged\":true}' WHERE task_id = ?",
        (str(task.task_id),),
    )
    with pytest.raises(PersistenceIntegrityError, match="normalized plan step"):
        store.get_plan(task.task_id)
    store.close()


def test_restart_pauses_inflight_work_and_requires_fresh_plan_consent(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    task = store.create_task("Synthetic goal", now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=_NOW)
    store.save_plan(_plan(task.task_id))
    store.transition_task(task.task_id, PersistentTaskState.VALIDATING, now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.PREVIEW_READY, now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.AWAITING_APPROVAL, now=_NOW)
    store.close()

    reopened = SQLiteTaskStore(database)
    recovered = reopened.get_task(task.task_id)
    assert recovered.state == PersistentTaskState.PAUSED
    assert recovered.plan_revision == 1
    assert reopened.get_plan(task.task_id).revision == 1
    recovery_events = [
        event
        for event in reopened.list_events(task.task_id)
        if event.event_type == "RESTART_RECOVERY_PAUSED"
    ]
    assert len(recovery_events) == 1
    assert recovery_events[0].metadata.values["requires_fresh_plan_and_consent"] is True
    reopened.close()


def test_second_live_store_cannot_simulate_restart_and_clean_close_releases_owner(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    first = SQLiteTaskStore(database)
    task = first.create_task("Synthetic goal", now=_NOW)
    first.transition_task(task.task_id, PersistentTaskState.PLANNING, now=_NOW)
    with pytest.raises(PersistenceBusyError, match="another process owns"):
        SQLiteTaskStore(database)
    assert first.get_task(task.task_id).state == PersistentTaskState.PLANNING
    first.close()

    reopened = SQLiteTaskStore(database)
    assert reopened.get_task(task.task_id).state == PersistentTaskState.PAUSED
    reopened.close()


def test_database_owner_lock_is_enforced_across_processes(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    first = SQLiteTaskStore(database)
    task = first.create_task("Synthetic goal", now=_NOW)
    first.transition_task(task.task_id, PersistentTaskState.PLANNING, now=_NOW)
    code = (
        "from aether.core.persistence.sqlite_store import SQLiteTaskStore, PersistenceBusyError; "
        "import sys; "
        "\ntry: SQLiteTaskStore(sys.argv[1])"
        "\nexcept PersistenceBusyError: print('BUSY')"
        "\nelse: raise SystemExit(4)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(database)],
        cwd=Path(__file__).parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "BUSY"
    assert first.get_task(task.task_id).state == PersistentTaskState.PLANNING
    first.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX flock pathname-replacement regression")
def test_replacing_owner_lock_path_cannot_grant_a_second_store_authority(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    first = SQLiteTaskStore(database)
    task = first.create_task("Synthetic goal", now=_NOW)
    first.transition_task(task.task_id, PersistentTaskState.PLANNING, now=_NOW)

    # Replace the historical sidecar pathname while Store A still owns the
    # database. Ownership now attaches to the SQLite database inode, not this
    # replaceable name, so Store B must fail before startup recovery can pause A.
    sidecar = database.with_name(database.name + ".owner.lock")
    sidecar.write_bytes(b"old lock pathname")
    replacement = sidecar.with_suffix(sidecar.suffix + ".replacement")
    replacement.write_bytes(b"replacement lock inode")
    replacement.replace(sidecar)

    code = (
        "from aether.core.persistence.sqlite_store import SQLiteTaskStore, PersistenceBusyError; "
        "import sys; "
        "\ntry: SQLiteTaskStore(sys.argv[1])"
        "\nexcept PersistenceBusyError: print('BUSY')"
        "\nelse: raise SystemExit(4)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(database)],
        cwd=Path(__file__).parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "BUSY"
    assert first.get_task(task.task_id).state == PersistentTaskState.PLANNING
    first.close()

    # Once A releases ownership, normal restart recovery remains allowed.
    reopened = SQLiteTaskStore(database)
    assert reopened.get_task(task.task_id).state == PersistentTaskState.PAUSED
    reopened.close()


def test_abnormal_process_exit_releases_owner_and_triggers_restart_recovery(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    code = (
        "from aether.core.persistence.sqlite_store import SQLiteTaskStore; "
        "from aether.core.persistence.models import PersistentTaskState; import os, sys; "
        "store = SQLiteTaskStore(sys.argv[1]); "
        "task = store.create_task('crash-recovery test'); "
        "store.transition_task(task.task_id, PersistentTaskState.PLANNING); "
        "print(task.task_id, flush=True); os._exit(0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(database)],
        cwd=Path(__file__).parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    task_id = UUID(result.stdout.strip())
    recovered = SQLiteTaskStore(database)
    assert recovered.get_task(task_id).state == PersistentTaskState.PAUSED
    recovered.close()


def test_uncommitted_transaction_is_discarded_on_close_and_reopen(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    task_id = uuid4()
    store._connection.execute("BEGIN IMMEDIATE")
    store._connection.execute(
        "INSERT INTO tasks(id, user_goal, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (
            str(task_id),
            "uncommitted goal",
            PersistentTaskState.RECEIVED.value,
            "2026-11-15T12:00:00Z",
            "2026-11-15T12:00:00Z",
        ),
    )
    store.close()
    reopened = SQLiteTaskStore(database)
    with pytest.raises(KeyError, match="unknown task"):
        reopened.get_task(task_id)
    reopened.close()


def test_phase2b_cannot_enter_execution_or_recovery_states(tmp_path) -> None:
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task = store.create_task("Synthetic goal", now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=_NOW)
    for disabled in (
        PersistentTaskState.PRECHECK,
        PersistentTaskState.EXECUTING,
        PersistentTaskState.POSTCHECK,
        PersistentTaskState.RECOVERING,
        PersistentTaskState.PARTIALLY_COMPLETED,
        PersistentTaskState.UNVERIFIED,
    ):
        with pytest.raises(IllegalPersistentTransition, match="does not permit"):
            store.transition_task(task.task_id, disabled, now=_NOW)
    store.close()


def test_phase1_state_contract_has_explicit_nonbreaking_adapter() -> None:
    for state in (
        TaskState.CREATED,
        TaskState.PLANNING,
        TaskState.AWAITING_APPROVAL,
        TaskState.COMPLETED,
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.PAUSED,
    ):
        assert phase1_state_from_persistent(persistent_state_from_phase1(state)) == state
    with pytest.raises(ValueError, match="no Phase 2B mapping"):
        persistent_state_from_phase1(TaskState.EXECUTING)
    with pytest.raises(ValueError, match="no Phase 1 mapping"):
        phase1_state_from_persistent(PersistentTaskState.VALIDATING)
    assert TaskState.EXECUTING.value == "EXECUTING"


def test_approval_decision_is_audit_only_bound_to_current_plan(tmp_path) -> None:
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task = store.create_task("Synthetic goal", now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=_NOW)
    plan = _plan(task.task_id)
    store.save_plan(plan)
    store.transition_task(task.task_id, PersistentTaskState.VALIDATING, now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.PREVIEW_READY, now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.AWAITING_APPROVAL, now=_NOW)
    record = ApprovalDecisionRecord(
        approval_id=uuid4(),
        task_id=task.task_id,
        plan_revision=1,
        plan_hash=plan.plan_hash,
        preview_id=uuid4(),
        preview_digest="a" * 64,
        decision=ApprovalDecisionValue.APPROVE,
        decided_at=_NOW,
    )
    store.record_approval_decision(record)
    assert store.get_approval_record(record.approval_id) == record
    assert record.authority == "NON_AUTHORIZING_AUDIT_RECORD"
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._connection.execute(
            "UPDATE approval_records SET decision = 'REJECT' WHERE id = ?",
            (str(record.approval_id),),
        )
    forged = record.model_copy(update={"plan_hash": "b" * 64})
    with pytest.raises(PersistenceError, match="current preview plan"):
        store.record_approval_decision(forged)
    store.close()


def test_tampered_approval_record_never_parses_as_authority(tmp_path) -> None:
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task = store.create_task("Synthetic goal", now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=_NOW)
    plan = _plan(task.task_id)
    store.save_plan(plan)
    store.transition_task(task.task_id, PersistentTaskState.VALIDATING, now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.PREVIEW_READY, now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.AWAITING_APPROVAL, now=_NOW)
    approval_id = uuid4()
    record = ApprovalDecisionRecord(
        approval_id=approval_id,
        task_id=task.task_id,
        plan_revision=1,
        plan_hash=plan.plan_hash,
        preview_id=uuid4(),
        preview_digest="c" * 64,
        decision=ApprovalDecisionValue.APPROVE,
        decided_at=_NOW,
    )
    store.record_approval_decision(record)
    store._connection.execute("DROP TRIGGER approval_records_no_update")
    # Simulate an offline editor bypassing SQL CHECK constraints. The typed
    # reader must still reject the row, and no API returns it as a grant.
    store._connection.execute("PRAGMA ignore_check_constraints = ON")
    store._connection.execute(
        "UPDATE approval_records SET authority = 'TRUSTED_GRANT' WHERE id = ?",
        (str(approval_id),),
    )
    with pytest.raises(PersistenceIntegrityError, match="invalid"):
        store.get_approval_record(approval_id)
    store.close()


def test_event_metadata_rejects_sensitive_fields_and_history_is_append_only(tmp_path) -> None:
    with pytest.raises(ValidationError, match="prohibited sensitive"):
        EventMetadata(values={"document_content": "private body"})
    with pytest.raises(ValidationError, match="prohibited sensitive"):
        EventMetadata(values={"file_path": "C:/private"})
    with pytest.raises(ValidationError, match="not allow-listed"):
        EventMetadata(values={"note": "unbounded free text is forbidden"})
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task = store.create_task("Synthetic goal", now=_NOW)
    events = store.list_events(task.task_id)
    assert len(events) == 1
    assert events[0].metadata.values == {"state": "RECEIVED"}
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store._connection.execute("DELETE FROM task_events WHERE task_id = ?", (str(task.task_id),))
    store.close()


def test_missing_append_only_trigger_after_database_tampering_fails_closed(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    store._connection.execute("DROP TRIGGER task_events_no_delete")
    store.close()
    with pytest.raises(PersistenceIntegrityError, match="schema objects are missing"):
        SQLiteTaskStore(database)


def test_bad_or_future_schema_fails_closed(tmp_path) -> None:
    database = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA user_version = 99")
    connection.close()
    with pytest.raises(PersistenceIntegrityError, match="newer than this application"):
        SQLiteTaskStore(database)


def test_database_symlink_is_rejected(tmp_path) -> None:
    target = tmp_path / "target.sqlite3"
    target.touch()
    link = tmp_path / "link.sqlite3"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        _skip_if_symlink_unavailable(exc)
    with pytest.raises(PersistenceError, match="symlink or reparse"):
        SQLiteTaskStore(link)


def test_hardlinked_database_is_rejected(tmp_path) -> None:
    original = tmp_path / "original.sqlite3"
    original.touch()
    alias = tmp_path / "alias.sqlite3"
    try:
        os.link(original, alias)
    except OSError:
        pytest.skip("hard-link creation is unavailable on this host")
    with pytest.raises(PersistenceError, match="hardlinked regular file"):
        SQLiteTaskStore(alias)


def test_symlinked_database_parent_is_rejected(tmp_path) -> None:
    actual_parent = tmp_path / "actual"
    actual_parent.mkdir(mode=0o700)
    redirected_parent = tmp_path / "redirected"
    try:
        redirected_parent.symlink_to(actual_parent, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        _skip_if_symlink_unavailable(exc)
    with pytest.raises(PersistenceError, match="symlink or reparse"):
        SQLiteTaskStore(redirected_parent / "aether.sqlite3")
    assert not (actual_parent / "aether.sqlite3").exists()


def test_parent_substitution_after_open_is_detected_before_reads(tmp_path) -> None:
    parent = tmp_path / "private"
    database = parent / "state.sqlite3"
    store = SQLiteTaskStore(database)
    task = store.create_task("Synthetic goal", now=_NOW)
    moved = tmp_path / "moved-private"
    try:
        try:
            parent.rename(moved)
        except PermissionError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 5:
                pytest.skip(
                    "Windows denied renaming a directory containing the open SQLite database "
                    "(WinError 5); synthetic identity-drift coverage runs separately"
                )
            raise
        try:
            parent.symlink_to(moved, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            _skip_if_symlink_unavailable(exc)
        with pytest.raises(PersistenceError, match="symlink or reparse"):
            store.get_task(task.task_id)
    finally:
        store.close()


def test_parent_identity_drift_is_rejected_before_reads(tmp_path, monkeypatch) -> None:
    parent = tmp_path / "private"
    database = parent / "state.sqlite3"
    store = SQLiteTaskStore(database)
    task = store.create_task("Synthetic goal", now=_NOW)
    original_stat = Path.stat

    def drifted_parent_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if path == parent:
            values = list(result)
            values[1] = int(values[1]) + 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(Path, "stat", drifted_parent_stat)
    try:
        with pytest.raises(PersistenceError, match="database parent identity changed"):
            store.get_task(task.task_id)
    finally:
        store.close()


def test_windows_junction_or_reparse_component_fails_closed_synthetically(
    tmp_path, monkeypatch
) -> None:
    junction = tmp_path / "simulated-junction"
    junction.mkdir()
    original = persistence_store.reject_reparse_components

    def reject_simulated_junction(path: Path) -> None:
        if junction in path.parents or path == junction:
            raise PathSafetyError("reparse_point_not_allowed")
        original(path)

    monkeypatch.setattr(persistence_store, "reject_reparse_components", reject_simulated_junction)
    with pytest.raises(PersistenceError, match="symlink or reparse"):
        SQLiteTaskStore(junction / "data" / "aether.sqlite3")


def test_database_path_volume_substitution_is_rejected(tmp_path, monkeypatch) -> None:
    mounted = tmp_path / "mounted-volume"
    mounted.mkdir()

    def inspect(path: Path) -> VolumeInfo:
        volume_id = (
            "synthetic-volume-b"
            if mounted in path.parents or path == mounted
            else "synthetic-volume-a"
        )
        return VolumeInfo(volume_id=volume_id, kind=VolumeKind.FIXED)

    monkeypatch.setattr(persistence_store, "inspect_volume", inspect)
    with pytest.raises(PersistenceError, match="volume boundary"):
        SQLiteTaskStore(mounted / "data" / "aether.sqlite3")


@pytest.mark.parametrize(
    "name",
    [
        "state:alternate.sqlite3",
        "CON.sqlite3",
        "CON .sqlite3",
        "CONIN$",
        "LPT¹.txt",
        "trailingdot.",
        "trailingspace ",
        "bad?.sqlite3",
    ],
)
@pytest.mark.parametrize("input_kind", ["str", "path"])
def test_windows_unsafe_database_components_are_rejected(
    tmp_path, name: str, input_kind: str
) -> None:
    guarded_parent = tmp_path / "must-not-be-created"
    database = guarded_parent / name
    database_input = os.fspath(database) if input_kind == "str" else database
    with pytest.raises(PersistenceError, match="unsafe component"):
        SQLiteTaskStore(database_input)
    assert not guarded_parent.exists()


def test_raw_windows_database_path_validation_precedes_normalization() -> None:
    persistence_store._validate_raw_database_path(r"C:\Aether\data\state.sqlite3")
    with pytest.raises(PersistenceError, match="unsafe component"):
        persistence_store._validate_raw_database_path(r"C:\Aether\data\trailingdot.")
    with pytest.raises(PersistenceError, match="unsafe component"):
        persistence_store._validate_raw_database_path(r"C:\Aether\data\state.sqlite3:stream")


def test_normalized_safe_database_basename_remains_usable(tmp_path) -> None:
    database = tmp_path / "trailingdot"
    store = SQLiteTaskStore(database)
    try:
        assert store.database_path == database
    finally:
        store.close()


def test_legitimate_local_appdata_shaped_directory_is_not_blocked_by_path_policy(tmp_path) -> None:
    database = tmp_path / "AppData" / "Local" / "AetherOS" / "data" / "state.sqlite3"
    store = SQLiteTaskStore(database)
    assert store.database_path == database
    store.close()
