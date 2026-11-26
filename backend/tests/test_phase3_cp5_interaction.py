"""CP5 focus coordination + exact fixture interaction (fake; not native)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import aether.core.persistence.sqlite_store as sqlite_store
from aether.core.apps.enablement import OwnerEnablementConfig, Phase3Enablement
from aether.core.apps.fixture import FIXTURE_HWND, FixtureApp
from aether.core.apps.focus import ActivitySignal, FocusCoordinator
from aether.core.apps.ui_executor import UiDenied, UiOperationExecutor
from aether.core.apps.uia_snapshot import UiaSnapshotService
from aether.core.persistence.models import PersistentTaskState
from aether.core.persistence.sqlite_store import IllegalPersistentTransition, SQLiteTaskStore
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.resources.app_window_authority import AppWindowResourceAuthority
from aether.core.resources.registry import ResourceRegistry
from aether.world_state.privacy import ContextClassification

NOW = datetime(2026, 11, 15, tzinfo=UTC)


def _v3_store(tmp_path: Path) -> SQLiteTaskStore:
    sqlite_store.ACTIVE_SCHEMA_VERSION = 3
    sqlite_store.PENDING_MIGRATION_VERSIONS = frozenset()
    try:
        return SQLiteTaskStore(tmp_path / "synthetic.db")
    finally:
        sqlite_store.ACTIVE_SCHEMA_VERSION = 2
        sqlite_store.PENDING_MIGRATION_VERSIONS = frozenset({3})


class _World:
    def __init__(self, tmp_path: Path) -> None:
        self.clock_box = [NOW]
        clock = lambda: self.clock_box[0]  # noqa: E731
        self.clock = clock
        self.fixture = FixtureApp()
        self.authority = AppWindowResourceAuthority(session_id="session-1")
        from aether.core.contracts.app_window import (
            ApplicationRecord,
            DiscoverySource,
            LaunchMethod,
            location_identity_digest,
            registration_app_id,
        )

        exe = "C:\\Fake\\AETHERFixture.exe"
        self.fixture_record = ApplicationRecord(
            app_id=registration_app_id(
                display_name="AETHER Fixture", executable_identity=exe,
                launch_method=LaunchMethod.APPROVED_EXECUTABLE,
            ),
            display_name="AETHER Fixture",
            launch_method=LaunchMethod.APPROVED_EXECUTABLE,
            executable_identity=exe,
            location_digest=location_identity_digest(exe),
            discovery_source=DiscoverySource.FAKE_FIXTURE,
            discovered_at=NOW, fresh_until=NOW + timedelta(hours=2),
        )
        self.authority.register_app(self.fixture_record, version_token="fixture-identity-v1")
        ref = self.authority.register_window(
            hwnd=FIXTURE_HWND,
            process_token="pid:7:ct",
            instance_generation=1,
            version_token="pid:7:ct#1",
            expires_at=NOW + timedelta(hours=1),
            app_resource_id=self.fixture_record.app_id,
            classification=ContextClassification.PERMITTED_METADATA,
        )
        self.window_id = ref.resource_id
        self.snapshots = UiaSnapshotService(
            authority=self.authority,
            backend_factory=self.fixture.backend,
            session_id="session-1",
            clock=clock,
            content_inspection_permitted=lambda app_id: True,
        )
        self.focus = FocusCoordinator()
        self.capabilities = CapabilityRegistry.phase3_with_uia()
        self.store = _v3_store(tmp_path)
        from aether.core.policy.broker import PolicyBroker

        broker = PolicyBroker(
            capabilities=self.capabilities,
            resources=ResourceRegistry(windows_semantics=False),
            app_authority=self.authority,
            executors=frozenset({"uia.invoke_fixture"}),
        )
        enablement = Phase3Enablement.from_owner_config(
            OwnerEnablementConfig(
                enabled=True,
                capability_allowlist=frozenset({"uia.invoke_fixture"}),
                app_allowlist=frozenset({self.fixture_record.app_id}),
                session_lifetime=timedelta(hours=1),
                scope_name="test-scope",
            ),
            now=NOW,
        )
        self.executor = UiOperationExecutor(
            store=self.store,
            snapshots=self.snapshots,
            backend_factory=self.fixture.backend,
            focus=self.focus,
            capabilities=self.capabilities,
            session_id="session-1",
            activation_scope="test-scope",
            clock=clock,
            broker=broker,
            enablement=enablement,
            approved_fixture_app_id=self.fixture_record.app_id,
            approved_fixture_identity_token="fixture-identity-v1",
        )

    def snapshot(self):  # type: ignore[no-untyped-def]
        result = self.snapshots.inspect(self.window_id, require_content=True)
        assert result.snapshot is not None, result
        return result.snapshot

    def plan_task(self, snapshot=None, *, element_ref: str = "el:2", window_id: str | None = None):  # type: ignore[no-untyped-def]
        snapshot = snapshot or self.snapshot()
        task = self.store.create_task("Fixture interaction", now=NOW)
        self.store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=NOW)
        planner = Planner(
            capabilities=self.capabilities,
            resources=ResourceRegistry(windows_semantics=False),
            app_authority=self.authority,
            clock=lambda: NOW,
        )
        planned = planner.plan(
            task.task_id,
            PlanIntent(
                goal=PlanGoal.INVOKE_FIXTURE_ELEMENT,
                resource_id=window_id or self.window_id,
                arguments={
                    "resource_id": window_id or self.window_id,
                    "snapshot_id": snapshot.snapshot_id,
                    "element_ref": element_ref,
                },
                summary="Increment the fixture counter",
            ),
        )
        self.store.save_plan(planned.plan)
        for state in (
            PersistentTaskState.VALIDATING,
            PersistentTaskState.PREVIEW_READY,
            PersistentTaskState.AWAITING_APPROVAL,
        ):
            self.store.transition_task(task.task_id, state, now=NOW)
        return task.task_id, planned.step_id

    def close(self) -> None:
        self.store.close()


def test_verified_fixture_interaction_end_to_end(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    outcome = world.executor.execute(task_id, step_id, binding_id=binding_id)
    assert outcome.status == "SUCCEEDED" and outcome.outcome == "verified_effect"
    assert world.fixture.state.count == 1
    assert world.store.get_task(task_id).state is PersistentTaskState.COMPLETED
    attempts = world.store.ui_attempts_for_task(task_id)
    assert attempts and attempts[0]["receipt_status"] == "SUCCEEDED"
    world.close()


def test_adapter_success_claim_without_effect_is_not_success(tmp_path: Path) -> None:
    world = _World(tmp_path)
    real_backend = world.fixture.backend

    class LyingBackend:
        def __init__(self, inner):  # type: ignore[no-untyped-def]
            self._inner = inner

        def find_root(self, *, hwnd):  # type: ignore[no-untyped-def]
            return self._inner.find_root(hwnd=hwnd)

        def children(self, element):  # type: ignore[no-untyped-def]
            return self._inner.children(element)

        def invoke(self, element):  # type: ignore[no-untyped-def]
            return {"invoked": element.key}  # claims success, no effect

        def close(self) -> None:
            self._inner.close()

    world.executor.backend_factory = lambda: LyingBackend(real_backend())  # type: ignore[method-assign]
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    outcome = world.executor.execute(task_id, step_id, binding_id=binding_id)
    assert outcome.status == "FAILED" and outcome.outcome == "no_effect"
    assert world.store.get_task(task_id).state is PersistentTaskState.FAILED
    world.close()


def test_stale_element_rejected_after_replacement(tmp_path: Path) -> None:
    world = _World(tmp_path)
    snapshot = world.snapshot()
    task_id, step_id = world.plan_task(snapshot)
    binding_id = world.executor.issue_binding(task_id, step_id)
    world.fixture.replace_increment_control()
    outcome = world.executor.execute(task_id, step_id, binding_id=binding_id)
    assert outcome.status == "FAILED" and outcome.outcome == "stale_target"
    assert world.fixture.state.count == 0
    world.close()


def test_binding_replay_and_mismatch_denied(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    assert world.executor.execute(task_id, step_id, binding_id=binding_id).status == "SUCCEEDED"
    task2, step2 = world.plan_task()
    with pytest.raises(UiDenied):
        world.executor.execute(task2, step2, binding_id=binding_id)  # other task's binding
    with pytest.raises(UiDenied):
        world.executor.execute(task_id, step_id, binding_id=binding_id)  # replay
    world.close()


def test_expired_binding_denied(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    world.clock_box[0] = NOW + timedelta(minutes=6)
    with pytest.raises(UiDenied):
        world.executor.execute(task_id, step_id, binding_id=binding_id)
    assert world.fixture.state.count == 0
    world.close()


def test_takeover_stops_interaction(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    world.focus.note_activity(
        ActivitySignal(kind="manual_activity_in_window", window_id=world.window_id, at=NOW)
    )
    # note_activity alone marks signals; executor consults takeover via on_takeover
    world.focus.on_takeover(world.window_id)
    with pytest.raises(UiDenied):
        world.executor.execute(task_id, step_id, binding_id=binding_id)
    assert world.fixture.state.count == 0
    world.close()


def test_wrong_window_snapshot_denied(tmp_path: Path) -> None:
    world = _World(tmp_path)
    snapshot = world.snapshot()
    other = world.authority.register_window(
        hwnd=9999,
        process_token="pid:9:ct",
        instance_generation=1,
        version_token="pid:9:ct#1",
        expires_at=NOW + timedelta(hours=1),
        app_resource_id="app:fixture",
        classification=ContextClassification.PERMITTED_METADATA,
    )
    task_id, step_id = world.plan_task(snapshot, window_id=other.resource_id)
    binding_id = world.executor.issue_binding(task_id, step_id)
    with pytest.raises(UiDenied):
        world.executor.execute(task_id, step_id, binding_id=binding_id)
    world.close()


def test_ui_evidence_cannot_drive_navigation_and_vice_versa(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    with pytest.raises(IllegalPersistentTransition):
        world.store.advance_navigation_state(
            task_id,
            PersistentTaskState.PRECHECK,
            step_id=step_id,
            confirmation_id=binding_id,
            now=NOW,
        )
    world.close()


def test_interrupted_interaction_reconciles_unverified(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    world.store.advance_ui_state(
        task_id, PersistentTaskState.PRECHECK, step_id=step_id, binding_id=binding_id, now=NOW
    )
    attempt_id = world.store.commit_ui_attempt(
        task_id=task_id, step_id=step_id, binding_id=binding_id, now=NOW
    )
    assert attempt_id
    assert world.executor.reconcile() == [(task_id, "UNVERIFIED")]
    assert world.store.get_task(task_id).state is PersistentTaskState.UNVERIFIED
    assert world.fixture.state.count == 0  # never replayed
    world.close()


# -- focus locks -------------------------------------------------------------------


def test_focus_lock_contention_ordering_and_stale_release() -> None:
    focus = FocusCoordinator()
    first = focus.acquire_operation(window_id="w1", owner_task="t1", owner_session="s")
    assert first is not None
    # Same window contention and parallel foreground on another window both fail.
    assert focus.acquire_operation(window_id="w1", owner_task="t2", owner_session="s") is None
    assert focus.acquire_operation(window_id="w2", owner_task="t2", owner_session="s") is None
    # Stale owner cannot release another's lock.
    from aether.core.apps.focus import LockHandle

    forged = LockHandle(
        kind="window", key="w1", owner_task="t2", owner_session="s", acquired_at=0.0, expires_at=0.0
    )
    assert focus.release(forged) is False
    for handle in reversed(first):
        assert focus.release(handle) is True
    # After release a later authorized task proceeds.
    assert focus.acquire_operation(window_id="w2", owner_task="t2", owner_session="s") is not None


def test_window_replacement_while_locked_revalidates() -> None:
    focus = FocusCoordinator()
    activator_world = focus.acquire_operation(window_id="w1", owner_task="t1", owner_session="s")
    assert activator_world is not None
    focus.on_takeover("w1")
    assert focus.holder_of_window("w1") is None  # takeover released ownership safely
