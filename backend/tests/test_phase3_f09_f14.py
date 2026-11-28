"""F09-F14 regressions: binding authority, activation path, outcomes.

Fake-backed; not native evidence.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from test_phase3_cp5_interaction import NOW, _World

from aether.core.apps.activation import WindowActivationService
from aether.core.apps.confirmation import TrustedNavigationConfirmer
from aether.core.apps.enablement import OwnerEnablementConfig, Phase3Enablement
from aether.core.apps.ui_executor import UiDenied
from aether.core.persistence.models import PersistentTaskState
from aether.core.persistence.sqlite_store import IllegalPersistentTransition
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner
from aether.core.policy.broker import PolicyBroker
from aether.core.resources.registry import ResourceRegistry

# -- F09: authoritative binding comparison ---------------------------------------


def test_changed_arguments_digest_rejected_at_commit(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    world.executor.issue_binding(task_id, step_id)
    # A second binding recorded with a forged arguments digest (as a
    # buggy/compromised issuer might persist) cannot be committed:
    # the store derives the digest from the persisted plan itself.
    from aether.core.apps.ui_binding import issue_binding as _issue

    snapshot = world.snapshot()
    forged = _issue(
        task_id=str(task_id),
        step_id=str(step_id),
        plan_revision=1,
        plan_hash=world.store.get_plan(task_id).canonical_json().__hash__().__str__(),
        capability_id="uia.invoke_fixture",
        arguments={"resource_id": "forged"},
        app_resource_id=world.fixture_record.app_id,
        window_resource_id=world.window_id,
        window_version_token=snapshot.window_version_token,
        snapshot_id=snapshot.snapshot_id,
        snapshot_generation=snapshot.generation,
        element_ref="el:2",
        element_runtime_id="fixture-increment",
        pattern="invoke",
        intended_effect="increment_fixture_count",
        session_id="session-1",
        activation_scope="test-scope",
        now=NOW,
    )
    import hashlib

    plan_hash = hashlib.sha256(world.store.get_plan(task_id).canonical_json().encode()).hexdigest()
    forged = _issue(
        task_id=str(task_id),
        step_id=str(step_id),
        plan_revision=1,
        plan_hash=plan_hash,
        capability_id="uia.invoke_fixture",
        arguments={"resource_id": "forged"},
        app_resource_id=world.fixture_record.app_id,
        window_resource_id=world.window_id,
        window_version_token=snapshot.window_version_token,
        snapshot_id=snapshot.snapshot_id,
        snapshot_generation=snapshot.generation,
        element_ref="el:2",
        element_runtime_id="fixture-increment",
        pattern="invoke",
        intended_effect="increment_fixture_count",
        session_id="session-1",
        activation_scope="test-scope",
        now=NOW,
    )
    with pytest.raises(IllegalPersistentTransition):
        # UNIQUE(task, step, revision) plus digest/binding mismatch:
        # recording a competing binding for the same plan is rejected.
        world.store.record_ui_binding(
            binding_id=forged.binding_id,
            task_id=task_id,
            step_id=step_id,
            capability_id="uia.invoke_fixture",
            arguments_sha256=forged.arguments_sha256,
            binding_sha256=forged.digest(),
            app_resource_id=forged.app_resource_id,
            window_resource_id=world.window_id,
            window_version_token=forged.window_version_token,
            snapshot_id=snapshot.snapshot_id,
            snapshot_generation=snapshot.generation,
            element_ref="el:2",
            element_runtime_id="fixture-increment",
            pattern="invoke",
            intended_effect="increment_fixture_count",
            session_id="session-1",
            activation_scope="test-scope",
            issued_at=forged.issued_at,
            expires_at=forged.expires_at,
        )
    world.close()


def test_concurrent_and_replay_consumption_rejected(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    world.store.advance_ui_state(
        task_id, PersistentTaskState.PRECHECK, step_id=step_id, binding_id=binding_id, now=NOW
    )
    attempt = world.store.commit_ui_attempt(
        task_id=task_id, step_id=step_id, binding_id=binding_id, now=NOW
    )
    assert attempt
    with pytest.raises(IllegalPersistentTransition):
        world.store.commit_ui_attempt(
            task_id=task_id, step_id=step_id, binding_id=binding_id, now=NOW
        )
    world.close()


def test_cross_session_binding_denied_by_broker_authorizer(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    world.executor.session_id = "other-session"
    with pytest.raises(UiDenied) as excinfo:
        world.executor.execute(task_id, step_id, binding_id=binding_id)
    assert "SESSION" in str(excinfo.value) or "session" in str(excinfo.value)
    world.close()


def test_readonly_capability_cannot_enter_t2_evidence_path(tmp_path: Path) -> None:
    world = _World(tmp_path)
    # Plan a read-only inspection step; recording a T2 binding for it
    # must fail: the evidence class is reserved for uia.invoke_fixture.
    snapshot = world.snapshot()
    task = world.store.create_task("Inspect", now=NOW)
    world.store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=NOW)
    planner = Planner(
        capabilities=world.capabilities,
        resources=ResourceRegistry(windows_semantics=False),
        app_authority=world.authority,
        clock=lambda: NOW,
    )
    planned = planner.plan(
        task.task_id,
        PlanIntent(
            goal=PlanGoal.INSPECT_UIA_ELEMENT,
            resource_id=world.window_id,
            arguments={
                "resource_id": world.window_id,
                "snapshot_id": snapshot.snapshot_id,
                "element_ref": "el:2",
            },
            summary="Inspect element",
        ),
    )
    world.store.save_plan(planned.plan)
    with pytest.raises(IllegalPersistentTransition):
        world.store.record_ui_binding(
            binding_id="uibind:forged",
            task_id=task.task_id,
            step_id=planned.step_id,
            capability_id="uia.inspect_element",
            arguments_sha256="0" * 64,
            binding_sha256="0" * 64,
            app_resource_id=world.fixture_record.app_id,
            window_resource_id=world.window_id,
            window_version_token=snapshot.window_version_token,
            snapshot_id=snapshot.snapshot_id,
            snapshot_generation=snapshot.generation,
            element_ref="el:2",
            element_runtime_id="fixture-increment",
            pattern="invoke",
            intended_effect="increment_fixture_count",
            session_id="session-1",
            activation_scope="test-scope",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    world.close()


def test_revoked_binding_denied(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    world.store.revoke_ui_binding(binding_id, now=NOW)
    with pytest.raises(UiDenied):
        world.executor.execute(task_id, step_id, binding_id=binding_id)
    world.close()


# -- F10: window activation on the T1 navigation path ------------------------------


def test_window_activation_uses_navigation_evidence(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task = world.store.create_task("Activate fixture window", now=NOW)
    world.store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=NOW)
    planner = Planner(
        capabilities=world.capabilities,
        resources=ResourceRegistry(windows_semantics=False),
        app_authority=world.authority,
        clock=lambda: NOW,
    )
    planned = planner.plan(
        task.task_id,
        PlanIntent(
            goal=PlanGoal.ACTIVATE_WINDOW,
            resource_id=world.window_id,
            arguments={"resource_id": world.window_id},
            summary="Activate the fixture window",
        ),
    )
    world.store.save_plan(planned.plan)
    for state in (
        PersistentTaskState.VALIDATING,
        PersistentTaskState.PREVIEW_READY,
        PersistentTaskState.AWAITING_APPROVAL,
    ):
        world.store.transition_task(task.task_id, state, now=NOW)
    state = {"foreground": None}

    def activate(hwnd: int) -> bool:
        state["foreground"] = hwnd
        return True

    enablement = Phase3Enablement.from_owner_config(
        OwnerEnablementConfig(
            enabled=True,
            capability_allowlist=frozenset({"window.activate"}),
            app_allowlist=frozenset({world.fixture_record.app_id}),
            session_lifetime=timedelta(hours=1),
            scope_name="test-scope",
        ),
        now=NOW,
    )
    broker = PolicyBroker(
        capabilities=world.capabilities,
        resources=ResourceRegistry(windows_semantics=False),
        app_authority=world.authority,
        executors=frozenset({"window.activate"}),
    )
    service = WindowActivationService(
        store=world.store,
        authority=world.authority,
        confirmer=TrustedNavigationConfirmer(),
        broker=broker,
        enablement=enablement,
        focus=world.focus,
        activate=activate,
        foreground_hwnd=lambda: state["foreground"],
        session_id="session-1",
        activation_scope="test-scope",
        clock=lambda: NOW,
    )
    confirmation_id = service.issue_confirmation(task.task_id, planned.step_id)
    outcome = service.execute(task.task_id, planned.step_id, confirmation_id=confirmation_id)
    assert outcome.status == "SUCCEEDED"
    assert world.store.get_task(task.task_id).state is PersistentTaskState.COMPLETED
    attempts = world.store.navigation_attempts_for_task(task.task_id)
    assert attempts and attempts[0]["receipt_status"] == "SUCCEEDED"
    world.close()


# -- F13: outcome semantics ---------------------------------------------------------


def test_takeover_during_execution_is_uncertain(tmp_path: Path) -> None:
    world = _World(tmp_path)
    real_backend = world.fixture.backend

    class TakeoverBackend:
        def __init__(self, inner):  # type: ignore[no-untyped-def]
            self._inner = inner

        def find_root(self, *, hwnd):  # type: ignore[no-untyped-def]
            return self._inner.find_root(hwnd=hwnd)

        def children(self, element):  # type: ignore[no-untyped-def]
            return self._inner.children(element)

        def invoke(self, element):  # type: ignore[no-untyped-def]
            result = self._inner.invoke(element)
            world.focus.on_takeover(world.window_id)  # human intervenes mid-operation
            return result

        def close(self) -> None:
            self._inner.close()

    world.executor.backend_factory = lambda: TakeoverBackend(real_backend())  # type: ignore[method-assign]
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    outcome = world.executor.execute(task_id, step_id, binding_id=binding_id)
    assert outcome.status == "UNVERIFIED" and outcome.outcome == "uncertain"
    world.close()


def test_disabled_control_denied_before_effect(tmp_path: Path) -> None:
    world = _World(tmp_path)
    snapshot = world.snapshot()
    disabled_ref = next(
        e.element_ref for e in snapshot.elements if e.runtime_id == "fixture-disabled"
    )
    task_id, step_id = world.plan_task(snapshot, element_ref=disabled_ref)
    binding_id = world.executor.issue_binding(task_id, step_id)
    with pytest.raises(UiDenied) as excinfo:
        world.executor.execute(task_id, step_id, binding_id=binding_id)
    assert "disabled" in str(excinfo.value)
    assert world.fixture.state.count == 0
    world.close()
