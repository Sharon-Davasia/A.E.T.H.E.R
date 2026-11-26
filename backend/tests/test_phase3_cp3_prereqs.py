"""CP3 prerequisite regressions R01-R05 (fake-backed; not native evidence)."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from test_phase3_launch import NOW, _World

from aether.core.apps.launcher import LaunchCallResult
from aether.core.apps.navigation_outcomes import NavigationOutcome
from aether.core.contracts.app_window import LaunchMethod
from aether.core.persistence.models import PersistentTaskState
from aether.core.persistence.sqlite_store import IllegalPersistentTransition
from aether.world_state import InMemoryWorldState
from aether.world_state.observer import (
    FakeWindowEventSource,
    GenerationClock,
    ObserverService,
    WindowEvent,
    WindowEventKind,
)

# -- R01: interruption boundaries ----------------------------------------------


def test_crash_before_attempt_is_distinguishable_and_cancellable(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, _a = world.confirm_and_authorize(task_id, step_id)
    world.store.advance_navigation_state(
        task_id,
        PersistentTaskState.PRECHECK,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        now=NOW,
    )
    # No attempt committed: reconciliation leaves the task alone and
    # cancellation still works cleanly.
    assert world.coordinator.reconcile() == []
    assert (
        world.coordinator.cancel(task_id, step_id, confirmation_id=confirmation.confirmation_id)
        is PersistentTaskState.CANCELLED
    )
    world.close()


def test_crash_after_attempt_in_precheck_recovers_failed_idempotently(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, _a = world.confirm_and_authorize(task_id, step_id)
    world.store.advance_navigation_state(
        task_id,
        PersistentTaskState.PRECHECK,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        now=NOW,
    )
    # Legacy two-step boundary: attempt committed, EXECUTING never reached.
    world.store.begin_navigation_attempt(
        task_id=task_id,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        now=NOW,
    )
    assert world.coordinator.reconcile() == [(task_id, "FAILED")]
    assert world.store.get_task(task_id).state is PersistentTaskState.FAILED
    assert world.coordinator.reconcile() == []  # idempotent
    assert world.adapter.calls == 0  # never replayed
    world.close()


# -- R02: cancellation / commitment races ---------------------------------------


def test_cancel_before_commitment_prevents_adapter_call(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    world.store.advance_navigation_state(
        task_id,
        PersistentTaskState.PRECHECK,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        now=NOW,
    )
    assert (
        world.coordinator.cancel(task_id, step_id, confirmation_id=confirmation.confirmation_id)
        is PersistentTaskState.CANCELLED
    )
    with pytest.raises(IllegalPersistentTransition):
        world.coordinator.execute(
            task_id,
            step_id,
            confirmation_id=confirmation.confirmation_id,
            authorization_id=authorization.authorization_id,
        )
    assert world.adapter.calls == 0
    world.close()


def test_cancel_after_commitment_reports_verified_truth(tmp_path: Path) -> None:
    world = _World(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    real_adapter = world.adapter

    class BlockingAdapter:
        def launch(
            self, *, app_id: str, method: LaunchMethod, canonical_target: str
        ) -> LaunchCallResult:
            entered.set()
            release.wait(timeout=10)
            return real_adapter.launch(
                app_id=app_id, method=method, canonical_target=canonical_target
            )

    world.coordinator._adapter = BlockingAdapter()  # type: ignore[attr-defined]
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    result: dict[str, object] = {}

    def _execute() -> None:
        try:
            result["outcome"] = world.coordinator.execute(
                task_id,
                step_id,
                confirmation_id=confirmation.confirmation_id,
                authorization_id=authorization.authorization_id,
            )
        except Exception as exc:
            result["error"] = exc

    thread = threading.Thread(target=_execute)
    thread.start()
    assert entered.wait(timeout=10)  # commitment passed, adapter in flight
    cancel_result: dict[str, object] = {}

    def _cancel() -> None:
        cancel_result["state"] = world.coordinator.cancel(
            task_id, step_id, confirmation_id=confirmation.confirmation_id
        )

    cancel_thread = threading.Thread(target=_cancel)
    cancel_thread.start()
    release.set()
    thread.join(timeout=10)
    cancel_thread.join(timeout=10)
    # Cancellation could not falsely claim success: the execution
    # completed and verified, and cancel reports that terminal truth.
    assert "error" not in result
    assert cancel_result["state"] is PersistentTaskState.COMPLETED
    assert world.store.get_task(task_id).state is PersistentTaskState.COMPLETED
    world.close()


def test_revocation_during_precheck_blocks_commitment(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    world.store.revoke_navigation_confirmation(confirmation.confirmation_id, now=NOW)
    with pytest.raises((IllegalPersistentTransition, Exception)):
        world.coordinator.execute(
            task_id,
            step_id,
            confirmation_id=confirmation.confirmation_id,
            authorization_id=authorization.authorization_id,
        )
    assert world.adapter.calls == 0
    world.close()


# -- R03: integrity provider conservatism ---------------------------------------


def test_integrity_provider_rejects_unsafe_targets(tmp_path: Path) -> None:
    from datetime import timedelta as td

    from aether.adapters.windows.native_launcher import NativeIntegrityProvider
    from aether.core.contracts.app_window import (
        ApplicationRecord,
        DiscoverySource,
        location_identity_digest,
        registration_app_id,
    )

    provider = NativeIntegrityProvider()
    target = tmp_path / "app.exe"
    target.write_bytes(b"synthetic")
    link = tmp_path / "link.exe"
    link.symlink_to(target)

    def record_for(identity: str) -> ApplicationRecord:
        return ApplicationRecord(
            app_id=registration_app_id(
                display_name="A",
                executable_identity=identity,
                launch_method=LaunchMethod.APPROVED_EXECUTABLE,
            ),
            display_name="A",
            launch_method=LaunchMethod.APPROVED_EXECUTABLE,
            executable_identity=identity,
            location_digest=location_identity_digest(identity),
            discovery_source=DiscoverySource.FAKE_FIXTURE,
            discovered_at=NOW,
            fresh_until=NOW + td(hours=1),
        )

    assert provider.verify(record_for(str(target))) is not None
    assert provider.verify(record_for(str(link))) is None  # reparse/symlink
    assert provider.verify(record_for("\\\\server\\share\\app.exe")) is None  # network
    assert provider.verify(record_for("C:relative\\app.exe")) is None  # drive-relative
    assert provider.verify(record_for("C:\\Fake\\app.txt")) is None  # unsupported type


def test_packaged_identity_requires_platform_query() -> None:
    from datetime import timedelta as td

    from aether.adapters.windows.native_launcher import NativeIntegrityProvider
    from aether.core.apps.launch_authority import LaunchAuthority, app_version_token
    from aether.core.contracts.app_window import (
        ApplicationRecord,
        DiscoverySource,
        location_identity_digest,
        registration_app_id,
    )

    aumid = "FakePackage!App"
    record = ApplicationRecord(
        app_id=registration_app_id(
            display_name="P",
            executable_identity=aumid,
            launch_method=LaunchMethod.APPS_FOLDER_ACTIVATION,
        ),
        display_name="P",
        launch_method=LaunchMethod.APPS_FOLDER_ACTIVATION,
        executable_identity=aumid,
        location_digest=location_identity_digest(aumid),
        discovery_source=DiscoverySource.APPS_FOLDER,
        discovered_at=NOW,
        fresh_until=NOW + td(hours=1),
    )
    # A repeated registry string is not verified package integrity.
    assert NativeIntegrityProvider().verify(record) is None
    provider = NativeIntegrityProvider(
        package_query=lambda a: ("FakePackage_1.0_x64__publisher", "1.0.0.0")
    )
    evidence = provider.verify(record)
    assert evidence is not None and evidence.package_version == "1.0.0.0"
    token_v1 = app_version_token(evidence)
    provider2 = NativeIntegrityProvider(
        package_query=lambda a: ("FakePackage_2.0_x64__publisher", "2.0.0.0")
    )
    evidence2 = provider2.verify(record)
    assert (
        evidence2 is not None and app_version_token(evidence2) != token_v1
    )  # drift changes version
    authority = LaunchAuthority(verifier=provider)  # type: ignore[arg-type]
    auth = authority.authorize(record, session_id="s", activation_scope="scope", now=NOW)
    assert auth.canonical_target == aumid


# -- R04: verifier attribution ---------------------------------------------------


def test_incomplete_baseline_cannot_establish_new_instance(tmp_path: Path) -> None:
    world = _World(tmp_path)
    world.platform.complete = False  # incomplete pre-launch baseline

    class SilentAdapter:
        calls = 0

        def launch(
            self, *, app_id: str, method: LaunchMethod, canonical_target: str
        ) -> LaunchCallResult:
            self.calls += 1
            world.platform.spawn(app_id)  # effect happens, but returns no identity
            return LaunchCallResult(accepted=True, process_token=None)

    world.coordinator._adapter = SilentAdapter()  # type: ignore[attr-defined]
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    outcome = world.coordinator.execute(
        task_id,
        step_id,
        confirmation_id=confirmation.confirmation_id,
        authorization_id=authorization.authorization_id,
    )
    # The spawned process might be the launch or might be the user's:
    # with an incomplete baseline and no returned identity, no
    # verified attribution is possible.
    assert outcome.status == "UNVERIFIED"
    assert outcome.outcome is NavigationOutcome.TIMEOUT_AFTER_EFFECT
    world.close()


def test_unrelated_process_does_not_satisfy_returned_identity(tmp_path: Path) -> None:
    world = _World(tmp_path)

    class MisattributingAdapter:
        def launch(
            self, *, app_id: str, method: LaunchMethod, canonical_target: str
        ) -> LaunchCallResult:
            world.platform.spawn(app_id)  # unrelated process appears
            return LaunchCallResult(accepted=True, process_token="pid:4242:creation-other")

    world.coordinator._adapter = MisattributingAdapter()  # type: ignore[attr-defined]
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    outcome = world.coordinator.execute(
        task_id,
        step_id,
        confirmation_id=confirmation.confirmation_id,
        authorization_id=authorization.authorization_id,
    )
    assert outcome.status == "UNVERIFIED"
    world.close()


# -- R05: observer -> WorldState -> authority atomic reconciliation --------------


def _mk_event(hwnd: int, pid: int = 10, creation: str = "t1") -> WindowEvent:
    from test_phase3_world_state import PERMITTED

    return WindowEvent(
        kind=WindowEventKind.WINDOW_CREATED,
        hwnd=hwnd,
        pid=pid,
        process_creation_time=creation,
        app_identity="fixture",
        classification=PERMITTED,
    )


def test_observer_reconcile_publishes_atomically_to_world_state() -> None:
    from test_phase3_world_state import _policy

    from aether.core.contracts.resource import ResourceRef
    from aether.core.resources.app_window_authority import (
        AppWindowAuthorityError,
        AppWindowResourceAuthority,
    )

    clock = GenerationClock()
    authority = AppWindowResourceAuthority()
    state = InMemoryWorldState(policy=_policy(), authority=authority, generation_clock=clock)
    source = FakeWindowEventSource()
    source.set_snapshot([_mk_event(1), _mk_event(2, pid=11)])
    service = ObserverService(
        source=source,
        on_event=lambda e: state.handle_event(e, now=NOW),
        generation_clock=clock,
        snapshot_handler=lambda events: state.apply_snapshot(events, now=NOW),
    )
    assert service.reconcile() is True
    assert service.stats.uncertain is False
    current = state.current(now=NOW)
    assert len(current) == 2
    first_ref = current[0].resource_id
    assert first_ref is not None and "#" in (current[0].version_token or "")
    # Stable reference for the unchanged live window after re-reconcile.
    assert service.reconcile() is True
    assert state.current(now=NOW)[0].resource_id == first_ref
    # Next snapshot drops window 1: its authority ref is invalidated.
    source.set_snapshot([_mk_event(2, pid=11)])
    assert service.reconcile() is True
    assert len(state.current(now=NOW)) == 1
    with pytest.raises(AppWindowAuthorityError):
        authority.authorize_ref(
            ResourceRef(kind="window", resource_id=first_ref), expected_kind="window"
        )
    # Same-process HWND recreation is a new instance + version.
    source.set_snapshot([_mk_event(2, pid=11), _mk_event(3, pid=11)])
    assert service.reconcile() is True
    state.handle_event(_mk_event(3, pid=11), now=NOW)  # unchanged: stable

    def _ref_for(hwnd: int) -> str:
        for observation in state.current(now=NOW):
            if (
                observation.resource_id
                and authority.resolve_window(observation.resource_id).hwnd == hwnd
            ):
                return observation.resource_id
        raise AssertionError(f"no ref for hwnd {hwnd}")

    ref3 = _ref_for(3)
    state.handle_event(WindowEvent(kind=WindowEventKind.WINDOW_DESTROYED, hwnd=3), now=NOW)
    state.handle_event(_mk_event(3, pid=11), now=NOW)  # recreated by same process
    ref3_new = _ref_for(3)
    assert ref3_new != ref3
    with pytest.raises(AppWindowAuthorityError):
        authority.authorize_ref(
            ResourceRef(kind="window", resource_id=ref3), expected_kind="window"
        )


def test_failed_enumeration_retains_uncertainty_through_snapshot_path() -> None:
    from test_phase3_world_state import _policy

    clock = GenerationClock()
    state = InMemoryWorldState(policy=_policy(), generation_clock=clock)
    source = FakeWindowEventSource()

    def _boom() -> list[WindowEvent]:
        raise RuntimeError("enumeration failed")

    source.reconcile = _boom  # type: ignore[method-assign]
    service = ObserverService(
        source=source,
        on_event=lambda e: state.handle_event(e, now=NOW),
        generation_clock=clock,
        snapshot_handler=lambda events: state.apply_snapshot(events, now=NOW),
    )
    assert service.reconcile() is False
    assert service.stats.uncertain is True
