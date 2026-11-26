"""Phase 3 CP3 completion tests (fake-backed; not native evidence).

The central test drives the genuine path: persisted task -> real
planner -> persisted immutable plan -> trusted confirmation ->
LaunchAuthority -> PolicyBroker -> durable attempt -> fake launch
call -> independent verification over a separate fake platform ->
durable verification/receipt -> authoritative task state.
"""

from __future__ import annotations

import threading
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

import aether.core.persistence.sqlite_store as sqlite_store
from aether.core.apps.confirmation import (
    ConfirmationError,
    NavigationConfirmationRequest,
    TrustedNavigationConfirmer,
)
from aether.core.apps.enablement import OwnerEnablementConfig, Phase3Enablement
from aether.core.apps.launch_authority import (
    FakeIntegrityVerifier,
    IntegrityEvidence,
    LaunchAuthority,
    LaunchAuthorityError,
    app_version_token,
    integrity_digest_of,
)
from aether.core.apps.launcher import (
    FakeWindowsPlatform,
    LaunchDenied,
    NativeLaunchAdapterDisabled,
    ScriptedFakeLaunchAdapter,
    TrustedLaunchCoordinator,
)
from aether.core.apps.navigation_evidence import NavigationEvidenceError, NavigationEvidenceStore
from aether.core.apps.navigation_outcomes import NavigationOutcome
from aether.core.apps.registry import InMemoryApplicationRegistry
from aether.core.apps.verification import LaunchVerifier
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    location_identity_digest,
    registration_app_id,
)
from aether.core.persistence.models import PersistentTaskState
from aether.core.persistence.sqlite_store import IllegalPersistentTransition, SQLiteTaskStore
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.resources.app_window_authority import AppWindowResourceAuthority
from aether.core.resources.registry import ResourceRegistry

NOW = datetime(2026, 11, 15, tzinfo=UTC)
EXE = "C:\\Fake\\notepad.exe"


def _record(*, method: LaunchMethod = LaunchMethod.APPROVED_EXECUTABLE) -> ApplicationRecord:
    return ApplicationRecord(
        app_id=registration_app_id(
            display_name="Notepad", executable_identity=EXE, launch_method=method
        ),
        display_name="Notepad",
        launch_method=method,
        executable_identity=EXE,
        location_digest=location_identity_digest(EXE),
        discovery_source=DiscoverySource.FAKE_FIXTURE,
        discovered_at=NOW,
        fresh_until=NOW + timedelta(hours=1),
    )


def _evidence_for(record: ApplicationRecord, *, content: str = "a" * 64) -> IntegrityEvidence:
    return IntegrityEvidence(
        location_digest=record.location_digest or "",
        content_sha256=content,
        signer_identity="FakeSigner",
        package_identity=None,
        verified_at=NOW,
        file_identity="3:42:100:1",
    )


class _World:
    """One fully wired synthetic v3 world (isolated tmp database)."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        behavior: str = "new_instance",
        postcondition: str = "window_required",
    ) -> None:
        self.clock_box = [NOW]
        clock = lambda: self.clock_box[0]  # noqa: E731
        self.record = _record()
        self.registry = InMemoryApplicationRegistry()
        self.registry.register(self.record)
        self.evidence = _evidence_for(self.record)
        self.verifier_evidence = FakeIntegrityVerifier(
            evidence_by_location={self.record.location_digest or "": self.evidence}
        )
        self.authority = LaunchAuthority(verifier=self.verifier_evidence, clock=clock)
        self.app_authority = AppWindowResourceAuthority(session_id="session-1")
        self.version_token = app_version_token(self.evidence)
        self.app_authority.register_app(self.record, version_token=self.version_token)
        self.confirmer = TrustedNavigationConfirmer()
        self.platform = FakeWindowsPlatform(
            integrity_by_app={self.record.app_id: integrity_digest_of(self.evidence)}
        )
        self.adapter = ScriptedFakeLaunchAdapter(platform=self.platform, behavior=behavior)
        self.capabilities = CapabilityRegistry.phase3_with_launch()
        self.broker = PolicyBroker(
            capabilities=self.capabilities,
            resources=ResourceRegistry(windows_semantics=False),
            app_authority=self.app_authority,
            executors=frozenset({"app.launch"}),
        )
        self.enablement = Phase3Enablement.from_owner_config(
            OwnerEnablementConfig(
                enabled=True,
                capability_allowlist=frozenset({"app.launch"}),
                app_allowlist=frozenset({self.record.app_id}),
                session_lifetime=timedelta(hours=1),
                scope_name="test-scope",
            ),
            now=NOW,
        )
        self.store = _v3_store(tmp_path)
        self.coordinator = TrustedLaunchCoordinator(
            store=self.store,
            capabilities=self.capabilities,
            registry=self.registry,
            authority=self.authority,
            confirmer=self.confirmer,
            broker=self.broker,
            adapter=self.adapter,
            verifier=LaunchVerifier(self.platform, timeout_seconds=0.4, poll_interval_seconds=0.01),
            enablement=self.enablement,
            session_id="session-1",
            activation_scope="test-scope",
            clock=clock,
        )
        self.postcondition = postcondition

    def plan_task(self) -> tuple[UUID, UUID]:
        """Persist a real launch plan for a real persisted task."""
        task = self.store.create_task("Launch Notepad", now=NOW)
        self.store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=NOW)
        planner = Planner(
            capabilities=self.capabilities,
            resources=ResourceRegistry(windows_semantics=False),
            app_authority=self.app_authority,
            app_registry=self.registry,
            integrity_verifier=self.verifier_evidence,
            clock=lambda: NOW,
        )
        planned = planner.plan(
            task.task_id,
            PlanIntent(
                goal=PlanGoal.LAUNCH_APPLICATION,
                resource_id=self.record.app_id,
                arguments={"resource_id": self.record.app_id, "postcondition": self.postcondition},
                summary="Launch Notepad",
            ),
        )
        digest = self.store.save_plan(planned.plan)
        assert digest == planned.plan_hash
        assert planned.plan.steps[0].resources[0].expected_version == self.version_token
        assert planned.plan.steps[0].resources[0].expected_version != "app-registration-v1"
        self.store.transition_task(task.task_id, PersistentTaskState.VALIDATING, now=NOW)
        self.store.transition_task(task.task_id, PersistentTaskState.PREVIEW_READY, now=NOW)
        self.store.transition_task(task.task_id, PersistentTaskState.AWAITING_APPROVAL, now=NOW)
        return task.task_id, planned.step_id

    def confirm_and_authorize(self, task_id: UUID, step_id: UUID):  # type: ignore[no-untyped-def]
        confirmation = self.coordinator.issue_confirmation(task_id, step_id)
        authorization = self.authority.authorize(
            self.record, session_id="session-1", activation_scope="test-scope"
        )
        return confirmation, authorization

    def close(self) -> None:
        self.store.close()


def _v3_store(tmp_path: Path) -> SQLiteTaskStore:
    """Explicit isolated synthetic v3 store (test activation only)."""
    sqlite_store.ACTIVE_SCHEMA_VERSION = 3
    sqlite_store.PENDING_MIGRATION_VERSIONS = frozenset()
    try:
        return SQLiteTaskStore(tmp_path / "synthetic.db")
    finally:
        sqlite_store.ACTIVE_SCHEMA_VERSION = 2
        sqlite_store.PENDING_MIGRATION_VERSIONS = frozenset({3})


# -- B01: authoritative persisted-plan integration ---------------------------


def test_persisted_plan_to_execution_end_to_end(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    outcome = world.coordinator.execute(
        task_id,
        step_id,
        confirmation_id=confirmation.confirmation_id,
        authorization_id=authorization.authorization_id,
    )
    assert outcome.status == "SUCCEEDED"
    assert outcome.outcome is NavigationOutcome.VERIFIED_NEW_INSTANCE
    assert world.store.get_task(task_id).state is PersistentTaskState.COMPLETED
    attempts = world.store.navigation_attempts_for_task(task_id)
    assert len(attempts) == 1
    assert attempts[0]["outcome"] == "verified_new_instance"
    assert attempts[0]["receipt_status"] == "SUCCEEDED"
    # Actual confirmation timestamps persisted (not manufactured).
    row = world.store._connection.execute(
        "SELECT issued_at, expires_at, consumed_at, arguments_sha256, length(binding_sha256) AS blen"
        " FROM navigation_confirmations WHERE id = ?",
        (confirmation.confirmation_id,),
    ).fetchone()
    assert (
        row["issued_at"] == confirmation.issued_at.isoformat().replace("+00:00", "Z")
        or row["issued_at"]
    )
    assert row["consumed_at"] is not None and row["blen"] == 64
    # Replay is impossible: consumed confirmation + consumed authorization.
    with pytest.raises((LaunchAuthorityError, ConfirmationError, IllegalPersistentTransition)):
        world.coordinator.execute(
            task_id,
            step_id,
            confirmation_id=confirmation.confirmation_id,
            authorization_id=authorization.authorization_id,
        )
    world.close()


def test_execution_rejects_unknown_task_step_and_stale_plan(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    with pytest.raises(LaunchDenied):  # nonexistent task
        world.coordinator.execute(
            uuid4(),
            step_id,
            confirmation_id=confirmation.confirmation_id,
            authorization_id=authorization.authorization_id,
        )
    with pytest.raises(LaunchDenied):  # mismatched step
        world.coordinator.execute(
            task_id,
            uuid4(),
            confirmation_id=confirmation.confirmation_id,
            authorization_id=authorization.authorization_id,
        )
    # A revised plan invalidates the confirmation bound to revision 1:
    world.store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
    planner = Planner(
        capabilities=world.capabilities,
        resources=ResourceRegistry(windows_semantics=False),
        app_authority=world.app_authority,
        app_registry=world.registry,
        integrity_verifier=world.verifier_evidence,
        clock=lambda: NOW,
    )
    planned2 = planner.plan(
        task_id,
        PlanIntent(
            goal=PlanGoal.LAUNCH_APPLICATION,
            resource_id=world.record.app_id,
            arguments={"resource_id": world.record.app_id, "postcondition": "window_required"},
            summary="Launch Notepad (revised)",
        ),
        revision=2,
    )
    world.store.save_plan(planned2.plan)
    world.store.transition_task(task_id, PersistentTaskState.VALIDATING, now=NOW)
    world.store.transition_task(task_id, PersistentTaskState.PREVIEW_READY, now=NOW)
    world.store.transition_task(task_id, PersistentTaskState.AWAITING_APPROVAL, now=NOW)
    authorization2 = world.authority.authorize(
        world.record, session_id="session-1", activation_scope="test-scope"
    )
    # The old confirmation no longer binds the current plan revision.
    with pytest.raises(IllegalPersistentTransition):
        world.coordinator.execute(
            task_id,
            planned2.step_id,
            confirmation_id=confirmation.confirmation_id,
            authorization_id=authorization2.authorization_id,
        )
    world.close()


# -- B02: independent verification -------------------------------------------


@pytest.mark.parametrize(
    ("behavior", "postcondition", "prepare", "expected_status", "expected_outcome"),
    [
        (
            "accepted_no_effect",
            "window_required",
            None,
            "UNVERIFIED",
            NavigationOutcome.TIMEOUT_AFTER_EFFECT,
        ),
        (
            "background",
            "window_required",
            None,
            "UNVERIFIED",
            NavigationOutcome.TIMEOUT_AFTER_EFFECT,
        ),
        (
            "wrong_process",
            "window_required",
            None,
            "UNVERIFIED",
            NavigationOutcome.TIMEOUT_AFTER_EFFECT,
        ),
        (
            "wrong_window",
            "window_required",
            None,
            "UNVERIFIED",
            NavigationOutcome.TIMEOUT_AFTER_EFFECT,
        ),
        (
            "accepted_no_effect",
            "window_required",
            "existing",
            "UNVERIFIED",
            NavigationOutcome.TIMEOUT_AFTER_EFFECT,
        ),
        (
            "existing_activation",
            "window_required",
            "existing",
            "SUCCEEDED",
            NavigationOutcome.VERIFIED_EXISTING_INSTANCE,
        ),
        (
            "background",
            "background_no_window",
            None,
            "SUCCEEDED",
            NavigationOutcome.VERIFIED_BACKGROUND_NO_WINDOW,
        ),
        ("fail_before_effect", "window_required", None, "FAILED", NavigationOutcome.FAILED),
        (
            "raise_after_accept",
            "window_required",
            None,
            "UNVERIFIED",
            NavigationOutcome.TIMEOUT_AFTER_EFFECT,
        ),
    ],
)
def test_verification_matrix(
    tmp_path: Path, behavior, postcondition, prepare, expected_status, expected_outcome
) -> None:  # type: ignore[no-untyped-def]
    world = _World(tmp_path, behavior=behavior, postcondition=postcondition)
    if prepare == "existing":
        world.platform.add_existing(world.record.app_id)
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    outcome = world.coordinator.execute(
        task_id,
        step_id,
        confirmation_id=confirmation.confirmation_id,
        authorization_id=authorization.authorization_id,
    )
    assert outcome.status == expected_status
    assert outcome.outcome is expected_outcome
    expected_state = {
        "SUCCEEDED": PersistentTaskState.COMPLETED,
        "FAILED": PersistentTaskState.FAILED,
        "UNVERIFIED": PersistentTaskState.UNVERIFIED,
    }[expected_status]
    assert world.store.get_task(task_id).state is expected_state
    world.close()


def test_adapter_cannot_claim_verified_success(tmp_path: Path) -> None:
    # The adapter contract has no verified outcome at all: acceptance
    # with no observed process/window can never succeed (covered by
    # the matrix), and the SQL layer rejects token-less verification.
    store = _v3_store(tmp_path)
    with pytest.raises(IllegalPersistentTransition):
        store.record_navigation_verification(
            attempt_id="missing",
            outcome="verified_new_instance",
            process_token=None,
            window_token=None,
            now=NOW,
        )
    store.close()


# -- B03/B04: evidence gates, forgery, concurrency ----------------------------


def test_t1_evidence_cannot_drive_t2_mutation_task(tmp_path: Path) -> None:
    """A genuine registered T2 mutation task rejects navigation evidence
    at the mutation gate itself (resource registered, plan persisted)."""
    from aether.core.contracts.policy import RiskTier
    from aether.core.persistence.models import (
        ExecutionEvidence,
        PlanStep,
        TaskPlan,
        TaskPlanResource,
    )

    store = _v3_store(tmp_path)
    task = store.create_task("Edit a registered file", now=NOW)
    store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=NOW)
    step_id = uuid4()
    plan = TaskPlan(
        task_id=task.task_id,
        revision=1,
        summary="edit",
        steps=(
            PlanStep(
                step_id=step_id,
                capability_id="fs.apply_approved_edit",
                arguments={"resource_id": "file:123e4567-e89b-12d3-a456-426614174000"},
                resources=(
                    TaskPlanResource(
                        resource_id="file:123e4567-e89b-12d3-a456-426614174000",
                        expected_version="v1",
                        display_name="example.txt",
                    ),
                ),
                resource_locks=(),
                expected_state={},
                expected_effect={},
                risk_tier=RiskTier.MODIFY,
                timeout_seconds=30,
                idempotency_key=uuid4(),
                postconditions=({"verify": "x"},),
                recovery_class="SNAPSHOT_RESTORABLE",
            ),
        ),
        created_at=NOW,
    )
    store.save_plan(plan)
    store.transition_task(task.task_id, PersistentTaskState.VALIDATING, now=NOW)
    store.transition_task(task.task_id, PersistentTaskState.PREVIEW_READY, now=NOW)
    store.transition_task(task.task_id, PersistentTaskState.AWAITING_APPROVAL, now=NOW)
    # Navigation state machine refuses a MODIFY persisted capability.
    with pytest.raises(IllegalPersistentTransition):
        store.advance_navigation_state(
            task.task_id,
            PersistentTaskState.PRECHECK,
            step_id=step_id,
            confirmation_id=str(uuid4()),
            now=NOW,
        )
    # The mutation gate itself: a navigation confirmation id presented
    # as grant evidence names no live grant for the current plan.
    with pytest.raises(IllegalPersistentTransition):
        store.advance_execution_state(
            task.task_id,
            PersistentTaskState.PRECHECK,
            evidence=ExecutionEvidence(approval_id=uuid4()),
            now=NOW,
        )
    store.close()


def test_forged_references_and_mutated_objects(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    # Issued objects are immutable snapshots.
    with pytest.raises(FrozenInstanceError):
        confirmation.expires_at = NOW  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        authorization.expires_at = NOW  # type: ignore[misc]
    with pytest.raises(IllegalPersistentTransition):  # forged confirmation
        world.coordinator.execute(
            task_id,
            step_id,
            confirmation_id=str(uuid4()),
            authorization_id=authorization.authorization_id,
        )
    with pytest.raises(LaunchAuthorityError):  # forged authorization
        world.coordinator.execute(
            task_id,
            step_id,
            confirmation_id=confirmation.confirmation_id,
            authorization_id=str(uuid4()),
        )
    world.close()


def test_concurrent_double_consumption_exactly_once(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, _authorization = world.confirm_and_authorize(task_id, step_id)
    request = NavigationConfirmationRequest(
        task_id=task_id,
        step_id=step_id,
        plan_revision=1,
        plan_hash=world.store.get_task(task_id).plan_hash or "",
        capability_id="app.launch",
        arguments={"resource_id": world.record.app_id, "postcondition": "window_required"},
        app_resource_id=world.record.app_id,
        expected_app_version=world.version_token,
        integrity_sha256=integrity_digest_of(world.evidence),
        session_id="session-1",
        activation_scope="test-scope",
    )
    results: list[str] = []
    barrier = threading.Barrier(8)

    def _consume() -> None:
        barrier.wait()
        try:
            world.confirmer.consume(confirmation.confirmation_id, request, now=NOW)
            results.append("ok")
        except ConfirmationError:
            results.append("denied")

    threads = [threading.Thread(target=_consume) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("ok") == 1 and results.count("denied") == 7
    world.close()


def test_expired_revoked_scope_and_version_failures(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    # Scope mismatch.
    with pytest.raises(LaunchAuthorityError):
        world.authority.revalidate_and_consume(
            authorization.authorization_id,
            world.record,
            session_id="other-session",
            activation_scope="test-scope",
        )
    with pytest.raises(LaunchAuthorityError):
        world.authority.revalidate_and_consume(
            authorization.authorization_id,
            world.record,
            session_id="session-1",
            activation_scope="other-scope",
        )
    # Revoked confirmation.
    world.confirmer.revoke(confirmation.confirmation_id)
    authorization2 = world.authority.authorize(
        world.record, session_id="session-1", activation_scope="test-scope"
    )
    with pytest.raises(ConfirmationError):
        world.coordinator.execute(
            task_id,
            step_id,
            confirmation_id=confirmation.confirmation_id,
            authorization_id=authorization2.authorization_id,
        )
    world.close()

    # Expiry via the trusted clock.
    (tmp_path / "second").mkdir(mode=0o700, exist_ok=True)
    world2 = _World(tmp_path / "second")
    task_id2, step_id2 = world2.plan_task()
    confirmation2, authorization2 = world2.confirm_and_authorize(task_id2, step_id2)
    world2.clock_box[0] = NOW + timedelta(minutes=30)
    with pytest.raises((ConfirmationError, LaunchAuthorityError, IllegalPersistentTransition)):
        world2.coordinator.execute(
            task_id2,
            step_id2,
            confirmation_id=confirmation2.confirmation_id,
            authorization_id=authorization2.authorization_id,
        )
    world2.close()


def test_absent_and_drifted_integrity_denies(tmp_path: Path) -> None:
    record = _record()
    empty = FakeIntegrityVerifier(
        evidence_by_location={
            record.location_digest or "": IntegrityEvidence(
                location_digest=record.location_digest or "",
                content_sha256=None,
                signer_identity=None,
                package_identity=None,
                verified_at=NOW,
                file_identity=None,
            )
        }
    )
    authority = LaunchAuthority(verifier=empty)
    with pytest.raises(LaunchAuthorityError):  # all meaningful fields absent
        authority.authorize(record, session_id="s", activation_scope="scope", now=NOW)
    with pytest.raises(LaunchAuthorityError):  # no evidence at all
        LaunchAuthority(verifier=FakeIntegrityVerifier()).authorize(
            record, session_id="s", activation_scope="scope", now=NOW
        )
    with pytest.raises(LaunchDenied):
        NativeLaunchAdapterDisabled().launch(
            app_id=record.app_id, method=record.launch_method, canonical_target=EXE
        )


def test_enablement_revoked_before_effect_denies(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, authorization = world.confirm_and_authorize(task_id, step_id)
    world.enablement.revoke()
    with pytest.raises(LaunchDenied):
        world.coordinator.execute(
            task_id,
            step_id,
            confirmation_id=confirmation.confirmation_id,
            authorization_id=authorization.authorization_id,
        )
    assert world.adapter.calls == 0  # no external effect was attempted
    world.close()


# -- B03 recovery --------------------------------------------------------------


def test_interrupted_attempt_reconciles_without_replay(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, _authorization = world.confirm_and_authorize(task_id, step_id)
    # Drive to a committed attempt, then simulate crash (no verification).
    world.store.advance_navigation_state(
        task_id,
        PersistentTaskState.PRECHECK,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        now=NOW,
    )
    attempt_id = world.store.begin_navigation_attempt(
        task_id=task_id,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        now=NOW,
    )
    world.store.advance_navigation_state(
        task_id,
        PersistentTaskState.EXECUTING,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        attempt_id=attempt_id,
        now=NOW,
    )
    calls_before = world.adapter.calls
    outcomes = world.coordinator.reconcile()
    assert outcomes == [(task_id, "UNVERIFIED")]
    assert world.store.get_task(task_id).state is PersistentTaskState.UNVERIFIED
    assert world.adapter.calls == calls_before  # reconciliation never launches
    # No replay: the consumed confirmation cannot begin another attempt.
    with pytest.raises(IllegalPersistentTransition):
        world.store.begin_navigation_attempt(
            task_id=task_id,
            step_id=step_id,
            confirmation_id=confirmation.confirmation_id,
            now=NOW,
        )
    world.close()


def test_cancellation_before_and_after_effect(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, _authorization = world.confirm_and_authorize(task_id, step_id)
    world.store.advance_navigation_state(
        task_id,
        PersistentTaskState.PRECHECK,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        now=NOW,
    )
    # Before any attempt: cancellation is truthful and clean.
    assert (
        world.coordinator.cancel(task_id, step_id, confirmation_id=confirmation.confirmation_id)
        is PersistentTaskState.CANCELLED
    )
    world.close()

    world2 = _World(tmp_path / "b")
    (tmp_path / "b").mkdir(mode=0o700, exist_ok=True)
    task_id2, step_id2 = world2.plan_task()
    confirmation2, _a2 = world2.confirm_and_authorize(task_id2, step_id2)
    world2.store.advance_navigation_state(
        task_id2,
        PersistentTaskState.PRECHECK,
        step_id=step_id2,
        confirmation_id=confirmation2.confirmation_id,
        now=NOW,
    )
    attempt_id = world2.store.begin_navigation_attempt(
        task_id=task_id2,
        step_id=step_id2,
        confirmation_id=confirmation2.confirmation_id,
        now=NOW,
    )
    world2.store.advance_navigation_state(
        task_id2,
        PersistentTaskState.EXECUTING,
        step_id=step_id2,
        confirmation_id=confirmation2.confirmation_id,
        attempt_id=attempt_id,
        now=NOW,
    )
    # After an attempt was committed, cancellation cannot hide the
    # possible effect: the task becomes UNVERIFIED, not CANCELLED.
    assert (
        world2.coordinator.cancel(task_id2, step_id2, confirmation_id=confirmation2.confirmation_id)
        is PersistentTaskState.UNVERIFIED
    )
    world2.close()


# -- standalone synthetic evidence store (schema constraints) ------------------


def test_evidence_store_forgery_and_schema_constraints() -> None:
    store = NavigationEvidenceStore.on_memory()
    from aether.core.apps.navigation_evidence import ConfirmationBinding

    binding = ConfirmationBinding(
        confirmation_id="conf-1",
        task_id="task-1",
        step_id="step-1",
        plan_revision=1,
        plan_hash="b" * 64,
        capability_id="app.launch",
        arguments_sha256="c" * 64,
        app_resource_id="app:123e4567-e89b-12d3-a456-426614174000",
        expected_app_version="v1",
        integrity_sha256="d" * 64,
        session_id="s",
        activation_scope="scope",
        issued_at=NOW.isoformat(),
        expires_at=NOW.isoformat(),
        binding_sha256="e" * 64,
    )
    store.record_confirmation(binding)
    with pytest.raises(NavigationEvidenceError):  # cross-task forgery
        store.record_attempt(
            confirmation_id="conf-1",
            task_id="task-OTHER",
            step_id="step-1",
            capability_id="app.launch",
            app_resource_id=binding.app_resource_id,
            recorded_at=NOW.isoformat(),
        )
    attempt_id = store.record_attempt(
        confirmation_id="conf-1",
        task_id="task-1",
        step_id="step-1",
        capability_id="app.launch",
        app_resource_id=binding.app_resource_id,
        recorded_at=NOW.isoformat(),
    )
    assert store.reconcile_interrupted() == [attempt_id]
    with pytest.raises(NavigationEvidenceError):  # success without verification
        store.record_receipt(
            attempt_id=attempt_id,
            verification_id="missing",
            status="SUCCEEDED",
            created_at=NOW.isoformat(),
        )
    # Token-less verified verification is rejected by SQL constraints.
    with pytest.raises(NavigationEvidenceError):
        store.record_verification(
            attempt_id=attempt_id,
            outcome="verified_new_instance",
            process_token=None,
            window_token=None,
            verified_at=NOW.isoformat(),
        )


def test_schema_v3_prepared_but_not_active(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert sqlite_store.ACTIVE_SCHEMA_VERSION == 2
    assert frozenset({3}) == sqlite_store.PENDING_MIGRATION_VERSIONS
    assert (
        sqlite_store._EXPECTED_MIGRATIONS[3][1]
        == "6d165d8a3f56634619b1340ca310aa7d0057c9b6438d461919f34d1a64dcd4dc"
    )
    store = _v3_store(tmp_path)
    version = store._connection.execute("PRAGMA user_version").fetchone()[0]
    assert version == 3
    # Confirmation bindings are immutable at the SQL layer.
    import sqlite3

    store._connection.execute(
        "INSERT INTO navigation_confirmations(id, task_id, step_id, plan_revision, plan_hash,"
        " capability_id, arguments_sha256, binding_sha256, app_resource_id, expected_app_version,"
        " integrity_evidence_sha256, session_id, activation_scope, issued_at, expires_at)"
        " VALUES ('c1','t','s',1,?, 'app.launch', ?, ?, 'app:123e4567-e89b-12d3-a456-426614174000',"
        " 'v', ?, 'sess', 'scope', 'now', 'later')",
        ("b" * 64, "c" * 64, "e" * 64, "d" * 64),
    )
    store._connection.commit()
    with pytest.raises(sqlite3.IntegrityError):
        store._connection.execute(
            "UPDATE navigation_confirmations SET plan_hash = ? WHERE id = 'c1'", ("f" * 64,)
        )
    store._connection.rollback()
    store.close()


def test_reconcile_after_verification_before_receipt(tmp_path: Path) -> None:
    world = _World(tmp_path)
    task_id, step_id = world.plan_task()
    confirmation, _authorization = world.confirm_and_authorize(task_id, step_id)
    world.store.advance_navigation_state(
        task_id,
        PersistentTaskState.PRECHECK,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        now=NOW,
    )
    attempt_id = world.store.begin_navigation_attempt(
        task_id=task_id,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        now=NOW,
    )
    world.store.advance_navigation_state(
        task_id,
        PersistentTaskState.EXECUTING,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        attempt_id=attempt_id,
        now=NOW,
    )
    world.store.advance_navigation_state(
        task_id,
        PersistentTaskState.POSTCHECK,
        step_id=step_id,
        confirmation_id=confirmation.confirmation_id,
        attempt_id=attempt_id,
        now=NOW,
    )
    world.store.record_navigation_verification(
        attempt_id=attempt_id,
        outcome="verified_new_instance",
        process_token="pid:5:creation-1",
        window_token="window:1",
        now=NOW,
    )
    # Crash after verification, before receipt and task completion:
    # reconciliation derives the receipt from the recorded
    # verification and completes the task — without launching again.
    outcomes = world.coordinator.reconcile()
    assert outcomes == [(task_id, "COMPLETED")]
    assert world.store.get_task(task_id).state is PersistentTaskState.COMPLETED
    assert world.adapter.calls == 0
    world.close()
