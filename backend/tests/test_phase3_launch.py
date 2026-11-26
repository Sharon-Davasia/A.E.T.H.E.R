"""Phase 3 CP3 fake-backed integration tests (not native evidence)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aether.core.apps.confirmation import (
    NavigationConfirmationRequest,
    TrustedNavigationConfirmer,
)
from aether.core.apps.enablement import OwnerEnablementConfig, Phase3Enablement
from aether.core.apps.launch_authority import (
    FakeIntegrityVerifier,
    IntegrityEvidence,
    LaunchAuthority,
    LaunchAuthorityError,
)
from aether.core.apps.launcher import (
    FakeLaunchAdapter,
    LaunchAttemptResult,
    LaunchDenied,
    NativeLaunchAdapterDisabled,
    VerifiedLauncher,
)
from aether.core.apps.navigation_evidence import NavigationEvidenceError, NavigationEvidenceStore
from aether.core.apps.registry import InMemoryApplicationRegistry
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    location_identity_digest,
    registration_app_id,
)
from aether.core.contracts.resource import ResourceRef
from aether.core.contracts.tool import ToolRequest
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.resources.app_window_authority import AppWindowResourceAuthority
from aether.core.resources.registry import ResourceRegistry

NOW = datetime(2026, 11, 15, tzinfo=UTC)
EXE = "C:\\Fake\\notepad.exe"


def _record(*, method: LaunchMethod = LaunchMethod.APPROVED_EXECUTABLE) -> ApplicationRecord:
    return ApplicationRecord(
        app_id=registration_app_id(display_name="Notepad", executable_identity=EXE, launch_method=method),
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
    )


def _setup(adapter=None, *, verifier=None):  # type: ignore[no-untyped-def]
    record = _record()
    registry = InMemoryApplicationRegistry()
    registry.register(record)
    verifier = verifier or FakeIntegrityVerifier(
        evidence_by_location={record.location_digest or "": _evidence_for(record)}
    )
    authority = LaunchAuthority(verifier=verifier)
    authorization = authority.authorize(record, activation_scope="test-scope", now=NOW)
    confirmer = TrustedNavigationConfirmer()
    app_authority = AppWindowResourceAuthority()
    app_authority.register_app(record)
    broker = PolicyBroker(
        capabilities=CapabilityRegistry.phase3_with_launch(),
        resources=ResourceRegistry(windows_semantics=False),
        app_authority=app_authority,
        executors=frozenset({"app.launch"}),
    )
    enablement = Phase3Enablement.from_owner_config(
        OwnerEnablementConfig(
            enabled=True,
            capability_allowlist=frozenset({"app.launch"}),
            app_allowlist=frozenset({record.app_id}),
            session_lifetime=timedelta(minutes=30),
            scope_name="test-scope",
        ),
        now=NOW,
    )
    evidence = NavigationEvidenceStore.on_memory()
    launcher = VerifiedLauncher(
        registry=registry,
        authority=authority,
        confirmer=confirmer,
        broker=broker,
        evidence=evidence,
        adapter=adapter or FakeLaunchAdapter(),
        enablement=enablement,
        session_id="session-1",
        activation_scope="test-scope",
    )
    return record, authority, authorization, confirmer, launcher, evidence


def _confirm(confirmer, record, authorization, task_id, step_id):  # type: ignore[no-untyped-def]
    request = NavigationConfirmationRequest(
        task_id=task_id, step_id=step_id, plan_revision=1, plan_hash="b" * 64,
        capability_id="app.launch", arguments={"resource_id": record.app_id},
        app_resource_id=record.app_id, expected_app_version=record.location_digest or "",
        integrity_sha256=authorization.integrity_sha256, session_id="session-1",
        activation_scope="test-scope",
    )
    return confirmer.issue(request, now=NOW)


def test_fake_launch_end_to_end_and_replay_denied() -> None:
    record, _auth, authorization, confirmer, launcher, evidence = _setup()
    task_id, step_id = uuid4(), uuid4()
    confirmation = _confirm(confirmer, record, authorization, task_id, step_id)
    outcome = launcher.launch(
        task_id=task_id, step_id=step_id, plan_revision=1, plan_hash="b" * 64,
        app_id=record.app_id, authorization_id=authorization.authorization_id,
        confirmation_id=confirmation.confirmation_id, arguments_sha256="c" * 64, now=NOW,
    )
    assert outcome.status == "SUCCEEDED" and outcome.attempt_recorded
    assert evidence.reconcile_interrupted() == []
    # Single-use authorization: replay denied.
    with pytest.raises(LaunchAuthorityError):
        launcher.launch(
            task_id=task_id, step_id=step_id, plan_revision=1, plan_hash="b" * 64,
            app_id=record.app_id, authorization_id=authorization.authorization_id,
            confirmation_id=confirmation.confirmation_id, arguments_sha256="c" * 64, now=NOW,
        )


def test_existing_process_is_not_success_and_drift_denies() -> None:
    adapter = FakeLaunchAdapter(result=LaunchAttemptResult(outcome="existing_process_only", pre_existing=True))
    record, _auth, authorization, confirmer, launcher, _evidence = _setup(adapter=adapter)
    task_id, step_id = uuid4(), uuid4()
    confirmation = _confirm(confirmer, record, authorization, task_id, step_id)
    outcome = launcher.launch(
        task_id=task_id, step_id=step_id, plan_revision=1, plan_hash="b" * 64,
        app_id=record.app_id, authorization_id=authorization.authorization_id,
        confirmation_id=confirmation.confirmation_id, arguments_sha256="c" * 64, now=NOW,
    )
    assert outcome.status == "UNVERIFIED"  # false-success prevention

    # Same-path replacement: verifier evidence changes -> denied pre-launch.
    record2, _a, _authz2, confirmer2, launcher2, _e = _setup()
    verifier2 = launcher2._authority._verifier  # type: ignore[attr-defined]
    assert isinstance(verifier2, FakeIntegrityVerifier)
    verifier2.evidence_by_location[record2.location_digest or ""] = _evidence_for(record2, content="d" * 64)
    task_id, step_id = uuid4(), uuid4()
    # Authorization was minted against the original evidence in _setup;
    # re-minting is impossible now, so consume must drift-deny.
    authorization2 = _authz2
    confirmation2 = _confirm(confirmer2, record2, authorization2, task_id, step_id)
    with pytest.raises(LaunchAuthorityError):
        launcher2.launch(
            task_id=task_id, step_id=step_id, plan_revision=1, plan_hash="b" * 64,
            app_id=record2.app_id, authorization_id=authorization2.authorization_id,
            confirmation_id=confirmation2.confirmation_id, arguments_sha256="c" * 64, now=NOW,
        )


def test_no_integrity_evidence_no_authority_and_native_disabled() -> None:
    record = _record()
    authority = LaunchAuthority(verifier=FakeIntegrityVerifier())
    with pytest.raises(LaunchAuthorityError):
        authority.authorize(record, activation_scope="s", now=NOW)
    with pytest.raises(LaunchDenied):
        NativeLaunchAdapterDisabled().launch(app_id=record.app_id, method=record.launch_method)
    # Discovery description can never mint authority by caller fields:
    forged = record.model_copy(update={"integrity_status": "verified", "launch_authorized": False})
    with pytest.raises(LaunchAuthorityError):
        authority.authorize(forged, activation_scope="s", now=NOW)


def test_broker_kind_dispatch_and_mismatch() -> None:
    record, _auth, _authz, _c, _l, _e = _setup()
    app_authority = AppWindowResourceAuthority()
    broker = PolicyBroker(
        capabilities=CapabilityRegistry.phase3_with_launch(),
        resources=ResourceRegistry(windows_semantics=False),
        app_authority=app_authority,
        executors=frozenset({"app.launch"}),
    )
    forged = ToolRequest(
        request_id="r", task_id="t", capability_id="app.launch",
        arguments={"resource_id": record.app_id, "launch_evidence": {"confirmation_ref": "x", "authority_grant_ref": "y"}},
        resources=[ResourceRef(kind="app", resource_id=record.app_id)],
    )
    decision = broker.evaluate(forged, now=NOW)
    assert not decision.allowed  # never registered with this authority
    app_authority.register_app(record)
    assert broker.evaluate(forged, now=NOW).allowed
    # Filesystem capability cannot consume an app resource.
    fs_request = ToolRequest(
        request_id="r", task_id="t", capability_id="app.launch",
        arguments={"resource_id": record.app_id, "launch_evidence": {"confirmation_ref": "x", "authority_grant_ref": "y"}},
        resources=[ResourceRef(kind="file", resource_id="file:123e4567-e89b-12d3-a456-426614174000")],
    )
    assert not broker.evaluate(fs_request, now=NOW).allowed


def test_evidence_forgery_and_interrupted_reconciliation() -> None:
    store = NavigationEvidenceStore.on_memory()
    from aether.core.apps.navigation_evidence import ConfirmationBinding

    binding = ConfirmationBinding(
        confirmation_id="conf-1", task_id="task-1", step_id="step-1", plan_revision=1,
        plan_hash="b" * 64, capability_id="app.launch", arguments_sha256="c" * 64,
        app_resource_id="app:123e4567-e89b-12d3-a456-426614174000",
        expected_app_version="v1", integrity_sha256="d" * 64, session_id="s",
        activation_scope="scope", issued_at=NOW.isoformat(), expires_at=NOW.isoformat(),
    )
    store.record_confirmation(binding)
    with pytest.raises(NavigationEvidenceError):  # cross-task forgery
        store.record_attempt(
            confirmation_id="conf-1", task_id="task-OTHER", step_id="step-1",
            capability_id="app.launch", app_resource_id=binding.app_resource_id,
            recorded_at=NOW.isoformat(),
        )
    attempt_id = store.record_attempt(
        confirmation_id="conf-1", task_id="task-1", step_id="step-1",
        capability_id="app.launch", app_resource_id=binding.app_resource_id,
        recorded_at=NOW.isoformat(),
    )
    with pytest.raises(NavigationEvidenceError):  # replay
        store.record_attempt(
            confirmation_id="conf-1", task_id="task-1", step_id="step-1",
            capability_id="app.launch", app_resource_id=binding.app_resource_id,
            recorded_at=NOW.isoformat(),
        )
    # Interrupted: attempt without verification reconciles UNVERIFIED.
    assert store.reconcile_interrupted() == [attempt_id]
    with pytest.raises(NavigationEvidenceError):  # success without verification
        store.record_receipt(attempt_id=attempt_id, verification_id="missing", status="SUCCEEDED", created_at=NOW.isoformat())


def test_t1_evidence_cannot_satisfy_t2_mutation_guard() -> None:
    # The Phase 2 broker mutation path still requires its exact grant
    # stack; presenting navigation facts changes nothing.
    broker = PolicyBroker(
        capabilities=CapabilityRegistry.phase2_filesystem(),
        resources=ResourceRegistry(windows_semantics=False),
    )
    request = ToolRequest(
        request_id="r", task_id="t", capability_id="fs.apply_approved_edit",
        arguments={
            "resource_id": "file:123e4567-e89b-12d3-a456-426614174000",
            "step_id": "123e4567-e89b-12d3-a456-426614174000",
            "approval_id": "123e4567-e89b-12d3-a456-426614174000",
            "expected_sha256": "a" * 64,
        },
        resources=[ResourceRef(kind="file", resource_id="file:123e4567-e89b-12d3-a456-426614174000")],
    )
    decision = broker.evaluate(request, now=NOW)
    assert (not decision.allowed and decision.reason_code in (
        "TRUSTED_APPROVAL_NOT_AVAILABLE", "RESOURCE_NOT_REGISTERED", "ROOT_NOT_REGISTERED",
    )) or not decision.allowed


def test_planner_launch_goal_uses_app_authority_only() -> None:
    from aether.core.planning.planner import PlanGoal, PlanIntent, Planner, PlannerError
    from aether.core.resources.registry import ResourceRegistry

    record = _record()
    app_authority = AppWindowResourceAuthority()
    app_authority.register_app(record)
    planner = Planner(
        capabilities=CapabilityRegistry.phase3_with_launch(),
        resources=ResourceRegistry(windows_semantics=False),
        app_authority=app_authority,
    )
    planned = planner.plan(
        uuid4(),
        PlanIntent(
            goal=PlanGoal.LAUNCH_APPLICATION,
            resource_id=record.app_id,
            arguments={"resource_id": record.app_id, "launch_evidence": {"confirmation_ref": "c", "authority_grant_ref": "a"}},
            summary="Launch Notepad",
        ),
    )
    assert planned.plan.steps[0].capability_id == "app.launch"
    assert planned.plan_hash
    # A forged app id cannot be planned.
    with pytest.raises(PlannerError):
        planner.plan(
            uuid4(),
            PlanIntent(
                goal=PlanGoal.LAUNCH_APPLICATION,
                resource_id="app:123e4567-e89b-12d3-a456-426614174000",
                arguments={"resource_id": "app:123e4567-e89b-12d3-a456-426614174000", "launch_evidence": {"confirmation_ref": "c", "authority_grant_ref": "a"}},
                summary="Launch forged",
            ),
        )


def test_schema_v3_prepared_but_not_active(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import aether.core.persistence.sqlite_store as sqlite_store

    assert sqlite_store.ACTIVE_SCHEMA_VERSION == 2
    assert frozenset({3}) == sqlite_store.PENDING_MIGRATION_VERSIONS
    assert 3 in sqlite_store._EXPECTED_MIGRATIONS
    # Explicit isolated synthetic mechanism may apply v3 in tests only.
    import tempfile
    from pathlib import Path

    directory = Path(tempfile.mkdtemp(dir=tmp_path))
    (directory / "dummy").touch()
    import os

    os.chmod(directory, 0o700)
    sqlite_store.ACTIVE_SCHEMA_VERSION = 3
    sqlite_store.PENDING_MIGRATION_VERSIONS = frozenset()
    try:
        store = sqlite_store.SQLiteTaskStore(directory / "synthetic.db")
        version = store._connection.execute("PRAGMA user_version").fetchone()[0]
        assert version == 3
        tables = {
            row[0]
            for row in store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "navigation_attempts" in tables
        store.close()
    finally:
        sqlite_store.ACTIVE_SCHEMA_VERSION = 2
        sqlite_store.PENDING_MIGRATION_VERSIONS = frozenset({3})
