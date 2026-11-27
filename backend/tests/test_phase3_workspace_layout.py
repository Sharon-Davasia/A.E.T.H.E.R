"""R2/R3 residuals: separate synthetic workspace from database storage,
and deterministic (clock-based) privacy/lifecycle enforcement.

Lifecycle covered here: authorization creation -> storage
initialization -> synthetic project creation -> controlled startup ->
trusted registration -> reference detection -> shutdown -> storage
reopen/restart reconciliation, with project evidence never inside
the schema-v3 database directory.

Fake platform seams only; nothing here is native Windows evidence.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_phase3_controlled_native import COMMIT, GESTURE_KEY

from aether.adapters.windows.fake_windows import build_fake_seams, fixture_executable
from aether.core.apps.acceptance_startup import (
    ControlledAcceptanceAuthorization,
    StartupDenied,
    campaign_layout_error,
)
from aether.core.apps.composition import Phase3Composition, build_native_platform
from aether.core.apps.launch_authority import app_version_token
from aether.core.contracts.app_window import (
    LaunchMethod,
    location_identity_digest,
    registration_app_id,
)
from aether.core.persistence.acceptance_storage import (
    _ALLOWED_NAMES,
    AcceptanceStorageError,
    OwnerAcceptanceAuthorization,
    open_acceptance_store,
)


class _CountingExplorer:
    def __init__(self, value: object) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        return self.value


def _authz(
    tmp_path: Path, *, expires_at: datetime, create_workspace: bool = True
) -> ControlledAcceptanceAuthorization:
    seams_token_holder = build_fake_seams()
    fixture_id = registration_app_id(
        display_name="AETHER Fixture",
        executable_identity=fixture_executable(),
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    token = app_version_token(
        seams_token_holder.integrity_verifier.verify(  # type: ignore[attr-defined]
            SimpleNamespace(location_digest=location_identity_digest(fixture_executable()))
        )
    )
    workspace = tmp_path / "aether-phase3-workspace-layout"
    identity: tuple[int, int] | None = None
    if create_workspace:
        workspace.mkdir(parents=True, exist_ok=True)
        ws_stat = workspace.stat()
        identity = (ws_stat.st_dev, ws_stat.st_ino)
    return ControlledAcceptanceAuthorization(
        approved_commit=COMMIT,
        decision_reference="owner-decision-layout",
        campaign_id="campaign-layout",
        storage_id="77777777-7777-4777-8777-777777777777",
        storage_path=str(tmp_path / "aether-phase3-acceptance-layout"),
        workspace_path=str(tmp_path / "aether-phase3-workspace-layout"),
        workspace_identity=identity,
        authorized_app_ids=frozenset({fixture_id}),
        capability_allowlist=frozenset({"app.launch", "uia.invoke_fixture"}),
        session_id="session-layout",
        activation_epoch="epoch-layout",
        expires_at=expires_at,
        privacy_mode="metadata_only",
        fixture_app_id=fixture_id,
        fixture_identity_token=token,
    )


def _open_store(authz: ControlledAcceptanceAuthorization, *, now: datetime):  # type: ignore[no-untyped-def]
    return open_acceptance_store(
        Path(authz.storage_path),
        authorization=OwnerAcceptanceAuthorization(
            decision_reference=authz.decision_reference,
            storage_id=authz.storage_id,
            expires_at=authz.expires_at,
            campaign_id=authz.campaign_id,
        ),
        now=now,
    )


def test_campaign_layout_validation(tmp_path: Path) -> None:
    # Platform-native absolute paths only (F1): constructed from
    # pytest's tmp_path so the cases hold under Windows semantics.
    storage = str(tmp_path / "aether-phase3-acceptance-c1")
    workspace = str(tmp_path / "aether-phase3-workspace-c1")
    assert campaign_layout_error(storage, workspace) is None
    assert campaign_layout_error(storage, "") == "synthetic_workspace_missing"
    assert campaign_layout_error(storage, storage) == "campaign_layout_paths_identical"
    # Workspace inside database storage (the old documented layout).
    assert (
        campaign_layout_error(storage, str(Path(storage) / "aether-phase3-workspace-c1"))
        == "campaign_layout_not_sibling"
    )
    assert campaign_layout_error(
        storage, str(tmp_path / "other" / "aether-phase3-workspace-c1")
    ) == ("campaign_layout_not_sibling")


def test_authorization_without_workspace_is_denied(tmp_path: Path) -> None:
    authz = _authz(tmp_path, expires_at=datetime.now(UTC) + timedelta(hours=2))
    import dataclasses

    bare = dataclasses.replace(authz, workspace_path="")
    with pytest.raises(StartupDenied, match="synthetic_workspace_missing"):
        bare.validate(
            current_commit=COMMIT,
            now=datetime.now(UTC),
            storage_marker=None,
        )


def test_workspace_lifecycle_and_storage_reopen(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    authz = _authz(tmp_path, expires_at=now + timedelta(hours=2))
    storage = Path(authz.storage_path)
    workspace = Path(authz.workspace_path)

    # 1-2. Storage initialization (database directory only).
    store = _open_store(authz, now=now)
    store.close()
    assert workspace not in storage.parents and storage not in workspace.parents

    # 3. Synthetic project creation inside the workspace sibling.
    project = workspace / "synthetic-project"
    project.mkdir(parents=True)
    marker = project / "pyproject.toml"
    marker.write_text('[project]\nname = "synthetic"\n', encoding="utf-8")

    # 4-6. Controlled startup, trusted registration, detection.
    seams = build_fake_seams()
    explorer = _CountingExplorer(str(project))
    seams.explorer_folder = explorer  # type: ignore[attr-defined]
    providers = build_native_platform(authz, seams=seams)
    comp = Phase3Composition.native(
        authorization=authz,
        current_commit=COMMIT,
        storage_dir=storage,
        gesture_key=GESTURE_KEY,
        platform=providers,
    )
    try:
        bridge = comp.bridge
        assert (
            bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})[
                "status"
            ]
            == "ready"
        )
        # Registration binds to the workspace, never the database dir.
        inside_db = bridge.register_project({"alias": "db", "path": str(storage)})
        assert inside_db["status"] == "unavailable"
        assert inside_db["reason"] == "root_outside_activation_boundary"
        registered = bridge.register_project({"alias": "project", "path": str(project)})
        assert registered["status"] == "ready", registered

        # Generic refresh: registered root only, no Explorer use.
        state = bridge.get_state({})
        assert explorer.calls == 0
        assert [c["evidenceSource"] for c in state["projects"]] == ["registered_project"]
        # Explicit check: Explorer consulted once, scope-validated.
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(4242)  # verified foreground event
        check = bridge.check_project_context({})
        assert explorer.calls == 1
        candidates = check["projects"]
        assert len(candidates) == 1
        assert candidates[0]["evidenceSource"] == "explorer_registered"
        assert candidates[0]["available"] is True
        assert comp.detector is not None
        resolution = comp.detector.resolve_reference("this project")
        assert resolution.candidate is not None and not resolution.clarification_required
    finally:
        # 7. Shutdown.
        assert comp.shutdown() is True

    # The database directory holds only acceptance-storage content;
    # project evidence was never written into it.
    assert {p.name for p in storage.iterdir()} <= set(_ALLOWED_NAMES)
    assert not (storage / "synthetic-project").exists()
    assert marker.read_text(encoding="utf-8") == '[project]\nname = "synthetic"\n'

    # 8. Storage reopen / restart reconciliation: succeeds without
    # deleting or relocating project evidence.
    reopened = _open_store(authz, now=datetime.now(UTC))
    reopened.close()
    assert marker.exists()

    # The content allowlist is NOT relaxed: unrelated content in the
    # database directory still prevents reopening.
    (storage / "intruder.txt").write_text("x", encoding="utf-8")
    with pytest.raises(AcceptanceStorageError, match="unrelated"):
        _open_store(authz, now=datetime.now(UTC))
    (storage / "intruder.txt").unlink()
    reopened = _open_store(authz, now=datetime.now(UTC))
    reopened.close()


def test_artifact_layout_uses_sibling_workspace(tmp_path: Path) -> None:
    from aether.core.apps.authorization_artifact import build_authorization
    from aether.core.apps.launch_authority import IntegrityEvidence

    now = datetime.now(UTC)

    class _Verifier:
        def verify(self, record):  # type: ignore[no-untyped-def]
            return IntegrityEvidence(
                location_digest=record.location_digest or "",
                content_sha256="c" * 64,
                signer_identity=None,
                package_identity=None,
                verified_at=now,
                file_identity="1:2:3:4",
            )

    artifact, storage_path = build_authorization(
        decision_reference="d",
        campaign_id="c9",
        app_display_names=[],
        acceptance_root=tmp_path,
        now=now,
        discovered_records=[],
        fixture_executable="C:\\Fixture\\AETHERFixture.exe",
        integrity_verifier=_Verifier(),
        commit="a" * 40,
    )
    workspace = Path(str(artifact["workspace_path"]))
    assert workspace.parent == storage_path.parent
    assert workspace != storage_path
    assert workspace.name == "aether-phase3-workspace-c9"
    assert campaign_layout_error(str(storage_path), str(workspace)) is None


def test_expiry_enforced_synchronously_with_deterministic_clock(tmp_path: Path) -> None:
    """No timer is involved: a controllable clock crosses expiry and
    every boundary (collection, capability presentation, observation
    resumption) must deny synchronously."""
    start = datetime.now(UTC)
    now_holder = [start]
    clock = lambda: now_holder[0]  # noqa: E731
    authz = _authz(tmp_path, expires_at=start + timedelta(hours=2))
    storage = Path(authz.storage_path)
    store = _open_store(authz, now=start)
    store.close()

    workspace = Path(authz.workspace_path)
    project = workspace / "synthetic-project"
    project.mkdir(parents=True)
    (project / "pyproject.toml").write_text('[project]\nname = "synthetic"\n', encoding="utf-8")

    seams = build_fake_seams()
    explorer = _CountingExplorer(str(project))
    seams.explorer_folder = explorer  # type: ignore[attr-defined]
    providers = build_native_platform(authz, seams=seams)
    comp = Phase3Composition.native(
        authorization=authz,
        current_commit=COMMIT,
        storage_dir=storage,
        gesture_key=GESTURE_KEY,
        platform=providers,
        clock=clock,
    )
    try:
        bridge = comp.bridge
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
        state = bridge.get_state({})
        assert explorer.calls == 0  # refresh alone never collects (F3)
        assert state["capabilities"]["app.launch"] is True
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(4242)
        check = bridge.check_project_context({})
        assert check["projects"] != []
        assert explorer.calls == 1
        assert state["nativeAvailable"] is True
        calls = explorer.calls

        # Cross expiry on the deterministic clock only (the real
        # background timer is hours away and never fires here).
        now_holder[0] = start + timedelta(hours=3)

        # A post-expiry privacy update must not restart observation
        # or present expired capabilities as available.
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
        assert bridge.check_project_context({})["status"] == "unavailable"
        state = bridge.get_state({})
        assert state["projects"] == []
        assert explorer.calls == calls
        assert all(value is False for value in state["capabilities"].values())
        # Expired compositions never present native execution as
        # available (F4), regardless of privacy presentation.
        assert state["nativeAvailable"] is False
        observer = comp.observer_service
        assert observer is None or getattr(observer, "running", False) is False
        comp.begin_observation()  # direct resumption attempt also denied
        assert observer is None or getattr(observer, "running", False) is False
        assert explorer.calls == calls
    finally:
        assert comp.shutdown() is True


def test_direct_reference_resolution_generation_change(tmp_path: Path) -> None:
    """Direct ProjectDetector use inherits generation protection: a
    privacy-generation change during collection invalidates the
    evidence for both detect() and resolve_reference()."""
    from aether.core.context.project_detection import ProjectDetector
    from aether.core.resources.registry import ResourceRegistry

    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "s"\n', encoding="utf-8")
    registry = ResourceRegistry()
    registry.register_root("project", project, allowed_capabilities=frozenset({"fs.inspect_file"}))

    generation = [0]

    def explorer() -> Path:
        generation[0] += 1  # privacy update lands mid-collection
        return project

    detector = ProjectDetector(
        registry=registry,
        explorer_folder=explorer,
        collection_permitted=lambda: True,
        collection_generation=lambda: generation[0],
    )
    assert detector.detect() == ()
    resolution = detector.resolve_reference("this project")
    assert resolution.candidate is None
    assert resolution.clarification_required
    assert resolution.reason == "project_evidence_invalidated"


def test_workspace_directory_validation_failures(tmp_path: Path) -> None:
    """Substituted link, missing dir, identity drift and wrong
    campaign identity all refuse controlled validation (F2)."""
    import shutil

    from aether.core.apps.acceptance_startup import workspace_directory_error

    now = datetime.now(UTC)
    authz = _authz(tmp_path, expires_at=now + timedelta(hours=2))
    storage = Path(authz.storage_path)
    workspace = Path(authz.workspace_path)
    assert workspace_directory_error(str(storage), str(workspace), authz.workspace_identity) is None

    def _validate(a):  # type: ignore[no-untyped-def]
        a.validate(current_commit=COMMIT, now=now, storage_marker=None)

    # Missing workspace directory.
    (tmp_path / "case-missing").mkdir(exist_ok=True)
    missing = _authz(
        tmp_path / "case-missing",
        expires_at=now + timedelta(hours=2),
        create_workspace=False,
    )
    assert (
        workspace_directory_error(missing.storage_path, missing.workspace_path, (1, 2))
        == "synthetic_workspace_missing"
    )

    # Wrong campaign identity (identity bound to another directory).
    other = tmp_path / "other-dir"
    other.mkdir()
    other_stat = other.stat()
    assert (
        workspace_directory_error(
            str(storage), str(workspace), (other_stat.st_dev, other_stat.st_ino)
        )
        == "synthetic_workspace_identity_mismatch"
    )
    with pytest.raises(StartupDenied, match="synthetic_workspace_identity_mismatch"):
        import dataclasses

        _validate(
            dataclasses.replace(authz, workspace_identity=(other_stat.st_dev, other_stat.st_ino))
        )

    # Substituted workspace symlink (no privilege needed on POSIX;
    # skipped where symlink creation is not permitted).
    moved = tmp_path / "workspace-real"
    shutil.copytree(workspace, moved)
    shutil.rmtree(workspace)
    try:
        workspace.symlink_to(moved, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert (
        workspace_directory_error(str(storage), str(workspace), authz.workspace_identity)
        == "synthetic_workspace_reparse"
    )
    with pytest.raises(StartupDenied, match="synthetic_workspace_reparse"):
        _validate(authz)


def test_registry_boundary_drift_refuses_registration(tmp_path: Path) -> None:
    """Registration revalidates the boundary directory (F2): identity
    drift and boundary substitution refuse, and roots outside the
    ORIGINAL workspace never register."""
    import shutil

    from aether.core.resources.registry import ResourceRegistry, ResourceRegistryError

    workspace = tmp_path / "aether-phase3-workspace-drift"
    project = workspace / "synthetic-project"
    project.mkdir(parents=True)
    ws_stat = workspace.stat()
    registry = ResourceRegistry(
        registration_boundary=workspace,
        registration_boundary_identity=(ws_stat.st_dev, ws_stat.st_ino),
    )
    root = registry.register_root(
        "project", project, allowed_capabilities=frozenset({"fs.inspect_file"})
    )
    assert root.canonical_root == project.resolve()

    # Identity drift: same path, different directory inode. The
    # original directory is kept alive under another name so its
    # inode cannot be recycled by the replacement.
    workspace.rename(tmp_path / "workspace-original")
    workspace.mkdir()
    project.mkdir()
    with pytest.raises(ResourceRegistryError, match="registration_boundary_identity_mismatch"):
        registry.register_root(
            "again", project, allowed_capabilities=frozenset({"fs.inspect_file"})
        )

    # Missing boundary.
    shutil.rmtree(workspace)
    with pytest.raises(ResourceRegistryError, match="registration_boundary_invalid"):
        registry.register_root("gone", project, allowed_capabilities=frozenset({"fs.inspect_file"}))


def test_workspace_junction_substitution_refused(tmp_path: Path) -> None:
    """C1 (Windows, no elevation): substituting the authorized
    synthetic workspace with a directory junction refuses startup
    validation; the junction destination can never be adopted as
    the registration boundary; and no registration outside the
    original workspace succeeds. Uses the established
    ``fs_support.make_junction`` helper (mklink /J). Missing-workspace
    and identity-drift coverage lives in the tests above and stays
    independently executable."""
    from fs_support import make_junction

    from aether.core.apps.acceptance_startup import workspace_directory_error
    from aether.core.resources.registry import ResourceRegistry, ResourceRegistryError

    now = datetime.now(UTC)
    authz = _authz(tmp_path, expires_at=now + timedelta(hours=2))
    storage = Path(authz.storage_path)
    workspace = Path(authz.workspace_path)
    assert workspace_directory_error(str(storage), str(workspace), authz.workspace_identity) is None

    project = workspace / "synthetic-project"
    project.mkdir()
    registry = ResourceRegistry(
        registration_boundary=workspace,
        registration_boundary_identity=authz.workspace_identity,
    )
    registry.register_root("project", project, allowed_capabilities=frozenset({"fs.inspect_file"}))

    # Substitute the workspace path with a junction to a destination
    # holding a lookalike project. The original directory survives
    # under another name (identity preserved for comparison).
    destination = tmp_path / "junction-destination"
    (destination / "synthetic-project").mkdir(parents=True)
    workspace.rename(tmp_path / "workspace-original")
    make_junction(workspace, destination)
    try:
        # Startup validation refuses the substituted workspace.
        assert (
            workspace_directory_error(str(storage), str(workspace), authz.workspace_identity)
            == "synthetic_workspace_reparse"
        )
        with pytest.raises(StartupDenied, match="synthetic_workspace_reparse"):
            authz.validate(current_commit=COMMIT, now=now, storage_marker=None)

        # The junction cannot be adopted as a registration boundary.
        with pytest.raises(ResourceRegistryError, match="registration_boundary_invalid"):
            ResourceRegistry(registration_boundary=workspace)

        # The previously valid registry refuses registration into
        # the junction destination (outside the original workspace):
        # its boundary revalidation fails closed.
        with pytest.raises(ResourceRegistryError, match="registration_boundary_invalid"):
            registry.register_root(
                "outside",
                destination / "synthetic-project",
                allowed_capabilities=frozenset({"fs.inspect_file"}),
            )
    finally:
        # Remove the junction itself; never delete through it.
        with contextlib.suppress(OSError):
            workspace.rmdir()
