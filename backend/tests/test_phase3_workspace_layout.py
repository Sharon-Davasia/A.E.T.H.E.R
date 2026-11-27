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


def _authz(tmp_path: Path, *, expires_at: datetime) -> ControlledAcceptanceAuthorization:
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
    return ControlledAcceptanceAuthorization(
        approved_commit=COMMIT,
        decision_reference="owner-decision-layout",
        campaign_id="campaign-layout",
        storage_id="77777777-7777-4777-8777-777777777777",
        storage_path=str(tmp_path / "aether-phase3-acceptance-layout"),
        workspace_path=str(tmp_path / "aether-phase3-workspace-layout"),
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


def test_campaign_layout_validation() -> None:
    storage = "/owner/aether-phase3-acceptance-c1"
    workspace = "/owner/aether-phase3-workspace-c1"
    assert campaign_layout_error(storage, workspace) is None
    assert campaign_layout_error(storage, "") == "synthetic_workspace_missing"
    assert campaign_layout_error(storage, storage) == "campaign_layout_paths_identical"
    # Workspace inside database storage (the old documented layout).
    assert (
        campaign_layout_error(storage, f"{storage}/aether-phase3-workspace-c1")
        == "campaign_layout_not_sibling"
    )
    assert campaign_layout_error(storage, "/other/aether-phase3-workspace-c1") == (
        "campaign_layout_not_sibling"
    )


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

        state = bridge.get_state({})
        candidates = state["projects"]
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


def test_artifact_layout_uses_sibling_workspace() -> None:
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
        acceptance_root=Path("/owner-root"),
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
        assert explorer.calls >= 1
        assert state["projects"] != []
        assert state["capabilities"]["app.launch"] is True
        calls = explorer.calls

        # Cross expiry on the deterministic clock only (the real
        # background timer is hours away and never fires here).
        now_holder[0] = start + timedelta(hours=3)

        # A post-expiry privacy update must not restart observation
        # or present expired capabilities as available.
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
        state = bridge.get_state({})
        assert state["projects"] == []
        assert explorer.calls == calls
        assert all(value is False for value in state["capabilities"].values())
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
