"""A/D corrections: authoritative collection gates for Explorer/project
detection (privacy + authorization lifetime + composition lifecycle,
synchronously, with provider-call-count evidence) and the trusted
controlled project-registration path (composition-owned registry,
campaign-storage boundary, native Explorer typing).

Fake platform seams only; nothing here is native Windows evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from test_phase3_controlled_native import COMMIT, GESTURE_KEY

from aether.adapters.windows.fake_windows import build_fake_seams, fixture_executable
from aether.core.apps.acceptance_startup import ControlledAcceptanceAuthorization
from aether.core.apps.composition import Phase3Composition, build_native_platform
from aether.core.apps.launch_authority import app_version_token
from aether.core.contracts.app_window import (
    LaunchMethod,
    location_identity_digest,
    registration_app_id,
)
from aether.core.persistence.acceptance_storage import (
    OwnerAcceptanceAuthorization,
    open_acceptance_store,
)


class _CountingExplorer:
    """Explorer provider fake: counts every collection."""

    def __init__(self, value: object) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        return self.value


def _start(tmp_path: Path, explorer: object) -> Phase3Composition:
    seams = build_fake_seams()
    fixture_id = registration_app_id(
        display_name="AETHER Fixture",
        executable_identity=fixture_executable(),
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    token = app_version_token(
        seams.integrity_verifier.verify(  # type: ignore[attr-defined]
            SimpleNamespace(location_digest=location_identity_digest(fixture_executable()))
        )
    )
    storage = tmp_path / "aether-phase3-acceptance-gates"
    authz = ControlledAcceptanceAuthorization(
        approved_commit=COMMIT,
        decision_reference="owner-decision-gates",
        campaign_id="campaign-gates",
        storage_id="44444444-4444-4444-8444-444444444444",
        storage_path=str(storage),
        authorized_app_ids=frozenset({fixture_id}),
        capability_allowlist=frozenset({"app.launch", "uia.invoke_fixture"}),
        session_id="session-gates",
        activation_epoch="epoch-gates",
        expires_at=datetime.now(UTC) + timedelta(hours=2),
        privacy_mode="metadata_only",
        fixture_app_id=fixture_id,
        fixture_identity_token=token,
    )
    store = open_acceptance_store(
        storage,
        authorization=OwnerAcceptanceAuthorization(
            decision_reference=authz.decision_reference,
            storage_id=authz.storage_id,
            expires_at=authz.expires_at,
            campaign_id=authz.campaign_id,
        ),
        now=datetime.now(UTC),
    )
    store.close()
    seams.explorer_folder = explorer  # type: ignore[attr-defined]
    providers = build_native_platform(authz, seams=seams)
    return Phase3Composition.native(
        authorization=authz,
        current_commit=COMMIT,
        storage_dir=storage,
        gesture_key=GESTURE_KEY,
        platform=providers,
    )


def _opt_in(comp: Phase3Composition) -> None:
    out = comp.bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
    assert out["status"] == "ready", out


def test_explorer_collection_requires_opt_in_and_stops_on_pause_optout_revoke(
    tmp_path: Path,
) -> None:
    explorer = _CountingExplorer(tmp_path / "somewhere-else")
    comp = _start(tmp_path, explorer)
    try:
        # Before opt-in: no collection at all (provider never called).
        state = comp.bridge.get_state({})
        assert state["projects"] == []
        assert explorer.calls == 0

        _opt_in(comp)
        state = comp.bridge.get_state({})
        assert explorer.calls >= 1
        assert [p["evidenceSource"] for p in state["projects"]] == ["explorer_discovered"]

        # Pause: collection stops synchronously.
        calls_after_opt_in = explorer.calls
        comp.bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": True})
        assert comp.bridge.get_state({})["projects"] == []
        assert explorer.calls == calls_after_opt_in

        # Opt-out: collection stops.
        comp.bridge.set_privacy({"optedIn": False, "mode": "off", "paused": False})
        assert comp.bridge.get_state({})["projects"] == []
        assert explorer.calls == calls_after_opt_in

        # Revocation: a later privacy update cannot reactivate
        # collection in a revoked composition.
        comp.revoke("test_revocation")
        _opt_in(comp)
        assert comp.bridge.get_state({})["projects"] == []
        assert explorer.calls == calls_after_opt_in
    finally:
        assert comp.shutdown() is True
    # After shutdown the provider is likewise never consulted again.
    assert comp.bridge.get_state({})["projects"] == []
    assert explorer.calls == calls_after_opt_in


def test_detector_gate_covers_reference_resolution() -> None:
    from aether.core.context.project_detection import ProjectDetector
    from aether.core.resources.registry import ResourceRegistry

    explorer = _CountingExplorer(Path("/definitely/not/registered"))
    detector = ProjectDetector(
        registry=ResourceRegistry(),
        explorer_folder=explorer,  # type: ignore[arg-type]
        collection_permitted=lambda: False,
    )
    assert detector.detect() == ()
    resolution = detector.resolve_reference("this project")
    assert resolution.candidate is None and resolution.reason == "no_fresh_project_evidence"
    assert explorer.calls == 0


def test_registration_detection_and_explorer_string_normalization(tmp_path: Path) -> None:
    storage = tmp_path / "aether-phase3-acceptance-gates"
    project = storage / "synthetic-project"
    # The native Explorer provider returns a *string*; composition
    # must normalize it to Path before the detector compares roots.
    explorer = _CountingExplorer(str(project))
    comp = _start(tmp_path, explorer)
    try:
        project.mkdir(parents=True)
        (project / "pyproject.toml").write_text('[project]\nname = "synthetic"\n')

        # Registration is an owner act (not collection): permitted
        # before opt-in, through the canonical registry checks.
        registered = comp.bridge.register_project({"alias": "project", "path": str(project)})
        assert registered["status"] == "ready", registered
        root_id = registered["rootId"]

        # Detection is still collection: nothing before opt-in.
        assert comp.bridge.get_state({})["projects"] == []
        assert explorer.calls == 0

        _opt_in(comp)
        state = comp.bridge.get_state({})
        assert explorer.calls >= 1
        candidates = state["projects"]
        assert len(candidates) == 1
        assert candidates[0]["evidenceSource"] == "explorer_registered"
        assert candidates[0]["available"] is True

        # Registry-issued identity + Windows path identity.
        detector = comp.detector
        assert detector is not None
        detected = detector.detect()
        assert detected[0].resource_id is not None
        assert detected[0].root_alias == "project"
        registry = comp.surface.project_registry
        assert registry is not None and registry._windows_semantics is True  # type: ignore[attr-defined]
        assert str(detector.registry.known_roots()[0].root_id) == root_id  # type: ignore[attr-defined]

        # Fresh reference resolution resolves deterministically.
        resolution = detector.resolve_reference("this project")
        assert resolution.candidate is not None and not resolution.clarification_required
    finally:
        assert comp.shutdown() is True


def test_registration_boundary_and_unregistered_explorer(tmp_path: Path) -> None:
    outside = tmp_path / "outside-project"
    explorer = _CountingExplorer(outside)
    comp = _start(tmp_path, explorer)
    try:
        outside.mkdir()
        # Outside the campaign storage boundary: refused, and no
        # authorized identity is issued for it.
        refused = comp.bridge.register_project({"alias": "outside", "path": str(outside)})
        assert refused["status"] == "unavailable"
        assert refused["reason"] == "root_outside_activation_boundary"

        _opt_in(comp)
        state = comp.bridge.get_state({})
        assert len(state["projects"]) == 1
        candidate = state["projects"][0]
        assert candidate["evidenceSource"] == "explorer_discovered"
        assert candidate["available"] is False  # unregistered: no resource identity
        assert "registration_required_before_use" in candidate["limitations"]

        # Ordinary (disabled) surfaces have no registration path.
        from aether.channel.phase3_bridge import Phase3Bridge, Phase3Surface

        disabled = Phase3Bridge(Phase3Surface.disabled())
        assert (
            disabled.register_project({"alias": "x", "path": str(outside)})["status"]
            == "unavailable"
        )
    finally:
        assert comp.shutdown() is True


def test_ambiguous_project_evidence_requires_clarification(tmp_path: Path) -> None:
    storage = tmp_path / "aether-phase3-acceptance-gates"
    first = storage / "synthetic-project"
    second = storage / "synthetic-project-b"
    explorer = _CountingExplorer(first)
    comp = _start(tmp_path, explorer)
    try:
        for root in (first, second):
            root.mkdir(parents=True)
            (root / "pyproject.toml").write_text('[project]\nname = "synthetic"\n')
        assert comp.bridge.register_project({"alias": "one", "path": str(first)})["status"] == (
            "ready"
        )
        assert comp.bridge.register_project({"alias": "two", "path": str(second)})["status"] == (
            "ready"
        )
        _opt_in(comp)
        detector = comp.detector
        assert detector is not None
        # registered (0.9) vs explorer-registered (0.8): the margin is
        # below the ambiguity threshold, so no silent choice is made.
        resolution = detector.resolve_reference("this project")
        assert resolution.candidate is None and resolution.clarification_required
        assert resolution.reason == "ambiguous_project_evidence"
    finally:
        assert comp.shutdown() is True


def test_collection_denied_after_authorization_expiry(tmp_path: Path) -> None:
    import time as _time

    seams = build_fake_seams()
    fixture_id = registration_app_id(
        display_name="AETHER Fixture",
        executable_identity=fixture_executable(),
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    token = app_version_token(
        seams.integrity_verifier.verify(  # type: ignore[attr-defined]
            SimpleNamespace(location_digest=location_identity_digest(fixture_executable()))
        )
    )
    storage = tmp_path / "aether-phase3-acceptance-gates"
    authz = ControlledAcceptanceAuthorization(
        approved_commit=COMMIT,
        decision_reference="owner-decision-gates",
        campaign_id="campaign-gates",
        storage_id="55555555-5555-4555-8555-555555555555",
        storage_path=str(storage),
        authorized_app_ids=frozenset({fixture_id}),
        capability_allowlist=frozenset({"app.launch"}),
        session_id="session-gates",
        activation_epoch="epoch-gates",
        expires_at=datetime.now(UTC) + timedelta(milliseconds=900),
        privacy_mode="metadata_only",
        fixture_app_id=fixture_id,
        fixture_identity_token=token,
    )
    store = open_acceptance_store(
        storage,
        authorization=OwnerAcceptanceAuthorization(
            decision_reference=authz.decision_reference,
            storage_id=authz.storage_id,
            expires_at=authz.expires_at,
            campaign_id=authz.campaign_id,
        ),
        now=datetime.now(UTC),
    )
    store.close()
    explorer = _CountingExplorer(tmp_path / "elsewhere")
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
        _opt_in(comp)
        assert comp.bridge.get_state({})["projects"] != []
        calls = explorer.calls
        _time.sleep(1.2)  # past expiry (timer + synchronous predicate agree)
        _opt_in(comp)  # attempted reactivation after expiry
        assert comp.bridge.get_state({})["projects"] == []
        assert explorer.calls == calls
    finally:
        assert comp.shutdown() is True


def test_invalid_registration_payloads_refused(tmp_path: Path) -> None:
    comp = _start(tmp_path, _CountingExplorer(None))
    try:
        assert comp.bridge.register_project({"alias": "x"})["status"] == "unavailable"
        assert (
            comp.bridge.register_project({"alias": "x", "path": "relative/dir"})["status"]
            == "unavailable"
        )
        assert comp.bridge.register_project({"alias": "x", "path": 42})["status"] == "unavailable"
    finally:
        assert comp.shutdown() is True
