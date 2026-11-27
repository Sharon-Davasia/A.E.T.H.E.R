"""B/C corrections: native packaged-application identity integration.

Discovery (AppsFolder AUMID) -> platform package-query integrity
evidence -> launch authorization -> IApplicationActivationManager
activation -> independent method-aware observation (process AUMID,
never image-path basename) -> verified receipt. Also: truthful
Start Menu roots under restricted environments, resolver-backed
search, launch-preparation refusal for unverifiable records, and
the authorization artifact's unambiguous-identity rule.

Fake platform seams only; nothing here is native Windows evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_phase3_controlled_native import COMMIT, GESTURE_KEY, _approve

from aether.adapters.windows.discovery import (
    DiscoveredAppCandidate,
    SourceStatus,
    StdlibWindowsDiscoveryProviders,
    _start_menu_roots,
)
from aether.adapters.windows.fake_windows import build_fake_seams, fixture_executable
from aether.adapters.windows.native_launcher import (
    NativeIntegrityProvider,
    _aumid_parts,
    native_package_query,
    package_identity_for_aumid,
)
from aether.core.apps.acceptance_startup import ControlledAcceptanceAuthorization
from aether.core.apps.composition import Phase3Composition, build_native_platform
from aether.core.apps.launch_authority import app_version_token
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    location_identity_digest,
    registration_app_id,
)
from aether.core.persistence.acceptance_storage import (
    OwnerAcceptanceAuthorization,
    open_acceptance_store,
)

AUMID = "Synthetic.Notes_8wekyb3d8bbwe!App"
PACKAGE_FULL_NAME = "Synthetic.Notes_1.2.3.4_x64__8wekyb3d8bbwe"
PACKAGE_VERSION = "1.2.3.4"
HOST_IMAGE = "C:\\Program Files\\WindowsApps\\Synthetic.Notes_1.2.3.4_x64__8wekyb3d8bbwe\\Notes.exe"
LEGACY_EXE = "C:\\Tools\\LegacyTool.exe"


class _QueryApi:
    """Fake appmodel API for the package-identity orchestration."""

    def __init__(self, packages, version=PACKAGE_VERSION, apps=(AUMID,)):
        self._packages = packages
        self._version = version
        self._apps = apps

    def packages_by_family(self, family):  # type: ignore[no-untyped-def]
        return self._packages

    def package_version(self, full):  # type: ignore[no-untyped-def]
        return self._version

    def application_ids(self, full):  # type: ignore[no-untyped-def]
        return list(self._apps) if self._apps is not None else None


def test_package_identity_requires_exact_unambiguous_aumid() -> None:
    assert _aumid_parts(AUMID) == ("Synthetic.Notes_8wekyb3d8bbwe", "App")
    for malformed in ("", "no-separator", "!App", "Family!", "a!b!c", "a\x00b!c", 42, None):
        assert _aumid_parts(malformed) is None
        assert package_identity_for_aumid(_QueryApi([PACKAGE_FULL_NAME]), malformed) is None

    good = _QueryApi([PACKAGE_FULL_NAME])
    assert package_identity_for_aumid(good, AUMID) == (PACKAGE_FULL_NAME, PACKAGE_VERSION)
    # Ambiguous or absent installed packages: no evidence.
    assert (
        package_identity_for_aumid(_QueryApi([PACKAGE_FULL_NAME, "Other_1.0_x64__pub"]), AUMID)
        is None
    )
    assert package_identity_for_aumid(_QueryApi([]), AUMID) is None
    assert package_identity_for_aumid(_QueryApi(None), AUMID) is None
    # The exact application must be a member of the package.
    assert (
        package_identity_for_aumid(_QueryApi([PACKAGE_FULL_NAME], apps=("Other!App",)), AUMID)
        is None
    )
    assert package_identity_for_aumid(_QueryApi([PACKAGE_FULL_NAME], apps=None), AUMID) is None
    # No version from the platform: no evidence.
    assert package_identity_for_aumid(_QueryApi([PACKAGE_FULL_NAME], version=None), AUMID) is None
    # Case-insensitive AUMID membership, exact identity otherwise.
    assert package_identity_for_aumid(good, AUMID.upper()) == (PACKAGE_FULL_NAME, PACKAGE_VERSION)
    # Off-Windows the production query is unavailable, never a guess.
    assert native_package_query(AUMID) is None
    # Malformed platform responses: no evidence, never partial trust.
    assert package_identity_for_aumid(_QueryApi([PACKAGE_FULL_NAME], version="1.2"), AUMID) is None
    assert (
        package_identity_for_aumid(_QueryApi([PACKAGE_FULL_NAME], version="1.2.3.70000"), AUMID)
        is None
    )
    assert (
        package_identity_for_aumid(_QueryApi([PACKAGE_FULL_NAME], version="not-a-version"), AUMID)
        is None
    )
    assert package_identity_for_aumid(_QueryApi([""]), AUMID) is None
    # Platform disagreement between full name and reported version.
    assert (
        package_identity_for_aumid(_QueryApi([PACKAGE_FULL_NAME], version="5.0.0.0"), AUMID) is None
    )


def test_bounded_buffer_string_reads() -> None:
    """F6: package-query string reads are contained and terminated."""
    import ctypes

    from aether.adapters.windows.native_launcher import _string_from_buffer

    w = ctypes.sizeof(ctypes.c_wchar)
    buffer = ctypes.create_unicode_buffer("Synthetic.Notes\x00Other", 24)
    base = ctypes.addressof(buffer)
    assert _string_from_buffer(buffer, base) == "Synthetic.Notes"
    assert _string_from_buffer(buffer, base + 16 * w) == "Other"
    # Pointer outside the buffer (either side) is never dereferenced.
    assert _string_from_buffer(buffer, base - w) is None
    assert _string_from_buffer(buffer, base + 24 * w) is None
    assert _string_from_buffer(buffer, base + 10_000 * w) is None
    # Misaligned pointer: malformed.
    assert _string_from_buffer(buffer, base + 1) is None
    # Unterminated content: malformed, never an unbounded read.
    unterminated = ctypes.create_unicode_buffer(4)
    pattern = (b"A" + b"\x00" * (w - 1)) * 4
    ctypes.memmove(unterminated, pattern, len(pattern))
    assert _string_from_buffer(unterminated, ctypes.addressof(unterminated)) is None


def test_start_menu_roots_never_use_relative_pseudo_roots() -> None:
    no_folder = lambda _kind: None  # noqa: E731
    assert _start_menu_roots({}, no_folder) == []
    assert _start_menu_roots({"APPDATA": "", "PROGRAMDATA": ""}, no_folder) == []
    roots = _start_menu_roots({"APPDATA": "C:\\Users\\x\\AppData\\Roaming"}, no_folder)
    assert len(roots) == 1 and roots[0].endswith("Programs")
    # Known folders win over missing env (restricted backend env).
    roots = _start_menu_roots({}, lambda kind: "D:\\KF" if kind == "roaming" else None)
    assert len(roots) == 1 and roots[0].startswith("D:\\KF")
    # Off-Windows the provider is truthfully unavailable.
    _candidates, status = StdlibWindowsDiscoveryProviders().start_menu_shortcuts()
    assert status.status == "unavailable"


class _Discovery:
    def start_menu_shortcuts(self):  # type: ignore[no-untyped-def]
        return (
            [
                DiscoveredAppCandidate(
                    display_name="Legacy Tool",
                    executable_identity=LEGACY_EXE,
                    publisher="Fake",
                    source="uninstall_registry",
                )
            ],
            SourceStatus(source="uninstall_registry", status="ok"),
        )

    def uninstall_entries(self):  # type: ignore[no-untyped-def]
        return ([], SourceStatus(source="uninstall_registry", status="ok"))

    def apps_folder_entries(self):  # type: ignore[no-untyped-def]
        return (
            [
                DiscoveredAppCandidate(
                    display_name="Synthetic Notes",
                    executable_identity=AUMID,
                    publisher=None,
                    source="apps_folder",
                )
            ],
            SourceStatus(source="apps_folder", status="ok"),
        )


class _PackagedObserverApi:
    """Wraps the fake observer API: packaged processes report a host
    image path (which matches nothing) plus their exact AUMID."""

    def __init__(self, base) -> None:  # type: ignore[no-untyped-def]
        self._base = base

    def __getattr__(self, name):  # type: ignore[no-untyped-def]
        return getattr(self._base, name)

    def get_process_image_path(self, pid):  # type: ignore[no-untyped-def]
        if self._base.get_process_aumid(pid):
            return HOST_IMAGE  # hosted image: NOT the registered identity
        return self._base.get_process_image_path(pid)

    def get_process_package_full_name(self, pid):  # type: ignore[no-untyped-def]
        # The running process's own package identity (live evidence),
        # matching the authorized catalogue identity in this scenario.
        if self._base.get_process_aumid(pid):
            return PACKAGE_FULL_NAME
        return None


class _Verifier:
    """Delegates packaged records to the real integrity provider with
    a fake platform package query; other records to the fake seams."""

    def __init__(self, base, query) -> None:  # type: ignore[no-untyped-def]
        self._base = base
        self._packaged = NativeIntegrityProvider(package_query=query)

    def verify(self, record):  # type: ignore[no-untyped-def]
        if getattr(record, "launch_method", None) is LaunchMethod.APPS_FOLDER_ACTIVATION:
            return self._packaged.verify(record)
        return self._base.verify(record)


def _start_packaged(tmp_path: Path, *, package_query):  # type: ignore[no-untyped-def]
    seams = build_fake_seams()
    base_verifier = seams.integrity_verifier
    verifier = _Verifier(base_verifier, package_query)
    packaged_id = registration_app_id(
        display_name="Synthetic Notes",
        executable_identity=AUMID,
        launch_method=LaunchMethod.APPS_FOLDER_ACTIVATION,
    )
    legacy_id = registration_app_id(
        display_name="Legacy Tool",
        executable_identity=LEGACY_EXE,
        launch_method=LaunchMethod.NONE,
    )
    fixture_id = registration_app_id(
        display_name="AETHER Fixture",
        executable_identity=fixture_executable(),
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    token = app_version_token(
        base_verifier.verify(  # type: ignore[attr-defined]
            SimpleNamespace(location_digest=location_identity_digest(fixture_executable()))
        )
    )
    storage = tmp_path / "aether-phase3-acceptance-packaged"
    _workspace = tmp_path / "aether-phase3-workspace-packaged"
    _workspace.mkdir(parents=True, exist_ok=True)
    _ws_stat = _workspace.stat()
    authz = ControlledAcceptanceAuthorization(
        approved_commit=COMMIT,
        decision_reference="owner-decision-packaged",
        campaign_id="campaign-packaged",
        storage_id="66666666-6666-4666-8666-666666666666",
        storage_path=str(storage),
        workspace_path=str(tmp_path / "aether-phase3-workspace-packaged"),
        workspace_identity=(_ws_stat.st_dev, _ws_stat.st_ino),
        authorized_app_ids=frozenset({packaged_id, legacy_id, fixture_id}),
        capability_allowlist=frozenset(
            {"app.launch", "window.activate", "uia.inspect_snapshot", "uia.inspect_element"}
        ),
        session_id="session-packaged",
        activation_epoch="epoch-packaged",
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
    seams.discovery_providers = _Discovery()  # type: ignore[attr-defined]
    seams.integrity_verifier = verifier  # type: ignore[attr-defined]
    seams.observer_api = _PackagedObserverApi(seams.observer_api)  # type: ignore[attr-defined]
    providers = build_native_platform(authz, seams=seams)
    comp = Phase3Composition.native(
        authorization=authz,
        current_commit=COMMIT,
        storage_dir=storage,
        gesture_key=GESTURE_KEY,
        platform=providers,
    )
    return comp, packaged_id, legacy_id


def test_packaged_launch_end_to_end_with_independent_verification(tmp_path: Path) -> None:
    query_calls: list[str] = []

    def query(aumid):  # type: ignore[no-untyped-def]
        query_calls.append(aumid)
        return (PACKAGE_FULL_NAME, PACKAGE_VERSION) if aumid == AUMID else None

    comp, packaged_id, legacy_id = _start_packaged(tmp_path, package_query=query)
    try:
        bridge = comp.bridge
        assert (
            bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})[
                "status"
            ]
            == "ready"
        )
        # Resolver-backed search: exact resolution through the channel.
        found = bridge.search_apps({"query": "Synthetic Notes"})
        assert found["resolution"] == "exact"
        assert [r["appId"] for r in found["results"]] == [packaged_id]
        listing = bridge.search_apps({"query": ""})
        assert {r["appId"] for r in listing["results"]} >= {packaged_id, legacy_id}

        # The NONE-method record is refused before any task exists.
        refused = bridge.prepare_launch({"appId": legacy_id})
        assert refused["status"] == "unavailable"

        prepared = bridge.prepare_launch({"appId": packaged_id})
        assert prepared["status"] == "ready", prepared
        preview = bridge.preview_operation({"taskId": prepared["taskId"], "effect": "app.launch"})
        assert preview["status"] == "ready", preview
        outcome = _approve(bridge, prepared["taskId"], preview, effect="app.launch")
        assert outcome["status"] == "ready" and outcome["outcome"] == "SUCCEEDED", outcome
        assert query_calls, "platform package query was never consulted"

        # Independent observation attributed the process by exact
        # AUMID (its image path matches no registered identity).
        providers_observation = comp.surface.executor  # noqa: F841 - composition retained
        receipt = bridge.get_receipt({"taskId": prepared["taskId"]})
        assert receipt["taskState"] == "COMPLETED"
        assert receipt["navigationAttempts"][0]["receipt_status"] == "SUCCEEDED"
    finally:
        assert comp.shutdown() is True


def test_packaged_launch_refused_without_package_evidence(tmp_path: Path) -> None:
    comp, packaged_id, _legacy_id = _start_packaged(tmp_path, package_query=lambda _a: None)
    try:
        bridge = comp.bridge
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
        # No package evidence: refusal happens at preparation, before
        # a task or a trusted gesture exists.
        prepared = bridge.prepare_launch({"appId": packaged_id})
        assert prepared["status"] == "unavailable"
        assert prepared["reason"] == "integrity_evidence_unavailable"
    finally:
        assert comp.shutdown() is True


def test_observation_packaged_attribution_rules() -> None:
    """Method-aware observation: exact AUMID only, ambiguity denied,
    image-path disagreement denied."""
    from aether.adapters.windows.native_observer import NativeObservationProvider
    from aether.core.apps.launch_authority import IntegrityEvidence

    def record(name: str, aumid: str) -> ApplicationRecord:
        now = datetime.now(UTC)
        return ApplicationRecord(
            app_id=registration_app_id(
                display_name=name,
                executable_identity=aumid,
                launch_method=LaunchMethod.APPS_FOLDER_ACTIVATION,
            ),
            display_name=name,
            launch_method=LaunchMethod.APPS_FOLDER_ACTIVATION,
            executable_identity=aumid,
            location_digest=location_identity_digest(aumid),
            discovery_source=DiscoverySource.APPS_FOLDER,
            discovered_at=now,
            fresh_until=now + timedelta(hours=1),
        )

    class _Api:
        # Deterministic sessions: every process (including this test
        # process, pid queried via os.getpid) is in session 1.
        live_full_name: str | None = PACKAGE_FULL_NAME

        def enumerate_windows(self):  # type: ignore[no-untyped-def]
            return [(11, 501)]

        def get_process_image_path(self, pid):  # type: ignore[no-untyped-def]
            return HOST_IMAGE

        def get_process_aumid(self, pid):  # type: ignore[no-untyped-def]
            return AUMID

        def get_process_package_full_name(self, pid):  # type: ignore[no-untyped-def]
            return self.live_full_name

        def get_process_creation_time(self, pid):  # type: ignore[no-untyped-def]
            return "creation-1"

        def get_process_session_id(self, pid):  # type: ignore[no-untyped-def]
            return 1

    class _VerifierOk:
        def verify(self, record):  # type: ignore[no-untyped-def]
            return IntegrityEvidence(
                location_digest=record.location_digest or "",
                content_sha256=None,
                signer_identity=None,
                package_identity=PACKAGE_FULL_NAME,
                verified_at=datetime.now(UTC),
                package_version=PACKAGE_VERSION,
            )

    one = record("Notes", AUMID)
    provider = NativeObservationProvider(
        api=_Api(), records=[one], integrity_verifier=_VerifierOk()
    )
    observation = provider.observe()
    assert [p.app_id for p in observation.processes] == [one.app_id]

    two = record("Notes Twin", AUMID)
    ambiguous = NativeObservationProvider(
        api=_Api(), records=[one, two], integrity_verifier=_VerifierOk()
    )
    assert ambiguous.observe().processes == ()  # ambiguous packaged identity denied

    class _NoAumid(_Api):
        def get_process_aumid(self, pid):  # type: ignore[no-untyped-def]
            return None

    unattributed = NativeObservationProvider(
        api=_NoAumid(), records=[one], integrity_verifier=_VerifierOk()
    )
    assert unattributed.observe().processes == ()  # never basename/name matching

    # R1: matching AUMID but a DIFFERENT running package version must
    # not verify - the live process identity is checked against the
    # fresh authorized package evidence, not the catalogue alone.
    class _WrongVersion(_Api):
        live_full_name = "Synthetic.Notes_9.9.9.9_x64__8wekyb3d8bbwe"

    mismatched = NativeObservationProvider(
        api=_WrongVersion(), records=[one], integrity_verifier=_VerifierOk()
    )
    assert mismatched.observe().processes == ()

    # R1: live package identity unavailable -> deny.
    class _NoLiveIdentity(_Api):
        live_full_name = None

    unavailable = NativeObservationProvider(
        api=_NoLiveIdentity(), records=[one], integrity_verifier=_VerifierOk()
    )
    assert unavailable.observe().processes == ()

    # R1: malformed live package identity -> deny.
    class _MalformedLive(_Api):
        live_full_name = "not-a-package-full-name"

    malformed = NativeObservationProvider(
        api=_MalformedLive(), records=[one], integrity_verifier=_VerifierOk()
    )
    assert malformed.observe().processes == ()

    # R1: unknown own-session identity fails closed (incomplete).
    import os as _os

    class _UnknownOwnSession(_Api):
        def get_process_session_id(self, pid):  # type: ignore[no-untyped-def]
            return None if pid == _os.getpid() else 1

    unknown_own = NativeObservationProvider(
        api=_UnknownOwnSession(), records=[one], integrity_verifier=_VerifierOk()
    )
    observation = unknown_own.observe()
    assert observation.processes == () and observation.complete is False

    # R1: unknown target-session identity denies attribution.
    class _UnknownTargetSession(_Api):
        def get_process_session_id(self, pid):  # type: ignore[no-untyped-def]
            return 1 if pid == _os.getpid() else None

    unknown_target = NativeObservationProvider(
        api=_UnknownTargetSession(), records=[one], integrity_verifier=_VerifierOk()
    )
    assert unknown_target.observe().processes == ()

    # R1: foreign session denies attribution.
    class _ForeignSession(_Api):
        def get_process_session_id(self, pid):  # type: ignore[no-untyped-def]
            return 1 if pid == _os.getpid() else 2

    foreign = NativeObservationProvider(
        api=_ForeignSession(), records=[one], integrity_verifier=_VerifierOk()
    )
    assert foreign.observe().processes == ()


def test_artifact_requires_unambiguous_identity_selection() -> None:
    from aether.core.apps.authorization_artifact import build_authorization
    from aether.core.apps.launch_authority import IntegrityEvidence

    now = datetime.now(UTC)

    def rec(name: str, identity: str, app_id: str) -> ApplicationRecord:
        return ApplicationRecord(
            app_id=app_id,
            display_name=name,
            launch_method=LaunchMethod.APPROVED_EXECUTABLE,
            executable_identity=identity,
            location_digest=location_identity_digest(identity),
            discovery_source=DiscoverySource.USER_REGISTERED_PORTABLE,
            discovered_at=now,
            fresh_until=now + timedelta(hours=2),
        )

    id_a = registration_app_id(
        display_name="Twin",
        executable_identity="C:\\A\\twin.exe",
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    id_b = registration_app_id(
        display_name="Twin",
        executable_identity="C:\\B\\twin.exe",
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    records = [rec("Twin", "C:\\A\\twin.exe", id_a), rec("Twin", "C:\\B\\twin.exe", id_b)]

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

    kwargs = dict(
        decision_reference="d",
        campaign_id="c",
        app_display_names=["Twin"],
        acceptance_root=Path("D:\\unused"),
        now=now,
        discovered_records=list(records),
        fixture_executable="C:\\Fixture\\AETHERFixture.exe",
        integrity_verifier=_Verifier(),
        commit="a" * 40,
    )
    with pytest.raises(ValueError, match="ambiguous"):
        build_authorization(**kwargs)  # type: ignore[arg-type]
    artifact, _storage = build_authorization(**kwargs, app_ids=[id_b])  # type: ignore[arg-type]
    assert id_b in artifact["authorized_app_ids"]
    assert id_a not in artifact["authorized_app_ids"]
