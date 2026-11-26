"""CP3-B05 tests: native launcher/integrity source via injected fakes.

Injected Win32 fakes only — not native Windows evidence, and no real
application is launched.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aether.adapters.windows.native_launcher import (
    NativeIntegrityProvider,
    NativeWindowsLaunchAdapter,
)
from aether.adapters.windows.native_observer import NativeObserverDisabled
from aether.core.apps.launcher import LaunchDenied
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    location_identity_digest,
    registration_app_id,
)

NOW = datetime(2026, 11, 15, tzinfo=UTC)


class FakeLaunchApi:
    def __init__(self, *, pid: int = 1234) -> None:
        self.pid = pid
        self.created: list[str] = []
        self.activated: list[str] = []
        self.closed: list[object] = []

    def create_process(self, canonical_executable: str):  # type: ignore[no-untyped-def]
        self.created.append(canonical_executable)
        return self.pid, "process-handle", "thread-handle"

    def activate_application(self, app_user_model_id: str) -> int:
        self.activated.append(app_user_model_id)
        return self.pid

    def close_handle(self, handle: object) -> None:
        self.closed.append(handle)

    def get_process_creation_time(self, pid: int) -> str | None:
        return "2026-11-15T00:00:00+00:00"


def test_native_adapter_disabled_without_activation() -> None:
    adapter = NativeWindowsLaunchAdapter(api=FakeLaunchApi(), activation=None)
    with pytest.raises(NativeObserverDisabled):
        adapter.launch(
            app_id="app:x",
            method=LaunchMethod.APPROVED_EXECUTABLE,
            canonical_target="C:\\Fake\\a.exe",
        )


def test_create_process_path_and_handle_cleanup() -> None:
    api = FakeLaunchApi()
    adapter = NativeWindowsLaunchAdapter.for_testing(api)
    result = adapter.launch_for_testing(
        app_id="app:x", method=LaunchMethod.APPROVED_EXECUTABLE, canonical_target="C:\\Fake\\a.exe"
    )
    assert result.accepted
    assert api.created == ["C:\\Fake\\a.exe"]  # canonical target only, no args/shell
    assert api.closed == ["thread-handle", "process-handle"]  # both handles closed


def test_apps_folder_activation_and_unapproved_method() -> None:
    api = FakeLaunchApi()
    adapter = NativeWindowsLaunchAdapter.for_testing(api)
    result = adapter.launch_for_testing(
        app_id="app:x", method=LaunchMethod.APPS_FOLDER_ACTIVATION, canonical_target="FakeApp!App"
    )
    assert result.accepted and api.activated == ["FakeApp!App"]
    with pytest.raises(LaunchDenied):
        adapter.launch_for_testing(app_id="app:x", method=LaunchMethod.NONE, canonical_target="")


def test_integrity_provider_hashes_real_file(tmp_path: Path) -> None:
    target = tmp_path / "fake-app.bin"
    target.write_bytes(b"synthetic-bytes")
    identity = str(target)
    record = ApplicationRecord(
        app_id=registration_app_id(
            display_name="FakeApp",
            executable_identity=identity,
            launch_method=LaunchMethod.APPROVED_EXECUTABLE,
        ),
        display_name="FakeApp",
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
        executable_identity=identity,
        location_digest=location_identity_digest(identity),
        discovery_source=DiscoverySource.FAKE_FIXTURE,
        discovered_at=NOW,
        fresh_until=NOW + timedelta(hours=1),
    )
    provider = NativeIntegrityProvider()
    evidence = provider.verify(record)
    assert evidence is not None and evidence.content_sha256 is not None
    assert evidence.file_identity is not None
    # Same-path replacement changes the version token.
    target.write_bytes(b"replaced-bytes!")
    evidence2 = provider.verify(record)
    assert evidence2 is not None and evidence2.content_sha256 != evidence.content_sha256
