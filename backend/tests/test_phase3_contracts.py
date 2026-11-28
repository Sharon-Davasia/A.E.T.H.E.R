"""Phase 3 CP0 contract tests: app/window identities, capabilities, adapter."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aether.adapters.fake import FakeAdapter
from aether.adapters.windows import FakeWindowsAdapter
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    ProcessInstanceIdentity,
    WindowInstanceIdentity,
    location_identity_digest,
    registration_app_id,
)
from aether.core.contracts.world_state import WorldStateObservation
from aether.core.policy.capabilities import CapabilityRegistry, CapabilityRegistryError

NOW = datetime(2026, 11, 15, tzinfo=UTC)


def _record(name: str = "Notepad") -> ApplicationRecord:
    exe = "C:\\Fake\\notepad.exe"
    return ApplicationRecord(
        app_id=registration_app_id(
            display_name=name, executable_identity=exe, launch_method=LaunchMethod.NONE
        ),
        display_name=name,
        executable_identity=exe,
        discovery_source=DiscoverySource.FAKE_FIXTURE,
        discovered_at=NOW,
        fresh_until=NOW,
        location_digest=location_identity_digest(exe),
    )


def test_registration_id_is_deterministic_and_distinct() -> None:
    a = registration_app_id(
        display_name="Notepad",
        executable_identity="C:\\Fake\\a.exe",
        launch_method=LaunchMethod.NONE,
    )
    b = registration_app_id(
        display_name=" notepad ",
        executable_identity="c:\\fake\\A.exe",
        launch_method=LaunchMethod.NONE,
    )
    c = registration_app_id(
        display_name="Notepad",
        executable_identity="C:\\Fake\\b.exe",
        launch_method=LaunchMethod.NONE,
    )
    assert a == b  # canonical identity, not display string
    assert a != c  # executable identity is part of registration identity
    assert a.startswith("app:")


def test_app_id_cannot_pose_as_filesystem_id() -> None:
    with pytest.raises(ValidationError):
        ApplicationRecord(
            app_id="file:123e4567-e89b-12d3-a456-426614174000",
            display_name="X",
            discovery_source=DiscoverySource.FAKE_FIXTURE,
            discovered_at=NOW,
            fresh_until=NOW,
        )
    # Filesystem capability argument patterns reject app ids and vice versa.
    registry = CapabilityRegistry.phase2_filesystem()
    with pytest.raises(CapabilityRegistryError):
        registry.validate("fs.read_file", {"resource_id": _record().app_id})


def test_window_version_token_binds_pid_creation_time() -> None:
    proc = ProcessInstanceIdentity(pid=42, creation_time=NOW)
    win = WindowInstanceIdentity(
        window_id="window:123e4567-e89b-12d3-a456-426614174000",
        hwnd=100,
        process=proc,
        observed_at=NOW,
    )
    reused_pid = ProcessInstanceIdentity(pid=42, creation_time=datetime(2026, 11, 16, tzinfo=UTC))
    win2 = WindowInstanceIdentity(
        window_id="window:123e4567-e89b-12d3-a456-426614174000",
        hwnd=100,
        process=reused_pid,
        observed_at=NOW,
    )
    assert win.version_token != win2.version_token  # PID reuse detected


def test_world_state_phase3_fields_are_additive() -> None:
    legacy = WorldStateObservation(observation_id="o1", kind="focused_window", observed_at=NOW)
    assert legacy.availability == "available" and legacy.resource_id is None
    extended = WorldStateObservation(
        observation_id="o2",
        kind="window_created",
        observed_at=NOW,
        resource_id="window:123e4567-e89b-12d3-a456-426614174000",
        version_token="tok",
    )
    assert extended.version_token == "tok"


def test_phase3_foundation_capabilities_are_observe_only() -> None:
    registry = CapabilityRegistry.phase3_foundation()
    for capability_id in (
        "world.observe",
        "app.discover",
        "app.resolve",
        "app.inspect",
        "window.inspect",
    ):
        definition = registry.get(capability_id)
        assert int(definition.risk_tier) == 0
    # No launch or interaction capability exists in CP0-CP2.
    for absent in ("app.launch", "window.activate", "uia.invoke"):
        with pytest.raises(CapabilityRegistryError):
            registry.get(absent)
    # App/window argument kinds are disjoint from filesystem patterns.
    with pytest.raises(CapabilityRegistryError):
        registry.validate(
            "app.inspect", {"resource_id": "file:123e4567-e89b-12d3-a456-426614174000"}
        )
    ok = registry.validate("app.inspect", {"resource_id": _record().app_id})
    assert ok.resource_id.startswith("app:")


def test_adapter_prepare_default_and_fake() -> None:
    from aether.core.contracts.tool import ToolRequest

    request = ToolRequest(request_id="r1", task_id="t1", capability_id="x.y")
    assert FakeAdapter().prepare(request)["prepared"] is False  # Phase 0 compat
    assert FakeWindowsAdapter().capabilities().supports_prepare is True
    assert FakeWindowsAdapter().prepare(request)["effectful"] is False
    # The foundation fake never reports a successful execution.
    receipt = FakeWindowsAdapter().execute(request)
    assert receipt.status == "FAILED" and FakeWindowsAdapter().verify(receipt) is False


def test_window_token_distinguishes_same_process_recreation() -> None:
    proc = ProcessInstanceIdentity(pid=42, creation_time=NOW)
    first = WindowInstanceIdentity(
        window_id="window:123e4567-e89b-12d3-a456-426614174000",
        hwnd=100,
        process=proc,
        observed_at=NOW,
        instance_generation=0,
    )
    recreated = WindowInstanceIdentity(
        window_id="window:123e4567-e89b-12d3-a456-426614174000",
        hwnd=100,
        process=proc,
        observed_at=NOW,
        instance_generation=1,
    )
    assert first.version_token != recreated.version_token


def test_missing_integrity_evidence_blocks_launch_authorization() -> None:
    record = _record()
    assert record.integrity_status == "unavailable"
    assert record.launch_authorized is False
    # Location digest hashes the location string only (F06): changing
    # bytes at the same path cannot change this digest, and the
    # contract never claims it detects replacement.
    from aether.core.contracts.app_window import location_identity_digest

    assert location_identity_digest("C:\\Fake\\a.exe") == location_identity_digest(
        "c:\\fake\\A.exe"
    )
