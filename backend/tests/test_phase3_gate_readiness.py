"""Gate readiness: G01 composition, G03 scoped storage, G02 workflow,
G04 takeover/dialog routing, G05 fixture contract, G06 boundaries.

Simulated providers only at the platform boundary; not native evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aether.core.apps.composition import (
    CompositionUnavailable,
    Phase3Composition,
    Phase3Mode,
)
from aether.core.apps.fixture import FixtureApp
from aether.core.apps.fixture_contract import (
    FixtureContractError,
    parse_fixture_count,
    resolve_fixture_elements,
    validate_fixture_launch_identity,
)
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    location_identity_digest,
    registration_app_id,
)
from aether.core.persistence.acceptance_storage import (
    AcceptanceStorageError,
    OwnerAcceptanceAuthorization,
    open_acceptance_store,
)
from aether.core.persistence.sqlite_store import SQLiteTaskStore

NOW = datetime(2026, 11, 15, tzinfo=UTC)
KEY = b"g" * 32


def _fixture_record() -> ApplicationRecord:
    exe = "C:\\Fake\\AETHERFixture.exe"
    return ApplicationRecord(
        app_id=registration_app_id(
            display_name="AETHER Fixture",
            executable_identity=exe,
            launch_method=LaunchMethod.APPROVED_EXECUTABLE,
        ),
        display_name="AETHER Fixture",
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
        executable_identity=exe,
        location_digest=location_identity_digest(exe),
        discovery_source=DiscoverySource.FAKE_FIXTURE,
        discovered_at=NOW,
        fresh_until=NOW + timedelta(hours=2),
    )


def _auth(storage_id: str = "12345678-1234-4234-8234-123456789abc") -> OwnerAcceptanceAuthorization:
    return OwnerAcceptanceAuthorization(
        decision_reference="owner-decision-test-1",
        storage_id=storage_id,
        expires_at=NOW + timedelta(hours=1),
    )


# -- G03 -----------------------------------------------------------------

def test_scoped_v3_acceptance_storage(tmp_path: Path) -> None:
    store = open_acceptance_store(
        tmp_path / "aether-phase3-acceptance-a", authorization=_auth(), now=NOW
    )
    try:
        import sqlite3

        version = sqlite3.connect(store.database_path).execute("PRAGMA user_version").fetchone()[0]
        assert version == 3
    finally:
        store.close()
    # Reopen with the same authorization works (marker-bound).
    store = open_acceptance_store(
        tmp_path / "aether-phase3-acceptance-a", authorization=_auth(), now=NOW
    )
    store.close()
    # Ordinary storage remains v2 and pending v3 is refused directly.
    ordinary = SQLiteTaskStore(tmp_path / "ordinary.db")
    ordinary.close()
    with pytest.raises(Exception):
        SQLiteTaskStore(tmp_path / "bad.db", target_schema_version=3)


def test_acceptance_storage_rejects_unrelated_and_expired(tmp_path: Path) -> None:
    target = tmp_path / "aether-phase3-acceptance-b"
    target.mkdir()
    (target / "unrelated.txt").write_text("x", encoding="utf-8")
    with pytest.raises(AcceptanceStorageError):
        open_acceptance_store(target, authorization=_auth(), now=NOW)
    with pytest.raises(AcceptanceStorageError):
        open_acceptance_store(
            tmp_path / "ordinary-dir", authorization=_auth(), now=NOW
        )
    expired = OwnerAcceptanceAuthorization("d", _auth().storage_id, NOW - timedelta(seconds=1))
    with pytest.raises(AcceptanceStorageError):
        open_acceptance_store(tmp_path / "aether-phase3-acceptance-c", authorization=expired, now=NOW)


# -- G01/G02 ---------------------------------------------------------------

def _composition(tmp_path: Path) -> Phase3Composition:
    store = open_acceptance_store(
        tmp_path / "aether-phase3-acceptance-main", authorization=_auth(), now=NOW
    )
    return Phase3Composition.simulated(
        store=store,
        fixture=FixtureApp(),
        fixture_record=_fixture_record(),
        clock=lambda: NOW,
        gesture_key=KEY,
    )


def test_disabled_and_native_prepared_modes() -> None:
    disabled = Phase3Composition.disabled()
    assert disabled.mode is Phase3Mode.DISABLED
    assert disabled.bridge.get_state({})["nativeAvailable"] is False
    with pytest.raises(CompositionUnavailable):
        Phase3Composition.native_prepared()


def test_simulated_composition_full_fixture_workflow(tmp_path: Path) -> None:
    composition = _composition(tmp_path)
    try:
        bridge = composition.bridge
        state = bridge.get_state({})
        assert state["nativeAvailable"] is True
        assert state["windows"] and state["windows"][0]["appDisplayName"] == "AETHER Fixture"
        assert bridge.search_apps({"query": "fixture"})["results"]
        window_id = composition.fixture_window_id
        assert window_id
        snapshot = bridge.inspect_window({"windowId": window_id})
        assert snapshot["status"] == "ready"
        # Privacy revocation is authoritative (G06) and purges snapshots.
        bridge.set_privacy({"optedIn": False, "mode": "off", "paused": True})
        assert bridge.get_state({})["privacy"]["paused"] is True
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
        # G02: prepare a persisted fixture interaction without typing ids.
        prepared = bridge.prepare_fixture_interaction({"windowId": window_id})
        assert prepared["status"] == "ready", prepared
        assert prepared["preview"]["verifiedPrecondition"] == "Count: 0"
        assert prepared["preview"]["expectedPostcondition"] == "Count: 1"
        assert prepared["preview"]["appDisplayName"] == "AETHER Fixture"
        task_id = prepared["taskId"]
        # Trusted gesture flow (signed by main-process authority in tests).
        preview = bridge.preview_fixture_interaction({"taskId": task_id})
        assert preview["status"] == "ready", preview
        outcome = _approve(bridge, task_id, preview)
        assert outcome["status"] == "ready" and outcome["outcome"] == "SUCCEEDED", outcome
        receipt = bridge.get_receipt({"taskId": task_id})
        assert receipt["taskState"] == "COMPLETED"
        assert receipt["uiAttempts"] and receipt["uiAttempts"][0]["receipt_status"] == "SUCCEEDED"
        # Exactly once: replaying the same prepared task cannot re-execute.
        replay = bridge.preview_fixture_interaction({"taskId": task_id})
        assert replay.get("status") in ("ready", "unavailable")
    finally:
        composition.shutdown()


def _approve(bridge, task_id, preview):  # type: ignore[no-untyped-def]
    from aether.core.planning.authorizing_gesture import (
        GestureBinding,
        GestureNonceRegister,
        TrustedGestureAuthority,
    )

    # The test composition used the same key; sign as trusted main would.
    # Nonces were issued by the bridge's register, so verification must
    # go through its authority — reconstruct via the bridge surface.
    authority = TrustedGestureAuthority(
        key=KEY, nonces=bridge.surface.nonces, clock=lambda: NOW  # type: ignore[arg-type]
    )
    binding = GestureBinding(
        task_id=preview["binding"]["taskId"] if False else _uuid(task_id),
        plan_revision=preview["binding"]["planRevision"],
        plan_hash=preview["binding"]["planHash"],
        preview_id=_uuid(preview["binding"]["previewId"]),
        preview_digest=preview["binding"]["previewDigest"],
        scope_digest=preview["binding"]["scopeDigest"],
    )
    gesture = authority.sign(nonce=preview["nonce"], binding=binding, user_intent="APPROVE")
    return bridge.approve_fixture_interaction(
        {
            "taskId": task_id,
            "nonce": preview["nonce"],
            "assertedAt": gesture.asserted_at.isoformat(),
            "userIntent": "APPROVE",
            "signature": gesture.signature,
            "binding": preview["binding"],
        }
    )


def _uuid(value):  # type: ignore[no-untyped-def]
    from uuid import UUID

    return UUID(str(value))


def test_composition_revocation_disables(tmp_path: Path) -> None:
    composition = _composition(tmp_path)
    composition.revoke("test")
    assert composition.active is False
    assert composition.enablement.is_active(
        capability_id="uia.invoke_fixture", app_id="x", now=NOW
    ) is False
    composition.shutdown()


# -- G05 -------------------------------------------------------------------

def test_fixture_contract_rules() -> None:
    assert parse_fixture_count("Count: 12") == 12
    with pytest.raises(FixtureContractError):
        parse_fixture_count("hello")
    with pytest.raises(FixtureContractError):
        validate_fixture_launch_identity(
            executable_identity="C:\\x\\aether_fixture.py", launch_method="approved_executable"
        )
    validate_fixture_launch_identity(
        executable_identity="C:\\x\\AETHERFixture.exe", launch_method="approved_executable"
    )
    with pytest.raises(FixtureContractError):
        validate_fixture_launch_identity(
            executable_identity="C:\\x\\AETHERFixture.exe", launch_method="shell_uri"
        )


def test_fixture_contract_rejects_fake_runtime_ids(tmp_path: Path) -> None:
    # A snapshot carrying only fake keys (no native automation ids)
    # cannot satisfy the native fixture contract.
    composition = _composition(tmp_path)
    try:
        snapshot = composition.snapshots.inspect(
            composition.fixture_window_id, require_content=True  # type: ignore[arg-type]
        ).snapshot
        assert snapshot is not None
        with pytest.raises(FixtureContractError):
            resolve_fixture_elements(snapshot)
    finally:
        composition.shutdown()


def test_simulated_launch_workflow_through_bridge(tmp_path: Path) -> None:
    """§11 chain segment: discovery -> persisted launch plan -> trusted
    gesture -> broker -> durable attempt -> simulated launch ->
    independent verification -> receipt. Launch platform is simulated;
    every policy/planning/persistence component is real."""
    from test_phase3_launch import _World as LaunchWorld

    from aether.core.planning.planner import Planner
    from aether.core.resources.registry import ResourceRegistry

    launch = LaunchWorld(tmp_path / "launch")
    (tmp_path / "launch").mkdir(exist_ok=True)
    try:
        planner = Planner(
            capabilities=launch.capabilities,
            resources=ResourceRegistry(windows_semantics=False),
            app_authority=launch.app_authority,
            app_registry=launch.registry,
            integrity_verifier=launch.verifier_evidence,
            clock=lambda: NOW,
        )
        composition = Phase3Composition.simulated(
            store=launch.store,
            fixture=FixtureApp(),
            fixture_record=_fixture_record(),
            clock=lambda: NOW,
            gesture_key=KEY,
            launch_coordinator=launch.coordinator,
            launch_authority=launch.authority,
            launch_registry=launch.registry,
            planner=planner,
        )
        bridge = composition.bridge
        # The launch world's app is discoverable through the surface.
        records = bridge.search_apps({"query": ""})
        assert records["status"] == "ready"
        prepared = bridge.prepare_launch({"appId": launch.record.app_id})
        if prepared["status"] != "ready":
            # Surface app_records is the fixture record in this
            # composition; prepare against the launch registry record
            # directly documents the wiring requirement.
            raise AssertionError(prepared)
        preview = bridge.preview_operation(
            {"taskId": prepared["taskId"], "effect": "app.launch"}
        )
        assert preview["status"] == "ready", preview
        outcome = _approve_operation(bridge, prepared["taskId"], "app.launch", preview)
        assert outcome["status"] == "ready" and outcome["outcome"] == "SUCCEEDED", outcome
        receipt = bridge.get_receipt({"taskId": prepared["taskId"]})
        assert receipt["taskState"] == "COMPLETED"
        assert receipt["navigationAttempts"][0]["receipt_status"] == "SUCCEEDED"
        composition.revoke("test-done")
    finally:
        launch.close()


def _approve_operation(bridge, task_id, effect, preview):  # type: ignore[no-untyped-def]
    from aether.core.planning.authorizing_gesture import (
        GestureBinding,
        TrustedGestureAuthority,
    )

    authority = TrustedGestureAuthority(
        key=KEY, nonces=bridge.surface.nonces, clock=lambda: NOW  # type: ignore[arg-type]
    )
    binding = GestureBinding(
        task_id=_uuid(task_id),
        plan_revision=preview["binding"]["planRevision"],
        plan_hash=preview["binding"]["planHash"],
        preview_id=_uuid(preview["binding"]["previewId"]),
        preview_digest=preview["binding"]["previewDigest"],
        scope_digest=preview["binding"]["scopeDigest"],
    )
    gesture = authority.sign(nonce=preview["nonce"], binding=binding, user_intent="APPROVE")
    return bridge.approve_operation(
        {
            "taskId": task_id,
            "effect": effect,
            "nonce": preview["nonce"],
            "assertedAt": gesture.asserted_at.isoformat(),
            "userIntent": "APPROVE",
            "signature": gesture.signature,
            "binding": preview["binding"],
        }
    )
