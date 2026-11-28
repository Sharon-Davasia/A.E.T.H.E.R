"""CP7 backend bridge: trusted fixture approval over the channel surface.

Fake providers; the gesture is signed with the same authority the
Electron main process uses. Not native evidence.
"""

from __future__ import annotations

from pathlib import Path

from test_phase3_cp5_interaction import NOW, _World

from aether.channel.phase3_bridge import Phase3Bridge, Phase3Surface
from aether.core.apps.recovery import RecoveryService
from aether.core.context.project_detection import ProjectDetector
from aether.core.planning.authorizing_gesture import (
    GestureNonceRegister,
    TrustedGestureAuthority,
)

KEY = b"k" * 32


def _bridge(tmp_path: Path) -> tuple[Phase3Bridge, _World, TrustedGestureAuthority]:
    world = _World(tmp_path)
    nonces = GestureNonceRegister(clock=lambda: NOW)
    authority = TrustedGestureAuthority(key=KEY, nonces=nonces, clock=lambda: NOW)
    surface = Phase3Surface(
        store=world.store,
        snapshots=world.snapshots,
        executor=world.executor,
        authority=world.authority,
        app_records=lambda: [world.fixture_record],
        detector=ProjectDetector(registry=_empty_registry(), clock=lambda: NOW),
        gesture_authority=authority,
        nonces=nonces,
        recovery=RecoveryService(store=world.store),
    )
    return Phase3Bridge(surface), world, authority


def _empty_registry():  # type: ignore[no-untyped-def]
    from aether.core.resources.registry import ResourceRegistry

    return ResourceRegistry(windows_semantics=False)


def test_disabled_surface_is_truthful() -> None:
    bridge = Phase3Bridge(Phase3Surface.disabled())
    state = bridge.get_state({})
    assert state["nativeAvailable"] is False
    assert state["disabledReason"] == "phase3_native_disabled"
    assert bridge.inspect_window({"windowId": "window:x"})["status"] == "unavailable"
    assert bridge.preview_fixture_interaction({"taskId": "x"})["status"] == "unavailable"


def test_fixture_approval_flow_end_to_end(tmp_path: Path) -> None:
    bridge, world, authority = _bridge(tmp_path)
    task_id, _step = world.plan_task()
    preview = bridge.preview_fixture_interaction({"taskId": str(task_id)})
    assert preview["status"] == "ready"
    assert preview["preview"]["intendedEffect"] == "increment_fixture_count"
    # A forged signature is refused and nothing executes.
    forged = bridge.approve_fixture_interaction(
        {
            "taskId": str(task_id),
            "nonce": preview["nonce"],
            "assertedAt": NOW.isoformat(),
            "userIntent": "APPROVE",
            "signature": "0" * 64,
            "binding": preview["binding"],
        }
    )
    assert forged["status"] == "unavailable"
    assert world.fixture.state.count == 0
    # The trusted gesture (as signed by Electron main) executes exactly once.
    from aether.core.planning.authorizing_gesture import GestureBinding

    binding = GestureBinding(
        task_id=task_id,
        plan_revision=preview["binding"]["planRevision"],
        plan_hash=preview["binding"]["planHash"],
        preview_id=_step,
        preview_digest=preview["binding"]["previewDigest"],
        scope_digest=preview["binding"]["scopeDigest"],
    )
    gesture = authority.sign(nonce=preview["nonce"], binding=binding, user_intent="APPROVE")
    outcome = bridge.approve_fixture_interaction(
        {
            "taskId": str(task_id),
            "nonce": preview["nonce"],
            "assertedAt": gesture.asserted_at.isoformat(),
            "userIntent": "APPROVE",
            "signature": gesture.signature,
            "binding": preview["binding"],
        }
    )
    assert outcome["status"] == "ready" and outcome["outcome"] == "SUCCEEDED"
    assert world.fixture.state.count == 1
    # Nonce is single-use: replaying the same gesture fails.
    replay = bridge.approve_fixture_interaction(
        {
            "taskId": str(task_id),
            "nonce": preview["nonce"],
            "assertedAt": gesture.asserted_at.isoformat(),
            "userIntent": "APPROVE",
            "signature": gesture.signature,
            "binding": preview["binding"],
        }
    )
    assert replay["status"] == "unavailable"
    assert world.fixture.state.count == 1
    state = bridge.get_task_state({"taskId": str(task_id)})
    assert state["taskState"] == "COMPLETED"
    world.close()


def test_privacy_change_voids_snapshots_via_bridge(tmp_path: Path) -> None:
    bridge, world, _authority = _bridge(tmp_path)
    result = bridge.inspect_window({"windowId": world.window_id})
    assert result["status"] == "ready"
    snapshot_id = result["snapshotId"]
    bridge.set_privacy({"optedIn": True, "mode": "metadata_only"})
    assert world.snapshots.get(snapshot_id).outcome.value == "snapshot_expired"
    world.close()
