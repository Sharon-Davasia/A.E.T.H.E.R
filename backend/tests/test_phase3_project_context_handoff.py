"""C2: desktop-to-backend project-context interaction contract.

The panel click can never be its own evidence: Explorer folder
collection happens only when a *verified foreground-change event*
for an Explorer window arrives inside a one-shot arm established
through the trusted path, and a successful check must rest on that
actual, fresh captured evidence.

Fake platform seams only; nothing here is native Windows evidence.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from test_phase3_controlled_native import COMMIT, GESTURE_KEY
from test_phase3_workspace_layout import _authz, _open_store

from aether.adapters.windows.fake_windows import build_fake_seams
from aether.core.apps.composition import Phase3Composition, build_native_platform

EXPLORER_HWND = 777
OTHER_HWND = 888


class _ExplorerByHwnd:
    """Foreground-Explorer provider keyed by verified window id."""

    def __init__(self, project: Path) -> None:
        self.folder = str(project)
        self.calls: list[object] = []
        self.on_call = None  # optional side effect during collection

    def __call__(self, hwnd: object = None) -> object:
        self.calls.append(hwnd)
        if self.on_call is not None:
            self.on_call()
        return self.folder if hwnd == EXPLORER_HWND else None


def _start(tmp_path: Path, *, clock=None, expires_at: datetime | None = None):  # type: ignore[no-untyped-def]
    authz = _authz(tmp_path, expires_at=expires_at or (datetime.now(UTC) + timedelta(hours=2)))
    store = _open_store(authz, now=datetime.now(UTC))
    store.close()
    workspace = Path(authz.workspace_path)
    project = workspace / "synthetic-project"
    project.mkdir(parents=True, exist_ok=True)
    (project / "pyproject.toml").write_text('[project]\nname = "synthetic"\n', encoding="utf-8")
    seams = build_fake_seams()
    explorer = _ExplorerByHwnd(project)
    seams.explorer_folder = explorer  # type: ignore[attr-defined]
    providers = build_native_platform(authz, seams=seams)
    comp = Phase3Composition.native(
        authorization=authz,
        current_commit=COMMIT,
        storage_dir=Path(authz.storage_path),
        gesture_key=GESTURE_KEY,
        platform=providers,
        clock=clock,
    )
    bridge = comp.bridge
    assert (
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})["status"]
        == "ready"
    )
    registered = bridge.register_project({"alias": "project", "path": str(project)})
    assert registered["status"] == "ready", registered
    return comp, explorer, project


def test_foreground_mismatch_and_missing_evidence(tmp_path: Path) -> None:
    comp, explorer, _project = _start(tmp_path)
    try:
        bridge = comp.bridge
        # No arm: no evidence, no provider contact.
        assert bridge.check_project_context({})["reason"] == "explorer_evidence_unavailable"
        assert explorer.calls == []

        # Foreground mismatch: the foreground window is not an
        # Explorer window, so nothing is captured and the arm is
        # NOT consumed.
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(OTHER_HWND)
        assert bridge.check_project_context({})["reason"] == "explorer_evidence_unavailable"

        # An unrelated window never consumes the one-shot arm - but
        # that failed completion attempt DID purge the backend
        # handoff (every completion is single-use). Re-arming lets
        # the real Explorer foreground complete the check.
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(EXPLORER_HWND)
        check = bridge.check_project_context({})
        assert check["status"] == "ready"
        assert [c["evidenceSource"] for c in check["projects"]] == ["explorer_registered"]
        assert explorer.calls == [OTHER_HWND, EXPLORER_HWND]
    finally:
        assert comp.shutdown() is True


def test_cancellation_drops_arm_and_evidence(tmp_path: Path) -> None:
    comp, explorer, _project = _start(tmp_path)
    try:
        bridge = comp.bridge
        assert bridge.arm_project_context({})["status"] == "armed"
        assert bridge.cancel_project_context({})["status"] == "ready"
        # After cancellation a foreground event collects nothing.
        comp.project_context_capture(EXPLORER_HWND)
        assert explorer.calls == []
        assert bridge.check_project_context({})["reason"] == "explorer_evidence_unavailable"

        # Captured evidence is likewise dropped by cancellation.
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(EXPLORER_HWND)
        assert bridge.cancel_project_context({})["status"] == "ready"
        assert bridge.check_project_context({})["reason"] == "explorer_evidence_unavailable"
    finally:
        assert comp.shutdown() is True


def test_arm_and_evidence_expiry_with_deterministic_clock(tmp_path: Path) -> None:
    start = datetime.now(UTC)
    now_holder = [start]
    comp, explorer, _project = _start(
        tmp_path,
        clock=lambda: now_holder[0],
        expires_at=start + timedelta(hours=2),
    )
    try:
        bridge = comp.bridge
        # Arm TTL (60 s) expiry: a later foreground event is ignored.
        assert bridge.arm_project_context({})["status"] == "armed"
        now_holder[0] = start + timedelta(seconds=61)
        comp.project_context_capture(EXPLORER_HWND)
        assert explorer.calls == []
        assert bridge.check_project_context({})["reason"] == "explorer_evidence_unavailable"

        # Captured-evidence freshness (60 s): capture, then let it
        # go stale before completing the check.
        now_holder[0] = start + timedelta(seconds=70)
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(EXPLORER_HWND)
        assert explorer.calls == [EXPLORER_HWND]
        now_holder[0] = start + timedelta(seconds=131)
        assert bridge.check_project_context({})["reason"] == "explorer_evidence_unavailable"

        # Authorization expiry: arming and capture both refuse.
        now_holder[0] = start + timedelta(hours=3)
        assert bridge.arm_project_context({})["status"] == "unavailable"
        comp.project_context_capture(EXPLORER_HWND)
        assert explorer.calls == [EXPLORER_HWND]
        assert bridge.check_project_context({})["status"] == "unavailable"
    finally:
        assert comp.shutdown() is True


def test_revocation_and_privacy_generation_invalidate(tmp_path: Path) -> None:
    comp, explorer, _project = _start(tmp_path)
    try:
        bridge = comp.bridge
        # Privacy generation change cancels the arm.
        assert bridge.arm_project_context({})["status"] == "armed"
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": True})
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
        comp.project_context_capture(EXPLORER_HWND)
        assert explorer.calls == []
        assert bridge.check_project_context({})["reason"] == "explorer_evidence_unavailable"

        # Revocation refuses arm, capture and check.
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(EXPLORER_HWND)
        comp.revoke("test_revocation")
        assert bridge.arm_project_context({})["status"] == "unavailable"
        assert bridge.check_project_context({})["status"] == "unavailable"
    finally:
        assert comp.shutdown() is True


def test_real_foreground_event_path_via_fake_platform(tmp_path: Path) -> None:
    """End-to-end over the event boundary: opt-in starts the real
    observer over fake seams; arming plus a genuine fake foreground
    activation produces the captured evidence (no polling by the
    backend - this test merely waits for the event pipeline)."""
    comp, explorer, _project = _start(tmp_path)
    try:
        bridge = comp.bridge
        assert bridge.arm_project_context({})["status"] == "armed"
        # Drive a real foreground change through the fake platform:
        # the fake state is reachable through the event source's API.
        source = comp.observer_service.source  # type: ignore[attr-defined]
        api = getattr(source, "_api", None) or getattr(source, "api", None)
        seams_state = getattr(api, "_state", None)  # FakeWindowsState
        assert seams_state is not None, "fake platform state not reachable"
        seams_state.windows[EXPLORER_HWND] = (5150, "explorer.exe")
        assert seams_state.activate(EXPLORER_HWND) is True
        # Wait for the foreground-event CAPTURE itself - repeatedly
        # invoking the single-use completion would consume the
        # handoff before the evidence exists.
        captured = None
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            captured = comp.surface.project_context_captured()
            if captured is not None:
                break
            time.sleep(0.05)
        assert captured is not None, "foreground capture never landed"
        check = bridge.check_project_context({})
        assert check.get("status") == "ready", check
        assert [c["evidenceSource"] for c in check["projects"]] == ["explorer_registered"]
        assert explorer.calls == [EXPLORER_HWND]
    finally:
        assert comp.shutdown() is True


def test_direct_revocation_before_capture(tmp_path: Path) -> None:
    """Revoking the composition directly (no privacy-detour) kills
    the armed handoff: the foreground event collects nothing."""
    comp, explorer, _project = _start(tmp_path)
    try:
        bridge = comp.bridge
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.revoke("test_direct_revocation")
        comp.project_context_capture(EXPLORER_HWND)
        assert explorer.calls == []
        assert bridge.check_project_context({})["status"] == "unavailable"
    finally:
        assert comp.shutdown() is True


def test_out_of_scope_folder_never_retained(tmp_path: Path) -> None:
    """Scope is validated before retention: an Explorer folder
    outside the registered workspace is never stored as evidence."""
    comp, explorer, _project = _start(tmp_path)
    try:
        bridge = comp.bridge
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        explorer.folder = str(elsewhere)
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(EXPLORER_HWND)
        assert explorer.calls == [EXPLORER_HWND]  # collection happened
        # ... but nothing was retained, so no check can rest on it.
        assert comp.surface.project_context_captured() is None
        check = bridge.check_project_context({})
        assert check["status"] == "unavailable"
        assert check["reason"] == "explorer_evidence_unavailable"
    finally:
        assert comp.shutdown() is True


def test_duplicate_completion_never_returns_same_evidence(tmp_path: Path) -> None:
    """Every completion attempt consumes and purges the handoff."""
    comp, explorer, _project = _start(tmp_path)
    try:
        bridge = comp.bridge
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(EXPLORER_HWND)
        assert bridge.check_project_context({})["status"] == "ready"
        # The same evidence can never complete a second check.
        second = bridge.check_project_context({})
        assert second["status"] == "unavailable"
        assert second["reason"] == "explorer_evidence_unavailable"
        # And a fresh foreground event alone cannot resurrect it:
        # the arm was consumed by the first completion.
        comp.project_context_capture(EXPLORER_HWND)
        assert explorer.calls == [EXPLORER_HWND]
        assert bridge.check_project_context({})["reason"] == "explorer_evidence_unavailable"
    finally:
        assert comp.shutdown() is True


def test_invalidation_during_native_collection(tmp_path: Path) -> None:
    """Authorization is rechecked AFTER native collection: a pause
    landing while the provider runs voids the sample before it is
    retained."""
    comp, explorer, _project = _start(tmp_path)
    try:
        bridge = comp.bridge
        explorer.on_call = lambda: bridge.set_privacy(
            {"optedIn": True, "mode": "metadata_only", "paused": True}
        )
        assert bridge.arm_project_context({})["status"] == "armed"
        comp.project_context_capture(EXPLORER_HWND)
        assert explorer.calls == [EXPLORER_HWND]  # collection ran...
        assert comp.surface.project_context_captured() is None  # ...not retained
        assert bridge.check_project_context({})["status"] == "unavailable"
    finally:
        assert comp.shutdown() is True
