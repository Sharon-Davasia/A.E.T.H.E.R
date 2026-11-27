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
        self._project = str(project)
        self.calls: list[object] = []

    def __call__(self, hwnd: object = None) -> object:
        self.calls.append(hwnd)
        return self._project if hwnd == EXPLORER_HWND else None


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

        # An unrelated window never consumes the one-shot arm: the
        # subsequent real Explorer foreground completes it.
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
        deadline = time.monotonic() + 10.0
        check: dict = {}
        while time.monotonic() < deadline:
            check = bridge.check_project_context({})
            if check.get("status") == "ready":
                break
            time.sleep(0.05)
        assert check.get("status") == "ready", check
        assert [c["evidenceSource"] for c in check["projects"]] == ["explorer_registered"]
        assert explorer.calls == [EXPLORER_HWND]
    finally:
        assert comp.shutdown() is True
