"""Raw Windows-API fakes for the controlled-provider construction path.

These fakes simulate only the Windows platform boundary (discovery
sources, CreateProcess, WinEvent hooks, process inspection). Every
provider above them — launch adapter, event source, observation
provider, UIA backend, worker supervisor — is the real production
object constructed by ``build_native_platform``. Nothing here is
native evidence, and the desktop app never selects this module.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from aether.adapters.windows.discovery import (
    DiscoveredAppCandidate,
    SourceStatus,
)
from aether.core.apps.composition import NativePlatformSeams
from aether.core.apps.launch_authority import FakeIntegrityVerifier, IntegrityEvidence
from aether.core.contracts.app_window import location_identity_digest

FAKE_NOTEPAD_EXE = "C:\\Windows\\notepad.exe"
_FIXTURE_EXE = str(
    Path(__file__).resolve().parents[4] / "tools" / "windows-fixture" / "AETHERFixture.exe"
)


@dataclass
class FakeWindowsState:
    """Shared fake platform state (processes/windows/foreground)."""

    windows: dict[int, tuple[int, str]] = field(default_factory=dict)  # hwnd -> (pid, exe)
    foreground: int | None = None
    hooks: dict[int, Callable[..., None]] = field(default_factory=dict)
    _next_pid: int = 4242
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def spawn(self, executable: str) -> int:
        with self._lock:
            pid = self._next_pid
            self._next_pid += 1
            # The simulated UIA worker serves the fixture tree at the
            # fixture's documented fake HWND.
            from aether.core.apps.fixture import FIXTURE_HWND

            hwnd = FIXTURE_HWND
            self.windows[hwnd] = (pid, executable)
            self.foreground = hwnd
            callbacks = list(self.hooks.values())
        for callback in callbacks:
            callback(0x8002, hwnd, 0, 0)  # EVENT_OBJECT_SHOW, OBJID_WINDOW
        return pid

    def activate(self, hwnd: int) -> bool:
        if hwnd not in self.windows:
            return False
        self.foreground = hwnd
        for callback in list(self.hooks.values()):
            callback(0x0003, hwnd, 0, 0)  # EVENT_SYSTEM_FOREGROUND
        return True


class _FakeDiscoveryProviders:
    def __init__(self, state: FakeWindowsState) -> None:
        self._state = state

    def start_menu_shortcuts(self) -> tuple[list[DiscoveredAppCandidate], SourceStatus]:
        return (
            [
                DiscoveredAppCandidate(
                    display_name="Notepad",
                    executable_identity=FAKE_NOTEPAD_EXE,
                    publisher="Fake",
                    source="user_registered_portable",
                )
            ],
            SourceStatus(source="start_menu_shortcut", status="ok"),
        )

    def uninstall_entries(self) -> tuple[list[DiscoveredAppCandidate], SourceStatus]:
        return ([], SourceStatus(source="uninstall_registry", status="ok"))

    def apps_folder_entries(self) -> tuple[list[DiscoveredAppCandidate], SourceStatus]:
        return ([], SourceStatus(source="apps_folder", status="ok"))


class _FakeLaunchApi:
    def __init__(self, state: FakeWindowsState) -> None:
        self._state = state

    def create_process(self, canonical_executable: str) -> tuple[int, object, object]:
        pid = self._state.spawn(canonical_executable)
        return pid, object(), object()

    def activate_application(self, app_user_model_id: str) -> int:
        return self._state.spawn(app_user_model_id)

    def close_handle(self, handle: object) -> None:
        return None

    def get_process_creation_time(self, pid: int) -> str | None:
        return "fake-creation-1"


class _FakeObserverApi:
    def __init__(self, state: FakeWindowsState) -> None:
        self._state = state
        self._next_handle = 1

    def initialize_message_queue(self) -> None:
        return None

    def set_win_event_hook(self, event_type: int, callback: Callable[..., None]) -> int:
        handle = self._next_handle
        self._next_handle += 1
        self._state.hooks[handle] = callback
        return handle

    def unhook_win_event(self, handle: int) -> bool:
        self._state.hooks.pop(handle, None)
        return True

    def message_pump(self, should_stop: object) -> None:
        while not should_stop():  # type: ignore[operator]
            time.sleep(0.01)

    def post_pump_quit(self) -> None:
        return None

    def get_window_process_id(self, hwnd: int) -> int:
        return self._state.windows.get(hwnd, (0, ""))[0]

    def get_process_creation_time(self, pid: int) -> str | None:
        return "fake-creation-1"

    def get_process_session_id(self, pid: int) -> int | None:
        return 1

    def get_process_name(self, pid: int) -> str | None:
        for _hwnd, (p, exe) in self._state.windows.items():
            if p == pid:
                return exe
        return None

    def is_process_elevated(self, pid: int) -> bool | None:
        return False

    def enumerate_windows(self) -> list[tuple[int, int]]:
        return [(hwnd, pid) for hwnd, (pid, _exe) in self._state.windows.items()]

    def get_foreground_window(self) -> int:
        return self._state.foreground or 0


class _FakeForegroundProvider:
    def __init__(self, state: FakeWindowsState) -> None:
        self._state = state

    def activate(self, hwnd: int) -> bool:
        return self._state.activate(hwnd)

    def foreground_hwnd(self) -> int | None:
        return self._state.foreground


def _evidence(executable: str) -> IntegrityEvidence:
    return IntegrityEvidence(
        location_digest=location_identity_digest(executable) or "",
        content_sha256="b" * 64,
        signer_identity="FakeSigner",
        package_identity=None,
        verified_at=datetime.now(UTC),
        file_identity="3:42:100:1",
    )


def fixture_executable() -> str:
    return _FIXTURE_EXE


def build_fake_seams() -> NativePlatformSeams:
    """Raw fake seams feeding the real provider construction path."""
    from aether.adapters.windows.native_activity import FakeActivitySource
    from aether.core.workers.subprocess_supervisor import default_worker_command

    state = FakeWindowsState()
    verifier = FakeIntegrityVerifier(
        evidence_by_location={
            location_identity_digest(FAKE_NOTEPAD_EXE) or "": _evidence(FAKE_NOTEPAD_EXE),
            location_identity_digest(_FIXTURE_EXE) or "": _evidence(_FIXTURE_EXE),
        }
    )
    return NativePlatformSeams(
        discovery_providers=_FakeDiscoveryProviders(state),
        launch_api=_FakeLaunchApi(state),
        observer_api=_FakeObserverApi(state),
        integrity_verifier=verifier,
        activity_factory=lambda emit_to: FakeActivitySource(emit_to=emit_to),
        foreground_provider=_FakeForegroundProvider(state),
        explorer_folder=lambda: None,
        worker_command=default_worker_command(simulated=True),
        pywinauto_module=_FakePywinautoModule(state),
    )


class _FakeElementInfo:
    def __init__(self, **kwargs: object) -> None:
        self.runtime_id = kwargs.get("runtime_id")
        self.control_type = kwargs.get("control_type", "Window")
        self.name = kwargs.get("name", "")
        self.automation_id = kwargs.get("automation_id", "")
        self.enabled = True
        self.is_offscreen = False
        self.is_password = False
        self.handle = 0
        self.iface_invoke = object() if kwargs.get("invoke") else None
        self.iface_value = None
        self.iface_selection_item = None
        self.iface_toggle = None
        self.iface_expand_collapse = None
        from types import SimpleNamespace

        self.rectangle = SimpleNamespace(left=0, top=0, right=10, bottom=10)


class _FakeElement:
    def __init__(self, info: _FakeElementInfo, children: list[_FakeElement] | None = None) -> None:
        self.element_info = info
        self._children = children or []
        self.invoked = False

    def children(self) -> list[_FakeElement]:
        return list(self._children)

    def exists(self, timeout: float = 0) -> bool:
        return True

    def invoke(self) -> None:
        self.invoked = True


class _FakeDesktop:
    def __init__(self, state: FakeWindowsState) -> None:
        self._state = state

    def window(self, handle: int) -> _FakeElement:
        status = _FakeElement(
            _FakeElementInfo(
                runtime_id=(1, 1), control_type="Text", name="Count: 0", automation_id="101"
            )
        )
        increment = _FakeElement(
            _FakeElementInfo(
                runtime_id=(1, 2),
                control_type="Button",
                name="Increment",
                automation_id="102",
                invoke=True,
            )
        )
        root = _FakeElement(
            _FakeElementInfo(
                runtime_id=(1,), control_type="Window", name="AETHER Fixture", automation_id="201"
            ),
            [status, increment],
        )
        if handle not in self._state.windows:
            root.exists = lambda timeout=0: False  # type: ignore[method-assign]
        return root


class _FakePywinautoModule:
    """Module-object fake standing in for pywinauto (raw API level)."""

    def __init__(self, state: FakeWindowsState) -> None:
        self._state = state

    def Desktop(self, backend: str) -> _FakeDesktop:
        return _FakeDesktop(self._state)
