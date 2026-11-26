"""F01/F02 tests: native observer/discovery via injected fakes.

Platform-interface fakes only — these are NOT native Windows evidence.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from aether.adapters.windows.discovery import (
    DiscoveredAppCandidate,
    SourceStatus,
    discover_applications,
)
from aether.adapters.windows.native_observer import (
    EVENT_OBJECT_CREATE,
    EVENT_OBJECT_DESTROY,
    EVENT_SYSTEM_FOREGROUND,
    NativeObserverDisabled,
    NativeWindowsEventSource,
)
from aether.world_state.observer import WindowEventKind


class FakeWin32Api:
    def __init__(self) -> None:
        self.hooks: dict[int, Callable[[int, int], None]] = {}
        self.unhooked: list[int] = []
        self.pump_ran = False
        self._next = 100

    def set_win_event_hook(self, event_min: int, event_max: int, callback) -> int:  # type: ignore[no-untyped-def]
        self._next += 1
        self.hooks[event_min] = callback
        return self._next

    def unhook_win_event(self, handle: int) -> bool:
        self.unhooked.append(handle)
        return True

    def message_pump(self, should_stop) -> None:  # type: ignore[no-untyped-def]
        self.pump_ran = True
        import time

        while not should_stop():
            time.sleep(0.005)

    def post_pump_quit(self) -> None:
        return None

    def get_window_process_id(self, hwnd: int) -> int:
        return 4242

    def get_process_creation_time(self, pid: int) -> str | None:
        return "2026-11-15T00:00:00+00:00"

    def get_process_name(self, pid: int) -> str | None:
        return "notepad.exe"

    def is_process_elevated(self, pid: int) -> bool:
        return False

    def enumerate_windows(self) -> list[tuple[int, int]]:
        return [(7, 4242), (8, 4242)]


def test_native_source_registers_hooks_normalizes_and_unhooks() -> None:
    api = FakeWin32Api()
    source = NativeWindowsEventSource.for_testing(api)
    seen = []
    source.start(seen.append)
    assert EVENT_SYSTEM_FOREGROUND in api.hooks and EVENT_OBJECT_CREATE in api.hooks
    api.hooks[EVENT_SYSTEM_FOREGROUND](EVENT_SYSTEM_FOREGROUND, 7)
    assert seen and seen[-1].kind is WindowEventKind.FOREGROUND_CHANGED
    assert seen[-1].pid == 4242 and seen[-1].source == "windows-winevent"
    api.hooks[EVENT_OBJECT_DESTROY](EVENT_OBJECT_DESTROY, 7)
    assert seen[-1].kind is WindowEventKind.WINDOW_DESTROYED
    source.stop()
    assert len(api.unhooked) == len(api.hooks)


def test_native_source_requires_activation_context() -> None:
    source = NativeWindowsEventSource(api=FakeWin32Api(), activation=None)
    with pytest.raises(NativeObserverDisabled):
        source.start(lambda event: None)
    with pytest.raises(NativeObserverDisabled):
        source.reconcile()


def test_native_reconcile_enumerates_current_windows() -> None:
    source = NativeWindowsEventSource.for_testing(FakeWin32Api())
    events = source.reconcile()
    assert len(events) == 2 and all(e.hwnd in (7, 8) for e in events)


class FakeDiscoveryProviders:
    def start_menu_shortcuts(self):  # type: ignore[no-untyped-def]
        return (
            [DiscoveredAppCandidate("Notepad", None, None, "start_menu_shortcut")],
            SourceStatus("start_menu_shortcut", "ok"),
        )

    def uninstall_entries(self):  # type: ignore[no-untyped-def]
        return (
            [
                DiscoveredAppCandidate(
                    "Notepad", "C:\\Fake\\notepad.exe", "FakeSoft", "uninstall_registry"
                )
            ],
            SourceStatus("uninstall_registry", "ok"),
        )

    def apps_folder_entries(self):  # type: ignore[no-untyped-def]
        return ([], SourceStatus("apps_folder", "unavailable", "shell_com_deferred"))


def test_discovery_batch_keeps_truthful_source_status() -> None:
    batch = discover_applications(
        FakeDiscoveryProviders(),
        portable_registrations=(
            DiscoveredAppCandidate(
                "Portable Tool", "D:\\Tools\\tool.exe", None, "user_registered_portable"
            ),
        ),
    )
    sources = {status.source: status.status for status in batch.statuses}
    assert sources["apps_folder"] == "unavailable"  # never empty-success
    assert sources["user_registered_portable"] == "ok"
    assert len(batch.candidates) == 3
