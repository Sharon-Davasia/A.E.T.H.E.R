"""Sec.2.1 tests: native thread ownership via thread-affine fake API.

Injected fake only — not native Windows evidence.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

import pytest

from aether.adapters.windows.native_observer import (
    EVENT_OBJECT_CREATE,
    EVENT_SYSTEM_FOREGROUND,
    NativeObserverDisabled,
    NativeWindowsEventSource,
)
from aether.world_state.observer import ObserverUnavailable, WindowEventKind


class ThreadAffineFakeApi:
    """Fake Win32 API that enforces single-thread (observer) affinity."""

    def __init__(self, *, fail_hook: bool = False) -> None:
        self.owner_thread: int | None = None
        self.violations: list[str] = []
        self.hooks: dict[int, Callable] = {}  # type: ignore[type-arg]
        self.unhooked: list[int] = []
        self.pump_thread: int | None = None
        self.fail_hook = fail_hook
        self.enumerate_error: Exception | None = None
        self.elevated: bool | None = None

    def _affine(self, what: str) -> None:
        current = threading.get_ident()
        if self.owner_thread is None:
            self.owner_thread = current
        elif current != self.owner_thread:
            self.violations.append(what)
            raise AssertionError(f"{what} called on wrong thread")

    def initialize_message_queue(self) -> None:
        self._affine("init")

    def set_win_event_hook(self, event_type, callback):  # type: ignore[no-untyped-def]
        self._affine("hook")
        if self.fail_hook:
            return 0
        self.hooks[event_type] = callback
        return 1000 + event_type

    def unhook_win_event(self, handle: int) -> bool:
        self._affine("unhook")
        self.unhooked.append(handle)
        return True

    def message_pump(self, should_stop) -> None:  # type: ignore[no-untyped-def]
        self._affine("pump")
        self.pump_thread = threading.get_ident()
        while not should_stop():
            time.sleep(0.005)

    def post_pump_quit(self) -> None:
        return None

    def get_window_process_id(self, hwnd: int) -> int:
        return 4242

    def get_process_creation_time(self, pid: int) -> str | None:
        return "2026-11-15T00:00:00+00:00"

    def get_process_session_id(self, pid: int) -> int | None:
        return 1

    def get_process_name(self, pid: int) -> str | None:
        return "notepad.exe"

    def is_process_elevated(self, pid: int) -> bool | None:
        return self.elevated

    def enumerate_windows(self) -> list[tuple[int, int]]:
        if self.enumerate_error is not None:
            raise self.enumerate_error
        return [(7, 4242)]

    def get_foreground_window(self) -> int:
        return 7


def test_hook_pump_unhook_all_on_observer_thread() -> None:
    api = ThreadAffineFakeApi()
    source = NativeWindowsEventSource.for_testing(api)
    seen = []
    source.start(seen.append)
    assert api.violations == []
    api.hooks[EVENT_SYSTEM_FOREGROUND](EVENT_SYSTEM_FOREGROUND, 7, 0, 0)
    assert seen and seen[-1].kind is WindowEventKind.FOREGROUND_CHANGED
    # Child-object events are not window events.
    before = len(seen)
    api.hooks[EVENT_OBJECT_CREATE](EVENT_OBJECT_CREATE, 7, 0, 5)
    assert len(seen) == before
    assert source.stop() is True
    assert len(api.unhooked) == len(api.hooks)
    assert api.violations == []  # would have raised on wrong-thread calls


def test_failed_hook_startup_reports_and_cleans_up() -> None:
    api = ThreadAffineFakeApi(fail_hook=True)
    source = NativeWindowsEventSource.for_testing(api)
    with pytest.raises(ObserverUnavailable):
        source.start(lambda event: None)
    # No hooks survive a failed startup; retry with working API works.
    api.fail_hook = False
    source.start(lambda event: None)
    assert source.stop() is True


def test_unknown_elevation_and_failed_enumeration_are_truthful() -> None:
    api = ThreadAffineFakeApi()
    api.elevated = None  # inspection failed
    source = NativeWindowsEventSource.for_testing(api)
    events = source.reconcile()
    assert events and events[0].elevated is None
    api.enumerate_error = RuntimeError("enumeration failed")
    with pytest.raises(RuntimeError):
        source.reconcile()  # never a successful empty snapshot


def test_activation_still_required() -> None:
    source = NativeWindowsEventSource(api=ThreadAffineFakeApi(), activation=None)
    with pytest.raises(NativeObserverDisabled):
        source.start(lambda event: None)
