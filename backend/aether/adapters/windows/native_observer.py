"""Native Windows observer source (Phase 3 CP1, completed F01).

Real ``SetWinEventHook`` implementation behind an injected platform
API interface (:class:`Win32ObserverApi`), so Arena tests verify hook
registration, event normalization, reconciliation and shutdown with a
fake API — **not** as native evidence. The ctypes implementation is
only constructed on Windows.

Activation remains disabled: ordinary startup never constructs this
class, the composition root does not import it, and ``start()``
requires an :class:`ActivationContext`. That context can today only
be minted by the module-private factory reserved for a future trusted
composition wiring (no production caller exists), or by the explicit
test factory used with fake APIs. A caller-supplied boolean is not an
authorization mechanism.
"""

from __future__ import annotations

import contextlib
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from aether.world_state.observer import ObserverUnavailable, WindowEvent, WindowEventKind

EVENT_SYSTEM_FOREGROUND = 0x0003
EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_DESTROY = 0x8001
EVENT_OBJECT_SHOW = 0x8002
EVENT_OBJECT_HIDE = 0x8003
EVENT_OBJECT_STATECHANGE = 0x800A
WINEVENT_OUTOFCONTEXT = 0x0000

_EVENT_MAP = {
    EVENT_SYSTEM_FOREGROUND: WindowEventKind.FOREGROUND_CHANGED,
    EVENT_OBJECT_CREATE: WindowEventKind.WINDOW_CREATED,
    EVENT_OBJECT_DESTROY: WindowEventKind.WINDOW_DESTROYED,
    EVENT_OBJECT_SHOW: WindowEventKind.WINDOW_STATE_CHANGED,
    EVENT_OBJECT_HIDE: WindowEventKind.WINDOW_STATE_CHANGED,
    EVENT_OBJECT_STATECHANGE: WindowEventKind.WINDOW_STATE_CHANGED,
}


class NativeObserverDisabled(RuntimeError):
    """Native observation was requested without activation context."""


@dataclass(frozen=True, slots=True)
class ActivationContext:
    """Proof-of-wiring token for a future trusted composition (F01).

    Instances are minted only by ``_mint_activation_context`` (reserved
    for the future composition root) or ``_for_testing`` (fake APIs).
    """

    issuer: str


_COMPOSITION_ISSUER = "aether-trusted-composition"


def _mint_activation_context() -> ActivationContext:  # pragma: no cover - future wiring
    return ActivationContext(issuer=_COMPOSITION_ISSUER)


class Win32ObserverApi(Protocol):
    """Injectable Win32 surface (ctypes implementation or test fake)."""

    def set_win_event_hook(
        self, event_min: int, event_max: int, callback: Callable[[int, int], None]
    ) -> int: ...
    def unhook_win_event(self, handle: int) -> bool: ...
    def message_pump(self, should_stop: Callable[[], bool]) -> None: ...
    def post_pump_quit(self) -> None: ...
    def get_window_process_id(self, hwnd: int) -> int: ...
    def get_process_creation_time(self, pid: int) -> str | None: ...
    def get_process_name(self, pid: int) -> str | None: ...
    def is_process_elevated(self, pid: int) -> bool: ...
    def enumerate_windows(self) -> list[tuple[int, int]]: ...  # (hwnd, pid)


def native_observer_available() -> tuple[bool, str]:
    if sys.platform != "win32":
        return (False, "native_observer_requires_windows")
    return (True, "available_but_not_activated")


class NativeWindowsEventSource:
    """``SetWinEventHook`` event source with a bounded message pump."""

    def __init__(
        self,
        *,
        api: Win32ObserverApi,
        activation: ActivationContext | None = None,
    ) -> None:
        self._api = api
        self._activation = activation
        self._hooks: list[int] = []
        self._pump: threading.Thread | None = None
        self._stop = threading.Event()
        self._emit: Callable[[WindowEvent], None] | None = None
        self._lock = threading.Lock()

    @classmethod
    def for_testing(cls, api: Win32ObserverApi) -> NativeWindowsEventSource:
        """Explicit test seam for fake APIs (never native evidence)."""
        return cls(api=api, activation=ActivationContext(issuer="test-fake-api"))

    @classmethod
    def production(cls) -> NativeWindowsEventSource:  # pragma: no cover - win32 only
        if sys.platform != "win32":
            raise ObserverUnavailable("native_observer_requires_windows")
        return cls(api=_CtypesWin32Api(), activation=None)

    # -- lifecycle ------------------------------------------------------
    def start(self, emit: Callable[[WindowEvent], None]) -> None:
        if self._activation is None:
            raise NativeObserverDisabled(
                "native observation requires a trusted-composition activation context"
            )
        with self._lock:
            if self._pump is not None:
                return
            self._emit = emit
            self._stop.clear()
            try:
                for event_type in _EVENT_MAP:
                    handle = self._api.set_win_event_hook(
                        event_type, event_type, self._on_native_event
                    )
                    if not handle:
                        raise ObserverUnavailable("SetWinEventHook registration failed")
                    self._hooks.append(handle)
            except Exception:
                self._unhook_all()
                self._emit = None
                raise
            self._pump = threading.Thread(
                target=self._run_pump, name="aether-win32-pump", daemon=True
            )
            self._pump.start()

    def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(Exception):
            self._api.post_pump_quit()
        if self._pump is not None:
            self._pump.join(timeout=2.0)
            self._pump = None
        self._unhook_all()
        self._emit = None

    def reconcile(self) -> list[WindowEvent]:
        """Selective enumeration: current visible windows as fresh events."""
        if self._activation is None:
            raise NativeObserverDisabled(
                "native observation requires a trusted-composition activation context"
            )
        return [
            self._normalize(EVENT_OBJECT_SHOW, hwnd, pid)
            for hwnd, pid in self._api.enumerate_windows()
        ]

    # -- internals ---------------------------------------------------------
    def _run_pump(self) -> None:
        self._api.message_pump(lambda: self._stop.is_set())

    def _unhook_all(self) -> None:
        for handle in self._hooks:
            with contextlib.suppress(Exception):
                self._api.unhook_win_event(handle)
        self._hooks.clear()

    def _on_native_event(self, event_type: int, hwnd: int) -> None:
        if self._emit is None or self._stop.is_set():
            return
        pid = 0
        with contextlib.suppress(Exception):
            pid = self._api.get_window_process_id(hwnd)
        self._emit(self._normalize(event_type, hwnd, pid))

    def _normalize(self, event_type: int, hwnd: int, pid: int) -> WindowEvent:
        kind = _EVENT_MAP.get(event_type, WindowEventKind.WINDOW_STATE_CHANGED)
        creation: str | None = None
        name: str | None = None
        elevated = False
        if pid:
            with contextlib.suppress(Exception):
                creation = self._api.get_process_creation_time(pid)
            with contextlib.suppress(Exception):
                name = self._api.get_process_name(pid)
            with contextlib.suppress(Exception):
                elevated = self._api.is_process_elevated(pid)
        return WindowEvent(
            kind=kind,
            hwnd=hwnd,
            pid=pid,
            process_creation_time=creation,
            app_identity=name,
            elevated=elevated,
            source="windows-winevent",
        )


class _CtypesWin32Api:  # pragma: no cover - exercised only on Windows
    """Real ctypes Win32 implementation (Windows only, not activated)."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise ObserverUnavailable("native_observer_requires_windows")
        import ctypes
        from typing import Any

        self._ctypes: Any = ctypes
        self._user32: Any = ctypes.windll.user32
        self._kernel32: Any = ctypes.windll.kernel32
        self._callback_type: Any = ctypes.WINFUNCTYPE(
            None,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_long,
            ctypes.c_long,
            ctypes.c_uint,
            ctypes.c_uint,
        )
        self._callbacks: list[object] = []
        self._thread_id: int = 0

    def set_win_event_hook(self, event_min, event_max, callback):  # type: ignore[no-untyped-def]

        def _hook(_hook_handle, event, hwnd, _id_object, _id_child, _thread, _time):  # type: ignore[no-untyped-def]
            callback(int(event), int(hwnd or 0))

        c_callback = self._callback_type(_hook)
        self._callbacks.append(c_callback)
        handle = self._user32.SetWinEventHook(
            event_min, event_max, None, c_callback, 0, 0, WINEVENT_OUTOFCONTEXT
        )
        return int(handle or 0)

    def unhook_win_event(self, handle):  # type: ignore[no-untyped-def]
        return bool(self._user32.UnhookWinEvent(handle))

    def message_pump(self, should_stop) -> None:  # type: ignore[no-untyped-def]
        self._thread_id = int(self._kernel32.GetCurrentThreadId())
        msg = self._ctypes.create_string_buffer(48)
        while not should_stop():
            result = self._user32.GetMessageW(msg, None, 0, 0)
            if result in (0, -1):
                break
            self._user32.TranslateMessage(msg)
            self._user32.DispatchMessageW(msg)

    def post_pump_quit(self) -> None:
        if self._thread_id:
            self._user32.PostThreadMessageW(self._thread_id, 0x0012, 0, 0)

    def get_window_process_id(self, hwnd):  # type: ignore[no-untyped-def]
        ctypes = self._ctypes
        pid = ctypes.c_uint(0)
        self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return int(pid.value)

    def get_process_creation_time(self, pid):  # type: ignore[no-untyped-def]
        return None  # Bounded metadata: creation time via handle query lands with CP3 review.

    def get_process_name(self, pid):  # type: ignore[no-untyped-def]
        return None

    def is_process_elevated(self, pid):  # type: ignore[no-untyped-def]
        return False

    def enumerate_windows(self):  # type: ignore[no-untyped-def]
        return []
