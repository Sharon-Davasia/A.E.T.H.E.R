"""Native Windows observer source (Phase 3, corrected sec.2.1/2.2).

One dedicated native observer thread owns message-queue
initialization, ``SetWinEventHook`` registration, callback lifetime,
the message pump, unregistration and final cleanup — registration,
pumping and unregistration never happen on any other thread, as the
Win32 API requires. Startup completes only after the native thread
acknowledges initialization (bounded wait); a failed initialization
is reported truthfully and no hook is left registered. Shutdown keeps
its thread reference when a join times out and reports failure.

Metadata providers (ctypes, Windows-only): process creation time,
session id, minimal process name, elevation (unknown — never false —
when inspection fails), top-level window enumeration and foreground
identification. No command lines, environment, or document content
are inspected.

Activation remains disabled: ordinary startup never constructs this
class, the composition root does not import it, and ``start()``
requires an :class:`ActivationContext` mintable only by the future
trusted-composition factory or the explicit fake-API test seam.
Python module privacy is not claimed to be a security boundary; the
actual enablement security design is in PHASE3_R1_DESIGN/ADR-015.
"""

from __future__ import annotations

import contextlib
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from aether.world_state.observer import ObserverUnavailable, WindowEvent, WindowEventKind

EVENT_SYSTEM_FOREGROUND = 0x0003
EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_DESTROY = 0x8001
EVENT_OBJECT_SHOW = 0x8002
EVENT_OBJECT_HIDE = 0x8003
EVENT_OBJECT_STATECHANGE = 0x800A
OBJID_WINDOW = 0
CHILDID_SELF = 0

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
    issuer: str


_COMPOSITION_ISSUER = "aether-trusted-composition"


def _mint_activation_context() -> ActivationContext:  # pragma: no cover - future wiring
    return ActivationContext(issuer=_COMPOSITION_ISSUER)


class Win32ObserverApi(Protocol):
    """Injectable Win32 surface. All hook/pump calls are thread-affine."""

    def initialize_message_queue(self) -> None: ...
    def set_win_event_hook(
        self, event_type: int, callback: Callable[[int, int, int, int], None]
    ) -> int: ...
    def unhook_win_event(self, handle: int) -> bool: ...
    def message_pump(self, should_stop: Callable[[], bool]) -> None: ...
    def post_pump_quit(self) -> None: ...
    def get_window_process_id(self, hwnd: int) -> int: ...
    def get_process_creation_time(self, pid: int) -> str | None: ...
    def get_process_session_id(self, pid: int) -> int | None: ...
    def get_process_name(self, pid: int) -> str | None: ...
    def is_process_elevated(self, pid: int) -> bool | None: ...  # None = unknown
    def enumerate_windows(self) -> list[tuple[int, int]]: ...  # raises on failure
    def get_foreground_window(self) -> int: ...


def native_observer_available() -> tuple[bool, str]:
    if sys.platform != "win32":
        return (False, "native_observer_requires_windows")
    return (True, "available_but_not_activated")


class NativeWindowsEventSource:
    """WinEvent source whose dedicated thread owns all native state."""

    def __init__(self, *, api: Win32ObserverApi, activation: ActivationContext | None = None) -> None:
        self._api = api
        self._activation = activation
        self._thread: threading.Thread | None = None
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

    # -- lifecycle -------------------------------------------------------
    def start(self, emit: Callable[[WindowEvent], None], *, timeout: float = 5.0) -> None:
        if self._activation is None:
            raise NativeObserverDisabled(
                "native observation requires a trusted-composition activation context"
            )
        with self._lock:
            if self._thread is not None:
                return
            self._emit = emit
            self._stop.clear()
            started = threading.Event()
            failure: list[BaseException] = []

            def _run() -> None:
                hooks: list[int] = []
                try:
                    self._api.initialize_message_queue()
                    for event_type in _EVENT_MAP:
                        handle = self._api.set_win_event_hook(event_type, self._on_native_event)
                        if not handle:
                            raise ObserverUnavailable("SetWinEventHook registration failed")
                        hooks.append(handle)
                except BaseException as exc:  # initialization failure
                    failure.append(exc)
                    started.set()
                    return
                started.set()  # startup acknowledged only after hooks live
                try:
                    self._api.message_pump(lambda: self._stop.is_set())
                finally:
                    for handle in hooks:
                        with contextlib.suppress(Exception):
                            self._api.unhook_win_event(handle)

            thread = threading.Thread(target=_run, name="aether-native-observer", daemon=True)
            self._thread = thread
            thread.start()
            if not started.wait(timeout=timeout):
                self._stop.set()
                with contextlib.suppress(Exception):
                    self._api.post_pump_quit()
                raise ObserverUnavailable("native observer startup acknowledgement timed out")
            if failure:
                thread.join(timeout=timeout)
                self._thread = None
                self._emit = None
                raise ObserverUnavailable(f"native observer failed to start: {failure[0]}")

    def stop(self, timeout: float = 2.0) -> bool:
        """Bounded shutdown; False (thread retained) if it stays alive."""
        self._stop.set()
        with contextlib.suppress(Exception):
            self._api.post_pump_quit()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():
                return False  # reference retained; never discarded
            self._thread = None
        self._emit = None
        return True

    def reconcile(self) -> list[WindowEvent]:
        """Complete enumeration snapshot; failure raises (never empty)."""
        if self._activation is None:
            raise NativeObserverDisabled(
                "native observation requires a trusted-composition activation context"
            )
        windows = self._api.enumerate_windows()  # may raise -> uncertainty upstream
        foreground = 0
        with contextlib.suppress(Exception):
            foreground = self._api.get_foreground_window()
        events: list[WindowEvent] = []
        for hwnd, pid in windows:
            event_type = EVENT_SYSTEM_FOREGROUND if hwnd == foreground and hwnd else EVENT_OBJECT_SHOW
            events.append(self._normalize(event_type, hwnd, pid))
        return events

    # -- internals ---------------------------------------------------------
    def _on_native_event(self, event_type: int, hwnd: int, _id_object: int, _id_child: int) -> None:
        # Only top-level window events: child/accessibility object
        # events must not masquerade as window lifecycle events.
        if _id_object != OBJID_WINDOW or _id_child != CHILDID_SELF:
            return
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
        elevated: bool | None = None
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
            # None stays unknown: failed elevation inspection is
            # never represented as confirmed non-elevated.
            elevated=elevated,
            source="windows-winevent",
        )


class _CtypesWin32Api:  # pragma: no cover - exercised only on Windows
    """Real ctypes Win32 implementation (Windows only, not activated).

    Pointer-width-safe signatures are declared for every call used.
    """

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise ObserverUnavailable("native_observer_requires_windows")
        import ctypes

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
        user32 = self._user32
        user32.SetWinEventHook.restype = ctypes.c_void_p
        user32.SetWinEventHook.argtypes = [
            ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
        ]
        user32.UnhookWinEvent.restype = ctypes.c_bool
        user32.UnhookWinEvent.argtypes = [ctypes.c_void_p]
        user32.GetWindowThreadProcessId.restype = ctypes.c_uint
        user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]

    # -- hook/pump (observer thread only) ---------------------------------
    def initialize_message_queue(self) -> None:
        ctypes = self._ctypes
        self._thread_id = int(self._kernel32.GetCurrentThreadId())
        msg = ctypes.create_string_buffer(48)
        self._user32.PeekMessageW(msg, None, 0, 0, 0)  # create the queue

    def set_win_event_hook(self, event_type: int, callback: Any) -> int:
        def _hook(_h, event, hwnd, id_object, id_child, _t, _time):  # type: ignore[no-untyped-def]
            callback(int(event), int(hwnd or 0), int(id_object), int(id_child))

        c_callback = self._callback_type(_hook)
        self._callbacks.append(c_callback)
        handle = self._user32.SetWinEventHook(
            event_type, event_type, None, c_callback, 0, 0, 0  # WINEVENT_OUTOFCONTEXT
        )
        return int(handle or 0)

    def unhook_win_event(self, handle: int) -> bool:
        return bool(self._user32.UnhookWinEvent(handle))

    def message_pump(self, should_stop: Any) -> None:
        ctypes = self._ctypes
        msg = ctypes.create_string_buffer(48)
        while not should_stop():
            result = self._user32.GetMessageW(msg, None, 0, 0)
            if result in (0, -1):
                break
            self._user32.TranslateMessage(msg)
            self._user32.DispatchMessageW(msg)

    def post_pump_quit(self) -> None:
        if self._thread_id:
            self._user32.PostThreadMessageW(self._thread_id, 0x0012, 0, 0)

    # -- bounded metadata providers ----------------------------------------
    def get_window_process_id(self, hwnd: int) -> int:
        ctypes = self._ctypes
        pid = ctypes.c_uint(0)
        self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return int(pid.value)

    def _open_process(self, pid: int) -> Any:
        # PROCESS_QUERY_LIMITED_INFORMATION (0x1000) only.
        return self._kernel32.OpenProcess(0x1000, False, pid)

    def get_process_creation_time(self, pid: int) -> str | None:
        ctypes = self._ctypes
        handle = self._open_process(pid)
        if not handle:
            return None
        try:
            creation = ctypes.c_ulonglong(0)
            exit_time = ctypes.c_ulonglong(0)
            kernel = ctypes.c_ulonglong(0)
            user = ctypes.c_ulonglong(0)
            ok = self._kernel32.GetProcessTimes(
                handle, ctypes.byref(creation), ctypes.byref(exit_time),
                ctypes.byref(kernel), ctypes.byref(user),
            )
            if not ok:
                return None
            # FILETIME (100ns since 1601) -> unix seconds -> ISO.
            import datetime as _dt

            unix = (int(creation.value) - 116444736000000000) / 10_000_000
            return _dt.datetime.fromtimestamp(unix, tz=_dt.UTC).isoformat()
        finally:
            self._kernel32.CloseHandle(handle)

    def get_process_session_id(self, pid: int) -> int | None:
        ctypes = self._ctypes
        session = ctypes.c_uint(0)
        ok = self._kernel32.ProcessIdToSessionId(pid, ctypes.byref(session))
        return int(session.value) if ok else None

    def get_process_name(self, pid: int) -> str | None:
        ctypes = self._ctypes
        handle = self._open_process(pid)
        if not handle:
            return None
        try:
            size = ctypes.c_uint(1024)
            buffer = ctypes.create_unicode_buffer(1024)
            ok = self._kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
            if not ok:
                return None
            path = buffer.value
            return path.replace("\\", "/").rsplit("/", 1)[-1] or None
        finally:
            self._kernel32.CloseHandle(handle)

    def is_process_elevated(self, pid: int) -> bool | None:
        ctypes = self._ctypes
        handle = self._open_process(pid)
        if not handle:
            return None  # unknown, never "confirmed non-elevated"
        try:
            token = ctypes.c_void_p(0)
            if not self._ctypes.windll.advapi32.OpenProcessToken(handle, 0x0008, ctypes.byref(token)):
                return None
            try:
                elevation = ctypes.c_uint(0)
                returned = ctypes.c_uint(0)
                ok = self._ctypes.windll.advapi32.GetTokenInformation(
                    token, 20, ctypes.byref(elevation), ctypes.sizeof(elevation), ctypes.byref(returned)
                )
                if not ok:
                    return None
                return bool(elevation.value)
            finally:
                self._kernel32.CloseHandle(token)
        finally:
            self._kernel32.CloseHandle(handle)

    def enumerate_windows(self) -> list[tuple[int, int]]:
        ctypes = self._ctypes
        found: list[tuple[int, int]] = []
        callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def _enum(hwnd, _lparam):  # type: ignore[no-untyped-def]
            if self._user32.IsWindowVisible(hwnd) and not self._user32.GetParent(hwnd):
                found.append((int(hwnd), self.get_window_process_id(hwnd)))
            return True

        c_callback = callback_type(_enum)
        if not self._user32.EnumWindows(c_callback, None):
            raise ObserverUnavailable("EnumWindows failed")
        return found

    def get_foreground_window(self) -> int:
        return int(self._user32.GetForegroundWindow() or 0)
