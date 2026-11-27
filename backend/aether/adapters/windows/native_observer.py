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
    # A03: the validated bootstrap bindings are retained and enforced,
    # never discarded after validation.
    session_id: str = ""
    activation_epoch: str = ""
    activation_scope: str = ""
    worker_id: str = ""
    permitted_operations: frozenset[str] = frozenset({"inspect", "invoke", "health", "shutdown"})
    expires_at: float = 0.0  # epoch seconds; 0 = no expiry minted

    def operation_permitted(self, operation: str, *, now: float) -> bool:
        if self.expires_at and now > self.expires_at:
            return False
        return operation in self.permitted_operations


_COMPOSITION_ISSUER = "aether-trusted-composition"


def _mint_activation_context() -> ActivationContext:  # pragma: no cover - future wiring
    return ActivationContext(issuer=_COMPOSITION_ISSUER)


def activation_context_from_parent_bootstrap(payload: object) -> ActivationContext:
    """Mint an activation context from a parent-owned bootstrap.

    The bootstrap arrives only over the worker's private parent-owned
    stdin pipe before any request is served (the same trusted
    bootstrap channel the desktop service uses). It must name the
    trusted-composition issuer and bounded session/epoch/scope
    identities; anything else is refused and the worker never starts.
    This is not an environment flag, CLI argument or importable token:
    without a parent that owns the pipe and writes this first line,
    no context exists.
    """
    if not isinstance(payload, dict):
        raise ValueError("worker bootstrap is malformed")
    if payload.get("issuer") != _COMPOSITION_ISSUER:
        raise ValueError("worker bootstrap issuer is not trusted")
    for field_name in ("session_id", "activation_epoch", "activation_scope"):
        value = payload.get(field_name)
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError("worker bootstrap identity is malformed")
    operations = payload.get("permitted_operations", ["inspect", "invoke", "health", "shutdown"])
    if (
        not isinstance(operations, list)
        or not operations
        or not all(
            isinstance(o, str) and o in ("inspect", "invoke", "health", "shutdown")
            for o in operations
        )
    ):
        raise ValueError("worker bootstrap operations are malformed")
    expires = payload.get("expires_at", 0)
    if not isinstance(expires, (int, float)) or isinstance(expires, bool) or expires < 0:
        raise ValueError("worker bootstrap expiry is malformed")
    import time as _time

    if expires and _time.time() > float(expires):
        raise ValueError("worker bootstrap has expired")
    return ActivationContext(
        issuer=_COMPOSITION_ISSUER,
        session_id=str(payload["session_id"]),
        activation_epoch=str(payload["activation_epoch"]),
        activation_scope=str(payload["activation_scope"]),
        worker_id=str(payload.get("worker_id", "")),
        permitted_operations=frozenset(operations),
        expires_at=float(expires),
    )


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

    def get_process_image_path(self, pid: int) -> str | None: ...
    def is_process_elevated(self, pid: int) -> bool | None: ...  # None = unknown
    def enumerate_windows(self) -> list[tuple[int, int]]: ...  # raises on failure
    def get_foreground_window(self) -> int: ...


def native_observer_available() -> tuple[bool, str]:
    if sys.platform != "win32":
        return (False, "native_observer_requires_windows")
    return (True, "available_but_not_activated")


class NativeWindowsEventSource:
    """WinEvent source whose dedicated thread owns all native state."""

    def __init__(
        self, *, api: Win32ObserverApi, activation: ActivationContext | None = None
    ) -> None:
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
                    # Partial initialization must not leak hooks:
                    # unhook whatever was installed, on this (the
                    # owning) thread, before reporting the failure.
                    for handle in hooks:
                        with contextlib.suppress(Exception):
                            self._api.unhook_win_event(handle)
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
            event_type = (
                EVENT_SYSTEM_FOREGROUND if hwnd == foreground and hwnd else EVENT_OBJECT_SHOW
            )
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
        from aether.world_state.privacy import ContextClassification

        # Authorization-grade identity is the full process image
        # path, never a basename: two different executables sharing
        # a filename must not be conflated.
        image_path = None
        if pid:
            getter = getattr(self._api, "get_process_image_path", None)
            if getter is not None:
                with contextlib.suppress(Exception):
                    image_path = getter(pid)
        return WindowEvent(
            kind=kind,
            hwnd=hwnd,
            pid=pid,
            process_creation_time=creation,
            app_identity=image_path or name,
            # Positive classification only from confirmed
            # non-elevated inspection; unknown elevation stays
            # UNKNOWN and therefore uncollectable (fail closed).
            classification=(
                ContextClassification.PERMITTED_METADATA
                if elevated is False
                else ContextClassification.UNKNOWN
            ),
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
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
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
            event_type,
            event_type,
            None,
            c_callback,
            0,
            0,
            0,  # WINEVENT_OUTOFCONTEXT
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

    def get_process_aumid(self, pid: int) -> str | None:
        """Exact application user model id of a packaged process.

        Platform-reported via GetApplicationUserModelId; a process
        without a package (ERROR_APPMODEL_NO_PACKAGE) or any failure
        yields None, which the observation provider treats as no
        packaged identity - never as a guess.
        """
        ctypes = self._ctypes
        kernel32 = self._kernel32
        ERROR_APPMODEL_NO_PACKAGE = 15700
        ERROR_INSUFFICIENT_BUFFER = 122
        handle = self._open_process(pid)
        if not handle:
            return None
        try:
            length = ctypes.c_uint32(0)
            result = kernel32.GetApplicationUserModelId(handle, ctypes.byref(length), None)
            if result == ERROR_APPMODEL_NO_PACKAGE:
                return None
            if result != ERROR_INSUFFICIENT_BUFFER or length.value == 0 or length.value > 1024:
                return None
            buffer = ctypes.create_unicode_buffer(length.value)
            result = kernel32.GetApplicationUserModelId(handle, ctypes.byref(length), buffer)
            if result != 0:
                return None
            return str(buffer.value) or None
        finally:
            kernel32.CloseHandle(handle)

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
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
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

    def get_process_image_path(self, pid: int) -> str | None:
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
            return buffer.value or None
        finally:
            self._kernel32.CloseHandle(handle)

    def is_process_elevated(self, pid: int) -> bool | None:
        ctypes = self._ctypes
        handle = self._open_process(pid)
        if not handle:
            return None  # unknown, never "confirmed non-elevated"
        try:
            token = ctypes.c_void_p(0)
            if not self._ctypes.windll.advapi32.OpenProcessToken(
                handle, 0x0008, ctypes.byref(token)
            ):
                return None
            try:
                elevation = ctypes.c_uint(0)
                returned = ctypes.c_uint(0)
                ok = self._ctypes.windll.advapi32.GetTokenInformation(
                    token,
                    20,
                    ctypes.byref(elevation),
                    ctypes.sizeof(elevation),
                    ctypes.byref(returned),
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


class NativeObservationProvider:
    """Independent launch-verification observation (A01).

    Enumerates top-level windows/processes directly from Win32 —
    deliberately separate from the launch adapter — and correlates
    processes to registered applications by executable basename plus
    integrity evidence. Used by ``LaunchVerifier``; never grants
    authority by itself.
    """

    def __init__(
        self,
        *,
        api: Win32ObserverApi,
        records: list[Any],
        integrity_verifier: object,
    ) -> None:
        self._api = api
        self._records = records
        self._verifier = integrity_verifier

    def observe(self):  # type: ignore[no-untyped-def]
        """Attribute windows/processes only on verified identity.

        A process is attributed to a registered application only
        when its *full* observed image path equals the registered
        executable identity, its creation time is known, it runs in
        this session, exactly one registered application claims that
        identity (ambiguity denies), and trusted integrity evidence
        for the registered executable exists. A different executable
        sharing a basename is never attributed.
        """
        import os
        from pathlib import PureWindowsPath

        from aether.core.apps.launch_authority import integrity_digest_of
        from aether.core.apps.verification import (
            ObservedProcess,
            ObservedWindow,
            PlatformObservation,
        )

        def _key(value: object) -> str:
            return PureWindowsPath(str(value or "")).as_posix().casefold()

        from aether.core.contracts.app_window import LaunchMethod

        by_identity: dict[str, list] = {}  # type: ignore[type-arg]
        by_aumid: dict[str, list] = {}  # type: ignore[type-arg]
        for record in self._records:
            identity = getattr(record, "executable_identity", None)
            if not identity:
                continue
            if getattr(record, "launch_method", None) is LaunchMethod.APPS_FOLDER_ACTIVATION:
                # Packaged identity is an AUMID, not a filesystem
                # path: it can only be attributed through the
                # process's own application user model id.
                by_aumid.setdefault(_key(identity), []).append(record)
            else:
                by_identity.setdefault(_key(identity), []).append(record)
        own_session = None
        with contextlib.suppress(Exception):
            own_session = self._api.get_process_session_id(os.getpid())
        processes: dict[str, ObservedProcess] = {}
        windows = []
        try:
            enumerated = self._api.enumerate_windows()
        except Exception:
            return PlatformObservation(processes=(), windows=(), complete=False)
        for hwnd, pid in enumerated:
            image_getter = getattr(self._api, "get_process_image_path", None)
            image_path = image_getter(pid) if image_getter is not None else None
            matches = by_identity.get(_key(image_path), []) if image_path else []
            if len(matches) > 1:
                continue  # ambiguous executable identity: deny attribution
            record = matches[0] if matches else None
            # Method-aware packaged attribution: the process's exact
            # AUMID (platform-reported) against packaged records. If
            # both identity routes resolve and disagree, attribution
            # is ambiguous and denied; basename/display-name matching
            # is never used.
            aumid_getter = getattr(self._api, "get_process_aumid", None)
            if aumid_getter is not None:
                observed_aumid = None
                with contextlib.suppress(Exception):
                    observed_aumid = aumid_getter(pid)
                if observed_aumid:
                    claimants = by_aumid.get(_key(observed_aumid), [])
                    if len(claimants) > 1:
                        continue  # ambiguous packaged identity
                    if claimants:
                        if record is not None and claimants[0] is not record:
                            continue  # identity disagreement: ambiguous
                        record = claimants[0]
            if record is None:
                continue  # unknown or inaccessible identity: deny attribution
            creation = self._api.get_process_creation_time(pid)
            if not creation:
                continue  # creation identity unknown: deny
            session = None
            with contextlib.suppress(Exception):
                session = self._api.get_process_session_id(pid)
            if own_session is not None and session != own_session:
                continue  # different session: deny
            token = f"{pid}:{creation}"
            if token not in processes:
                evidence = self._verifier.verify(record)  # type: ignore[attr-defined]
                if evidence is None:
                    continue  # no trusted evidence: deny
                processes[token] = ObservedProcess(
                    process_token=token,
                    app_id=record.app_id,
                    integrity_sha256=integrity_digest_of(evidence),
                    started_after_attempt=True,
                )
            windows.append(
                ObservedWindow(
                    window_token=f"hwnd:{hwnd}",
                    process_token=token,
                    app_id=record.app_id,
                )
            )
        return PlatformObservation(
            processes=tuple(processes.values()), windows=tuple(windows), complete=True
        )

    def observe_fixture(self, fixture=None, process_token=None, hwnd=None, *, app_id=None):  # type: ignore[no-untyped-def]
        """Fixture-only live observation for fixture verification.

        Unlike ``observe()`` (the broad launch-verification
        enumeration), this returns only the exact fixture process /
        window instance requested. The fixture executable identity
        must be claimed by exactly one registered record, the live
        process image path must equal that full identity, creation
        time and session must be known and current, and trusted
        integrity evidence must exist. Any ambiguity, inaccessibility
        or mismatch yields no fixture process (denial upstream).
        """
        import os
        from pathlib import PureWindowsPath

        from aether.core.apps.launch_authority import integrity_digest_of
        from aether.core.apps.verification import (
            ObservedProcess,
            ObservedWindow,
            PlatformObservation,
        )

        def _key(value: object) -> str:
            return PureWindowsPath(str(value or "")).as_posix().casefold()

        record = None
        if (
            fixture is not None
            and hasattr(fixture, "app_id")
            and hasattr(fixture, "executable_identity")
        ):
            record = fixture
        else:
            wanted = app_id or (fixture if isinstance(fixture, str) else None)
            if wanted is None and fixture is not None:
                wanted = getattr(fixture, "app_id", None)
            matches = [r for r in self._records if getattr(r, "app_id", None) == wanted]
            if len(matches) != 1:
                return PlatformObservation(processes=(), windows=(), complete=False)
            record = matches[0]
        identity = getattr(record, "executable_identity", None)
        if not identity:
            return PlatformObservation(processes=(), windows=(), complete=False)
        claimants = [
            r
            for r in self._records
            if _key(getattr(r, "executable_identity", None)) == _key(identity)
        ]
        if len(claimants) != 1 or getattr(claimants[0], "app_id", None) != record.app_id:
            return PlatformObservation(processes=(), windows=(), complete=False)
        evidence = self._verifier.verify(record)  # type: ignore[attr-defined]
        if evidence is None:
            return PlatformObservation(processes=(), windows=(), complete=False)
        digest = integrity_digest_of(evidence)
        own_session = None
        with contextlib.suppress(Exception):
            own_session = self._api.get_process_session_id(os.getpid())
        if own_session is None:
            # Unknown own session: no fixture identity can be
            # verified, so the observation is incomplete and empty.
            return PlatformObservation(processes=(), windows=(), complete=False)
        target_pid: int | None = None
        if process_token is not None:
            try:
                target_pid = int(str(process_token).split(":", 1)[0])
            except (TypeError, ValueError):
                return PlatformObservation(processes=(), windows=(), complete=False)
        try:
            enumerated = self._api.enumerate_windows()
        except Exception:
            return PlatformObservation(processes=(), windows=(), complete=False)
        processes: dict[str, ObservedProcess] = {}
        windows = []
        for found_hwnd, pid in enumerated:
            if hwnd is not None and found_hwnd != hwnd:
                continue
            if target_pid is not None and pid != target_pid:
                continue
            image_getter = getattr(self._api, "get_process_image_path", None)
            image_path = image_getter(pid) if image_getter is not None else None
            if not image_path or _key(image_path) != _key(identity):
                continue
            creation = self._api.get_process_creation_time(pid)
            if not creation:
                continue
            token = f"{pid}:{creation}"
            if process_token is not None and token != process_token:
                continue
            session = None
            with contextlib.suppress(Exception):
                session = self._api.get_process_session_id(pid)
            if session is None or session != own_session:
                continue  # unknown or foreign session: deny identity
            if token not in processes:
                processes[token] = ObservedProcess(
                    process_token=token,
                    app_id=record.app_id,
                    integrity_sha256=digest,
                    started_after_attempt=False,
                )
            windows.append(
                ObservedWindow(
                    window_token=f"hwnd:{found_hwnd}",
                    process_token=token,
                    app_id=record.app_id,
                )
            )
        return PlatformObservation(
            processes=tuple(processes.values()), windows=tuple(windows), complete=True
        )


class NativeForegroundProvider:  # pragma: no cover - Windows only
    """Bounded native window activation + foreground verification."""

    def __init__(self, *, user32: Any = None) -> None:
        if user32 is None:
            import ctypes

            windll: Any = getattr(ctypes, "windll", None)
            user32 = windll.user32
        self._user32: Any = user32

    def activate(self, hwnd: int) -> bool:
        """Bounded SetForegroundWindow attempt, verified by polling."""
        import time

        user32 = self._user32
        try:
            user32.BringWindowToTop(hwnd)
            user32.SetForegroundWindow(hwnd)
        except Exception:
            return False
        for _ in range(10):  # at most ~0.5s, then truthful failure
            if self.foreground_hwnd() == hwnd:
                return True
            time.sleep(0.05)
        return False

    def foreground_hwnd(self) -> int | None:
        try:
            hwnd = int(self._user32.GetForegroundWindow())
        except Exception:
            return None
        return hwnd or None
