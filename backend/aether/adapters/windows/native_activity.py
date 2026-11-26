"""Privacy-preserving native activity signals (CP6), disabled.

Real source behind the same activation gate as the other native
adapters: a Win32 event-hook source (EVENT_SYSTEM_FOREGROUND and
same-window focus/input-origin *signals* only). It records no
keystrokes, typed text, pointer histories or clipboard content, and
runs only while a controlled operation is active in production
wiring. On any other platform, or without trusted activation,
construction raises. ``FakeActivitySource`` serves tests.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aether.adapters.windows.native_observer import ActivationContext
from aether.core.apps.focus import ActivitySignal


class NativeActivityDisabled(RuntimeError):
    pass


@dataclass(slots=True)
class FakeActivitySource:
    """Deterministic signal source for tests (not native evidence)."""

    emit_to: Callable[[ActivitySignal], None] | None = None
    _signals: list[ActivitySignal] = field(default_factory=list)

    def emit(self, signal: ActivitySignal) -> None:
        self._signals.append(signal)
        if self.emit_to is not None:
            self.emit_to(signal)

    def foreground_changed(self, window_id: str | None) -> None:
        self.emit(
            ActivitySignal(kind="foreground_changed", window_id=window_id, at=datetime.now(UTC))
        )

    def manual_activity(self, window_id: str) -> None:
        self.emit(
            ActivitySignal(
                kind="manual_activity_in_window", window_id=window_id, at=datetime.now(UTC)
            )
        )


class NativeActivitySource:
    """WinEvent-hook activity source (Windows, activation-gated)."""

    def __init__(
        self,
        *,
        activation: ActivationContext | None,
        emit_to: Callable[[ActivitySignal], None],
        resolve_window_id: Callable[[int], str | None] | None = None,
    ) -> None:
        if sys.platform != "win32" or activation is None:
            raise NativeActivityDisabled(
                "native activity monitoring requires Windows + trusted activation; disabled"
            )
        self._emit_to: Callable[[ActivitySignal], None] = emit_to
        # G04: actual foreground HWND -> authorized window resource id,
        # resolved only through the app/window authority (injected by
        # trusted composition). Unresolvable foreground = None, which
        # the focus coordinator treats conservatively.
        self._resolve_window_id = resolve_window_id
        self._hook: int | None = None
        self._focus_hook: int | None = None
        self._callback: object = None
        self._focus_callback: object = None
        self._thread: object = None
        self._thread_id: int | None = None
        self._started = False

    def start(self) -> None:  # pragma: no cover - Windows-only
        """Install hooks on a dedicated hook thread and pump messages.

        WinEvent hooks with a thread filter require a message loop on
        the installing thread; that thread owns the hooks and is the
        only thread that removes them. ``stop`` posts WM_QUIT to it
        and joins it, so no hook or thread outlives the source.
        """
        import threading

        if self._started:
            return
        ready: list[BaseException | None] = []

        def _run() -> None:
            import ctypes

            user32 = ctypes.windll.user32  # type: ignore[attr-defined]
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            self._thread_id = int(kernel32.GetCurrentThreadId())
            EVENT_SYSTEM_FOREGROUND = 0x0003
            EVENT_OBJECT_FOCUS = 0x8005
            WINEVENT_OUTOFCONTEXT = 0x0000
            callback_type = ctypes.WINFUNCTYPE(  # type: ignore[attr-defined]
                None,
                ctypes.c_void_p,
                ctypes.c_uint,
                ctypes.c_void_p,
                ctypes.c_long,
                ctypes.c_long,
                ctypes.c_uint,
                ctypes.c_uint,
            )
            emit = self._emit_to
            resolve = self._resolve_window_id

            def _window_id(hwnd: object) -> str | None:
                try:
                    return resolve(int(hwnd)) if resolve is not None and hwnd else None  # type: ignore[arg-type]
                except Exception:
                    return None

            def _foreground(hook: object, event: object, hwnd: object, id_object: object, id_child: object, thread: object, time_ms: object) -> None:
                # Content-free: foreground identity only, no input data.
                emit(ActivitySignal(kind="foreground_changed", window_id=_window_id(hwnd), at=datetime.now(UTC)))

            def _focus(hook: object, event: object, hwnd: object, id_object: object, id_child: object, thread: object, time_ms: object) -> None:
                # Same-window activity *signal* only: that focus moved
                # inside a window. No key/pointer/clipboard content.
                window_id = _window_id(hwnd)
                if window_id is not None:
                    emit(ActivitySignal(kind="manual_activity_in_window", window_id=window_id, at=datetime.now(UTC)))

            try:
                self._callback = callback_type(_foreground)
                self._focus_callback = callback_type(_focus)
                self._hook = user32.SetWinEventHook(
                    EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, None,
                    self._callback, 0, 0, WINEVENT_OUTOFCONTEXT,
                )
                if not self._hook:
                    raise NativeActivityDisabled("activity hook could not be installed")
                self._focus_hook = user32.SetWinEventHook(
                    EVENT_OBJECT_FOCUS, EVENT_OBJECT_FOCUS, None,
                    self._focus_callback, 0, 0, WINEVENT_OUTOFCONTEXT,
                )
                ready.append(None)
            except BaseException as exc:  # surfaced to start() caller
                ready.append(exc)
                return
            # Message pump owned by this hook thread.
            msg = ctypes.create_string_buffer(48)
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            if self._hook:
                user32.UnhookWinEvent(self._hook)
                self._hook = None
            if self._focus_hook:
                user32.UnhookWinEvent(self._focus_hook)
                self._focus_hook = None

        thread = threading.Thread(target=_run, name="aether-activity-hook", daemon=True)
        self._thread = thread
        thread.start()
        # Bounded wait for hook installation outcome.
        import time as _time

        deadline = _time.monotonic() + 5.0
        while not ready and _time.monotonic() < deadline:
            _time.sleep(0.01)
        if not ready or ready[0] is not None:
            self.stop()
            raise NativeActivityDisabled("activity hook could not be installed")
        self._started = True

    def stop(self) -> None:  # pragma: no cover - Windows-only
        import ctypes

        thread = self._thread
        if thread is None:
            return
        if self._thread_id is not None:
            WM_QUIT = 0x0012
            ctypes.windll.user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)  # type: ignore[attr-defined]
        thread.join(timeout=5.0)  # type: ignore[attr-defined]
        self._thread = None
        self._thread_id = None
        self._started = False
