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
        self, *, activation: ActivationContext | None, emit_to: Callable[[ActivitySignal], None]
    ) -> None:
        if sys.platform != "win32" or activation is None:
            raise NativeActivityDisabled(
                "native activity monitoring requires Windows + trusted activation; disabled"
            )
        self._emit_to: Callable[[ActivitySignal], None] = emit_to
        self._hook: int | None = None
        self._callback: object = None

    def start(self) -> None:  # pragma: no cover - Windows-only
        import ctypes

        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        EVENT_SYSTEM_FOREGROUND = 0x0003
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

        def _callback(
            hook: object,
            event: object,
            hwnd: object,
            id_object: object,
            id_child: object,
            thread: object,
            time_ms: object,
        ) -> None:
            # Content-free signal: only that foreground changed.
            emit(ActivitySignal(kind="foreground_changed", window_id=None, at=datetime.now(UTC)))

        self._callback = callback_type(_callback)
        self._hook = user32.SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            None,
            self._callback,
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
        if not self._hook:
            raise NativeActivityDisabled("activity hook could not be installed")

    def stop(self) -> None:  # pragma: no cover - Windows-only
        if self._hook:
            import ctypes

            ctypes.windll.user32.UnhookWinEvent(self._hook)  # type: ignore[attr-defined]
            self._hook = None
