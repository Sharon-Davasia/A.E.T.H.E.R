"""Native Windows observer source (Phase 3 CP1) — DISABLED by default.

This module is source behind explicit platform *and* activation
guards. It is not imported by the composition root, the channel
service, or any ordinary launch path, and constructing it raises
unless both guards pass. CP1 does not activate real Windows sensors;
the class exists so the platform seam is reviewed with the foundation
and can be enabled only by a separately authorized checkpoint.

Implementation sketch uses ctypes ``SetWinEventHook`` with a Win32
message pump on its own thread. It collects bounded metadata only,
subject to the caller's privacy policy at the collection boundary.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from aether.world_state.observer import ObserverUnavailable, WindowEvent


class NativeObserverDisabled(RuntimeError):
    """Native observation was requested without authorization guards."""


def native_observer_available() -> tuple[bool, str]:
    """Truthfully report whether the native observer could run here."""
    if sys.platform != "win32":
        return (False, "native_observer_requires_windows")
    return (True, "available_but_not_activated")


class NativeWindowsEventSource:
    """Guarded ``SetWinEventHook`` event source (not activated in CP1)."""

    def __init__(self, *, activation_authorized: bool = False) -> None:
        if sys.platform != "win32":
            raise ObserverUnavailable("native_observer_requires_windows")
        if not activation_authorized:
            raise NativeObserverDisabled(
                "native observation requires separate Phase 3 activation authorization"
            )
        self._activation_authorized = activation_authorized

    def start(self, emit: Callable[[WindowEvent], None]) -> None:  # pragma: no cover
        raise NativeObserverDisabled("native observation is not activated in CP0-CP2")

    def stop(self) -> None:  # pragma: no cover - never started in CP1
        return None

    def reconcile(self) -> list[WindowEvent]:  # pragma: no cover
        raise NativeObserverDisabled("native observation is not activated in CP0-CP2")
