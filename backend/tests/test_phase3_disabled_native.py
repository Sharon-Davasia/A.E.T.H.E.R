"""Phase 3 disabled-path tests: native capability stays off.

Not native Windows evidence.
"""

from __future__ import annotations

import sys

import pytest

from aether.adapters.windows.discovery import windows_discovery_available
from aether.adapters.windows.native_observer import (
    NativeObserverDisabled,
    NativeWindowsEventSource,
    native_observer_available,
)
from aether.core.composition import TrustedComposition
from aether.world_state.observer import ObserverUnavailable


def test_native_observer_cannot_start_without_activation() -> None:
    available, _reason = native_observer_available()
    if sys.platform != "win32":
        assert available is False
    with pytest.raises((NativeObserverDisabled, ObserverUnavailable)):
        NativeWindowsEventSource.production().start(lambda event: None)


def test_discovery_reports_unavailable_off_windows() -> None:
    available, reason = windows_discovery_available()
    if sys.platform != "win32":
        assert available is False and "windows" in reason


def test_phase2_composition_has_no_phase3_enablement() -> None:
    import aether.core.composition as composition

    assert frozenset({"fs.apply_approved_edit", "fs.undo_edit"}) == composition._EDIT_CAPABILITIES
    assert not hasattr(TrustedComposition, "launch_application")
