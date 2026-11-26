"""Phase 3 disabled-path tests: native capability stays off (CP0-CP2).

These run on any platform and assert fail-closed behaviour; they are
not native Windows evidence.
"""

from __future__ import annotations

import sys

import pytest

from aether.adapters.windows.discovery import (
    discover_start_menu,
    discover_uninstall_registry,
    windows_discovery_available,
)
from aether.adapters.windows.native_observer import (
    NativeObserverDisabled,
    NativeWindowsEventSource,
    native_observer_available,
)
from aether.core.composition import TrustedComposition
from aether.world_state.observer import ObserverUnavailable


def test_native_observer_cannot_start_without_authorization() -> None:
    available, _reason = native_observer_available()
    if sys.platform != "win32":
        assert available is False
        with pytest.raises(ObserverUnavailable):
            NativeWindowsEventSource(activation_authorized=True)
    else:  # pragma: no cover - exercised in native runs only
        with pytest.raises(NativeObserverDisabled):
            NativeWindowsEventSource(activation_authorized=False)


def test_discovery_sources_are_inert_in_foundation() -> None:
    available, reason = windows_discovery_available()
    if sys.platform != "win32":
        assert available is False and "windows" in reason
    # Foundation discovery never returns real-user data in tests and
    # never executes anything; both sources are inert pre-activation.
    assert discover_uninstall_registry() == []
    assert discover_start_menu() == []


def test_phase2_composition_has_no_phase3_enablement() -> None:
    # Ordinary composition gains no app/window execution surface in
    # CP0-CP2: the edit capability set and mutation gating are exact.
    import aether.core.composition as composition

    assert frozenset({"fs.apply_approved_edit", "fs.undo_edit"}) == composition._EDIT_CAPABILITIES
    assert not hasattr(TrustedComposition, "launch_application")
