"""Windows application discovery sources (Phase 3 CP2) — guarded, read-only.

Discovery reads supported registration metadata only. It never
executes a discovered binary, never runs uninstall commands, never
follows shortcut payloads as code, and never treats discovery as
launch authorization. On non-Windows platforms every source reports
unavailable truthfully. This module is not wired into ordinary
launches in CP0-CP2.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DiscoveredAppCandidate:
    """Raw discovery evidence before registry normalization."""

    display_name: str
    executable_identity: str | None
    publisher: str | None
    source: str


def windows_discovery_available() -> tuple[bool, str]:
    if sys.platform != "win32":
        return (False, "windows_discovery_requires_windows")
    return (True, "available_but_not_activated")


def discover_uninstall_registry() -> list[DiscoveredAppCandidate]:
    """Read uninstall-registration *metadata* (never execute its commands).

    Guarded: returns no candidates off Windows. On Windows (future
    activation) this reads DisplayName/DisplayIcon/Publisher values
    only; UninstallString is deliberately never read as an executable.
    """
    if sys.platform != "win32":  # pragma: no cover - platform guard
        return []
    return []  # Not activated in CP0-CP2; see PHASE3_PLAN CP2/CP3 gate.


def discover_start_menu() -> list[DiscoveredAppCandidate]:
    """Enumerate Start Menu shortcut *names* (targets not executed)."""
    if sys.platform != "win32":  # pragma: no cover - platform guard
        return []
    return []  # Not activated in CP0-CP2.
