"""Windows application discovery sources (Phase 3 CP2, completed F02).

Bounded, read-only discovery behind an injected provider interface so
Arena tests use metadata fixtures/fakes — not native evidence. Real
providers use stdlib only (``winreg``, ``os.scandir``): they read
registration *metadata*, never execute binaries, never read or run
uninstall strings as commands, never evaluate shortcut targets as
code, and never recursively scan the machine. Results carry per-source
status; an unavailable/unsupported source is reported truthfully and
never presented as an empty success. Not wired into ordinary startup.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Protocol

MAX_RECORDS_PER_SOURCE = 512
MAX_FIELD_CHARS = 512


@dataclass(frozen=True, slots=True)
class DiscoveredAppCandidate:
    """Raw discovery evidence before registry normalization."""

    display_name: str
    executable_identity: str | None
    publisher: str | None
    source: str


@dataclass(frozen=True, slots=True)
class SourceStatus:
    source: str
    status: str  # "ok" | "partial" | "unavailable"
    detail: str = ""


@dataclass(frozen=True, slots=True)
class DiscoveryBatch:
    candidates: tuple[DiscoveredAppCandidate, ...]
    statuses: tuple[SourceStatus, ...]


class DiscoveryProviders(Protocol):
    """Injectable discovery surface (real stdlib providers or fakes)."""

    def start_menu_shortcuts(self) -> tuple[list[DiscoveredAppCandidate], SourceStatus]: ...
    def uninstall_entries(self) -> tuple[list[DiscoveredAppCandidate], SourceStatus]: ...
    def apps_folder_entries(self) -> tuple[list[DiscoveredAppCandidate], SourceStatus]: ...


def _bound(value: object) -> str:
    return str(value)[:MAX_FIELD_CHARS]


class StdlibWindowsDiscoveryProviders:
    """Real read-only providers (Windows only; inert elsewhere)."""

    def start_menu_shortcuts(self) -> tuple[list[DiscoveredAppCandidate], SourceStatus]:
        if sys.platform != "win32":  # pragma: no cover - platform guard
            return [], SourceStatus("start_menu_shortcut", "unavailable", "requires_windows")
        roots = [
            os.path.join(
                os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs"
            ),
            os.path.join(
                os.environ.get("PROGRAMDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs"
            ),
        ]
        candidates: list[DiscoveredAppCandidate] = []
        for root in roots:  # bounded, single-level + one sublevel
            if not root or not os.path.isdir(root):
                continue
            for base in (root, *[os.path.join(root, d) for d in _subdirs(root)]):
                for entry in _scandir_bounded(base):
                    if entry.lower().endswith(".lnk") and len(candidates) < MAX_RECORDS_PER_SOURCE:
                        name = os.path.splitext(os.path.basename(entry))[0]
                        candidates.append(
                            DiscoveredAppCandidate(
                                display_name=_bound(name),
                                executable_identity=None,  # target never evaluated
                                publisher=None,
                                source="start_menu_shortcut",
                            )
                        )
        return candidates, SourceStatus("start_menu_shortcut", "ok")

    def uninstall_entries(self) -> tuple[list[DiscoveredAppCandidate], SourceStatus]:
        if sys.platform != "win32":  # pragma: no cover - platform guard
            return [], SourceStatus("uninstall_registry", "unavailable", "requires_windows")
        candidates: list[DiscoveredAppCandidate] = []
        try:  # pragma: no cover - Windows only
            import winreg

            paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                ),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ]
            for hive, path in paths:
                with winreg.OpenKey(hive, path) as key:
                    for index in range(min(winreg.QueryInfoKey(key)[0], MAX_RECORDS_PER_SOURCE)):
                        try:
                            sub_name = winreg.EnumKey(key, index)
                            with winreg.OpenKey(key, sub_name) as sub:
                                display = _read_value(sub, "DisplayName")
                                if not display:
                                    continue
                                candidates.append(
                                    DiscoveredAppCandidate(
                                        display_name=_bound(display),
                                        executable_identity=_bound(
                                            _read_value(sub, "DisplayIcon") or ""
                                        )
                                        or None,
                                        publisher=_bound(_read_value(sub, "Publisher") or "")
                                        or None,
                                        source="uninstall_registry",
                                    )
                                )
                        except OSError:
                            continue
        except OSError:
            return candidates, SourceStatus("uninstall_registry", "partial", "registry_read_failed")
        return candidates, SourceStatus("uninstall_registry", "ok")

    def apps_folder_entries(self) -> tuple[list[DiscoveredAppCandidate], SourceStatus]:
        # AppsFolder/packaged-app enumeration requires Shell COM
        # (IShellFolder over shell:AppsFolder). pywin32 is deferred to
        # the UIA checkpoint, so this source truthfully reports
        # unavailable rather than pretending to succeed empty.
        _ = self
        return [], SourceStatus(
            "apps_folder", "unavailable", "shell_com_provider_deferred_to_uia_checkpoint"
        )


def _subdirs(root: str) -> list[str]:  # pragma: no cover - Windows path helper
    try:
        return [d for d in os.listdir(root)[:64] if os.path.isdir(os.path.join(root, d))]
    except OSError:
        return []


def _scandir_bounded(base: str) -> list[str]:  # pragma: no cover - Windows path helper
    try:
        return [os.path.join(base, name) for name in os.listdir(base)[:MAX_RECORDS_PER_SOURCE]]
    except OSError:
        return []


def _read_value(key: object, name: str) -> str | None:  # pragma: no cover - Windows only
    try:
        import winreg

        value, _kind = winreg.QueryValueEx(key, name)  # type: ignore[attr-defined]
        return str(value) if value else None
    except OSError:
        return None


def windows_discovery_available() -> tuple[bool, str]:
    if sys.platform != "win32":
        return (False, "windows_discovery_requires_windows")
    return (True, "available_but_not_activated")


def discover_applications(
    providers: DiscoveryProviders,
    *,
    portable_registrations: tuple[DiscoveredAppCandidate, ...] = (),
) -> DiscoveryBatch:
    """Aggregate bounded discovery with truthful per-source status.

    ``portable_registrations`` is the explicit user-registered portable
    application contract: caller-supplied registrations, recorded with
    their provenance, never auto-discovered or executed.
    """
    candidates: list[DiscoveredAppCandidate] = []
    statuses: list[SourceStatus] = []
    for getter in (
        providers.start_menu_shortcuts,
        providers.uninstall_entries,
        providers.apps_folder_entries,
    ):
        found, status = getter()
        candidates.extend(found[:MAX_RECORDS_PER_SOURCE])
        statuses.append(status)
    for registration in portable_registrations:
        candidates.append(
            DiscoveredAppCandidate(
                display_name=_bound(registration.display_name),
                executable_identity=registration.executable_identity,
                publisher=registration.publisher,
                source="user_registered_portable",
            )
        )
    statuses.append(SourceStatus("user_registered_portable", "ok"))
    return DiscoveryBatch(candidates=tuple(candidates), statuses=tuple(statuses))
