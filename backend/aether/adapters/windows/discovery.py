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
from typing import Any, Protocol

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
        roots = _start_menu_roots(os.environ, _known_folder_path)
        scanned = [root for root in roots if os.path.isdir(root)]
        if not scanned:
            # No root could be resolved or examined (e.g. the
            # restricted backend environment carries neither the
            # environment variables nor shell folder access): the
            # source is unavailable, never an empty "ok".
            return [], SourceStatus(
                "start_menu_shortcut", "unavailable", "start_menu_roots_unavailable"
            )
        candidates: list[DiscoveredAppCandidate] = []
        for root in scanned:  # bounded, single-level + one sublevel
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
        status = (
            SourceStatus("start_menu_shortcut", "ok")
            if len(scanned) == len(roots)
            else SourceStatus("start_menu_shortcut", "partial", "some_start_menu_roots_unavailable")
        )
        return candidates, status

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
        """Enumerate AppsFolder/packaged apps via Shell COM (pywin32).

        Documented contracts used (read-only throughout):
        - ``IShellFolder.ParseDisplayName(hwnd, bindCtx, name)``
          returns ``(pidl, eaten, attributes)``; ``"shell:AppsFolder"``
          is the parsing name of the AppsFolder.
        - Items are leaf applications: ``EnumObjects`` must be called
          with ``SHCONTF_NONFOLDERS | SHCONTF_FASTITEMS`` (folder-only
          flags enumerate nothing useful here).
        - ``GetDisplayNameOf(pidl, SHGDN_NORMAL)`` is the
          human-readable display name; ``SHGDN_FORPARSING`` is the
          canonical AppUserModelId. The two are never conflated:
          a parsing name that is not AUMID-shaped confers no
          activation identity.
        Stage failures report ``unavailable`` naming the stage;
        per-item failures degrade to ``partial``. Nothing here
        invents identities or authorizes anything.
        """
        if sys.platform != "win32":  # pragma: no cover - platform guard
            return [], SourceStatus("apps_folder", "unavailable", "requires_windows")
        try:  # pragma: no cover - Windows only
            import pythoncom  # type: ignore[import-untyped]
            from win32com.shell import shell, shellcon  # type: ignore[import-untyped]
        except Exception:
            return [], SourceStatus("apps_folder", "unavailable", "shell_com_unavailable")
        initialized = False
        try:  # pragma: no cover - Windows only
            pythoncom.CoInitialize()
            initialized = True
            try:
                desktop = shell.SHGetDesktopFolder()
                pidl, _eaten, _attrs = desktop.ParseDisplayName(0, None, "shell:AppsFolder")
                folder = desktop.BindToObject(pidl, None, shell.IID_IShellFolder)
            except Exception:
                return [], SourceStatus("apps_folder", "unavailable", "apps_folder_open_failed")
            try:
                enumerator = folder.EnumObjects(
                    0, shellcon.SHCONTF_NONFOLDERS | shellcon.SHCONTF_FASTITEMS
                )
            except Exception:
                return [], SourceStatus("apps_folder", "unavailable", "apps_folder_enum_failed")
            candidates: list[DiscoveredAppCandidate] = []
            failures = 0
            if enumerator is not None:
                examined = 0
                # Bounded enumeration: never walk the shell forever.
                while (
                    len(candidates) < MAX_RECORDS_PER_SOURCE
                    and examined <= MAX_RECORDS_PER_SOURCE * 8
                ):
                    try:
                        items = enumerator.Next(1)
                    except Exception:
                        failures += 1
                        break
                    if not items:
                        break
                    examined += 1
                    try:
                        item_pidl = items[0]
                        display = folder.GetDisplayNameOf(item_pidl, shellcon.SHGDN_NORMAL)
                        parsing = folder.GetDisplayNameOf(item_pidl, shellcon.SHGDN_FORPARSING)
                    except Exception:
                        failures += 1
                        continue
                    name = _bound(display).strip() if display else ""
                    if not name:
                        failures += 1
                        continue
                    candidates.append(
                        DiscoveredAppCandidate(
                            display_name=name,
                            executable_identity=_aumid_or_none(parsing),
                            publisher=None,
                            source="apps_folder",
                        )
                    )
            if failures:
                return candidates, SourceStatus(
                    "apps_folder", "partial", "apps_folder_items_failed"
                )
            return candidates, SourceStatus("apps_folder", "ok")
        except Exception:  # pragma: no cover - Windows only
            return [], SourceStatus("apps_folder", "unavailable", "shell_com_unavailable")
        finally:  # pragma: no cover - Windows only
            if initialized:
                pythoncom.CoUninitialize()


def _aumid_or_none(parsing_name: object) -> str | None:
    """Canonical activation identity from an AppsFolder parsing name.

    Only AUMID-shaped values (``PackageFamily!AppId``, no path
    separators, no whitespace padding games) become identities;
    anything else - including filesystem paths some shell items
    report for parsing - stays identity-less, never invented.
    """
    if not isinstance(parsing_name, str):
        return None
    value = parsing_name.strip()
    family, separator, application = value.partition("!")
    if not separator or not family or not application or "!" in application:
        return None
    if any(char in value for char in ("\\", "/", " ", "\t", "\x00")):
        return None
    return _bound(value)


def _start_menu_roots(environ: os._Environ[str], known_folder: object) -> list[str]:
    """Start Menu roots from shell known folders, env as fallback.

    The Electron-spawned backend runs with a deliberately restricted
    environment (no APPDATA/PROGRAMDATA); known-folder resolution
    keeps discovery correct there. A base that cannot be resolved
    contributes NO root - a relative pseudo-root is never scanned.
    """
    resolve = known_folder  # Callable[[str], str | None]
    bases = [
        resolve("roaming") or environ.get("APPDATA", ""),  # type: ignore[operator]
        resolve("programdata") or environ.get("PROGRAMDATA", ""),  # type: ignore[operator]
    ]
    return [
        os.path.join(base, "Microsoft", "Windows", "Start Menu", "Programs")
        for base in bases
        if base
    ]


_KNOWN_FOLDER_GUIDS = {
    # FOLDERID_RoamingAppData / FOLDERID_ProgramData
    "roaming": "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}",
    "programdata": "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}",
}


def _known_folder_path(kind: str) -> str | None:  # pragma: no cover - Windows only
    """SHGetKnownFolderPath for the Start Menu base folders."""
    try:
        import ctypes
        from ctypes import wintypes

        class _Guid(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        text = _KNOWN_FOLDER_GUIDS[kind].strip("{}")
        parts = text.split("-")
        guid = _Guid(
            int(parts[0], 16),
            int(parts[1], 16),
            int(parts[2], 16),
            (ctypes.c_ubyte * 8)(*bytes.fromhex(parts[3] + parts[4])),
        )
        shell32 = getattr(ctypes, "windll").shell32  # noqa: B009
        ole32 = getattr(ctypes, "windll").ole32  # noqa: B009
        path_ptr = ctypes.c_wchar_p()
        if shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(path_ptr)) != 0:
            return None
        try:
            return str(path_ptr.value) if path_ptr.value else None
        finally:
            if path_ptr.value:
                ole32.CoTaskMemFree(path_ptr)
    except Exception:
        return None


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

        handle: Any = key
        query_value_ex: Any = winreg.__dict__.get("QueryValueEx")
        value, _kind = query_value_ex(handle, name)
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
