"""Conservative lexical, reparse-point and volume checks for local paths."""

from __future__ import annotations

import ctypes
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Protocol


class VolumeKind(StrEnum):
    FIXED = "fixed"
    REMOVABLE = "removable"
    NETWORK = "network"
    OPTICAL = "optical"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class VolumeInfo:
    volume_id: str
    kind: VolumeKind


class VolumeInspector(Protocol):
    def inspect(self, path: Path) -> VolumeInfo: ...


class PathSafetyError(ValueError):
    """A path could not be safely interpreted or is outside supported media."""


def relative_parts(value: str) -> tuple[str, ...]:
    """Parse a caller-relative path using Windows rules on every host OS."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise PathSafetyError("invalid_relative_path")
    if "\x00" in value or ":" in value:
        raise PathSafetyError("invalid_relative_path")
    windows = PureWindowsPath(value)
    if windows.drive or windows.root or windows.is_absolute():
        raise PathSafetyError("absolute_path_not_allowed")
    raw_parts = re.split(r"[\\/]", value)
    if not raw_parts or any(part in {"", ".", ".."} for part in raw_parts):
        raise PathSafetyError("path_traversal_not_allowed")
    for part in raw_parts:
        if part.endswith((".", " ")) or any(ord(char) < 32 for char in part):
            raise PathSafetyError("invalid_windows_path_component")
        if any(char in part for char in '<>"|?*'):
            raise PathSafetyError("invalid_windows_path_component")
        stem = part.split(".", 1)[0].casefold()
        if _is_reserved_device_name(stem):
            raise PathSafetyError("reserved_windows_path_component")
    return tuple(raw_parts)


def _is_reserved_device_name(stem: str) -> bool:
    """Match Win32 reserved device basenames, including superscript COM/LPT digits."""
    if stem in {"con", "prn", "aux", "nul", "conin$", "conout$"}:
        return True
    return re.fullmatch(r"(?:com|lpt)(?:[1-9]|[¹²³])", stem) is not None


def inspect_volume(path: Path) -> VolumeInfo:
    """Return conservative volume identity/type, using Win32 on Windows."""
    if os.name == "nt":
        return _inspect_windows_volume(path)
    try:
        device = path.stat().st_dev
    except OSError as exc:
        raise PathSafetyError("volume_identity_unavailable") from exc
    return VolumeInfo(f"posix-dev:{device}", VolumeKind.FIXED)


def _inspect_windows_volume(path: Path) -> VolumeInfo:
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    volume_root = ctypes.create_unicode_buffer(32768)
    if not kernel32.GetVolumePathNameW(str(path), volume_root, len(volume_root)):
        return VolumeInfo("unknown", VolumeKind.UNKNOWN)
    drive_type = kernel32.GetDriveTypeW(volume_root.value)
    kinds = {
        2: VolumeKind.REMOVABLE,
        3: VolumeKind.FIXED,
        4: VolumeKind.NETWORK,
        5: VolumeKind.OPTICAL,
    }
    kind = kinds.get(drive_type, VolumeKind.UNKNOWN)
    serial = ctypes.c_uint32()
    if kind == VolumeKind.UNKNOWN or not kernel32.GetVolumeInformationW(
        volume_root.value,
        None,
        0,
        ctypes.byref(serial),
        None,
        None,
        None,
        0,
    ):
        return VolumeInfo("unknown", VolumeKind.UNKNOWN)
    return VolumeInfo(f"win-volume:{serial.value:08x}", kind)


def reject_reparse_components(path: Path) -> None:
    """Reject symlinks and Windows reparse points in every existing component."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            # A missing final component is checked separately by the resolver.
            continue
        except OSError as exc:
            raise PathSafetyError("path_component_unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise PathSafetyError("reparse_point_not_allowed")
        attributes = getattr(metadata, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if attributes & reparse_flag:
            raise PathSafetyError("reparse_point_not_allowed")
        is_junction = getattr(os.path, "isjunction", None)
        if is_junction is not None and is_junction(current):
            raise PathSafetyError("reparse_point_not_allowed")


def is_protected_path(path: Path) -> bool:
    """Conservatively identify ordinary OS, credential and secret locations."""
    parts = tuple(part.casefold() for part in path.parts)
    protected_parts = {
        "windows",
        "system32",
        "syswow64",
        "program files",
        "program files (x86)",
        "programdata",
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".git",
        ".svn",
        ".hg",
        ".config",
        ".local",
        ".password-store",
        "appdata",
        "application support",
        "keychains",
        "user data",
        "credentials",
        "credential manager",
        "login data",
        "cookies",
        "web data",
    }
    if any(part in protected_parts for part in parts):
        return True
    name = path.name.casefold()
    if (
        name == ".env"
        or name.startswith(".env.")
        or name
        in {
            "credentials.json",
            "secrets.json",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
        }
    ):
        return True
    return path.suffix.casefold() in {".pem", ".p12", ".pfx", ".key", ".kdbx"}
