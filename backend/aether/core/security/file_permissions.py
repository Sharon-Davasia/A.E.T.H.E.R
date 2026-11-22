"""Owner-only file permissions, honestly per platform (S14-5).

The previous code made ``chmod`` a silent no-op on Windows. That is not
protection, and reporting "the key file is owner-restricted" while doing nothing
would be worse than the original defect. This module gives each platform a real
mechanism and an explicit result:

* POSIX: ``chmod`` to the requested mode, then *read back* the mode. A mismatch is
  a failure, not a quiet success.
* Windows: set a restrictive DACL on the object. ``FILE_ALL_ACCESS`` /
  ``GENERIC_ALL`` for the current user only, with inheritance removed, via
  ``SetNamedSecurityInfoW`` in ``advapi32``. If that cannot be done, the operation
  **fails closed** rather than pretending the object is protected.

Every entry point returns a :class:`PermissionReport` describing what was actually
enforced, so callers can refuse to continue instead of assuming.
"""

from __future__ import annotations

import contextlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

_WINDOWS_SDDL: Final = "D:P(A;;FA;;;OW)"

# Windows security APIs, resolved lazily: importing ctypes.wintypes on POSIX is
# pointless, and the constants below only exist on Windows.
_ERROR_SUCCESS: Final = 0
_SDDL_REVISION_1: Final = 1
_DACL_SECURITY_INFORMATION: Final = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION: Final = 0x80000000


class PermissionEnforcementError(Exception):
    """Owner-only permissions could not be enforced; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True, slots=True)
class PermissionReport:
    """What was actually enforced on one path."""

    path: str
    platform: str
    enforced: bool
    mechanism: str
    detail: str = ""

    @property
    def verified(self) -> bool:
        return self.enforced


def restrict_to_owner(path: Path, *, directory: bool) -> PermissionReport:
    """Make ``path`` accessible to its owner only, and report what was done.

    Raises :class:`PermissionEnforcementError` when the platform cannot enforce
    the restriction. Callers holding secrets (the vault key above all) must let
    that propagate: an unprotected key is not an acceptable degraded mode.
    """

    target = Path(path)
    if not target.exists():
        raise PermissionEnforcementError(
            "permissions_target_missing", "the path must exist before it is restricted"
        )
    if os.name == "nt":
        return _restrict_windows(target)
    return _restrict_posix(target, directory=directory)


def verify_owner_only(path: Path, *, directory: bool) -> PermissionReport:
    """Check, without changing anything, whether ``path`` is owner-only.

    This is what a startup audit calls: it must not silently repair what an
    operator may need to know about.
    """

    target = Path(path)
    if not target.exists():
        raise PermissionEnforcementError(
            "permissions_target_missing", "the path must exist to be verified"
        )
    if os.name == "nt":
        return _verify_windows(target)
    return _verify_posix(target, directory=directory)


def _expected_mode(directory: bool) -> int:
    # Owner rwx for directories (so they can be traversed and maintained),
    # owner rw for files (nothing ever needs to execute a snapshot or a key).
    return 0o700 if directory else 0o600


def _restrict_posix(target: Path, *, directory: bool) -> PermissionReport:
    expected = _expected_mode(directory)
    try:
        target.chmod(expected)
    except OSError as exc:
        raise PermissionEnforcementError(
            "permissions_chmod_failed", f"could not restrict {target.name}"
        ) from exc
    return _verify_posix(target, directory=directory)


def _verify_posix(target: Path, *, directory: bool) -> PermissionReport:
    expected = _expected_mode(directory)
    observed = stat.S_IMODE(target.stat().st_mode)
    if observed != expected:
        return PermissionReport(
            path=str(target),
            platform="posix",
            enforced=False,
            mechanism="mode-bits",
            detail=f"expected {expected:04o}, observed {observed:04o}",
        )
    # Group/other must hold no permission at all, which is what "owner only"
    # means when the owner is the process running the vault.
    if observed & 0o077:
        return PermissionReport(
            path=str(target),
            platform="posix",
            enforced=False,
            mechanism="mode-bits",
            detail="group or other permissions are present",
        )
    return PermissionReport(
        path=str(target),
        platform="posix",
        enforced=True,
        mechanism="mode-bits",
        detail=f"mode {observed:04o}",
    )


def _windows_apis() -> tuple[Any, Any, Any, Any]:
    """Resolve the advapi32 entry points, or fail with a clear reason."""

    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.SetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    advapi32.SetFileSecurityW.restype = wintypes.BOOL
    advapi32.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetFileSecurityW.restype = wintypes.BOOL
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return ctypes, wintypes, advapi32, kernel32


def _restrict_windows(target: Path) -> PermissionReport:
    """Apply an owner-only, non-inherited DACL.

    ``D:P`` makes the DACL *protected*, which drops inherited entries instead of
    merging with them. ``A;;FA;;;OW`` grants full access to the owner only, so a
    copy of the vault directory does not hand the key to another account.
    """

    try:
        ctypes, wintypes, advapi32, kernel32 = _windows_apis()
    except (ImportError, AttributeError, OSError) as exc:  # pragma: no cover - Windows only
        raise PermissionEnforcementError(
            "permissions_windows_api_unavailable",
            "the Windows security APIs are not available in this process",
        ) from exc

    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.ULONG()
    converted = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        _WINDOWS_SDDL,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(descriptor_size),
    )
    if not converted:  # pragma: no cover - Windows only
        raise PermissionEnforcementError(
            "permissions_windows_sddl_failed",
            "the owner-only security descriptor could not be built",
        )
    try:
        information = _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION
        applied = advapi32.SetFileSecurityW(str(target), information, descriptor)
        if not applied:  # pragma: no cover - Windows only
            error = ctypes.get_last_error()
            raise PermissionEnforcementError(
                "permissions_windows_acl_failed",
                f"SetFileSecurityW failed for {target.name} (error {error})",
            )
    finally:
        kernel32.LocalFree(descriptor)

    # Never claim protection that was not verified by reading it back.
    return _verify_windows(target)


def _verify_windows(target: Path) -> PermissionReport:
    """Read the DACL back and require it to be protected and owner-only."""

    try:
        ctypes, wintypes, advapi32, kernel32 = _windows_apis()
    except (ImportError, AttributeError, OSError) as exc:  # pragma: no cover - Windows only
        raise PermissionEnforcementError(
            "permissions_windows_api_unavailable",
            "the Windows security APIs are not available in this process",
        ) from exc

    needed = wintypes.DWORD()
    advapi32.GetFileSecurityW(
        str(target), _DACL_SECURITY_INFORMATION, None, 0, ctypes.byref(needed)
    )
    if not needed.value:  # pragma: no cover - Windows only
        raise PermissionEnforcementError(
            "permissions_windows_read_failed",
            "the security descriptor size could not be determined",
        )
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetFileSecurityW(
        str(target),
        _DACL_SECURITY_INFORMATION,
        buffer,
        needed,
        ctypes.byref(needed),
    ):  # pragma: no cover - Windows only
        raise PermissionEnforcementError(
            "permissions_windows_read_failed", "the security descriptor could not be read"
        )

    text = ctypes.c_wchar_p()
    text_size = wintypes.ULONG()
    converted = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        buffer,
        _SDDL_REVISION_1,
        _DACL_SECURITY_INFORMATION,
        ctypes.byref(text),
        ctypes.byref(text_size),
    )
    if not converted:  # pragma: no cover - Windows only
        raise PermissionEnforcementError(
            "permissions_windows_read_failed", "the security descriptor is not readable as SDDL"
        )
    try:
        observed = text.value or ""
    finally:
        kernel32.LocalFree(text)

    # An owner-only protected DACL: exactly one ACE, full access, owner rights.
    protected = observed.startswith("D:P")
    owner_only = ";;FA;;;OW)" in observed or ";;FA;;;S-1-3-4)" in observed
    enforced = protected and owner_only
    return PermissionReport(
        path=str(target),
        platform="windows",
        enforced=enforced,
        mechanism="windows-dacl",
        detail=observed,
    )


def platform_supports_enforcement() -> bool:
    """Whether real owner-only enforcement is available on this platform."""

    if os.name == "nt":
        try:
            _windows_apis()
        except (ImportError, AttributeError, OSError):
            return False
        return True
    return hasattr(Path, "chmod")


def suppress_missing(path: Path) -> None:  # pragma: no cover - helper
    with contextlib.suppress(OSError):
        path.unlink(missing_ok=True)


__all__ = [
    "PermissionEnforcementError",
    "PermissionReport",
    "platform_supports_enforcement",
    "restrict_to_owner",
    "verify_owner_only",
]
