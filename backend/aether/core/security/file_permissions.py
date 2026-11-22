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

# Access-mask bits that grant the right to read, write or execute. Any of these in
# an ACE is a disclosure/modification risk, so a protected-but-broad DACL is not
# accepted merely because it also contains an owner ACE.
_ACCESS_MASK_READ: Final = 0x0001
_ACCESS_MASK_WRITE: Final = 0x0002
_ACCESS_MASK_APPEND: Final = 0x0004
_ACCESS_MASK_DELETE_CHILD: Final = 0x0040
_ACCESS_MASK_WRITE_DAC: Final = 0x00040000
_ACCESS_MASK_WRITE_OWNER: Final = 0x00080000
_GENERIC_ALL: Final = 0x10000000
_GENERIC_WRITE: Final = 0x40000000
_GENERIC_READ: Final = 0x80000000
_DANGEROUS_ACCESS_BITS: Final = (
    _ACCESS_MASK_READ
    | _ACCESS_MASK_WRITE
    | _ACCESS_MASK_APPEND
    | _ACCESS_MASK_DELETE_CHILD
    | _ACCESS_MASK_WRITE_DAC
    | _ACCESS_MASK_WRITE_OWNER
    | _GENERIC_ALL
    | _GENERIC_WRITE
    | _GENERIC_READ
)

# The only principals permitted to hold access on a vault object.
#   OW  = owner rights (this file's owner)
#   S-1-3-4 = OWNER RIGHTS, the SDDL spelling of the same principal
_OWNER_PRINCIPALS: Final = frozenset({"OW", "S-1-3-4"})
_ACE_FLAG_INHERITED: Final = 0x10
_ACE_TYPE_ALLOW: Final = "A"

# SDDL uses two-letter access-mask abbreviations, not only hexadecimal. Reading
# them as hex made the parser refuse real descriptors (``FA`` is not hex), so the
# table is explicit. Values are the standard access bits.
_SDDL_RIGHTS: Final[dict[str, int]] = {
    "GR": 0x80000000,  # GENERIC_READ
    "GW": 0x40000000,  # GENERIC_WRITE
    "GX": 0x20000000,  # GENERIC_EXECUTE
    "GA": 0x10000000,  # GENERIC_ALL
    "FA": 0x001F01FF,  # FILE_ALL_ACCESS
    "FR": 0x00120089,  # FILE_GENERIC_READ
    "FW": 0x00120116,  # FILE_GENERIC_WRITE
    "FX": 0x001200A0,  # FILE_GENERIC_EXECUTE
    "RD": 0x00010000,  # FILE_READ_DATA / LIST_DIRECTORY
    "WD": 0x00040000,  # FILE_WRITE_DATA / ADD_FILE
    "AD": 0x00080000,  # FILE_APPEND_DATA / ADD_SUBDIRECTORY
    "REA": 0x00040000,  # FILE_READ_EA
    "WEA": 0x00100000,  # FILE_WRITE_EA
    "X": 0x00200000,  # FILE_EXECUTE / TRAVERSE
    "DC": 0x00400000,  # FILE_DELETE_CHILD
    "RA": 0x00800000,  # FILE_READ_ATTRIBUTES
    "WA": 0x01000000,  # FILE_WRITE_ATTRIBUTES
    "D": 0x00010000,  # DELETE (standard right)
    "RC": 0x00020000,  # READ_CONTROL
    "SD": 0x00040000,  # DELETE
    "WDAC": 0x00040000,  # WRITE_DAC token spelling
    "WO": 0x00080000,  # WRITE_OWNER
}
# Multi-letter keys must be tried longest-first so "FA" is not read as "F"+"A".
_SDDL_RIGHTS_BY_LENGTH = sorted(_SDDL_RIGHTS, key=len, reverse=True)


# SDDL inheritance ACE flags.
_SDDL_ACE_FLAGS: Final[dict[str, int]] = {
    "AI": 0x10,  # INHERITED_ACE (SDDL spells it ID for inherited-from-parent)
    "ID": 0x10,
    "OI": 0x01,  # OBJECT_INHERIT
    "CI": 0x02,  # CONTAINER_INHERIT
    "IO": 0x80,  # INHERIT_ONLY
    "NP": 0x04,  # NO_PROPAGATE
}
_SDDL_ACE_FLAGS_BY_LENGTH = sorted(_SDDL_ACE_FLAGS, key=len, reverse=True)


def parse_ace_flags(text: str) -> int:
    """Interpret SDDL ACE flags, which are letter pairs, not hexadecimal."""

    value = text.strip().upper()
    if not value:
        return 0
    if value.isdigit():
        return int(value, 16)
    flags = 0
    remaining = value
    while remaining:
        for key in _SDDL_ACE_FLAGS_BY_LENGTH:
            if remaining.startswith(key):
                flags |= _SDDL_ACE_FLAGS[key]
                remaining = remaining[len(key) :]
                break
        else:
            raise PermissionEnforcementError(
                "permissions_windows_unparseable",
                f"unrecognised ACE flag abbreviation {remaining!r}",
            )
    return flags


def parse_access_mask(text: str) -> int:
    """Interpret an SDDL access mask, abbreviated or hexadecimal, or raise.

    Abbreviations are tried first: ``FA`` means FILE_ALL_ACCESS, not 0xFA, and
    treating it as hex would silently under-report the granted rights. An explicit
    ``0x`` prefix, and a value of digits only, are read as hexadecimal.
    """

    value = text.strip()
    if not value:
        return 0
    if value[:2].lower() == "0x":
        try:
            return int(value, 16)
        except ValueError as exc:
            raise PermissionEnforcementError(
                "permissions_windows_unparseable", "an ACE mask is not hexadecimal"
            ) from exc
    if value.isdigit():
        return int(value, 16)
    mask = 0
    remaining = value.upper()
    while remaining:
        for key in _SDDL_RIGHTS_BY_LENGTH:
            if remaining.startswith(key):
                mask |= _SDDL_RIGHTS[key]
                remaining = remaining[len(key) :]
                break
        else:
            raise PermissionEnforcementError(
                "permissions_windows_unparseable",
                f"unrecognised access-mask abbreviation {remaining!r}",
            )
    return mask


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

    return evaluate_windows_dacl(target, observed)


@dataclass(frozen=True, slots=True)
class AceAnalysis:
    """One parsed access-control entry."""

    ace_type: str
    flags: int
    mask: int
    principal: str

    @property
    def inherited(self) -> bool:
        return bool(self.flags & _ACE_FLAG_INHERITED)

    @property
    def grants_access(self) -> bool:
        return self.ace_type == _ACE_TYPE_ALLOW and bool(self.mask & _DANGEROUS_ACCESS_BITS)


def parse_sddl_dacl(sddl: str) -> tuple[bool, tuple[AceAnalysis, ...]]:
    """Parse an SDDL string into (protected, ACEs).

    Only the DACL portion is interpreted: ``D:`` introduces it, ``P`` marks it
    protected, ``NO_ACCESS_CONTROL`` (``NO_ACCESS_CONTROL``/``N``) or a null DACL
    (``NO_ACCESS_CONTROL``) are rejected, and each parenthesised ACE is read as
    ``type;flags;mask;object;inherit;principal``.

    Raises :class:`PermissionEnforcementError` on anything unparseable, because a
    DACL that cannot be read cannot be trusted.
    """

    text = sddl.strip()
    if not text:
        raise PermissionEnforcementError(
            "permissions_windows_unparseable", "the security descriptor is empty"
        )
    if not text.startswith("D:"):
        raise PermissionEnforcementError(
            "permissions_windows_unparseable", "the descriptor has no DACL section"
        )
    remainder = text[2:]
    protected = False
    if remainder.startswith("P"):
        protected = True
        remainder = remainder[1:]

    aces: list[AceAnalysis] = []
    position = 0
    while position < len(remainder):
        character = remainder[position]
        if character.isspace():
            position += 1
            continue
        if character != "(":
            if remainder[position:].startswith("NO_ACCESS_CONTROL"):
                # An unprotected null DACL grants everyone full control.
                return False, ()
            raise PermissionEnforcementError(
                "permissions_windows_unparseable",
                f"unexpected DACL content at offset {position}",
            )
        end = remainder.find(")", position)
        if end < 0:
            raise PermissionEnforcementError("permissions_windows_unparseable", "unterminated ACE")
        fields = remainder[position + 1 : end].split(";")
        if len(fields) < 6:
            raise PermissionEnforcementError(
                "permissions_windows_unparseable", "an ACE has fewer than six fields"
            )
        ace_type, flags_text, mask_text, _object, _inherit, principal = fields[:6]
        flags = parse_ace_flags(flags_text)
        mask = parse_access_mask(mask_text)
        aces.append(
            AceAnalysis(
                ace_type=ace_type or _ACE_TYPE_ALLOW,
                flags=flags,
                mask=mask,
                principal=principal,
            )
        )
        position = end + 1
    return protected, tuple(aces)


def evaluate_windows_dacl(target: Path, sddl: str) -> PermissionReport:
    """Decide whether a DACL actually protects ``target`` as owner-only.

    The previous implementation accepted any string containing an owner ACE, so a
    descriptor that *also* granted Everyone or Users access passed. This evaluates
    the whole inventory instead:

    * the DACL must be present and protected (no inherited ACEs can widen it);
    * there must be at least one ACE, and none of them may be inherited;
    * every ACE must be an allow-ACE for the owner principal;
    * deny-ACEs, unknown ACE types and any other principal are rejected.

    A deny-ACE is refused rather than reasoned about: on a vault object it means
    the effective access is not what this check can prove, and "prove" is the
    only acceptable standard for a key file.
    """

    protected, aces = parse_sddl_dacl(sddl)
    reasons: list[str] = []
    if not protected:
        reasons.append("DACL is not protected (inherited ACEs may apply)")
    if not aces:
        reasons.append("DACL grants no access at all, or is null")
    for ace in aces:
        if ace.inherited:
            reasons.append(f"inherited ACE for {ace.principal}")
            continue
        if ace.ace_type != _ACE_TYPE_ALLOW:
            reasons.append(f"non-allow ACE ({ace.ace_type}) for {ace.principal}")
            continue
        if ace.principal not in _OWNER_PRINCIPALS:
            if ace.grants_access:
                reasons.append(f"access granted to unauthorized principal {ace.principal}")
            else:
                reasons.append(f"unexpected principal {ace.principal} in DACL")
    enforced = not reasons
    detail = sddl if enforced else f"{sddl} | " + "; ".join(reasons)
    return PermissionReport(
        path=str(target),
        platform="windows",
        enforced=enforced,
        mechanism="windows-dacl",
        detail=detail,
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
