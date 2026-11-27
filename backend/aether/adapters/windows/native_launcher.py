"""Native Windows launch implementation source (CP3-B05) — DISABLED.

Real bounded launch source behind the same activation boundary as
the native observer. Production behavior remains default-denied:
construction requires an :class:`ActivationContext` from trusted
composition, no production caller exists, and ordinary application
startup never constructs this adapter.

Approved mechanisms only (Master Specification preference order —
supported Windows application interfaces before any UI fallback):

- ``approved_executable``: ``CreateProcessW`` against the canonical
  approved executable identity from the trusted authorization. No
  argument string is accepted from the model or renderer (the
  command line is exactly the quoted canonical path), no shell, no
  shell-mediated execution, no installer execution, no elevation verb.
- ``apps_folder_activation``: ``IApplicationActivationManager
  .ActivateApplication`` with the registered AppUserModelId. No
  arbitrary URI/protocol activation.

Process/thread handles are closed on every path. The adapter reports
only whether the platform accepted the launch call; verified success
is decided independently by the launch verifier from observed
process/window evidence. There is no retry of uncertain effects.
Categories that cannot be launched with an approved mechanism are
denied truthfully rather than given an unsafe fallback.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from aether.adapters.windows.native_observer import ActivationContext, NativeObserverDisabled
from aether.core.apps.launch_authority import IntegrityEvidence
from aether.core.apps.launcher import LaunchCallResult, LaunchDenied
from aether.core.contracts.app_window import (
    ApplicationRecord,
    LaunchMethod,
    location_identity_digest,
)
from aether.core.resources.path_safety import PathSafetyError, reject_reparse_components

MAX_INTEGRITY_FILE_BYTES = 1 << 30  # 1 GiB streamed-hash bound


class Win32LaunchApi(Protocol):
    """Injectable native launch surface (fake-verified in tests)."""

    def create_process(self, canonical_executable: str) -> tuple[int, object, object]:
        """CreateProcessW; returns (pid, process_handle, thread_handle)."""
        ...

    def activate_application(self, app_user_model_id: str) -> int:
        """IApplicationActivationManager.ActivateApplication; returns pid."""
        ...

    def close_handle(self, handle: object) -> None: ...

    def get_process_creation_time(self, pid: int) -> str | None: ...


class NativeIntegrityProvider:
    """Native integrity-evidence source for approved launch identity.

    For executable targets, content identity is established by
    streaming bytes from the *same opened file handle* whose OS file
    identity is recorded, and the identity is re-validated after
    inspection: replacement or mutation during inspection yields no
    evidence. Approved targets are restricted to canonical local
    executable identities: UNC/network paths, drive-relative paths,
    reparse points (symlinks), non-regular files and unsupported
    extensions are rejected conservatively. For packaged (AppsFolder)
    applications, installed package identity and version come from
    the platform package query — a repeated registry string is not
    treated as independently verified package integrity, and without
    a package-query result there is no evidence. Signer evidence is
    supplied by the platform hook when available and otherwise
    remains explicitly unavailable. The documented residual
    verify-to-create race (CP3 sec.5) is unchanged.
    """

    def __init__(self, *, signer_of: Any = None, package_query: Any = None) -> None:
        self._signer_of = signer_of  # Callable[[str], str | None] | None
        # Callable[[str], tuple[str, str] | None]: AUMID -> (package
        # full identity, package version) from the platform.
        self._package_query = package_query

    def verify(self, record: ApplicationRecord) -> IntegrityEvidence | None:
        from datetime import UTC, datetime

        identity = record.executable_identity
        if identity is None or record.location_digest is None:
            return None
        if location_identity_digest(identity) != record.location_digest:
            return None
        if record.launch_method is LaunchMethod.APPS_FOLDER_ACTIVATION:
            if self._package_query is None:
                return None
            try:
                queried = self._package_query(identity)
            except Exception:
                return None
            if queried is None:
                return None
            package_identity, package_version = queried
            if not package_identity or not package_version:
                return None
            return IntegrityEvidence(
                location_digest=record.location_digest,
                content_sha256=None,
                signer_identity=None,
                package_identity=package_identity,
                verified_at=datetime.now(UTC),
                package_version=package_version,
            )
        if record.launch_method is not LaunchMethod.APPROVED_EXECUTABLE:
            return None
        if not _is_supported_local_executable(identity):
            return None
        digest = hashlib.sha256()
        total = 0
        try:
            descriptor = os.open(identity, os.O_RDONLY)
        except OSError:
            return None
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                return None
            file_identity = _file_identity(before)
            with os.fdopen(os.dup(descriptor), "rb") as handle:
                while chunk := handle.read(1 << 20):
                    total += len(chunk)
                    if total > MAX_INTEGRITY_FILE_BYTES:
                        return None
                    digest.update(chunk)
            after = os.fstat(descriptor)
        except OSError:
            return None
        finally:
            os.close(descriptor)
        if _file_identity(after) != file_identity:
            return None  # identity changed during inspection: no evidence
        signer = None
        if self._signer_of is not None:
            try:
                signer = self._signer_of(identity)
            except Exception:
                signer = None
        return IntegrityEvidence(
            location_digest=record.location_digest,
            content_sha256=digest.hexdigest(),
            signer_identity=signer,
            package_identity=None,
            verified_at=datetime.now(UTC),
            file_identity=file_identity,
        )


def _file_identity(info: os.stat_result) -> str:
    return f"{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}"


def _is_supported_local_executable(identity: str) -> bool:
    """Canonical, supported local executable identities only."""
    if identity.startswith(("\\\\", "//")):
        return False  # UNC / network path
    windows_style = len(identity) >= 2 and identity[1] == ":"
    if windows_style:
        if len(identity) < 4 or identity[2] not in ("\\", "/"):
            return False  # drive-relative or malformed
        if not identity.casefold().endswith(".exe"):
            return False  # unsupported executable identity
    elif not os.path.isabs(identity):
        return False  # relative identity is never canonical
    try:
        # Rejects symlinks, Windows reparse points and directory
        # junctions in every path component. os.path.islink() is not
        # sufficient on Windows: it does not reliably report
        # directory junctions.
        reject_reparse_components(Path(identity))
    except PathSafetyError:
        return False  # reparse point / symlink / junction: conservative deny
    return True


# ---------------------------------------------------------------------------
# Native packaged-application identity (AppsFolder / AUMID verification)
#
# An AUMID ("<package family>!<application id>") is verified against
# the platform package catalogue - never against registry strings,
# display names or discovery records:
#   1. GetPackagesByPackageFamily must return exactly one installed
#      package for the family (current user); zero or several is
#      ambiguous and yields no evidence.
#   2. GetPackageApplicationIds for that package must list the exact
#      requested AUMID (application-specific membership).
#   3. The version comes from the platform PACKAGE_ID of the same
#      package (GetPackageInfo), not from string inference.
# Any malformed input, API failure or unverifiable identity returns
# None (no evidence), which the integrity provider and launch
# authority already treat as denial.
# ---------------------------------------------------------------------------

_MAX_FAMILY_PACKAGES = 128
_MAX_PACKAGE_APPLICATIONS = 256
_MAX_PACKAGE_QUERY_BUFFER = 1 << 20  # bytes, hard bound for native buffers


class PackageQueryApi(Protocol):
    """Injectable appmodel boundary (ctypes in production)."""

    def packages_by_family(self, family_name: str) -> list[str] | None: ...

    def package_version(self, package_full_name: str) -> str | None: ...

    def application_ids(self, package_full_name: str) -> list[str] | None: ...


def _aumid_parts(aumid: object) -> tuple[str, str] | None:
    if not isinstance(aumid, str) or "\x00" in aumid:
        return None
    family, separator, application = aumid.partition("!")
    if not separator or not family or not application or "!" in application:
        return None
    return family, application


def package_identity_for_aumid(api: PackageQueryApi, aumid: object) -> tuple[str, str] | None:
    """Resolve an exact AUMID to (package full name, version) or None."""
    parts = _aumid_parts(aumid)
    if parts is None:
        return None
    family, _application = parts
    packages = api.packages_by_family(family)
    if not packages or len(packages) != 1:
        return None  # absent or ambiguous installed identity
    package_full_name = packages[0]
    application_ids = api.application_ids(package_full_name)
    if not application_ids:
        return None
    if str(aumid).casefold() not in {entry.casefold() for entry in application_ids}:
        return None  # the exact application is not in this package
    version = api.package_version(package_full_name)
    if not version:
        return None
    return package_full_name, version


def native_package_query(aumid: str) -> tuple[str, str] | None:  # pragma: no cover - Windows only
    """Production package query over the Win32 appmodel APIs."""
    try:
        return package_identity_for_aumid(_CtypesPackageQueryApi(), aumid)
    except Exception:
        return None


class _CtypesPackageQueryApi:  # pragma: no cover - Windows only source
    """GetPackagesByPackageFamily / GetPackageInfo / GetPackageApplicationIds."""

    _ERROR_INSUFFICIENT_BUFFER = 122
    _PACKAGE_FILTER_ALL_LOADED = 0x00000000

    def __init__(self) -> None:
        import ctypes

        self._ctypes = ctypes
        windll: Any = getattr(ctypes, "windll", None)
        if windll is None:
            raise OSError("appmodel requires Windows")
        self._kernel32: Any = windll.kernel32

    def packages_by_family(self, family_name: str) -> list[str] | None:
        ctypes = self._ctypes
        kernel32 = self._kernel32
        count = ctypes.c_uint32(0)
        length = ctypes.c_uint32(0)
        kernel32.GetPackagesByPackageFamily(
            family_name, ctypes.byref(count), None, ctypes.byref(length), None
        )
        if count.value == 0 or count.value > _MAX_FAMILY_PACKAGES:
            return [] if count.value == 0 else None
        if length.value == 0 or length.value > 32768:
            return None
        buffer = ctypes.create_unicode_buffer(length.value)
        pointers = (ctypes.c_void_p * count.value)()
        filled = ctypes.c_uint32(count.value)
        filled_length = ctypes.c_uint32(length.value)
        result = kernel32.GetPackagesByPackageFamily(
            family_name,
            ctypes.byref(filled),
            pointers,
            ctypes.byref(filled_length),
            buffer,
        )
        if result != 0:
            return None
        names: list[str] = []
        for index in range(min(filled.value, _MAX_FAMILY_PACKAGES)):
            address = pointers[index]
            if not address:
                return None
            names.append(ctypes.wstring_at(address))
        return names

    def _open_package_info(self, package_full_name: str):  # type: ignore[no-untyped-def]
        ctypes = self._ctypes
        reference = ctypes.c_void_p()
        result = self._kernel32.OpenPackageInfoByFullName(
            package_full_name, 0, ctypes.byref(reference)
        )
        if result != 0 or not reference.value:
            return None
        return reference

    def package_version(self, package_full_name: str) -> str | None:
        ctypes = self._ctypes
        kernel32 = self._kernel32
        reference = self._open_package_info(package_full_name)
        if reference is None:
            return None
        try:
            length = ctypes.c_uint32(0)
            count = ctypes.c_uint32(0)
            kernel32.GetPackageInfo(
                reference,
                self._PACKAGE_FILTER_ALL_LOADED,
                ctypes.byref(length),
                None,
                ctypes.byref(count),
            )
            if length.value == 0 or length.value > _MAX_PACKAGE_QUERY_BUFFER:
                return None
            buffer = ctypes.create_string_buffer(length.value)
            filled = ctypes.c_uint32(count.value)
            result = kernel32.GetPackageInfo(
                reference,
                self._PACKAGE_FILTER_ALL_LOADED,
                ctypes.byref(length),
                buffer,
                ctypes.byref(filled),
            )
            if result != 0 or filled.value < 1:
                return None
            # PACKAGE_INFO { reserved, flags, PACKAGE_ID id, ... };
            # PACKAGE_ID { reserved, architecture, PACKAGE_VERSION
            # version { Revision, Build, Minor, Major : UINT16 } }.
            raw = buffer.raw
            if len(raw) < 24:
                return None
            import struct

            revision, build, minor, major = struct.unpack_from("<HHHH", raw, 16)
            return f"{major}.{minor}.{build}.{revision}"
        finally:
            kernel32.ClosePackageInfo(reference)

    def application_ids(self, package_full_name: str) -> list[str] | None:
        ctypes = self._ctypes
        kernel32 = self._kernel32
        reference = self._open_package_info(package_full_name)
        if reference is None:
            return None
        try:
            length = ctypes.c_uint32(0)
            count = ctypes.c_uint32(0)
            kernel32.GetPackageApplicationIds(
                reference, ctypes.byref(length), None, ctypes.byref(count)
            )
            if count.value == 0 or count.value > _MAX_PACKAGE_APPLICATIONS:
                return [] if count.value == 0 else None
            if length.value == 0 or length.value > _MAX_PACKAGE_QUERY_BUFFER:
                return None
            buffer = ctypes.create_string_buffer(length.value)
            filled = ctypes.c_uint32(count.value)
            result = kernel32.GetPackageApplicationIds(
                reference, ctypes.byref(length), buffer, ctypes.byref(filled)
            )
            if result != 0 or filled.value < 1:
                return None
            pointers = (ctypes.c_void_p * filled.value).from_buffer(buffer)
            ids: list[str] = []
            for index in range(filled.value):
                address = pointers[index]
                if not address:
                    return None
                ids.append(ctypes.wstring_at(address))
            return ids
        finally:
            kernel32.ClosePackageInfo(reference)


@dataclass(slots=True)
class NativeWindowsLaunchAdapter:
    """Bounded native launcher; disabled without trusted activation."""

    api: Win32LaunchApi
    activation: ActivationContext | None = None

    @classmethod
    def for_testing(cls, api: Win32LaunchApi) -> NativeWindowsLaunchAdapter:
        """Test seam: a fake API stands in for Windows; no test token is
        produced, and this constructor is never used by production wiring."""
        return cls(api=api, activation=None)

    def launch(
        self, *, app_id: str, method: LaunchMethod, canonical_target: str
    ) -> LaunchCallResult:
        if self.activation is None:
            raise NativeObserverDisabled(
                "native launcher requires trusted activation; it is disabled"
            )
        return self._launch(method=method, canonical_target=canonical_target)

    def launch_for_testing(
        self, *, app_id: str, method: LaunchMethod, canonical_target: str
    ) -> LaunchCallResult:
        """Exercise the real launch logic against an injected fake API."""
        return self._launch(method=method, canonical_target=canonical_target)

    def _process_token(self, pid: int) -> str | None:
        """Returned process identity for verifier correlation (R04)."""
        creation = self.api.get_process_creation_time(pid)
        return f"{pid}:{creation}" if creation else None

    def _launch(self, *, method: LaunchMethod, canonical_target: str) -> LaunchCallResult:
        if not canonical_target or "\x00" in canonical_target:
            raise LaunchDenied("canonical_target_invalid")
        if method is LaunchMethod.APPROVED_EXECUTABLE:
            pid, process_handle, thread_handle = self.api.create_process(canonical_target)
            try:
                if pid <= 0:
                    return LaunchCallResult(accepted=False, error_code="create_process_no_pid")
                return LaunchCallResult(accepted=True, process_token=self._process_token(pid))
            finally:
                self.api.close_handle(thread_handle)
                self.api.close_handle(process_handle)
        if method is LaunchMethod.APPS_FOLDER_ACTIVATION:
            pid = self.api.activate_application(canonical_target)
            if pid <= 0:
                return LaunchCallResult(accepted=False, error_code="activation_no_pid")
            return LaunchCallResult(accepted=True, process_token=self._process_token(pid))
        # No unsafe fallback for unapproved categories.
        raise LaunchDenied("launch_method_not_approved")


class _CtypesWin32LaunchApi:  # pragma: no cover - Windows only source
    """Real Win32 implementation. Never constructed in ordinary startup."""

    def __init__(self) -> None:
        import sys

        if sys.platform != "win32":
            raise LaunchDenied("native_launcher_requires_windows")
        import ctypes

        self._ctypes: Any = ctypes
        self._kernel32: Any = ctypes.windll.kernel32

    def create_process(self, canonical_executable: str) -> tuple[int, object, object]:
        ctypes = self._ctypes

        class STARTUPINFO(ctypes.Structure):  # type: ignore[name-defined,misc]
            _fields_ = [  # noqa: RUF012
                ("cb", ctypes.c_ulong),
                ("lpReserved", ctypes.c_wchar_p),
                ("lpDesktop", ctypes.c_wchar_p),
                ("lpTitle", ctypes.c_wchar_p),
                ("dwX", ctypes.c_ulong),
                ("dwY", ctypes.c_ulong),
                ("dwXSize", ctypes.c_ulong),
                ("dwYSize", ctypes.c_ulong),
                ("dwXCountChars", ctypes.c_ulong),
                ("dwYCountChars", ctypes.c_ulong),
                ("dwFillAttribute", ctypes.c_ulong),
                ("dwFlags", ctypes.c_ulong),
                ("wShowWindow", ctypes.c_ushort),
                ("cbReserved2", ctypes.c_ushort),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", ctypes.c_void_p),
                ("hStdOutput", ctypes.c_void_p),
                ("hStdError", ctypes.c_void_p),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):  # type: ignore[name-defined,misc]
            _fields_ = [  # noqa: RUF012
                ("hProcess", ctypes.c_void_p),
                ("hThread", ctypes.c_void_p),
                ("dwProcessId", ctypes.c_ulong),
                ("dwThreadId", ctypes.c_ulong),
            ]

        startup = STARTUPINFO()
        startup.cb = ctypes.sizeof(startup)
        info = PROCESS_INFORMATION()
        # Command line is exactly the quoted canonical path: no
        # model/renderer-supplied arguments can be expressed here.
        command_line = ctypes.create_unicode_buffer(f'"{canonical_executable}"')
        ok = self._kernel32.CreateProcessW(
            canonical_executable,
            command_line,
            None,
            None,
            False,
            0,
            None,
            None,
            ctypes.byref(startup),
            ctypes.byref(info),
        )
        if not ok:
            raise LaunchDenied("create_process_failed")
        return int(info.dwProcessId), info.hProcess, info.hThread

    def activate_application(self, app_user_model_id: str) -> int:
        # IApplicationActivationManager::ActivateApplication via COM
        # vtable (CLSID C2F03A33-21F5-47FA-B4BB-156362A2F239,
        # IID 2E941141-7F97-4756-BA1D-9DECDE894A3D). Activation
        # arguments are empty: none are accepted from any caller.
        ctypes = self._ctypes

        class GUID(ctypes.Structure):  # type: ignore[name-defined,misc]
            _fields_ = [  # noqa: RUF012
                ("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8),
            ]

            def __init__(self, text: str) -> None:
                import uuid

                value = uuid.UUID(text)
                super().__init__(
                    value.time_low,
                    value.time_mid,
                    value.time_hi_version,
                    (ctypes.c_ubyte * 8)(*value.bytes[8:]),
                )

        ole32 = ctypes.windll.ole32
        # COINIT_APARTMENTTHREADED. RPC_E_CHANGED_MODE means the
        # apartment was already initialized differently: proceed
        # without owning initialization (and without uninitializing).
        init_hr = ole32.CoInitializeEx(None, 0x2)
        owns_apartment = init_hr in (0, 1)  # S_OK / S_FALSE
        if init_hr not in (0, 1, -2147417850):  # RPC_E_CHANGED_MODE
            raise LaunchDenied("com_apartment_initialization_failed")
        manager = ctypes.c_void_p()
        try:
            hr = ole32.CoCreateInstance(
                ctypes.byref(GUID("{C2F03A33-21F5-47FA-B4BB-156362A2F239}")),
                None,
                0x1,  # CLSCTX_INPROC_SERVER
                ctypes.byref(GUID("{2E941141-7F97-4756-BA1D-9DECDE894A3D}")),
                ctypes.byref(manager),
            )
            if hr != 0 or not manager:
                raise LaunchDenied("application_activation_manager_unavailable")
            vtable = ctypes.cast(manager, ctypes.POINTER(ctypes.c_void_p))
            activate = ctypes.WINFUNCTYPE(
                ctypes.c_long,
                ctypes.c_void_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
            )(vtable[3])
            pid = ctypes.c_ulong(0)
            hr = activate(manager, app_user_model_id, "", 0, ctypes.byref(pid))
            if hr != 0:
                raise LaunchDenied("application_activation_failed")
            return int(pid.value)
        finally:
            if manager:
                vtable = ctypes.cast(manager, ctypes.POINTER(ctypes.c_void_p))
                release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtable[2])
                release(manager)
            if owns_apartment:
                ole32.CoUninitialize()

    def close_handle(self, handle: object) -> None:
        if handle:
            self._kernel32.CloseHandle(handle)

    def get_process_creation_time(self, pid: int) -> str | None:
        return None  # provided by the observer's metadata providers
