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
from dataclasses import dataclass
from typing import Any, Protocol

from aether.adapters.windows.native_observer import ActivationContext, NativeObserverDisabled
from aether.core.apps.launch_authority import IntegrityEvidence
from aether.core.apps.launcher import LaunchCallResult, LaunchDenied
from aether.core.contracts.app_window import (
    ApplicationRecord,
    LaunchMethod,
    location_identity_digest,
)

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

    Establishes executable content identity by streaming the canonical
    file's bytes (bounded) and its OS file identity. Signer evidence
    is supplied by the platform API hook when available; an unknown
    signer is reported as unknown, never invented. For AppsFolder
    activation the package/AppUserModel identity is the evidence.
    Reading is limited to the canonical identity already present in
    the trusted registry record; no discovery or execution occurs.
    """

    def __init__(self, *, signer_of: Any = None) -> None:
        self._signer_of = signer_of  # Callable[[str], str | None] | None

    def verify(self, record: ApplicationRecord) -> IntegrityEvidence | None:
        from datetime import UTC, datetime

        identity = record.executable_identity
        if identity is None or record.location_digest is None:
            return None
        if location_identity_digest(identity) != record.location_digest:
            return None
        if record.launch_method is LaunchMethod.APPS_FOLDER_ACTIVATION:
            return IntegrityEvidence(
                location_digest=record.location_digest,
                content_sha256=None,
                signer_identity=None,
                package_identity=identity,
                verified_at=datetime.now(UTC),
            )
        if record.launch_method is not LaunchMethod.APPROVED_EXECUTABLE:
            return None
        digest = hashlib.sha256()
        total = 0
        try:
            info = os.stat(identity)
            with open(identity, "rb") as handle:
                while chunk := handle.read(1 << 20):
                    total += len(chunk)
                    if total > MAX_INTEGRITY_FILE_BYTES:
                        return None
                    digest.update(chunk)
        except OSError:
            return None
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
            file_identity=f"{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}",
        )


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

    def _launch(self, *, method: LaunchMethod, canonical_target: str) -> LaunchCallResult:
        if not canonical_target or "\x00" in canonical_target:
            raise LaunchDenied("canonical_target_invalid")
        if method is LaunchMethod.APPROVED_EXECUTABLE:
            pid, process_handle, thread_handle = self.api.create_process(canonical_target)
            try:
                if pid <= 0:
                    return LaunchCallResult(accepted=False, error_code="create_process_no_pid")
                return LaunchCallResult(accepted=True)
            finally:
                self.api.close_handle(thread_handle)
                self.api.close_handle(process_handle)
        if method is LaunchMethod.APPS_FOLDER_ACTIVATION:
            pid = self.api.activate_application(canonical_target)
            if pid <= 0:
                return LaunchCallResult(accepted=False, error_code="activation_no_pid")
            return LaunchCallResult(accepted=True)
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
        ole32.CoInitializeEx(None, 0x2)  # COINIT_APARTMENTTHREADED
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
            ole32.CoUninitialize()

    def close_handle(self, handle: object) -> None:
        if handle:
            self._kernel32.CloseHandle(handle)

    def get_process_creation_time(self, pid: int) -> str | None:
        return None  # provided by the observer's metadata providers
