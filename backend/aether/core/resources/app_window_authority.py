"""Session-ephemeral app/window resource authority (Phase 3).

Issues real ``app:<uuid>`` / ``window:<uuid>`` resource references.
Window references are session-ephemeral: the authority maps a broker
id to (HWND, process instance, instance generation) internally; raw
HWNDs never appear in a resource id. Re-registering the same HWND
under a new process instance or instance generation invalidates the
previous reference — resolving or authorizing it fails closed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from uuid import uuid4

from aether.core.contracts.app_window import ApplicationRecord
from aether.core.contracts.resource import DataClass, ResourceRef


class AppWindowAuthorityError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class WindowBinding:
    window_id: str
    hwnd: int
    process_token: str
    instance_generation: int
    version_token: str


class AppWindowResourceAuthority:
    """Broker-side authority for app/window resources (not a sandbox)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._apps: dict[str, ApplicationRecord] = {}
        self._windows: dict[str, WindowBinding] = {}
        self._by_hwnd: dict[int, str] = {}

    def register_app(self, record: ApplicationRecord) -> ResourceRef:
        with self._lock:
            self._apps[record.app_id] = record
        return ResourceRef(
            kind="app",
            resource_id=record.app_id,
            observed_version=record.location_digest,
            data_class=DataClass.INTERNAL,
        )

    def register_window(
        self, *, hwnd: int, process_token: str, instance_generation: int, version_token: str
    ) -> ResourceRef:
        """Issue a fresh window ref, invalidating any previous HWND binding."""
        with self._lock:
            previous_id = self._by_hwnd.get(hwnd)
            if previous_id is not None:
                self._windows.pop(previous_id, None)
            window_id = f"window:{uuid4()}"
            self._windows[window_id] = WindowBinding(
                window_id=window_id,
                hwnd=hwnd,
                process_token=process_token,
                instance_generation=instance_generation,
                version_token=version_token,
            )
            self._by_hwnd[hwnd] = window_id
        return ResourceRef(kind="window", resource_id=window_id, observed_version=version_token)

    def resolve_window(self, window_id: str) -> WindowBinding:
        with self._lock:
            binding = self._windows.get(window_id)
        if binding is None:
            raise AppWindowAuthorityError("window_resource_not_registered")
        return binding

    def invalidate_window(self, window_id: str) -> None:
        with self._lock:
            binding = self._windows.pop(window_id, None)
            if binding is not None and self._by_hwnd.get(binding.hwnd) == window_id:
                self._by_hwnd.pop(binding.hwnd, None)

    def authorize_ref(self, ref: ResourceRef, *, expected_kind: str) -> None:
        """Fail closed unless the ref was issued here for this kind."""
        if ref.kind != expected_kind:
            raise AppWindowAuthorityError("resource_kind_mismatch")
        with self._lock:
            if expected_kind == "app":
                if ref.resource_id not in self._apps:
                    raise AppWindowAuthorityError("app_resource_not_registered")
            elif expected_kind == "window":
                binding = self._windows.get(ref.resource_id)
                if binding is None:
                    raise AppWindowAuthorityError("window_resource_not_registered")
                if (
                    ref.observed_version is not None
                    and ref.observed_version != binding.version_token
                ):
                    raise AppWindowAuthorityError("window_resource_stale")
            else:
                raise AppWindowAuthorityError("resource_kind_mismatch")
