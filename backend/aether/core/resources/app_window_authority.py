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
from datetime import datetime
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
    expires_at: datetime | None = None
    # CP4 context: which app this window belongs to and how the
    # platform classified it (unknown fails closed for inspection).
    app_resource_id: str | None = None
    classification: object | None = None  # world_state.privacy.ContextClassification
    elevated: bool | None = None


class AppWindowResourceAuthority:
    """Broker-side authority for app/window resources (not a sandbox)."""

    def __init__(self, *, session_id: str | None = None) -> None:
        self._lock = threading.Lock()
        self._apps: dict[str, ApplicationRecord] = {}
        self._app_versions: dict[str, str] = {}
        self._windows: dict[str, WindowBinding] = {}
        self._by_hwnd: dict[int, str] = {}
        self.session_id = session_id

    def register_app(
        self, record: ApplicationRecord, *, version_token: str | None = None
    ) -> ResourceRef:
        """Register an app, optionally with its trusted version token."""
        with self._lock:
            self._apps[record.app_id] = record
            if version_token is not None:
                self._app_versions[record.app_id] = version_token
        return ResourceRef(
            kind="app",
            resource_id=record.app_id,
            observed_version=version_token or record.location_digest,
            data_class=DataClass.INTERNAL,
        )

    def app_version_token(self, app_id: str) -> str | None:
        with self._lock:
            return self._app_versions.get(app_id)

    def register_window(
        self,
        *,
        hwnd: int,
        process_token: str,
        instance_generation: int,
        version_token: str,
        expires_at: datetime | None = None,
        app_resource_id: str | None = None,
        classification: object | None = None,
        elevated: bool | None = None,
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
                expires_at=expires_at,
                app_resource_id=app_resource_id,
                classification=classification,
                elevated=elevated,
            )
            self._by_hwnd[hwnd] = window_id
        return ResourceRef(kind="window", resource_id=window_id, observed_version=version_token)

    def known_windows(self) -> tuple[WindowBinding, ...]:
        """All currently registered window bindings (bounded, in-memory)."""
        with self._lock:
            return tuple(self._windows.values())

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

    def authorize_ref(
        self, ref: ResourceRef, *, expected_kind: str, now: datetime | None = None
    ) -> None:
        """Fail closed unless the ref was issued here, is current, fresh
        and available for this kind.

        An app ref carrying an exact expected version (``observed_version``)
        requires the authority to hold matching trusted version evidence;
        missing version evidence denies, never passes.
        """
        if ref.kind != expected_kind:
            raise AppWindowAuthorityError("resource_kind_mismatch")
        with self._lock:
            if expected_kind == "app":
                record = self._apps.get(ref.resource_id)
                if record is None:
                    raise AppWindowAuthorityError("app_resource_not_registered")
                if not record.available:
                    raise AppWindowAuthorityError("app_resource_unavailable")
                if now is not None and record.fresh_until <= now:
                    raise AppWindowAuthorityError("app_resource_stale")
                if ref.observed_version is not None:
                    current = self._app_versions.get(ref.resource_id)
                    if current is None:
                        raise AppWindowAuthorityError("app_resource_version_unavailable")
                    if current != ref.observed_version:
                        raise AppWindowAuthorityError("app_resource_version_mismatch")
            elif expected_kind == "window":
                binding = self._windows.get(ref.resource_id)
                if binding is None:
                    raise AppWindowAuthorityError("window_resource_not_registered")
                if (
                    ref.observed_version is not None
                    and ref.observed_version != binding.version_token
                ):
                    raise AppWindowAuthorityError("window_resource_stale")
                if now is not None and binding.expires_at is not None and binding.expires_at <= now:
                    raise AppWindowAuthorityError("window_resource_expired")
            else:
                raise AppWindowAuthorityError("resource_kind_mismatch")
