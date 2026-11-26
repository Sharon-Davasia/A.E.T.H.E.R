"""Native UIA adapter (CP4): snapshot inspection behind disabled activation.

Real source, Windows-only construction. Ordinary startup never builds
it: without a trusted activation context (and off Windows) the
factory raises ``NativeUiaDisabled``. On Linux it is importable and
testable only by injecting a fake ``pywinauto`` module object.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from aether.adapters.windows.native_observer import ActivationContext
from aether.adapters.windows.native_uia import NativeUiaDisabled, build_native_uia_backend
from aether.core.apps.uia_snapshot import SnapshotResult, UiaSnapshotService
from aether.core.contracts.uia import UiaLimits
from aether.core.resources.app_window_authority import AppWindowResourceAuthority

__all__ = ["NativeUiaAdapter", "NativeUiaDisabled"]


class NativeUiaAdapter:
    """Window-authorized UIA snapshot inspection (native, disabled by default)."""

    def __init__(
        self,
        *,
        authority: AppWindowResourceAuthority,
        activation: ActivationContext | None,
        session_id: str,
        pywinauto_module: Any = None,
        clock: Callable[[], datetime] | None = None,
        content_inspection_permitted: Callable[[str], bool] | None = None,
    ) -> None:
        backend = build_native_uia_backend(
            activation=activation, pywinauto_module=pywinauto_module
        )
        self._service = UiaSnapshotService(
            authority=authority,
            backend_factory=lambda: backend,
            session_id=session_id,
            clock=clock,
            content_inspection_permitted=content_inspection_permitted,
        )

    def inspect_window(
        self,
        window_resource_id: str,
        *,
        require_content: bool = False,
        limits: UiaLimits | None = None,
    ) -> SnapshotResult:
        return self._service.inspect(
            window_resource_id, require_content=require_content, limits=limits
        )
