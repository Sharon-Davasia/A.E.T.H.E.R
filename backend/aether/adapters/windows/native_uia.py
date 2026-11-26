"""Real pywinauto/UIA backend behind disabled activation (CP4).

This is the native provider: it resolves the authorized window's UIA
root via pywinauto's UIA backend and walks the *real* element tree
through the bounded ``UiaBackend`` protocol. It is never constructed
by ordinary startup; ``build_native_uia_backend`` raises unless the
process runs on Windows under a trusted activation context, mirroring
the native observer/launcher gates. Protected/elevated surfaces are
not read: a provider failure surfaces as a typed backend error for the
caller to classify, never as partial silent success.

Linux CI exercises this module only through injected fakes of the
``pywinauto`` module object, so these tests are not native evidence.
"""

from __future__ import annotations

from typing import Any

from aether.adapters.windows.native_observer import ActivationContext
from aether.adapters.windows.uia_backend import RawElement, UiaBackendError, UiaElementStale


class NativeUiaDisabled(RuntimeError):
    pass


def _pattern_names(element: Any) -> frozenset[str]:
    names: set[str] = set()
    info = element.element_info
    for attribute, pattern in (
        ("iface_invoke", "invoke"),
        ("iface_value", "value"),
        ("iface_selection_item", "selectionitem"),
        ("iface_toggle", "toggle"),
        ("iface_expand_collapse", "expandcollapse"),
    ):
        try:
            if getattr(info, attribute, None) is not None:
                names.add(pattern)
        except Exception:
            continue
    return frozenset(names)


class PywinautoUiaBackend:
    """``UiaBackend`` over pywinauto's UIA element tree (Windows only)."""

    def __init__(self, *, pywinauto_module: Any, root_window: Any) -> None:
        self._pywinauto = pywinauto_module
        self._root_window = root_window
        self._known: dict[str, Any] = {}

    # -- helpers -----------------------------------------------------

    def _register(self, element: Any) -> RawElement:
        info = element.element_info
        runtime_id = ".".join(str(p) for p in (info.runtime_id or (info.handle or id(element),)))
        children: tuple[str, ...] = ()
        try:
            children = tuple(self._key(c.element_info) for c in element.children())
        except Exception:
            children = ()
        raw = RawElement(
            key=runtime_id,
            control_type=str(info.control_type or "unknown"),
            name=(info.name or None),
            automation_id=(info.automation_id or None),
            patterns=_pattern_names(element),
            is_enabled=bool(info.enabled),
            is_offscreen=bool(getattr(info, "is_offscreen", False)),
            is_password=bool(getattr(info, "is_password", False)),
            bounding_rect=_rect(info.rectangle),
            value_present=False,
            children_keys=children,
        )
        self._known[runtime_id] = element
        return raw

    @staticmethod
    def _key(info: Any) -> str:
        return ".".join(str(p) for p in (info.runtime_id or (info.handle or 0,)))

    def _live(self, element: RawElement) -> Any:
        impl = self._known.get(element.key)
        if impl is None:
            raise UiaElementStale(f"element {element.key} is no longer tracked")
        try:
            _ = impl.element_info.control_type  # raises when the element is gone
        except Exception as exc:
            raise UiaElementStale(f"element {element.key} disappeared") from exc
        return impl

    # -- UiaBackend ---------------------------------------------------

    def find_root(self, *, hwnd: int) -> RawElement | None:
        try:
            desktop = self._pywinauto.Desktop(backend="uia")
            window = desktop.window(handle=hwnd)
            if not window.exists(timeout=0):
                return None
            return self._register(window)
        except Exception as exc:
            raise UiaBackendError(f"uia_root_unavailable: {type(exc).__name__}") from exc

    def children(self, element: RawElement) -> tuple[RawElement, ...]:
        impl = self._live(element)
        try:
            return tuple(self._register(child) for child in impl.children())
        except UiaElementStale:
            raise
        except Exception as exc:
            raise UiaBackendError(f"uia_children_failed: {type(exc).__name__}") from exc

    def invoke(self, element: RawElement) -> dict[str, object]:
        impl = self._live(element)
        try:
            impl.invoke()
        except Exception as exc:
            raise UiaBackendError(f"uia_invoke_failed: {type(exc).__name__}") from exc
        return {"invoked": element.key}

    def read_value(self, element: RawElement) -> dict[str, object]:
        impl = self._live(element)
        try:
            value = impl.iface_value.CurrentValue
        except Exception as exc:
            raise UiaBackendError(f"uia_value_failed: {type(exc).__name__}") from exc
        # Presence only: the value itself is classified at the service
        # layer; password values never reach it (service drops them).
        return {"value_present": bool(value), "element_key": element.key}

    def close(self) -> None:
        self._known.clear()
        self._root_window = None


def _rect(rectangle: Any) -> tuple[int, int, int, int] | None:
    try:
        return (
            int(rectangle.left),
            int(rectangle.top),
            int(rectangle.right),
            int(rectangle.bottom),
        )
    except Exception:
        return None


def build_native_uia_backend(
    *, activation: ActivationContext | None, pywinauto_module: Any = None
) -> PywinautoUiaBackend:
    """Construct the native backend; disabled without trusted activation."""
    import sys

    if pywinauto_module is not None:
        # Explicit test seam (mirrors NativeWindowsLaunchAdapter.for_testing):
        # an injected module object stands in for pywinauto. Never used
        # by production wiring, and produces no native evidence.
        return PywinautoUiaBackend(pywinauto_module=pywinauto_module, root_window=None)
    if sys.platform != "win32" or activation is None:
        raise NativeUiaDisabled("native UIA requires Windows + trusted activation; disabled")
    import pywinauto as real_pywinauto  # type: ignore[import-not-found]  # pragma: no cover

    return PywinautoUiaBackend(pywinauto_module=real_pywinauto, root_window=None)
