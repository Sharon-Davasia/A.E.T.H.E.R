"""Native UIA backend exercised via an injected fake pywinauto module.

This is structural test evidence only — not native Windows evidence.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aether.adapters.windows.native_uia import (
    NativeUiaDisabled,
    build_native_uia_backend,
)


class _Info:
    def __init__(self, name: str, runtime: tuple[int, ...], *, enabled: bool = True) -> None:
        self.name = name
        self.runtime_id = runtime
        self.handle = runtime[-1]
        self.control_type = "Button"
        self.automation_id = ""
        self.enabled = enabled
        self.is_offscreen = False
        self.rectangle = SimpleNamespace(left=0, top=0, right=10, bottom=10)
        self.iface_invoke = object()
        self.iface_value = None


class _El:
    def __init__(self, name: str, runtime: tuple[int, ...], children=()) -> None:
        self.element_info = _Info(name, runtime)
        self._children = list(children)
        self.invoked = False

    def children(self):
        return list(self._children)

    def invoke(self):
        self.invoked = True


class _Desktop:
    def __init__(self, root) -> None:
        self._root = root

    def window(self, handle=None):
        return self._root


class _Window(_El):
    def exists(self, timeout=0):
        return True


def _fake_module():
    button = _El("Increment", (1, 2))
    root = _Window("Fixture", (1,), children=[button])
    return SimpleNamespace(Desktop=lambda backend: _Desktop(root)), root, button


def test_native_backend_walks_fake_pywinauto_tree() -> None:
    module, _root, button = _fake_module()
    backend = build_native_uia_backend(activation=None, pywinauto_module=module)
    raw_root = backend.find_root(hwnd=123)
    assert raw_root is not None and raw_root.name == "Fixture"
    kids = backend.children(raw_root)
    assert len(kids) == 1 and "invoke" in kids[0].patterns
    assert backend.invoke(kids[0]) == {"invoked": kids[0].key}
    assert button.invoked is True
    backend.close()


def test_native_backend_disabled_without_activation() -> None:
    import sys

    if sys.platform == "win32":
        pytest.skip("platform gate differs on Windows")
    with pytest.raises(NativeUiaDisabled):
        build_native_uia_backend(activation=None)


def test_native_service_adapter_uses_injected_module() -> None:
    from datetime import UTC, datetime, timedelta

    from aether.adapters.windows.uia import NativeUiaAdapter
    from aether.core.apps.uia_snapshot import UiaOutcome
    from aether.core.resources.app_window_authority import AppWindowResourceAuthority
    from aether.world_state.privacy import ContextClassification

    module, _root, _button = _fake_module()
    now = datetime(2026, 11, 15, tzinfo=UTC)
    authority = AppWindowResourceAuthority(session_id="s")
    ref = authority.register_window(
        hwnd=123,
        process_token="pid:1:ct",
        instance_generation=1,
        version_token="pid:1:ct#1",
        expires_at=now + timedelta(minutes=5),
        app_resource_id="app:fixture",
        classification=ContextClassification.PERMITTED_METADATA,
    )
    adapter = NativeUiaAdapter(
        authority=authority,
        activation=None,
        session_id="s",
        pywinauto_module=module,
        clock=lambda: now,
    )
    result = adapter.inspect_window(ref.resource_id)
    assert result.outcome in (UiaOutcome.OK, UiaOutcome.TRUNCATED)
    assert result.snapshot is not None and len(result.snapshot.elements) == 2
