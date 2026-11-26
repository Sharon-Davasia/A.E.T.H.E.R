"""UIA provider backend protocol and the deterministic fake (CP4).

The real backend (``adapters.windows.native_uia``) implements this
protocol against pywinauto/UIA behind disabled activation. Tests on
any platform use ``FakeUiaBackend`` with a controlled element tree,
staleness, latency and failure injection. Fakes never constitute
native evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class UiaBackendError(Exception):
    """Typed provider failure (timeout/unavailable/stale/etc.)."""


class UiaElementStale(UiaBackendError):
    pass


@dataclass(frozen=True, slots=True)
class RawElement:
    key: str
    control_type: str
    name: str | None = None
    automation_id: str | None = None
    patterns: frozenset[str] = frozenset()
    is_enabled: bool = True
    is_offscreen: bool = False
    is_password: bool = False
    bounding_rect: tuple[int, int, int, int] | None = None
    value_present: bool = False
    depth: int = 0
    children_keys: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WindowHandle:
    hwnd: int
    process_token: str


class UiaBackend(Protocol):
    def find_root(self, *, hwnd: int) -> RawElement | None: ...

    def children(self, element: RawElement) -> tuple[RawElement, ...]: ...

    def invoke(self, element: RawElement) -> dict[str, object]: ...

    def read_value(self, element: RawElement) -> dict[str, object]: ...

    def close(self) -> None: ...


@dataclass(slots=True)
class FakeUiaBackend:
    """Deterministic in-memory UIA tree (test evidence only)."""

    elements: dict[str, RawElement] = field(default_factory=dict)
    roots: dict[int, str] = field(default_factory=dict)
    stale_keys: set[str] = field(default_factory=set)
    closed: bool = False
    invoke_outcomes: dict[str, dict[str, object]] = field(default_factory=dict)

    def add_root(self, *, hwnd: int, root: RawElement, descendants: list[RawElement]) -> None:
        self.roots[hwnd] = root.key
        self.elements[root.key] = root
        for element in descendants:
            self.elements[element.key] = element

    def replace(self, old_key: str, new: RawElement) -> None:
        """Simulate controlled element replacement/invalidation."""
        parent = next((e for e in self.elements.values() if old_key in e.children_keys), None)
        self.elements.pop(old_key, None)
        self.elements[new.key] = new
        self.stale_keys.add(old_key)
        if parent is not None:
            object.__setattr__(
                parent,
                "children_keys",
                tuple(new.key if k == old_key else k for k in parent.children_keys),
            )

    def _live(self, element: RawElement) -> RawElement:
        live = self.elements.get(element.key)
        if live is None or element.key in self.stale_keys:
            raise UiaElementStale(f"element {element.key} is stale")
        return live

    def find_root(self, *, hwnd: int) -> RawElement | None:
        key = self.roots.get(hwnd)
        return self.elements.get(key) if key else None

    def children(self, element: RawElement) -> tuple[RawElement, ...]:
        live = self._live(element)
        return tuple(self.elements[k] for k in live.children_keys if k in self.elements)

    def invoke(self, element: RawElement) -> dict[str, object]:
        live = self._live(element)
        if "invoke" not in live.patterns:
            raise UiaBackendError("unsupported pattern: invoke")
        if not live.is_enabled:
            raise UiaBackendError("element is disabled")
        return dict(self.invoke_outcomes.get(live.key, {"invoked": live.key}))

    def read_value(self, element: RawElement) -> dict[str, object]:
        live = self._live(element)
        if "value" not in live.patterns:
            raise UiaBackendError("unsupported pattern: value")
        return {"value_present": live.value_present, "element_key": live.key}

    def close(self) -> None:
        self.closed = True
