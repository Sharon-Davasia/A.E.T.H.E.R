"""Deterministic synthetic fixture application model (CP5 sec.10).

The smallest standard-controls fixture: an identifiable window, a
bounded status text, a harmless Increment button with a deterministic
effect (status count +1), a disabled control, a simulated
password control, a modal-dialog trigger, controlled element
replacement/invalidation and a controlled delayed response. Synthetic
data only; no files, network, other applications or settings.

On the owner's Windows machine the same control contract is to be
exercised by a small native fixture app later (see
docs/engineering/PHASE3_NATIVE_TESTS.md); this model is the Linux
stand-in and is never native evidence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from aether.adapters.windows.uia_backend import FakeUiaBackend, RawElement, UiaBackendError

FIXTURE_HWND = 4242
FIXTURE_APP_ID = "app:fixture-synthetic"

INCREMENT_KEY = "fixture-increment"
STATUS_KEY = "fixture-status"
DISABLED_KEY = "fixture-disabled"
PASSWORD_KEY = "fixture-password"
MODAL_KEY = "fixture-modal-trigger"
MODAL_DIALOG_KEY = "fixture-modal-dialog"


@dataclass(slots=True)
class FixtureState:
    count: int = 0
    modal_open: bool = False
    delay_seconds: float = 0.0
    replaced: bool = False
    status_override: str | None = None

    @property
    def status_text(self) -> str:
        return self.status_override or f"Count: {self.count}"


class FixtureBackend(FakeUiaBackend):
    """FakeUiaBackend whose tree/effects are driven by FixtureState."""

    def __init__(self, state: FixtureState) -> None:
        super().__init__()
        self._state = state
        self._rebuild()

    def _rebuild(self) -> None:
        self.elements.clear()
        self.roots.clear()
        increment_key = "fixture-increment-v2" if self._state.replaced else INCREMENT_KEY
        children = [
            RawElement(
                key=increment_key,
                control_type="Button",
                name="Increment",
                patterns=frozenset({"invoke"}),
                depth=1,
            ),
            RawElement(key=STATUS_KEY, control_type="Text", name=self._state.status_text, depth=1),
            RawElement(
                key=DISABLED_KEY,
                control_type="Button",
                name="Disabled action",
                patterns=frozenset({"invoke"}),
                is_enabled=False,
                depth=1,
            ),
            RawElement(
                key=PASSWORD_KEY,
                control_type="Edit",
                name="Password",
                patterns=frozenset({"value"}),
                is_password=True,
                value_present=True,
                depth=1,
            ),
            RawElement(
                key=MODAL_KEY,
                control_type="Button",
                name="Open dialog",
                patterns=frozenset({"invoke"}),
                depth=1,
            ),
        ]
        if self._state.modal_open:
            children.append(
                RawElement(
                    key=MODAL_DIALOG_KEY, control_type="Window", name="Fixture dialog", depth=1
                )
            )
        root = RawElement(
            key="fixture-root",
            control_type="Window",
            name="AETHER Fixture",
            depth=0,
            children_keys=tuple(c.key for c in children),
        )
        self.add_root(hwnd=FIXTURE_HWND, root=root, descendants=children)

    def invoke(self, element: RawElement) -> dict[str, object]:
        if self._state.delay_seconds:
            time.sleep(self._state.delay_seconds)
            raise TimeoutError("fixture delayed response exceeded deadline")
        live = self._live(element)
        if live.key.endswith("increment") or live.key.endswith("increment-v2"):
            if not live.is_enabled:
                raise UiaBackendError("element is disabled")
            self._state.count += 1
            status = self.elements.get(STATUS_KEY)
            if status is not None:
                object.__setattr__(status, "name", self._state.status_text)
            return {"invoked": live.key, "count": self._state.count}
        if live.key == MODAL_KEY:
            self._state.modal_open = True
            return {"invoked": live.key, "modal": True}
        return super().invoke(element)


@dataclass(slots=True)
class FixtureApp:
    """Owns the synthetic fixture state and produces fresh backends."""

    state: FixtureState = field(default_factory=FixtureState)

    def backend(self) -> FixtureBackend:
        return FixtureBackend(self.state)

    def replace_increment_control(self) -> None:
        """Controlled invalidation: the old runtime identity dies."""
        self.state.replaced = True
