"""Event-driven window/process observer foundation (Phase 3 CP1, R6).

Platform-independent core: a bounded event queue, overflow accounting
with uncertainty marking and reconciliation, freshness, lifecycle
(start/stop/restart) and privacy-gated collection. The event source is
a protocol; tests use :class:`FakeWindowEventSource`, clearly a fake.
The native Windows source lives in
``aether.adapters.windows.native_observer`` behind platform+activation
guards and is never started by this module or by ordinary launches.

Threading: the service owns a single consumer thread when ``start()``
is called; all state mutation is lock-guarded and shutdown joins the
thread with a bounded timeout. Elapsed/expiry logic in the WorldState
service uses caller-supplied instants so tests are deterministic.
"""

from __future__ import annotations

import contextlib
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

# Provisional engineering defaults (not measured guarantees, R6).
DEFAULT_QUEUE_CAPACITY = 256
DEFAULT_RECONCILE_SECONDS = 5.0


class ObserverUnavailable(RuntimeError):
    """The platform observer cannot run; state must not be invented."""


class WindowEventKind(StrEnum):
    FOREGROUND_CHANGED = "foreground_changed"
    WINDOW_CREATED = "window_created"
    WINDOW_DESTROYED = "window_destroyed"
    WINDOW_STATE_CHANGED = "window_state_changed"
    PROCESS_EXITED = "process_exited"
    RECONCILIATION_REQUIRED = "reconciliation_required"


@dataclass(frozen=True, slots=True)
class WindowEvent:
    """One normalized platform event (bounded metadata only)."""

    kind: WindowEventKind
    # Opaque platform handles kept inside the adapter/service layer.
    hwnd: int = 0
    pid: int = 0
    # Process creation instant (ISO string) disambiguating PID reuse.
    process_creation_time: str | None = None
    app_identity: str | None = None
    title: str | None = None  # only ever set after privacy gating
    elevated: bool = False


class WindowEventSource(Protocol):
    """A source of normalized window events (fake or native)."""

    def start(self, emit: Callable[[WindowEvent], None]) -> None: ...
    def stop(self) -> None: ...
    def reconcile(self) -> list[WindowEvent]: ...


class FakeWindowEventSource:
    """Deterministic fake event source for platform-independent tests.

    This is a fake: it provides no native Windows evidence.
    """

    def __init__(self, initial: list[WindowEvent] | None = None) -> None:
        self._emit: Callable[[WindowEvent], None] | None = None
        self._initial = list(initial or [])
        self.started = False

    def start(self, emit: Callable[[WindowEvent], None]) -> None:
        self._emit = emit
        self.started = True
        for event in self._initial:
            emit(event)

    def stop(self) -> None:
        self.started = False
        self._emit = None

    def reconcile(self) -> list[WindowEvent]:
        return []

    def push(self, event: WindowEvent) -> None:
        if self._emit is None:
            raise ObserverUnavailable("fake event source is not started")
        self._emit(event)


@dataclass(slots=True)
class ObserverStats:
    received: int = 0
    dropped_overflow: int = 0
    reconciliations: int = 0
    uncertain: bool = False


@dataclass(slots=True)
class ObserverService:
    """Bounded, privacy-gated observer over an injected event source."""

    source: WindowEventSource
    on_event: Callable[[WindowEvent], None]
    queue_capacity: int = DEFAULT_QUEUE_CAPACITY
    _queue: queue.Queue[WindowEvent] = field(init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    stats: ObserverStats = field(default_factory=ObserverStats, init=False)
    running: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.queue_capacity < 1:
            raise ValueError("queue_capacity must be >= 1")
        self._queue = queue.Queue(maxsize=self.queue_capacity)

    # -- lifecycle ---------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            self.running = True
        self.source.start(self._enqueue)
        self._thread = threading.Thread(target=self._consume, name="aether-observer", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Thread-safe shutdown; joins the consumer with a bound."""
        self._stop.set()
        try:
            self.source.stop()
        finally:
            if self._thread is not None:
                self._thread.join(timeout=timeout)
            with self._lock:
                self.running = False
                self._thread = None

    # -- intake --------------------------------------------------------
    def _enqueue(self, event: WindowEvent) -> None:
        with self._lock:
            self.stats.received += 1
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Overflow (R6): count it, mark state uncertain, and demand
            # reconciliation. Dropped destruction/privacy events must
            # never silently preserve stale authorization-grade state:
            # uncertainty propagates to the WorldState service, which
            # invalidates current observations on reconcile.
            with self._lock:
                self.stats.dropped_overflow += 1
                self.stats.uncertain = True
            with contextlib.suppress(queue.Full):
                self._queue.put_nowait(WindowEvent(kind=WindowEventKind.RECONCILIATION_REQUIRED))

    def reconcile(self) -> None:
        """Re-observe via the source and clear overflow uncertainty."""
        events = self.source.reconcile()
        for event in events:
            self._enqueue(event)
        with self._lock:
            self.stats.reconciliations += 1
            if self.stats.dropped_overflow == 0:
                self.stats.uncertain = False

    # -- consumption ---------------------------------------------------
    def _consume(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue
            self.on_event(event)

    def drain_for_test(self, timeout: float = 1.0) -> None:
        """Deterministically process queued events (tests only)."""
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                event = self._queue.get(timeout=0.02)
            except queue.Empty:
                return
            self.on_event(event)
