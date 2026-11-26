"""Event-driven window/process observer foundation (Phase 3 CP1, F03/F07).

Corrected semantics:

- Overflow never relies on enqueueing into the full queue. It sets an
  out-of-band invalidation signal, bumps the invalidation generation,
  invokes the invalidation callback immediately, and marks state
  uncertain until a *successful reconciliation of that generation*.
- Queue entries are generation-stamped; entries from before an
  invalidation (or a previous lifecycle/source generation) are
  discarded by the consumer and can never restore stale state.
- Lifecycle is serialized; ``running`` is set only after the source
  starts successfully, partial startup rolls back, shutdown reports
  failure if the consumer does not terminate, and restart drops all
  queued pre-shutdown events.
- Periodic reconciliation is available via ``reconcile_interval``
  (0 disables) with bounded retries per cycle — no infinite loops.
- Counters saturate instead of growing without bound.

The event source is a protocol; tests use :class:`FakeWindowEventSource`
(clearly a fake). The native Windows source lives in
``aether.adapters.windows.native_observer`` behind platform+activation
guards and is never started by this module or by ordinary launches.
"""

from __future__ import annotations

import contextlib
import dataclasses
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from aether.world_state.privacy import ContextClassification

# Provisional engineering defaults (not measured guarantees).
DEFAULT_QUEUE_CAPACITY = 256
DEFAULT_RECONCILE_SECONDS = 5.0
_MAX_COUNTER = (1 << 62) - 1
_MAX_RECONCILE_ATTEMPTS = 3


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
    hwnd: int = 0
    pid: int = 0
    # Process creation instant (ISO string) disambiguating PID reuse.
    # Missing identity is never authorization-grade (F04).
    process_creation_time: str | None = None
    app_identity: str | None = None
    title: str | None = None  # only ever retained after privacy gating
    elevated: bool | None = None  # None = unknown, never assumed non-elevated
    # Adapter-supplied context classification (F04 three-valued).
    classification: ContextClassification = ContextClassification.UNKNOWN
    # Evidence provenance: "fake" for test sources, platform name for
    # native sources. Fake evidence is never labelled native.
    source: str = "fake"
    # Authoritative collection generation, stamped by the observer at
    # collection time and validated by WorldState at commit.
    generation: int = 0


class WindowEventSource(Protocol):
    """A source of normalized window events (fake or native)."""

    def start(self, emit: Callable[[WindowEvent], None]) -> None: ...
    def stop(self) -> bool | None: ...
    def reconcile(self) -> list[WindowEvent]: ...


class FakeWindowEventSource:
    """Deterministic fake event source. Provides no native evidence."""

    def __init__(self, initial: list[WindowEvent] | None = None) -> None:
        self._emit: Callable[[WindowEvent], None] | None = None
        self._initial = list(initial or [])
        self._snapshot: list[WindowEvent] = []
        self.started = False
        self.fail_start = False

    def start(self, emit: Callable[[WindowEvent], None]) -> None:
        if self.fail_start:
            raise ObserverUnavailable("fake source configured to fail startup")
        self._emit = emit
        self.started = True
        for event in self._initial:
            emit(event)

    def stop(self) -> None:
        self.started = False
        self._emit = None

    def reconcile(self) -> list[WindowEvent]:
        return list(self._snapshot)

    def set_snapshot(self, events: list[WindowEvent]) -> None:
        self._snapshot = list(events)

    def push(self, event: WindowEvent) -> None:
        if self._emit is None:
            raise ObserverUnavailable("fake event source is not started")
        self._emit(event)


def _bump_early(value: int) -> int:
    return min(value + 1, (1 << 62) - 1)


class GenerationClock:
    """One authoritative collection generation shared end-to-end.

    The observer stamps each event at collection; the stamp travels
    through the queue and callback; WorldState validates it at the
    retained-state commit boundary. Invalidation from either side
    advances the same clock, so in-flight stale callbacks can never
    repopulate state after pause/privacy/overflow invalidation.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value = 0

    def current(self) -> int:
        with self._lock:
            return self._value

    def advance(self) -> int:
        with self._lock:
            self._value = _bump_early(self._value)
            return self._value


@dataclass(slots=True)
class ObserverStats:
    received: int = 0
    dropped_overflow: int = 0  # cumulative telemetry
    generation_dropped: int = 0  # drops in the current generation
    reconciliations: int = 0
    consumer_errors: int = 0
    uncertain: bool = False


def _bump(value: int) -> int:
    return min(value + 1, _MAX_COUNTER)


@dataclass(slots=True)
class ObserverService:
    """Bounded, generation-aware observer over an injected event source."""

    source: WindowEventSource
    on_event: Callable[[WindowEvent], None]
    on_invalidate: Callable[[], None] | None = None
    # Atomic snapshot publication pathway (CP3-R05): when wired,
    # reconciliation hands the complete generation-stamped snapshot
    # to the handler (WorldState.apply_snapshot) instead of enqueueing
    # entries individually. Uncertainty clears only on publication.
    snapshot_handler: Callable[[list[WindowEvent]], bool] | None = None
    generation_clock: GenerationClock | None = None
    queue_capacity: int = DEFAULT_QUEUE_CAPACITY
    reconcile_interval: float = 0.0  # seconds; 0 disables periodic reconciliation
    _queue: queue.Queue[tuple[int, WindowEvent]] = field(init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _reconcile_thread: threading.Thread | None = field(default=None, init=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False)
    _invalidate_signal: threading.Event = field(default_factory=threading.Event, init=False)
    _lifecycle: threading.Lock = field(default_factory=threading.Lock, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _source_generation: int = field(default=0, init=False)
    stats: ObserverStats = field(default_factory=ObserverStats, init=False)
    running: bool = field(default=False, init=False)
    _health: str = field(default="stopped", init=False)
    _paused: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.queue_capacity < 1:
            raise ValueError("queue_capacity must be >= 1")
        if self.generation_clock is None:
            self.generation_clock = GenerationClock()
        self._queue = queue.Queue(maxsize=self.queue_capacity)

    @property
    def generation(self) -> int:
        assert self.generation_clock is not None
        return self.generation_clock.current()

    def _advance_generation(self) -> int:
        assert self.generation_clock is not None
        return self.generation_clock.advance()

    @property
    def invalidation_pending(self) -> bool:
        return self._invalidate_signal.is_set()

    def health(self) -> str:
        with self._lock:
            return self._health

    # -- lifecycle (serialized, F07) ------------------------------------
    def start(self) -> None:
        with self._lifecycle:
            with self._lock:
                if self.running:
                    return
            self._stop.clear()
            with self._lock:
                self._paused = False
            # Drop any pre-shutdown queued events; bump generations so
            # callbacks from an obsolete source generation are ignored.
            self._drain_queue()
            with self._lock:
                self._source_generation = _bump(self._source_generation)
                self._advance_generation()
                source_generation = self._source_generation
            try:
                self.source.start(lambda event: self._enqueue(event, source_generation))
            except Exception:
                # Roll back partial initialization truthfully.
                with contextlib.suppress(Exception):
                    self.source.stop()
                with self._lock:
                    self.running = False
                    self._health = "unavailable"
                raise
            thread = threading.Thread(target=self._consume, name="aether-observer", daemon=True)
            with self._lock:
                self._thread = thread
                self.running = True
                self._health = "running"
            thread.start()
            if self.reconcile_interval > 0:
                reconcile_thread = threading.Thread(
                    target=self._reconcile_loop, name="aether-observer-reconcile", daemon=True
                )
                with self._lock:
                    self._reconcile_thread = reconcile_thread
                reconcile_thread.start()

    def stop(self, timeout: float = 2.0) -> bool:
        """Bounded shutdown. Returns False if the consumer stays alive."""
        with self._lifecycle:
            self._stop.set()
            # Source shutdown failure is propagated truthfully: a
            # raising or False-returning source stop is not success.
            source_stopped = True
            try:
                if self.source.stop() is False:
                    source_stopped = False
            except Exception:
                source_stopped = False
            with self._lock:
                self._source_generation = _bump(self._source_generation)
                thread, reconcile_thread = self._thread, self._reconcile_thread
            alive = False
            for worker in (thread, reconcile_thread):
                if worker is not None:
                    worker.join(timeout=timeout)
                    alive = alive or worker.is_alive()
            with self._lock:
                if alive or not source_stopped:
                    self._health = "degraded"  # never claim clean shutdown
                    return False
                self.running = False
                self._thread = None
                self._reconcile_thread = None
                self._health = "stopped"
            self._drain_queue()
            return True

    @property
    def collection_paused(self) -> bool:
        with self._lock:
            return self._paused

    def pause_collection(self) -> None:
        """Pause at the source boundary (F04), not merely in retention."""
        with self._lock:
            self._paused = True
        with contextlib.suppress(Exception):
            self.source.stop()
        with self._lock:
            self._source_generation = _bump(self._source_generation)
        self._advance_generation()
        self._notify_invalidate()

    # -- intake -----------------------------------------------------------
    def _enqueue(self, event: WindowEvent, source_generation: int) -> None:
        with self._lock:
            if source_generation != self._source_generation or self._stop.is_set():
                return  # obsolete source generation callback
            self.stats.received = _bump(self.stats.received)
            generation = self.generation
        event = dataclasses.replace(event, generation=generation)
        try:
            self._queue.put_nowait((generation, event))
        except queue.Full:
            self._overflow()

    def push_for_test(self, event: WindowEvent) -> None:
        """Enqueue through the same generation path the source uses."""
        with self._lock:
            source_generation = self._source_generation
        self._enqueue(event, source_generation)

    def _overflow(self) -> None:
        with self._lock:
            self.stats.dropped_overflow = _bump(self.stats.dropped_overflow)
            self.stats.generation_dropped = _bump(self.stats.generation_dropped)
            self.stats.uncertain = True
        self._advance_generation()
        # Out-of-band signal: cannot be lost to a full queue (F03).
        self._invalidate_signal.set()
        self._notify_invalidate()

    def _notify_invalidate(self) -> None:
        if self.on_invalidate is not None:
            with contextlib.suppress(Exception):
                self.on_invalidate()

    # -- reconciliation -----------------------------------------------------
    def reconcile(self) -> bool:
        """Re-establish fresh state for the current generation.

        Returns True only when a complete enumeration succeeded with
        no overflow during this generation. Failed/incomplete
        enumeration retains uncertainty (it is not proof windows
        disappeared). Bounded attempts; no infinite retry.
        """
        with self._lock:
            if self._paused:
                return False  # paused observation cannot collect
        for _attempt in range(_MAX_RECONCILE_ATTEMPTS):
            self._drain_queue()  # reconciliation supersedes stale queued events
            with self._lock:
                self._advance_generation()
                self.stats.generation_dropped = 0
            self._notify_invalidate()
            try:
                events = self.source.reconcile()
            except Exception:
                with self._lock:
                    self.stats.uncertain = True
                return False
            with self._lock:
                source_generation = self._source_generation
            if self.snapshot_handler is not None:
                stamped = [
                    dataclasses.replace(event, generation=self.generation) for event in events
                ]
                if self.snapshot_handler(stamped):
                    with self._lock:
                        self.stats.reconciliations = _bump(self.stats.reconciliations)
                        if self.stats.generation_dropped == 0:
                            self.stats.uncertain = False
                            self._invalidate_signal.clear()
                            return True
                with self._lock:
                    self.stats.uncertain = True
                return False
            for event in events:
                self._enqueue(event, source_generation)
            with self._lock:
                self.stats.reconciliations = _bump(self.stats.reconciliations)
                if self.stats.generation_dropped == 0:
                    self.stats.uncertain = False
                    self._invalidate_signal.clear()
                    return True
                # Overflow during reconciliation: retain uncertainty
                # and reconcile again (bounded by the attempt loop).
        return False

    def _reconcile_loop(self) -> None:
        while not self._stop.wait(self.reconcile_interval):
            # Periodic reconciliation runs even when apparently healthy:
            # events can be missed without an explicit overflow. It must
            # never collect while observation is paused or stopped.
            with self._lock:
                paused = self._paused
            if paused:
                continue
            self.reconcile()

    # -- consumption ---------------------------------------------------------
    def _consume(self) -> None:
        while not self._stop.is_set():
            try:
                generation, event = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue
            with self._lock:
                stale = generation != self.generation
            if stale:
                continue  # pre-invalidation event can never restore state
            try:
                self.on_event(event)
            except Exception:
                with self._lock:
                    self.stats.consumer_errors = _bump(self.stats.consumer_errors)
                    self.stats.uncertain = True
                    self._health = "degraded"

    def _drain_queue(self) -> None:
        with contextlib.suppress(queue.Empty):
            while True:
                self._queue.get_nowait()

    def drain_for_test(self) -> None:
        """Deterministically process queued events (tests only).

        Refuses to compete with a live production consumer thread.
        """
        with self._lock:
            running = self.running
        if running:
            raise ObserverUnavailable("drain_for_test requires a stopped consumer")
        while True:
            try:
                generation, event = self._queue.get_nowait()
            except queue.Empty:
                return
            with self._lock:
                stale = generation != self.generation
            if stale:
                continue
            self.on_event(event)
