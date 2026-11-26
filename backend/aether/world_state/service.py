"""In-memory WorldState service (Phase 3 CP1, corrected F04/F07).

Privacy-generation coherent: every policy change, pause, or
invalidation bumps an observation generation; insertion checks the
generation and the policy under the same lock, so an event permitted
under an obsolete generation can never become current. Pause stops
collection at the source via the observer service (this store also
drops retained state immediately).

Retention: in-memory only, bounded capacity, TTL expiry. Query
results are defensive copies. Wall-clock timestamps govern expiry;
monotonic receipt times are retained separately for elapsed checks.
Unknown process identity yields stale, low-strength evidence — never
authorization-grade identity. Title-bearing observations carry
UNTRUSTED provenance and PRIVATE classification.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from aether.core.contracts.resource import DataClass, Provenance
from aether.core.contracts.world_state import WorldStateObservation
from aether.world_state.observer import GenerationClock, WindowEvent, WindowEventKind
from aether.world_state.privacy import (
    ContextClassification,
    ObservationPolicy,
    classify_context,
    collect_permitted,
)

DEFAULT_OBSERVATION_TTL = timedelta(seconds=30)
DEFAULT_MAX_WINDOWS = 512
MAX_TITLE_CHARS = 256


@dataclass(slots=True)
class _WindowEntry:
    observation: WorldStateObservation
    hwnd: int
    process_token: str
    generation: int
    received_monotonic: float


@dataclass(slots=True)
class InMemoryWorldState:
    """Privacy-gated, expiring, bounded, in-memory observation store."""

    policy: ObservationPolicy
    ttl: timedelta = DEFAULT_OBSERVATION_TTL
    max_windows: int = DEFAULT_MAX_WINDOWS
    generation_clock: GenerationClock | None = None
    authority: object | None = None  # AppWindowResourceAuthority (avoid cycle)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _windows: dict[int, _WindowEntry] = field(default_factory=dict, init=False)
    _foreground_hwnd: int | None = field(default=None, init=False)
    _sequence: int = field(default=0, init=False)
    _generation: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.generation_clock is not None:
            self._generation = self.generation_clock.current()

    def _advance_generation(self) -> None:
        if self.generation_clock is not None:
            self._generation = self.generation_clock.advance()
        else:
            self._generation += 1
    paused: bool = field(default=False, init=False)
    over_capacity_drops: int = field(default=0, init=False)

    # -- generation / policy control ------------------------------------
    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def set_policy(self, policy: ObservationPolicy) -> None:
        """Atomically apply a policy and invalidate retained state."""
        with self._lock:
            self.policy = policy
            self._advance_generation()
            self._windows.clear()
            self._foreground_hwnd = None

    def invalidate_all(self) -> None:
        """Out-of-band invalidation (overflow/reconciliation, F03)."""
        with self._lock:
            self._advance_generation()
            self._windows.clear()
            self._foreground_hwnd = None

    def pause(self) -> None:
        with self._lock:
            self.paused = True
            self._advance_generation()
            self._windows.clear()
            self._foreground_hwnd = None

    def resume(self) -> None:
        """Resume requires fresh observation: retained state stays empty."""
        with self._lock:
            self.paused = False
            self._advance_generation()
            self._windows.clear()
            self._foreground_hwnd = None

    # -- event intake (collection boundary, R5/F04) ------------------------
    def handle_event(
        self, event: WindowEvent, *, now: datetime, generation: int | None = None
    ) -> None:
        # Generation + policy + insertion are one locked operation.
        with self._lock:
            if self.generation_clock is not None:
                self._generation = self.generation_clock.current()
            # Commit-boundary generation validation: explicit caller
            # generation wins; otherwise the collection stamp carried
            # on the event is authoritative.
            effective_generation = generation if generation is not None else event.generation
            if effective_generation and effective_generation != self._generation:
                return  # stale event from before invalidation/pause
            if generation is not None and generation != self._generation:
                return  # obsolete privacy/observation generation
            if self.paused:
                return
            if event.kind is WindowEventKind.WINDOW_DESTROYED:
                self._windows.pop(event.hwnd, None)
                if self._foreground_hwnd == event.hwnd:
                    self._foreground_hwnd = None
                return
            if event.kind is WindowEventKind.PROCESS_EXITED:
                doomed = [
                    hwnd
                    for hwnd, entry in self._windows.items()
                    if entry.process_token.startswith(f"{event.pid}:")
                ]
                for hwnd in doomed:
                    self._windows.pop(hwnd, None)
                if self._foreground_hwnd in doomed:
                    self._foreground_hwnd = None
                return
            if event.kind is WindowEventKind.RECONCILIATION_REQUIRED:
                self._advance_generation()
                self._windows.clear()
                self._foreground_hwnd = None
                return

            is_foreground = event.kind is WindowEventKind.FOREGROUND_CHANGED
            classification = classify_context(
                event.app_identity,
                adapter_classification=event.classification,
                elevated=event.elevated,
            )
            if is_foreground and classification is ContextClassification.PROHIBITED_SENSITIVE:
                # Focus moved to an excluded/inaccessible app: the
                # previously active foreground is no longer current.
                self._foreground_hwnd = None
                return
            if not collect_permitted(
                self.policy,
                app_identity=event.app_identity,
                classification=event.classification,
                elevated=event.elevated,
                is_foreground=is_foreground,
            ):
                return
            if self.policy.mode.value == "active_app_only" and is_foreground:
                # Only the active app may be retained as current.
                self._windows.clear()
            if event.hwnd not in self._windows and len(self._windows) >= self.max_windows:
                self.over_capacity_drops += 1
                return

            self._sequence += 1
            identity_known = event.process_creation_time is not None
            process_token = f"{event.pid}:{event.process_creation_time or 'unknown'}"
            title = (event.title or "")[:MAX_TITLE_CHARS]
            observation = WorldStateObservation(
                observation_id=f"obs-{self._sequence}",
                kind=event.kind.value,
                summary=title,
                source=event.source,
                observed_at=now,
                expires_at=now + self.ttl,
                data_class=DataClass.PRIVATE if title else DataClass.INTERNAL,
                provenance=Provenance.UNTRUSTED if title else Provenance.SYSTEM_OBSERVED,
                evidence_strength=0.9 if (event.source != "fake" and identity_known) else 0.4,
                version_token=process_token,
                availability="available" if identity_known else "stale",
                resource_id=self._window_resource_id(event, process_token),
            )
            self._windows[event.hwnd] = _WindowEntry(
                observation=observation,
                hwnd=event.hwnd,
                process_token=process_token,
                generation=self._generation,
                received_monotonic=time.monotonic(),
            )
            if is_foreground:
                self._foreground_hwnd = event.hwnd

    def apply_snapshot(self, events: list[WindowEvent], *, now: datetime) -> None:
        """Atomically replace retained state with a complete snapshot.

        Partial snapshots are never published: the caller must only
        invoke this with a complete enumeration for one generation.
        """
        with self._lock:
            self._windows.clear()
            self._foreground_hwnd = None
            generation = self._generation
        for event in events:
            self.handle_event(event, now=now, generation=generation)

    def _window_resource_id(self, event: WindowEvent, process_token: str) -> str | None:
        if self.authority is None:
            return None
        from aether.core.resources.app_window_authority import AppWindowResourceAuthority

        assert isinstance(self.authority, AppWindowResourceAuthority)
        generation = getattr(event, "_instance_generation", 0)
        ref = self.authority.register_window(
            hwnd=event.hwnd,
            process_token=process_token,
            instance_generation=int(generation or 0),
            version_token=process_token,
        )
        return ref.resource_id

    # -- expiry / queries ----------------------------------------------------
    def cleanup_expired(self, *, now: datetime) -> int:
        with self._lock:
            expired = [
                hwnd
                for hwnd, entry in self._windows.items()
                if entry.observation.expires_at is not None and entry.observation.expires_at <= now
            ]
            for hwnd in expired:
                self._windows.pop(hwnd, None)
            if self._foreground_hwnd in expired:
                self._foreground_hwnd = None
            return len(expired)

    def current(self, *, now: datetime) -> list[WorldStateObservation]:
        self.cleanup_expired(now=now)
        with self._lock:
            # Defensive copies: callers cannot mutate retained state.
            return [entry.observation.model_copy(deep=True) for entry in self._windows.values()]

    def foreground(self, *, now: datetime) -> WorldStateObservation | None:
        self.cleanup_expired(now=now)
        with self._lock:
            if self._foreground_hwnd is None:
                return None
            entry = self._windows.get(self._foreground_hwnd)
            return entry.observation.model_copy(deep=True) if entry else None
