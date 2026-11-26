"""In-memory WorldState service (Phase 3 CP1).

Holds only privacy-permitted, bounded, expiring observations in
memory. Nothing is persisted; pause or a privacy-mode change
invalidates retained observations immediately; expired or invalidated
observations are never returned as current. HWND/PID reuse is handled
by binding the current window entry to the process-instance token:
the same HWND under a different process instance is a different
window and replaces (invalidates) the previous entry.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from aether.core.contracts.resource import DataClass
from aether.core.contracts.world_state import WorldStateObservation
from aether.world_state.observer import WindowEvent, WindowEventKind
from aether.world_state.privacy import ObservationPolicy, collect_permitted

DEFAULT_OBSERVATION_TTL = timedelta(seconds=30)
MAX_TITLE_CHARS = 256


@dataclass(slots=True)
class _WindowEntry:
    observation: WorldStateObservation
    hwnd: int
    process_token: str


@dataclass(slots=True)
class InMemoryWorldState:
    """Privacy-gated, expiring, in-memory observation store."""

    policy: ObservationPolicy
    ttl: timedelta = DEFAULT_OBSERVATION_TTL
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _windows: dict[int, _WindowEntry] = field(default_factory=dict, init=False)
    _foreground_hwnd: int | None = field(default=None, init=False)
    _sequence: int = field(default=0, init=False)
    paused: bool = field(default=False, init=False)

    # -- policy control ------------------------------------------------
    def set_policy(self, policy: ObservationPolicy) -> None:
        """Apply a new privacy policy; retained data is invalidated."""
        with self._lock:
            self.policy = policy
            self._windows.clear()
            self._foreground_hwnd = None

    def pause(self) -> None:
        """One-click pause: collection stops and retained state drops."""
        with self._lock:
            self.paused = True
            self._windows.clear()
            self._foreground_hwnd = None

    def resume(self) -> None:
        with self._lock:
            self.paused = False

    # -- event intake (collection boundary, R5) -------------------------
    def handle_event(self, event: WindowEvent, *, now: datetime) -> None:
        if self.paused:
            return
        is_foreground = event.kind is WindowEventKind.FOREGROUND_CHANGED
        if event.kind is WindowEventKind.WINDOW_DESTROYED:
            with self._lock:
                self._windows.pop(event.hwnd, None)
                if self._foreground_hwnd == event.hwnd:
                    self._foreground_hwnd = None
            return
        if event.kind is WindowEventKind.PROCESS_EXITED:
            with self._lock:
                # Process identity is carried in the version token; drop
                # entries whose bound pid matches the exited process.
                doomed = [
                    h
                    for h, e in self._windows.items()
                    if e.process_token.startswith(f"{event.pid}:")
                ]
                for hwnd in doomed:
                    self._windows.pop(hwnd, None)
                if self._foreground_hwnd in doomed:
                    self._foreground_hwnd = None
            return
        if event.kind is WindowEventKind.RECONCILIATION_REQUIRED:
            # Overflow/reconciliation: nothing retained may be presented
            # as current until re-observed (R6).
            with self._lock:
                self._windows.clear()
                self._foreground_hwnd = None
            return
        # Collection gate *before* any title/metadata is retained.
        if not collect_permitted(
            self.policy,
            app_identity=event.app_identity,
            elevated=event.elevated,
            is_foreground=is_foreground,
        ):
            return
        with self._lock:
            self._sequence += 1
            # Identity binds pid + creation time: the same HWND under a
            # recycled pid with a different creation time is a new
            # window instance, never the previous one.
            process_token = f"{event.pid}:{event.process_creation_time or 'unknown'}"
            title = (event.title or "")[:MAX_TITLE_CHARS]
            observation = WorldStateObservation(
                observation_id=f"obs-{self._sequence}",
                kind=event.kind.value,
                summary=title,
                source="windows-observer",
                observed_at=now,
                expires_at=now + self.ttl,
                data_class=DataClass.INTERNAL,
                evidence_strength=0.9,
                version_token=process_token,
            )
            previous = self._windows.get(event.hwnd)
            if previous is not None and previous.process_token != process_token:
                # HWND reuse under a new process instance invalidates
                # the old entry by replacement (never merges identity).
                pass
            self._windows[event.hwnd] = _WindowEntry(
                observation=observation, hwnd=event.hwnd, process_token=process_token
            )
            if is_foreground:
                self._foreground_hwnd = event.hwnd

    # -- queries ---------------------------------------------------------
    def current(self, *, now: datetime) -> list[WorldStateObservation]:
        """Non-expired observations only; expired entries are dropped."""
        with self._lock:
            live = [
                entry.observation
                for entry in self._windows.values()
                if entry.observation.expires_at is None or entry.observation.expires_at > now
            ]
            expired = [
                hwnd
                for hwnd, entry in self._windows.items()
                if entry.observation.expires_at is not None and entry.observation.expires_at <= now
            ]
            for hwnd in expired:
                self._windows.pop(hwnd, None)
            return live

    def foreground(self, *, now: datetime) -> WorldStateObservation | None:
        with self._lock:
            hwnd = self._foreground_hwnd
            if hwnd is None:
                return None
            entry = self._windows.get(hwnd)
            if entry is None:
                return None
            if entry.observation.expires_at is not None and entry.observation.expires_at <= now:
                self._windows.pop(hwnd, None)
                self._foreground_hwnd = None
                return None
            return entry.observation
