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
    resource_id: str | None = None
    instance_generation: int = 0


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
    _instance_generations: dict[int, int] = field(default_factory=dict, init=False)
    _last_token_by_hwnd: dict[int, str] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        if self.generation_clock is not None:
            self._generation = self.generation_clock.current()

    def _advance_generation(self) -> None:
        if self.generation_clock is not None:
            self._generation = self.generation_clock.advance()
        else:
            self._generation += 1

    # -- authority lifecycle integration (CP3-B06) -------------------------
    def _invalidate_ref(self, entry: _WindowEntry | None) -> None:
        """Invalidate the authority ref belonging to a dropped observation."""
        if entry is None or entry.resource_id is None or self.authority is None:
            return
        from aether.core.resources.app_window_authority import AppWindowResourceAuthority

        if isinstance(self.authority, AppWindowResourceAuthority):
            self.authority.invalidate_window(entry.resource_id)

    def _drop(self, hwnds: list[int]) -> None:
        """Remove entries and invalidate their window authority refs."""
        for hwnd in hwnds:
            self._invalidate_ref(self._windows.pop(hwnd, None))
            # Forget the last instance token so a same-process HWND
            # recreation is a new instance generation (R05).
            self._last_token_by_hwnd.pop(hwnd, None)
            if self._foreground_hwnd == hwnd:
                self._foreground_hwnd = None

    def _clear_all(self) -> None:
        for entry in list(self._windows.values()):
            self._invalidate_ref(entry)
        self._windows.clear()
        self._foreground_hwnd = None

    _MAX_GENERATION_BOOKKEEPING = 4096

    def _next_instance_generation(self, hwnd: int, process_token: str) -> int:
        """Actual per-HWND instance generation (CP3-B06).

        Increments whenever the process instance behind an HWND
        changes, so a recreated window instance is distinguishable
        from its predecessor and receives a fresh authority ref.
        """
        if self._last_token_by_hwnd.get(hwnd) != process_token:
            self._instance_generations[hwnd] = self._instance_generations.get(hwnd, 0) + 1
            self._last_token_by_hwnd[hwnd] = process_token
        if len(self._instance_generations) > self._MAX_GENERATION_BOOKKEEPING:
            # Bounded bookkeeping: forget generations of windows that
            # are neither retained nor the latest instance for an HWND.
            for stale in list(self._instance_generations):
                if stale not in self._windows and stale != hwnd:
                    self._instance_generations.pop(stale, None)
                    self._last_token_by_hwnd.pop(stale, None)
        return self._instance_generations[hwnd]

    def _publish_entry(
        self, entry: _WindowEntry, event: WindowEvent, existing: _WindowEntry | None = None
    ) -> _WindowEntry:
        """Register the entry's authority ref at publication time only.

        An unchanged live window keeps its stable reference and
        instance version; only an actual instance replacement mints a
        new reference (and invalidates the previous one).
        """
        if existing is not None and existing.process_token == entry.process_token:
            entry.resource_id = existing.resource_id
            entry.instance_generation = existing.instance_generation
            entry.observation = entry.observation.model_copy(
                update={
                    "resource_id": existing.resource_id,
                    "version_token": existing.observation.version_token,
                }
            )
            return entry
        if self.authority is None:
            return entry
        from aether.core.resources.app_window_authority import AppWindowResourceAuthority

        assert isinstance(self.authority, AppWindowResourceAuthority)
        instance_generation = self._next_instance_generation(entry.hwnd, entry.process_token)
        # The version token represents the actual window instance,
        # not merely its process: process token + instance generation.
        version_token = f"{entry.process_token}#{instance_generation}"
        ref = self.authority.register_window(
            hwnd=event.hwnd,
            process_token=entry.process_token,
            instance_generation=instance_generation,
            version_token=version_token,
            expires_at=entry.observation.expires_at,
        )
        entry.resource_id = ref.resource_id
        entry.instance_generation = instance_generation
        entry.observation = entry.observation.model_copy(
            update={"resource_id": ref.resource_id, "version_token": version_token}
        )
        return entry

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
            self._clear_all()

    def invalidate_all(self) -> None:
        """Out-of-band invalidation (overflow/reconciliation, F03)."""
        with self._lock:
            self._advance_generation()
            self._clear_all()

    def pause(self) -> None:
        with self._lock:
            self.paused = True
            self._advance_generation()
            self._clear_all()

    def resume(self) -> None:
        """Resume requires fresh observation: retained state stays empty."""
        with self._lock:
            self.paused = False
            self._advance_generation()
            self._clear_all()

    # -- event intake (collection boundary, R5/F04) ------------------------
    def _stage_entry(
        self, event: WindowEvent, *, now: datetime, sequence: int, generation: int
    ) -> _WindowEntry | None:
        """Build (but do not publish) an entry for one event.

        Privacy classification/filtering happens here, at collection.
        Authority registration is deferred to publication so a staged
        snapshot that is never published cannot disturb retained refs.
        """
        identity_known = event.process_creation_time is not None
        process_token = f"{event.pid}:{event.process_creation_time or 'unknown'}"
        title = (event.title or "")[:MAX_TITLE_CHARS]
        observation = WorldStateObservation(
            observation_id=f"obs-{sequence}",
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
            resource_id=None,
        )
        return _WindowEntry(
            observation=observation,
            hwnd=event.hwnd,
            process_token=process_token,
            generation=generation,
            received_monotonic=time.monotonic(),
        )

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
                self._drop([event.hwnd])
                return
            if event.kind is WindowEventKind.PROCESS_EXITED:
                doomed = [
                    hwnd
                    for hwnd, entry in self._windows.items()
                    if entry.process_token.startswith(f"{event.pid}:")
                ]
                self._drop(doomed)
                return
            if event.kind is WindowEventKind.RECONCILIATION_REQUIRED:
                self._advance_generation()
                self._clear_all()
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
                # No longer collectable: a retained window for this
                # HWND loses its authorization-grade reference too.
                if event.hwnd in self._windows:
                    self._drop([event.hwnd])
                return
            if self.policy.mode.value == "active_app_only" and is_foreground:
                # Only the active app may be retained as current.
                others = [hwnd for hwnd in self._windows if hwnd != event.hwnd]
                self._drop(others)
            if event.hwnd not in self._windows and len(self._windows) >= self.max_windows:
                self.over_capacity_drops += 1
                return

            self._sequence += 1
            entry = self._stage_entry(
                event, now=now, sequence=self._sequence, generation=self._generation
            )
            assert entry is not None
            self._windows[event.hwnd] = self._publish_entry(
                entry, event, existing=self._windows.get(event.hwnd)
            )
            if is_foreground:
                self._foreground_hwnd = event.hwnd

    def apply_snapshot(self, events: list[WindowEvent], *, now: datetime) -> bool:
        """Publish a complete snapshot atomically (CP3-B06).

        The snapshot is staged and validated *off* the retained state
        and swapped in under one lock only if the observation
        generation and policy are unchanged and observation is not
        paused. A rejected snapshot publishes nothing, clears no
        uncertainty, and leaves every retained window authority ref
        untouched; a published snapshot invalidates the refs of
        windows it drops. Returns whether publication occurred. A
        reader therefore can never observe a partially applied
        snapshot: queries take the same lock as the swap.
        """
        with self._lock:
            if self.generation_clock is not None:
                self._generation = self.generation_clock.current()
            if self.paused:
                return False
            staged_generation = self._generation
            staged_policy = self.policy
            base_sequence = self._sequence
        staged: dict[int, _WindowEntry] = {}
        staged_foreground: int | None = None
        sequence = base_sequence
        for event in events:
            if event.generation and event.generation != staged_generation:
                return False  # mixed/obsolete generation snapshot
            if event.kind in (WindowEventKind.WINDOW_DESTROYED, WindowEventKind.PROCESS_EXITED):
                staged.pop(event.hwnd, None)
                continue
            classification = classify_context(
                event.app_identity,
                adapter_classification=event.classification,
                elevated=event.elevated,
            )
            if event.kind is WindowEventKind.FOREGROUND_CHANGED and (
                classification is ContextClassification.PROHIBITED_SENSITIVE
            ):
                continue
            if not collect_permitted(
                staged_policy,
                app_identity=event.app_identity,
                classification=event.classification,
                elevated=event.elevated,
                is_foreground=event.kind is WindowEventKind.FOREGROUND_CHANGED,
            ):
                continue
            sequence += 1
            entry = self._stage_entry(
                event, now=now, sequence=sequence, generation=staged_generation
            )
            assert entry is not None
            staged[event.hwnd] = entry
            if event.kind is WindowEventKind.FOREGROUND_CHANGED:
                staged_foreground = event.hwnd
        with self._lock:
            if (
                self.paused
                or self._generation != staged_generation
                or self.policy is not staged_policy
            ):
                return False  # privacy/generation changed mid-construction
            dropped = [hwnd for hwnd in self._windows if hwnd not in staged]
            self._drop(dropped)
            published: dict[int, _WindowEntry] = {}
            for hwnd, entry in staged.items():
                event = next(e for e in events if e.hwnd == hwnd)
                published[hwnd] = self._publish_entry(
                    entry, event, existing=self._windows.get(hwnd)
                )
            self._windows = published
            self._foreground_hwnd = staged_foreground if staged_foreground in published else None
            self._sequence = max(self._sequence, sequence)
            return True

    # -- expiry / queries ----------------------------------------------------
    def cleanup_expired(self, *, now: datetime) -> int:
        with self._lock:
            expired = [
                hwnd
                for hwnd, entry in self._windows.items()
                if entry.observation.expires_at is not None and entry.observation.expires_at <= now
            ]
            self._drop(expired)
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
