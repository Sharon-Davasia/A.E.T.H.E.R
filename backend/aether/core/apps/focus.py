"""Typed focus/window resource locks + manual-takeover handling (CP5-R8).

Locks coordinate *our own* tasks; they are never proof that a target
window is still valid — window/process identity and focus are
revalidated at every operation boundary. Acquisition ordering is
deterministic (window lock before the shared foreground lock) so two
tasks can never deadlock or run parallel foreground operations on
different windows. Locks have bounded duration and explicit release;
stale owners cannot release another owner's lock; expired locks are
reconciled rather than blocking later authorized tasks forever.

Manual takeover uses privacy-preserving activity signals only:
relevant foreground changes and same-window manual-activity signals.
No key values, typed text, pointer histories or clipboard content are
ever recorded. On takeover, automated actions stop, focus ownership
is released safely and stale observations are invalidated; resumption
requires a fresh precheck.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

MAX_LOCK_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class LockHandle:
    kind: str  # "window" | "foreground"
    key: str
    owner_task: str
    owner_session: str
    acquired_at: float
    expires_at: float
    # F13: unique ownership token; release and validity require it, so
    # a stale or forged handle can never act for the current owner.
    token: str = ""


@dataclass(slots=True)
class _HeldLock:
    handle: LockHandle
    window_id: str | None


@dataclass(frozen=True, slots=True)
class ActivitySignal:
    """Privacy-preserving activity signal (no content of any kind)."""

    kind: str  # "foreground_changed" | "manual_activity_in_window" | "focus_lost"
    window_id: str | None
    at: datetime


@dataclass(slots=True)
class FocusCoordinator:
    """Deterministic, bounded focus/window lock coordination."""

    monotonic: Callable[[], float] = time.monotonic
    max_lock_seconds: float = MAX_LOCK_SECONDS
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _held: dict[tuple[str, str], _HeldLock] = field(default_factory=dict)
    _takeover_windows: set[str] = field(default_factory=set)
    _invalidated_snapshots: set[str] = field(default_factory=set)

    # -- acquisition ----------------------------------------------------

    def _reconcile_expired_locked(self) -> None:
        now = self.monotonic()
        for key in [k for k, v in self._held.items() if v.handle.expires_at <= now]:
            self._held.pop(key, None)

    def acquire_window(
        self, *, window_id: str, owner_task: str, owner_session: str, duration: float | None = None
    ) -> LockHandle | None:
        return self._acquire("window", window_id, owner_task, owner_session, duration, window_id)

    def acquire_foreground(
        self, *, owner_task: str, owner_session: str, window_id: str, duration: float | None = None
    ) -> LockHandle | None:
        """The single shared foreground-desktop lock (one holder system-wide)."""
        return self._acquire(
            "foreground", "desktop", owner_task, owner_session, duration, window_id
        )

    def _acquire(
        self,
        kind: str,
        key: str,
        owner_task: str,
        owner_session: str,
        duration: float | None,
        window_id: str | None,
    ) -> LockHandle | None:
        with self._lock:
            self._reconcile_expired_locked()
            slot = (kind, key)
            existing = self._held.get(slot)
            if existing is not None:
                # Same-task re-entry must not bypass session ownership.
                if (
                    existing.handle.owner_task == owner_task
                    and existing.handle.owner_session == owner_session
                ):
                    return existing.handle
                return None  # contention: fail, never queue-steal focus
            now = self.monotonic()
            handle = LockHandle(
                kind=kind,
                key=key,
                owner_task=owner_task,
                owner_session=owner_session,
                acquired_at=now,
                expires_at=now + min(duration or self.max_lock_seconds, MAX_LOCK_SECONDS),
            )
            self._held[slot] = _HeldLock(handle=handle, window_id=window_id)
            return handle

    def acquire_operation(
        self, *, window_id: str, owner_task: str, owner_session: str
    ) -> tuple[LockHandle, LockHandle] | None:
        """Deterministic ordering: window lock, then foreground lock.

        On foreground contention the window lock is released, so a
        failed task never blocks later authorized tasks.
        """
        window_lock = self.acquire_window(
            window_id=window_id, owner_task=owner_task, owner_session=owner_session
        )
        if window_lock is None:
            return None
        foreground_lock = self.acquire_foreground(
            owner_task=owner_task, owner_session=owner_session, window_id=window_id
        )
        if foreground_lock is None:
            self.release(window_lock)
            return None
        return window_lock, foreground_lock

    # -- release / reconciliation ----------------------------------------

    def release(self, handle: LockHandle) -> bool:
        """Release only the caller's own lock; stale owners fail."""
        with self._lock:
            slot = (handle.kind, handle.key)
            existing = self._held.get(slot)
            if existing is None:
                return False
            current = existing.handle
            if (
                current.token != handle.token
                or current.owner_task != handle.owner_task
                or current.owner_session != handle.owner_session
            ):
                return False  # another owner's lock: not ours to release
            self._held.pop(slot, None)
            return True

    def is_valid(self, handle: LockHandle) -> bool:
        """True while this exact ownership token is held and unexpired.

        Expiry never silently transfers ownership while a worker may
        still be executing: callers must re-check validity at every
        dispatch boundary and treat a lapsed lock after possible
        effect as uncertain, not as permission to proceed.
        """
        with self._lock:
            existing = self._held.get((handle.kind, handle.key))
            if existing is None or existing.handle.token != handle.token:
                return False
            return existing.handle.expires_at > self.monotonic()

    def release_task(self, owner_task: str) -> int:
        with self._lock:
            keys = [k for k, v in self._held.items() if v.handle.owner_task == owner_task]
            for key in keys:
                self._held.pop(key, None)
            return len(keys)

    def reconcile_after_crash(self) -> int:
        """Drop expired locks (e.g. after restart); returns count dropped."""
        with self._lock:
            before = len(self._held)
            self._reconcile_expired_locked()
            return before - len(self._held)

    def holder_of_window(self, window_id: str) -> str | None:
        with self._lock:
            self._reconcile_expired_locked()
            held = self._held.get(("window", window_id))
            return held.handle.owner_task if held else None

    # -- manual takeover ---------------------------------------------------

    def note_activity(self, signal: ActivitySignal) -> None:
        """Record a takeover-relevant signal (content-free)."""
        with self._lock:
            if signal.window_id is not None and signal.kind in (
                "manual_activity_in_window",
                "focus_lost",
                "foreground_changed",
            ):
                self._takeover_windows.add(signal.window_id)

    def takeover_detected(self, window_id: str) -> bool:
        with self._lock:
            return window_id in self._takeover_windows

    def on_takeover(self, window_id: str, *, snapshot_ids: tuple[str, ...] = ()) -> None:
        """Stop automation on this window: drop its locks, stale its snapshots."""
        with self._lock:
            self._takeover_windows.add(window_id)
            for key in [k for k, v in self._held.items() if v.window_id == window_id]:
                self._held.pop(key, None)
            self._invalidated_snapshots.update(snapshot_ids)

    def snapshot_invalidated(self, snapshot_id: str) -> bool:
        with self._lock:
            return snapshot_id in self._invalidated_snapshots

    def clear_takeover(self, window_id: str) -> None:
        """Called only by a fresh precheck before any resumption."""
        with self._lock:
            self._takeover_windows.discard(window_id)


def lock_deadline_exceeded(handle: LockHandle, *, now: datetime, acquired_wall: datetime) -> bool:
    return now - acquired_wall > timedelta(seconds=MAX_LOCK_SECONDS)
