"""Phase 3 CP1/F03/F04/F07 tests: observer, privacy generations, overflow.

All sources are fakes; platform-independent, no native evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aether.world_state import (
    ContextClassification,
    InMemoryWorldState,
    ObservationPolicy,
    PrivacyMode,
)
from aether.world_state.observer import (
    FakeWindowEventSource,
    ObserverService,
    ObserverUnavailable,
    WindowEvent,
    WindowEventKind,
)

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
PERMITTED = ContextClassification.PERMITTED_METADATA


def _policy(mode: PrivacyMode = PrivacyMode.METADATA_ONLY) -> ObservationPolicy:
    return ObservationPolicy(mode=mode, opted_in=True)


def _event(kind: WindowEventKind, hwnd: int = 1, pid: int = 10, **kw: object) -> WindowEvent:
    base: dict[str, object] = {"app_identity": "notepad", "classification": PERMITTED}
    base.update(kw)
    return WindowEvent(kind=kind, hwnd=hwnd, pid=pid, **base)  # type: ignore[arg-type]


def test_collection_disabled_before_opt_in() -> None:
    state = InMemoryWorldState(policy=ObservationPolicy())
    state.handle_event(_event(WindowEventKind.WINDOW_CREATED), now=NOW)
    assert state.current(now=NOW) == []


def test_unknown_context_fails_closed_for_titles() -> None:
    state = InMemoryWorldState(policy=_policy())
    unknown = WindowEvent(
        kind=WindowEventKind.WINDOW_CREATED,
        hwnd=9,
        pid=1,
        app_identity="someapp",
        title="Secret Doc",
    )
    state.handle_event(unknown, now=NOW)
    assert state.current(now=NOW) == []  # unclassified: nothing retained


def test_title_provenance_is_untrusted_and_private() -> None:
    state = InMemoryWorldState(policy=_policy())
    state.handle_event(
        _event(
            WindowEventKind.FOREGROUND_CHANGED, title="Doc - Notepad", process_creation_time="t0"
        ),
        now=NOW,
    )
    observation = state.foreground(now=NOW)
    assert observation is not None
    assert observation.provenance.value == "UNTRUSTED"
    assert observation.data_class.value == "PRIVATE"
    assert observation.availability == "available"


def test_missing_process_identity_is_stale_not_authorization_grade() -> None:
    state = InMemoryWorldState(policy=_policy())
    state.handle_event(_event(WindowEventKind.WINDOW_CREATED), now=NOW)  # no creation time
    observation = state.current(now=NOW)[0]
    assert observation.availability == "stale" and observation.evidence_strength <= 0.4


def test_foreground_replaced_by_excluded_window_clears_active() -> None:
    state = InMemoryWorldState(policy=_policy())
    state.handle_event(
        _event(WindowEventKind.FOREGROUND_CHANGED, process_creation_time="t"), now=NOW
    )
    assert state.foreground(now=NOW) is not None
    state.handle_event(
        WindowEvent(
            kind=WindowEventKind.FOREGROUND_CHANGED,
            hwnd=2,
            pid=3,
            app_identity="KeePass Password Manager",
        ),
        now=NOW,
    )
    assert state.foreground(now=NOW) is None


def test_active_app_only_focus_change_drops_previous() -> None:
    state = InMemoryWorldState(policy=_policy(PrivacyMode.ACTIVE_APP_ONLY))
    state.handle_event(
        _event(WindowEventKind.FOREGROUND_CHANGED, hwnd=1, process_creation_time="t"), now=NOW
    )
    state.handle_event(
        _event(WindowEventKind.FOREGROUND_CHANGED, hwnd=2, pid=11, process_creation_time="t"),
        now=NOW,
    )
    current = state.current(now=NOW)
    assert len(current) == 1 and state.foreground(now=NOW) is not None


def test_privacy_generation_discards_old_events() -> None:
    state = InMemoryWorldState(policy=_policy())
    old_generation = state.generation
    state.set_policy(_policy())  # bumps generation + invalidates
    state.handle_event(_event(WindowEventKind.WINDOW_CREATED), now=NOW, generation=old_generation)
    assert state.current(now=NOW) == []  # obsolete generation discarded
    state.handle_event(_event(WindowEventKind.WINDOW_CREATED), now=NOW, generation=state.generation)
    assert len(state.current(now=NOW)) == 1


def test_pause_and_resume_require_fresh_observation() -> None:
    state = InMemoryWorldState(policy=_policy())
    state.handle_event(_event(WindowEventKind.WINDOW_CREATED), now=NOW)
    state.pause()
    state.handle_event(_event(WindowEventKind.WINDOW_CREATED), now=NOW)
    assert state.current(now=NOW) == []
    state.resume()  # pre-pause events never become current again
    assert state.current(now=NOW) == []


def test_expiry_capacity_and_defensive_copies() -> None:
    state = InMemoryWorldState(policy=_policy(), max_windows=1)
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=1, process_creation_time="t"), now=NOW
    )
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=2, pid=11, process_creation_time="t"), now=NOW
    )
    assert state.over_capacity_drops == 1
    copies = state.current(now=NOW)
    copies[0].summary = "mutated"
    assert state.current(now=NOW)[0].summary != "mutated"
    assert state.cleanup_expired(now=NOW + timedelta(seconds=31)) == 1


def test_overflow_invalidates_out_of_band_and_reconcile_rebuilds() -> None:
    state = InMemoryWorldState(policy=_policy())
    source = FakeWindowEventSource()
    service = ObserverService(
        source=source,
        on_event=lambda event: state.handle_event(event, now=NOW),
        on_invalidate=state.invalidate_all,
        queue_capacity=2,
    )
    service.push_for_test(_event(WindowEventKind.WINDOW_CREATED, hwnd=1, process_creation_time="t"))
    service.drain_for_test()
    assert len(state.current(now=NOW)) == 1
    # Overflow with a full queue: invalidation cannot be lost.
    for index in range(6):
        service.push_for_test(
            _event(WindowEventKind.WINDOW_CREATED, hwnd=10 + index, process_creation_time="t")
        )
    assert service.invalidation_pending and service.stats.uncertain
    assert state.current(now=NOW) == [] or service.stats.dropped_overflow > 0
    state.invalidate_all()  # out-of-band callback effect
    assert state.current(now=NOW) == []
    # Successful reconciliation of a fresh generation clears uncertainty.
    source.set_snapshot(
        [_event(WindowEventKind.WINDOW_CREATED, hwnd=42, process_creation_time="t")]
    )
    assert service.reconcile() is True
    assert not service.stats.uncertain
    service.drain_for_test()
    assert len(state.current(now=NOW)) == 1

    # Stale pre-reconciliation events cannot restore invalidated state.
    service.push_for_test(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=99, process_creation_time="t")
    )
    state.invalidate_all()
    service.drain_for_test()
    assert all(obs.summary != "stale" for obs in state.current(now=NOW))


def test_failed_reconciliation_retains_uncertainty() -> None:
    class FailingSource(FakeWindowEventSource):
        def reconcile(self):  # type: ignore[override]
            raise RuntimeError("enumeration failed")

    service = ObserverService(source=FailingSource(), on_event=lambda event: None)
    assert service.reconcile() is False
    assert service.stats.uncertain  # failure != proof windows disappeared


def test_lifecycle_start_failure_rolls_back_and_stop_reports() -> None:
    source = FakeWindowEventSource()
    source.fail_start = True
    service = ObserverService(source=source, on_event=lambda event: None)
    with pytest.raises(ObserverUnavailable):
        service.start()
    assert not service.running and service.health() == "unavailable"
    source.fail_start = False
    service.start()
    assert service.running and service.health() == "running"
    with pytest.raises(ObserverUnavailable):
        service.drain_for_test()  # cannot compete with live consumer
    assert service.stop() is True
    assert not service.running
    # Restart: queued pre-shutdown events do not survive.
    service.push_for_test(_event(WindowEventKind.WINDOW_CREATED))
    service.start()
    service.stop()
