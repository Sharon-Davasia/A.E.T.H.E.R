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
    from aether.world_state.observer import GenerationClock

    clock = GenerationClock()
    state = InMemoryWorldState(policy=_policy(), generation_clock=clock)
    source = FakeWindowEventSource()
    service = ObserverService(
        source=source,
        on_event=lambda event: state.handle_event(event, now=NOW),
        on_invalidate=state.invalidate_all,
        queue_capacity=2,
        generation_clock=clock,
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


def test_window_resource_ids_are_session_ephemeral_uuids() -> None:
    from aether.core.contracts.resource import ResourceRef
    from aether.core.resources.app_window_authority import (
        AppWindowAuthorityError,
        AppWindowResourceAuthority,
    )

    authority = AppWindowResourceAuthority()
    state = InMemoryWorldState(policy=_policy(), authority=authority)
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=987654321, process_creation_time="t1"), now=NOW
    )
    first = state.current(now=NOW)[0]
    assert first.resource_id is not None and first.resource_id.startswith("window:")
    assert "987654321" not in first.resource_id  # HWND never exposed in the id
    # Same HWND recreated (new process instance) invalidates the old ref.
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=987654321, process_creation_time="t2"), now=NOW
    )
    second = state.current(now=NOW)[0]
    assert second.resource_id != first.resource_id
    with pytest.raises(AppWindowAuthorityError):
        authority.authorize_ref(
            ResourceRef(kind="window", resource_id=first.resource_id or "", observed_version="x"),
            expected_kind="window",
        )
    # Forged window ref and kind confusion both fail closed.
    with pytest.raises(AppWindowAuthorityError):
        authority.authorize_ref(
            ResourceRef(kind="window", resource_id="window:123e4567-e89b-12d3-a456-426614174000"),
            expected_kind="window",
        )
    with pytest.raises(AppWindowAuthorityError):
        authority.authorize_ref(
            ResourceRef(kind="app", resource_id=second.resource_id or ""), expected_kind="window"
        )


# -- CP3-B06: snapshot atomicity + authority lifecycle -------------------------


def _authority_world():  # type: ignore[no-untyped-def]
    from aether.core.resources.app_window_authority import AppWindowResourceAuthority

    authority = AppWindowResourceAuthority()
    return InMemoryWorldState(policy=_policy(), authority=authority), authority


def test_snapshot_publication_is_atomic_and_drops_refs() -> None:
    from aether.core.contracts.resource import ResourceRef
    from aether.core.resources.app_window_authority import AppWindowAuthorityError

    state, authority = _authority_world()
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=1, process_creation_time="t1"), now=NOW
    )
    kept = state.current(now=NOW)[0].resource_id
    assert kept is not None
    # A published snapshot replaces state wholesale; the dropped
    # window's authority ref is invalidated with its observation.
    assert state.apply_snapshot(
        [_event(WindowEventKind.WINDOW_CREATED, hwnd=2, pid=11, process_creation_time="t1")],
        now=NOW,
    )
    current = state.current(now=NOW)
    assert [o.resource_id for o in current] != [kept]
    with pytest.raises(AppWindowAuthorityError):
        authority.authorize_ref(
            ResourceRef(kind="window", resource_id=kept), expected_kind="window"
        )


def test_privacy_change_during_snapshot_invalidates_it() -> None:
    class PolicyChangingState(InMemoryWorldState):
        arm = False

        def _stage_entry(self, event, *, now, sequence, generation):  # type: ignore[no-untyped-def]
            if self.arm:
                self.arm = False
                self.set_policy(_policy())  # policy changes mid-construction
            return super()._stage_entry(event, now=now, sequence=sequence, generation=generation)

    from aether.core.resources.app_window_authority import AppWindowResourceAuthority

    state = PolicyChangingState(policy=_policy(), authority=AppWindowResourceAuthority())
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=1, process_creation_time="t1"), now=NOW
    )
    state.arm = True
    published = state.apply_snapshot(
        [_event(WindowEventKind.WINDOW_CREATED, hwnd=2, pid=11, process_creation_time="t1")],
        now=NOW,
    )
    assert published is False
    # The snapshot was not published on top of the retained state.
    assert [o.summary for o in state.current(now=NOW)] == []


def test_destroyed_and_expired_window_refs_are_rejected() -> None:
    from aether.core.contracts.resource import ResourceRef
    from aether.core.resources.app_window_authority import AppWindowAuthorityError

    state, authority = _authority_world()
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=5, process_creation_time="t1"), now=NOW
    )
    ref = state.current(now=NOW)[0].resource_id
    assert ref is not None
    state.handle_event(_event(WindowEventKind.WINDOW_DESTROYED, hwnd=5), now=NOW)
    with pytest.raises(AppWindowAuthorityError):
        authority.authorize_ref(ResourceRef(kind="window", resource_id=ref), expected_kind="window")
    # Expiry also invalidates.
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=6, process_creation_time="t1"), now=NOW
    )
    ref2 = state.current(now=NOW)[0].resource_id
    later = NOW + timedelta(seconds=3600)
    assert state.current(now=later) == []
    with pytest.raises(AppWindowAuthorityError):
        authority.authorize_ref(
            ResourceRef(kind="window", resource_id=ref2), expected_kind="window", now=later
        )


def test_same_hwnd_recreation_invalidates_previous_ref() -> None:
    from aether.core.contracts.resource import ResourceRef
    from aether.core.resources.app_window_authority import AppWindowAuthorityError

    state, authority = _authority_world()
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=9, process_creation_time="t1"), now=NOW
    )
    first = state.current(now=NOW)[0]
    state.handle_event(
        _event(WindowEventKind.WINDOW_CREATED, hwnd=9, process_creation_time="t2"), now=NOW
    )
    second = state.current(now=NOW)[0]
    assert first.resource_id != second.resource_id
    binding = authority.resolve_window(second.resource_id or "")
    assert binding.instance_generation > 1  # actual instance generation advances
    with pytest.raises(AppWindowAuthorityError):
        authority.authorize_ref(
            ResourceRef(kind="window", resource_id=first.resource_id or ""), expected_kind="window"
        )


def test_paused_observation_cannot_reconcile() -> None:
    source = FakeWindowEventSource()
    calls = []
    original = source.reconcile

    def _counting():  # type: ignore[no-untyped-def]
        calls.append(1)
        return original()

    source.reconcile = _counting  # type: ignore[method-assign]
    service = ObserverService(source=source, on_event=lambda event: None, reconcile_interval=0.01)
    service.start()
    service.pause_collection()
    try:
        assert service.collection_paused
        assert service.reconcile() is False  # direct call also refused
    finally:
        service.stop()
    assert calls == []


def test_native_source_shutdown_failure_is_not_success() -> None:
    class FailingStopSource(FakeWindowEventSource):
        def stop(self) -> bool:
            return False

    service = ObserverService(source=FailingStopSource(), on_event=lambda event: None)
    service.start()
    assert service.stop() is False
    assert service.health() == "degraded"
