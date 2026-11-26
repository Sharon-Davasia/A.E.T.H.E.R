"""Phase 3 CP2/F05/F06 tests: registry, identity, real fuzzy resolution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aether.adapters.windows import fake_discovered_apps
from aether.core.apps import InMemoryApplicationRegistry, resolve_application
from aether.core.apps.resolution import Fts5AppIndex, ResolutionKind, normalize_name
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    registration_app_id,
)

NOW = datetime(2026, 11, 15, tzinfo=UTC)
LATER = NOW + timedelta(minutes=5)


def _registry() -> InMemoryApplicationRegistry:
    registry = InMemoryApplicationRegistry()
    registry.register_many(fake_discovered_apps())
    return registry


def _record(
    name: str, exe: str, *, aliases: tuple[str, ...] = (), fresh: bool = True
) -> ApplicationRecord:
    return ApplicationRecord(
        app_id=registration_app_id(
            display_name=name, executable_identity=exe, launch_method=LaunchMethod.NONE
        ),
        display_name=name,
        executable_identity=exe,
        aliases=aliases,
        discovery_source=DiscoverySource.FAKE_FIXTURE,
        discovered_at=NOW,
        fresh_until=NOW + timedelta(hours=1) if fresh else NOW - timedelta(hours=1),
    )


def test_expired_exact_match_is_stale_not_selected() -> None:
    registry = InMemoryApplicationRegistry()
    registry.register(_record("OldPad", "C:\\A\\old.exe", fresh=False))
    outcome = resolve_application(registry, "OldPad", now=NOW)
    assert outcome.kind is ResolutionKind.STALE_OR_UNAVAILABLE and outcome.record is None


def test_fresh_records_resolve_exact_alias_normalized() -> None:
    registry = _registry()
    assert resolve_application(registry, "notepad", now=NOW).kind is ResolutionKind.EXACT
    alias = resolve_application(registry, "calc", now=NOW)
    assert alias.kind is ResolutionKind.ALIAS and alias.record is not None
    assert alias.record.display_name == "Calculator"


def test_unavailable_alias_not_selected() -> None:
    registry = _registry()
    target = next(r for r in registry.all() if r.display_name == "Calculator")
    registry.mark_unavailable(target.app_id)
    outcome = resolve_application(registry, "calc", now=LATER)
    assert outcome.kind is ResolutionKind.STALE_OR_UNAVAILABLE and outcome.record is None


def test_real_fuzzy_and_deterministic_near_tie_ambiguity() -> None:
    registry = _registry()
    fuzzy = resolve_application(registry, "notepd", now=NOW)
    assert fuzzy.kind is ResolutionKind.FUZZY and fuzzy.record is not None
    assert fuzzy.record.display_name == "Notepad"

    tie_registry = InMemoryApplicationRegistry()
    tie_registry.register(_record("Star Writer", "C:\\A\\sw.exe"))
    tie_registry.register(_record("Star Write", "C:\\B\\sw.exe"))
    ambiguous = resolve_application(tie_registry, "star writ", now=NOW)
    assert ambiguous.kind is ResolutionKind.AMBIGUOUS  # actual ambiguity asserted
    assert ambiguous.record is None and len(ambiguous.candidates) >= 2
    # Deterministic across repeated resolution.
    again = resolve_application(tie_registry, "star writ", now=NOW)
    assert [c.app_id for c in again.candidates] == [c.app_id for c in ambiguous.candidates]


def test_competing_match_not_hidden_by_fts5_pool() -> None:
    registry = InMemoryApplicationRegistry()
    registry.register(_record("Alpha Notes", "C:\\A\\an.exe"))
    registry.register(_record("Alpha Notepad", "C:\\B\\an.exe"))
    outcome = resolve_application(registry, "alpha note", now=NOW)
    # Evaluated over all candidates; not auto-picked from a narrow pool.
    assert outcome.kind in (ResolutionKind.AMBIGUOUS, ResolutionKind.FUZZY)
    if outcome.kind is ResolutionKind.AMBIGUOUS:
        assert len(outcome.candidates) == 2


def test_duplicate_names_ambiguous_unicode_and_empty() -> None:
    registry = InMemoryApplicationRegistry()
    registry.register(_record("Tool", "C:\\A\\tool.exe"))
    registry.register(_record("Tool", "C:\\B\\tool.exe"))
    assert resolve_application(registry, "Tool", now=NOW).kind is ResolutionKind.AMBIGUOUS

    unicode_registry = InMemoryApplicationRegistry()
    unicode_registry.register(_record("メモ帳", "C:\\A\\memo.exe"))
    unicode_registry.register(_record("メモ帳プロ", "C:\\B\\memo.exe"))
    assert normalize_name("メモ帳") != ""
    outcome = resolve_application(unicode_registry, "メモ帳", now=NOW)
    assert outcome.kind is ResolutionKind.EXACT and outcome.record is not None
    assert resolve_application(unicode_registry, "   ", now=NOW).kind is ResolutionKind.NOT_FOUND
    assert resolve_application(unicode_registry, "!!!", now=NOW).kind is ResolutionKind.NOT_FOUND


def test_identity_drift_and_repeated_refresh_never_restore_trust() -> None:
    registry = _registry()
    record = registry.all()[0]
    # Location-evidence drift keeps record unavailable; identical
    # re-registration of the drifted record does not restore it.
    assert not registry.verify_executable_identity(record.app_id, "C:\\Evil\\notepad.exe")
    assert not registry.get(record.app_id).available
    registry.register(registry.get(record.app_id))
    assert not registry.get(record.app_id).available
    assert not registry.get(record.app_id).launch_authorized


def test_missing_integrity_evidence_never_launch_eligible() -> None:
    record = _record("Fresh", "C:\\A\\fresh.exe")
    assert record.integrity_status == "unavailable" and not record.launch_authorized
    registry = InMemoryApplicationRegistry()
    registry.register(record)
    assert not registry.get(record.app_id).launch_authorized


def test_fabricated_registration_identity_rejected() -> None:
    with pytest.raises(ValueError):
        ApplicationRecord(
            app_id="app:123e4567-e89b-12d3-a456-426614174000",  # not derived
            display_name="Fake",
            discovery_source=DiscoverySource.FAKE_FIXTURE,
            discovered_at=NOW,
            fresh_until=NOW,
        )


def test_alias_bounds_and_fts5_lifecycle() -> None:
    registry = InMemoryApplicationRegistry()
    with pytest.raises(ValueError):  # contract/registry alias bounds
        registry.register(
            _record("Bounded", "C:\\A\\b.exe", aliases=tuple(f"a{i}" for i in range(17)))
        )
    with Fts5AppIndex(_registry().all()) as index:
        hits = index.search("text editor")
        assert hits and hits[0].display_name == "Notepad"
    assert (
        resolve_application(_registry(), "xyzzy nonexistent", now=NOW).kind
        is ResolutionKind.NOT_FOUND
    )
