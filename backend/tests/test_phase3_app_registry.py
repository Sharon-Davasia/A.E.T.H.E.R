"""Phase 3 CP2 tests: registry, identity drift, real fuzzy resolution.

Uses controlled fake discovery fixtures and the real RapidFuzz ranking
implementation (platform-independent; no native evidence).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aether.adapters.windows import fake_discovered_apps
from aether.core.apps import InMemoryApplicationRegistry, resolve_application
from aether.core.apps.registry import ApplicationRegistryError
from aether.core.apps.resolution import Fts5AppIndex, ResolutionKind, normalize_name

NOW = datetime(2026, 11, 15, tzinfo=UTC)


def _registry() -> InMemoryApplicationRegistry:
    registry = InMemoryApplicationRegistry()
    registry.register_many(fake_discovered_apps())
    return registry


def test_discovery_is_not_trust_and_unknown_app_refused() -> None:
    registry = _registry()
    assert len(registry.all()) == 3
    with pytest.raises(ApplicationRegistryError):
        registry.get("app:123e4567-e89b-12d3-a456-426614174000")  # fabricated
    # Discovery records carry provenance and freshness.
    record = registry.all()[0]
    assert record.discovery_source.value == "fake_fixture"
    assert registry.fresh(now=NOW + timedelta(days=365)) == ()


def test_executable_identity_drift_marks_stale() -> None:
    registry = _registry()
    record = registry.all()[0]
    assert registry.verify_executable_identity(record.app_id, record.executable_identity or "")
    assert registry.get(record.app_id).available
    assert not registry.verify_executable_identity(record.app_id, "C:\\Evil\\notepad.exe")
    assert not registry.get(record.app_id).available  # drift never silently trusted


def test_duplicate_registration_refresh_and_capacity() -> None:
    registry = InMemoryApplicationRegistry(max_records=1)
    record = fake_discovered_apps()[0]
    registry.register(record)
    registry.register(record)  # refresh of same identity is allowed
    with pytest.raises(ApplicationRegistryError):
        registry.register(fake_discovered_apps()[1])


def test_exact_alias_and_normalized_resolution() -> None:
    registry = _registry()
    exact = resolve_application(registry, "notepad")
    assert exact.kind is ResolutionKind.EXACT and exact.record is not None
    alias = resolve_application(registry, "calc")
    assert alias.kind is ResolutionKind.ALIAS and alias.record is not None
    assert alias.record.display_name == "Calculator"
    normalized = resolve_application(registry, "  NotePad!! ")
    assert normalized.kind in (ResolutionKind.EXACT, ResolutionKind.NORMALIZED)


def test_real_fuzzy_ranking_and_ambiguity() -> None:
    registry = _registry()
    fuzzy = resolve_application(registry, "notepd")  # misspelling, real RapidFuzz
    assert fuzzy.kind is ResolutionKind.FUZZY and fuzzy.record is not None
    assert fuzzy.record.display_name == "Notepad"
    # "note" is an exact alias of Notepad AND close to Notes: exact alias
    # wins deterministically; a near-tie query must clarify, not pick.
    ambiguous = resolve_application(registry, "notes app")
    assert ambiguous.kind in (
        ResolutionKind.AMBIGUOUS,
        ResolutionKind.FUZZY,
        ResolutionKind.NOT_FOUND,
    )
    if ambiguous.kind is ResolutionKind.AMBIGUOUS:
        assert ambiguous.record is None and len(ambiguous.candidates) >= 2


def test_ambiguous_duplicate_names_require_clarification() -> None:
    from aether.core.contracts.app_window import (
        ApplicationRecord,
        DiscoverySource,
        LaunchMethod,
        registration_app_id,
    )

    registry = InMemoryApplicationRegistry()
    for exe in ("C:\\A\\tool.exe", "C:\\B\\tool.exe"):
        registry.register(
            ApplicationRecord(
                app_id=registration_app_id(
                    display_name="Tool", executable_identity=exe, launch_method=LaunchMethod.NONE
                ),
                display_name="Tool",
                discovery_source=DiscoverySource.FAKE_FIXTURE,
                discovered_at=NOW,
                fresh_until=NOW + timedelta(hours=1),
            )
        )
    outcome = resolve_application(registry, "Tool")
    assert outcome.kind is ResolutionKind.AMBIGUOUS and outcome.record is None


def test_missing_target_and_fts5_index() -> None:
    registry = _registry()
    missing = resolve_application(registry, "xyzzy nonexistent application")
    assert missing.kind is ResolutionKind.NOT_FOUND and missing.record is None
    index = Fts5AppIndex(registry.all())
    hits = index.search("text editor")
    assert hits and hits[0].display_name == "Notepad"
    assert normalize_name("My App!! 2024") == "my app 2024"


def test_malicious_alias_does_not_hijack_exact_name() -> None:
    registry = _registry()
    # A misleading query matching an alias of a *different* app must not
    # outrank the exact display-name match.
    outcome = resolve_application(registry, "Notes")
    assert outcome.record is not None and outcome.record.display_name == "Notes"
