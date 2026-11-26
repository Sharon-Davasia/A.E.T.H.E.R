"""Deterministic application-name resolution (Phase 3 CP2).

Order: exact name -> explicit alias -> normalized -> FTS5 candidate
retrieval -> RapidFuzz ranking. A fuzzy score is evidence, never proof
of identity or authorization; ambiguous results require clarification
and are never auto-selected. FTS5 runs on an in-memory SQLite database
(no schema migration, no real-user database).
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from enum import StrEnum

from rapidfuzz import fuzz

from aether.core.apps.registry import InMemoryApplicationRegistry
from aether.core.contracts.app_window import ApplicationRecord

# Provisional thresholds (engineering defaults, to be measured natively).
FUZZY_ACCEPT_THRESHOLD = 85.0
FUZZY_MARGIN = 8.0

_NON_WORD = re.compile(r"[^a-z0-9]+")


def normalize_name(value: str) -> str:
    return _NON_WORD.sub(" ", value.casefold()).strip()


class ResolutionKind(StrEnum):
    EXACT = "exact"
    ALIAS = "alias"
    NORMALIZED = "normalized"
    FUZZY = "fuzzy"
    AMBIGUOUS = "ambiguous"
    NOT_FOUND = "not_found"


@dataclass(frozen=True, slots=True)
class ResolutionOutcome:
    kind: ResolutionKind
    record: ApplicationRecord | None
    candidates: tuple[ApplicationRecord, ...]
    scores: tuple[float, ...]


class Fts5AppIndex:
    """In-memory SQLite FTS5 index over names+aliases (no migration)."""

    def __init__(self, records: tuple[ApplicationRecord, ...]) -> None:
        self._db = sqlite3.connect(":memory:")
        self._db.execute("CREATE VIRTUAL TABLE app_search USING fts5(app_id UNINDEXED, text)")
        self._by_id = {record.app_id: record for record in records}
        for record in records:
            text = " ".join([record.display_name, *record.aliases])
            self._db.execute(
                "INSERT INTO app_search(app_id, text) VALUES (?, ?)",
                (record.app_id, text),
            )

    def search(self, query: str, *, limit: int = 10) -> list[ApplicationRecord]:
        terms = [t for t in normalize_name(query).split() if t]
        if not terms:
            return []
        match = " OR ".join(f'"{term}"' for term in terms)
        try:
            rows = self._db.execute(
                "SELECT app_id FROM app_search WHERE app_search MATCH ? LIMIT ?",
                (match, limit),
            ).fetchall()
        except sqlite3.Error:
            return []
        return [self._by_id[row[0]] for row in rows if row[0] in self._by_id]


def resolve_application(
    registry: InMemoryApplicationRegistry, query: str, *, now: object | None = None
) -> ResolutionOutcome:
    """Resolve ``query`` deterministically; ambiguity never auto-picks."""
    records = registry.all()
    folded = query.strip().casefold()
    normalized = normalize_name(query)

    exact = [r for r in records if r.display_name.casefold() == folded]
    if len(exact) == 1:
        return ResolutionOutcome(ResolutionKind.EXACT, exact[0], tuple(exact), (100.0,))
    if len(exact) > 1:
        return ResolutionOutcome(ResolutionKind.AMBIGUOUS, None, tuple(exact), ())

    alias = [r for r in records if any(a.casefold() == folded for a in r.aliases)]
    if len(alias) == 1:
        return ResolutionOutcome(ResolutionKind.ALIAS, alias[0], tuple(alias), (100.0,))
    if len(alias) > 1:
        return ResolutionOutcome(ResolutionKind.AMBIGUOUS, None, tuple(alias), ())

    norm = [r for r in records if normalize_name(r.display_name) == normalized]
    if len(norm) == 1:
        return ResolutionOutcome(ResolutionKind.NORMALIZED, norm[0], tuple(norm), (95.0,))
    if len(norm) > 1:
        return ResolutionOutcome(ResolutionKind.AMBIGUOUS, None, tuple(norm), ())

    # Candidate retrieval via FTS5, then real RapidFuzz ranking over
    # the full record set scores (retrieval only narrows the display
    # set; ranking is computed on names+aliases for determinism).
    index = Fts5AppIndex(records)
    retrieved = index.search(query)
    scored: list[tuple[float, ApplicationRecord]] = []
    pool = retrieved if retrieved else list(records)
    for record in pool:
        names = [record.display_name, *record.aliases]
        score = max(float(fuzz.WRatio(query, name)) for name in names)
        scored.append((score, record))
    scored.sort(key=lambda item: (-item[0], item[1].app_id))
    if not scored or scored[0][0] < FUZZY_ACCEPT_THRESHOLD:
        return ResolutionOutcome(ResolutionKind.NOT_FOUND, None, (), ())
    if len(scored) > 1 and (scored[0][0] - scored[1][0]) < FUZZY_MARGIN:
        top = tuple(record for _, record in scored[:3])
        return ResolutionOutcome(
            ResolutionKind.AMBIGUOUS, None, top, tuple(s for s, _ in scored[:3])
        )
    return ResolutionOutcome(ResolutionKind.FUZZY, scored[0][1], (scored[0][1],), (scored[0][0],))
