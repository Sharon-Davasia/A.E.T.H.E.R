"""Deterministic application-name resolution (Phase 3 CP2, F05).

Order: exact -> explicit alias -> normalized -> RapidFuzz ranking
over **all** fresh, available records. FTS5 assists retrieval/display
only and never eliminates competing candidates from ambiguity checks
(the registry is bounded, so full evaluation is cheap). Successful
resolution uses fresh records only; an exclusively stale/unavailable
match yields ``stale_or_unavailable``, never an auto-selected target.
Ambiguity requires clarification. A fuzzy score is evidence, never
proof of identity or authorization.
"""

from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from rapidfuzz import fuzz

from aether.core.apps.registry import InMemoryApplicationRegistry
from aether.core.contracts.app_window import ApplicationRecord

# Provisional thresholds (engineering defaults, to be measured natively).
FUZZY_ACCEPT_THRESHOLD = 85.0
FUZZY_MARGIN = 8.0
MAX_QUERY_LENGTH = 256

_NON_WORD = re.compile(r"[^\w]+", re.UNICODE)


def normalize_name(value: str) -> str:
    """Unicode-aware normalization (distinct scripts stay distinct)."""
    return _NON_WORD.sub(" ", value.casefold()).strip()


class ResolutionKind(StrEnum):
    EXACT = "exact"
    ALIAS = "alias"
    NORMALIZED = "normalized"
    FUZZY = "fuzzy"
    AMBIGUOUS = "ambiguous"
    NOT_FOUND = "not_found"
    STALE_OR_UNAVAILABLE = "stale_or_unavailable"


@dataclass(frozen=True, slots=True)
class ResolutionOutcome:
    kind: ResolutionKind
    record: ApplicationRecord | None
    candidates: tuple[ApplicationRecord, ...]
    scores: tuple[float, ...]


class Fts5AppIndex:
    """In-memory SQLite FTS5 index (no migration); explicitly closed."""

    def __init__(self, records: tuple[ApplicationRecord, ...]) -> None:
        self._db = sqlite3.connect(":memory:")
        self._by_id = {record.app_id: record for record in records}
        with closing(self._db.cursor()) as cursor:
            cursor.execute("CREATE VIRTUAL TABLE app_search USING fts5(app_id UNINDEXED, text)")
            for record in records:
                text = " ".join([record.display_name, *record.aliases])
                cursor.execute(
                    "INSERT INTO app_search(app_id, text) VALUES (?, ?)", (record.app_id, text)
                )
        self._db.commit()

    def search(self, query: str, *, limit: int = 10) -> list[ApplicationRecord]:
        terms = [term for term in normalize_name(query).split() if term]
        if not terms:
            return []
        match = " OR ".join(f'"{term}"' for term in terms)
        try:
            with closing(self._db.cursor()) as cursor:
                rows = cursor.execute(
                    "SELECT app_id FROM app_search WHERE app_search MATCH ? LIMIT ?",
                    (match, limit),
                ).fetchall()
        except sqlite3.Error:
            return []
        return [self._by_id[row[0]] for row in rows if row[0] in self._by_id]

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Fts5AppIndex:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _order_key(item: tuple[float, ApplicationRecord]) -> tuple[float, str, str]:
    score, record = item
    return (-score, normalize_name(record.display_name), record.app_id)


def resolve_application(
    registry: InMemoryApplicationRegistry, query: str, *, now: datetime
) -> ResolutionOutcome:
    """Resolve ``query`` against fresh records deterministically."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not query.strip() or len(query) > MAX_QUERY_LENGTH or not normalize_name(query):
        return ResolutionOutcome(ResolutionKind.NOT_FOUND, None, (), ())

    all_records = registry.all()
    fresh = registry.fresh(now=now)

    def _stale_if_only_stale(matches: list[ApplicationRecord]) -> ResolutionOutcome | None:
        if matches and not fresh:
            return ResolutionOutcome(ResolutionKind.STALE_OR_UNAVAILABLE, None, tuple(matches), ())
        return None

    folded = query.strip().casefold()
    normalized = normalize_name(query)

    exact_all = [r for r in all_records if r.display_name.casefold() == folded]
    exact = [r for r in fresh if r.display_name.casefold() == folded]
    if len(exact) == 1:
        return ResolutionOutcome(ResolutionKind.EXACT, exact[0], tuple(exact), (100.0,))
    if len(exact) > 1:
        return ResolutionOutcome(ResolutionKind.AMBIGUOUS, None, tuple(exact), ())
    if exact_all and not exact:
        return _stale_if_only_stale(exact_all) or ResolutionOutcome(
            ResolutionKind.STALE_OR_UNAVAILABLE, None, tuple(exact_all), ()
        )

    alias_all = [r for r in all_records if any(a.casefold() == folded for a in r.aliases)]
    alias = [r for r in fresh if any(a.casefold() == folded for a in r.aliases)]
    if len(alias) == 1:
        return ResolutionOutcome(ResolutionKind.ALIAS, alias[0], tuple(alias), (100.0,))
    if len(alias) > 1:
        return ResolutionOutcome(ResolutionKind.AMBIGUOUS, None, tuple(alias), ())
    if alias_all and not alias:
        return ResolutionOutcome(ResolutionKind.STALE_OR_UNAVAILABLE, None, tuple(alias_all), ())

    norm = [r for r in fresh if normalize_name(r.display_name) == normalized]
    if len(norm) == 1:
        return ResolutionOutcome(ResolutionKind.NORMALIZED, norm[0], tuple(norm), (95.0,))
    if len(norm) > 1:
        return ResolutionOutcome(ResolutionKind.AMBIGUOUS, None, tuple(norm), ())

    # Fuzzy: evaluate every fresh candidate. FTS5 retrieval is used
    # only as an assist/display signal and never narrows this pool.
    scored: list[tuple[float, ApplicationRecord]] = []
    for record in fresh:
        names = [record.display_name, *record.aliases]
        normalized_query = normalize_name(query)
        score = max(
            max(
                float(fuzz.WRatio(query, name)),
                float(fuzz.ratio(normalized_query, normalize_name(name))),
            )
            for name in names
        )
        scored.append((score, record))
    scored.sort(key=_order_key)
    if not scored or scored[0][0] < FUZZY_ACCEPT_THRESHOLD:
        stale_pool = [r for r in all_records]
        if stale_pool and not fresh:
            return ResolutionOutcome(ResolutionKind.STALE_OR_UNAVAILABLE, None, (), ())
        return ResolutionOutcome(ResolutionKind.NOT_FOUND, None, (), ())
    if len(scored) > 1 and (scored[0][0] - scored[1][0]) < FUZZY_MARGIN:
        top = tuple(record for _, record in scored[:3])
        return ResolutionOutcome(
            ResolutionKind.AMBIGUOUS, None, top, tuple(score for score, _ in scored[:3])
        )
    return ResolutionOutcome(ResolutionKind.FUZZY, scored[0][1], (scored[0][1],), (scored[0][0],))
