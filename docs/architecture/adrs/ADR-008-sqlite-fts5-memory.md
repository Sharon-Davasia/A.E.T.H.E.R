# ADR-008: SQLite + FTS5 with provenance and scoped memory

**Status:** Accepted
**Date:** 2026-11-14 (master spec v1.0)

## Context

Memory must distinguish user statements, observed evidence, inferences,
and untrusted source text, with traceable provenance, scoped isolation,
and true forgetting. A vector DB is not initially justified.

## Decision

SQLite (ACID, WAL, migrations, FTS5) is the authoritative store.
Namespaces: `GLOBAL_USER`, `PROJECT:<uuid>`, `EPISODIC`, plus
`DOCUMENT_INDEX` and a separate `AUDIT` store. Four record types:
Preference, FactClaim, ProjectDecision, Episode — each with scope,
subject/predicate/object, source type, verification status, validity
interval, sensitivity, and supersession. Bi-temporal reasoning where
applicable. Embeddings/vector search only if benchmarked relevance
shows material improvement over FTS5, running locally. No cloud
embeddings. Phase 0: contracts only, no engine.

## Alternatives considered

Vector DB first (rejected: premature infrastructure; benchmark first).
Raw chat-log dumping (rejected: confuses projects, promotes guesses).

## Consequences

- Inferred habits never silently become permanent rules.
- Deletion must clear index, caches, and reconcile on restore.
- No memory becomes a security permission.

## Spec references

Memory goals; Storage decisions; R-008, R-011.
