# ADR-014: Phase 3 Windows observation (event-driven, privacy-gated, in-memory)

**Status:** Proposed (CP0 foundation; native activation not authorized)
**Date:** 2026-11-15

## Context
Phase 3 requires window/process awareness without polling, content
capture, or persistent activity history. ADR-007 already selects
event-driven WorldState with privacy modes.

## Decision
Observer behind a platform event-source protocol (`SetWinEventHook`
native source guarded by platform+activation checks; fake source for
platform-independent tests). Privacy filtering occurs at collection:
`off` until opt-in, then `metadata_only`; sensitive/elevated/
unclassifiable contexts excluded. Observations live in memory only,
expire (TTL), and are invalidated on destruction, process exit,
privacy change, pause, and queue-overflow reconciliation. Provisional
bounds: queue 256, TTL 30 s (unmeasured defaults).

## Consequences
No native sensor runs in ordinary launches in CP0–CP2. Evidence
strength is never authorization. Native activation, takeover
detection (R2 design), and measured performance budgets require
separate review.
