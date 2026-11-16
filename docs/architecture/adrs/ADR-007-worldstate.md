# ADR-007: Event-driven WorldState + selective reconciliation

**Status:** Accepted
**Date:** 2026-11-14 (master spec v1.0)

## Context

AETHER must know what the user is looking at ("fix this bug") without
polling the OS destructively or overflowing model context.

## Decision

WorldState is an observer-maintained local resource graph with source,
observation time, freshness, evidence strength (never permission
authority), and sensitivity. Windows `SetWinEventHook`, targeted
`ReadDirectoryChangesW`/watchdog, and extension events reduce polling;
selective periodic reconciliation + on-demand inspection complete it.
This is not zero-CPU. User-selectable privacy modes: off, metadata_only
(default after opt-in), active_app_only, workspace_context,
content_on_demand. Clipboard/screenshots/content are never monitored
by default.

## Alternatives considered

100 ms polling loops (rejected: CPU drain, context overflow).
Raw process-list injection (rejected: secrets exposure, token waste).

## Consequences

- Compact permission-filtered summaries feed the context assembler.
- `psutil` command lines are minimised (may expose secrets).
- Phase 0: observation contract only, no observers.

## Spec references

WorldState service; State observation privacy policy; R-012.
