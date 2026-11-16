# ADR-006: Headless-first adapters; UIA/vision as fallbacks

**Status:** Accepted
**Date:** 2026-11-14 (master spec v1.0)

## Context

GUI automation via coordinates is fragile. Structured APIs, COM, and
accessibility trees are more reliable where available, but coverage
varies by application.

## Decision

Control ladder per action: supported application API/extension/CLI →
native COM/Windows interface → UI Automation tree → visual/coordinate
fallback (approval-gated). Adapters exchange typed artifacts through a
shared bus; cross-adapter workflows go through the broker. Universal
app discovery covers many, not all, applications. No universal 99%/100%
coverage is claimed.

## Alternatives considered

Coordinate-first automation (rejected: brittle, unverifiable).
Per-app bespoke code for every app (rejected: does not scale; use
registry + generic UIA + Big-5 adapters).

## Consequences

- Each adapter declares `discover/capabilities/inspect/prepare/
  precheck/execute/verify/describe_recovery/health`.
- Vision fallback requires local multimodal support or approved
  specialist and cannot bypass approval.
- Phase 0: fake adapters only.

## Spec references

Control ladder; Application adapter contract; R-005, R-006.
