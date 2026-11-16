# ADR-010: Ambient Ghost/Summon/Pulse/Dashboard UI

**Status:** Accepted (design direction; implementation deferred to Phase 5)
**Date:** 2026-11-14 (master spec v1.0)

## Context

The assistant should be unobtrusive when idle and responsive when
summoned, without stealing focus from the user's work.

## Decision

Four-state lifecycle: Ghost Mode (invisible, tray icon only, 95% of
time) → Summon Mode (compact bar, auto-fades) → Task Pulse (thin top
bar/pill with step text) → Critical Alert (focused Tier 3 modal).
Dual-window Electron: unfocusable click-through HUD + on-demand
Dashboard. Approval surface is separate from untrusted content.
Visual baseline: light slate palette, cobalt/indigo accents,
glassmorphism, Inter/Geist + JetBrains Mono, spring motion, Lucide
icons. Personality: respectful senior colleague, concise, dry wit,
one follow-up per task, blunt honesty.

## Alternatives considered

Persistent HUD (rejected: steals focus, breaks WorldState).
Chat-window-only UI (rejected: no ambient awareness).

## Consequences

- Accessibility/usability validation required before Phase 5.
- Notification gate (mute on calls, queue on fullscreen) is mandatory.
- Phase 0: no UI code; design tokens documented for later.

## Spec references

Four-state lifecycle; Core screens; Visual system; Personality contract.
