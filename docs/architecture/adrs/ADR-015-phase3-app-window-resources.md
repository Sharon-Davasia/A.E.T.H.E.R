# ADR-015: Application/window resource authority and UI-operation binding direction

**Status:** Proposed (contracts in CP0–CP2; execution not authorized)
**Date:** 2026-11-15

## Context
The Phase 2 registry/broker are filesystem-specific by design
(`file:`/`directory:` ids in capability arguments, exact grants, and
audit contracts). Phase 3 must not widen those restrictions as a
shortcut (R3/R4).

## Decision
Separate typed app/window identities (`core/contracts/app_window.py`):
registration identity, executable identity evidence (drift → stale),
process instance (pid+creation time), window instance (broker id
binding HWND+process instance+UIA runtime id). Capability resource
dispatch follows the registered capability's declared kind;
`CapabilityRegistry.phase3_foundation()` registers T0
observation/discovery contracts only. Any effectful UI operation will
use a *separate* typed UI-operation binding reusing the trusted
gesture/attestation/consumption principles — never `_EDIT_CAPABILITIES`
and never a second policy broker — under a distinct default-disabled
Phase 3 enablement (Decision 4). Detailed design requires separate
review before CP3/CP5.

## Consequences
Discovered ≠ trusted ≠ authorized. Forged `app:`/`window:` ids cannot
be interpreted as filesystem resources and vice versa. Launching and
UI interaction remain disabled in CP0–CP2.
