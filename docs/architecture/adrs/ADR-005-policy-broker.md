# ADR-005: Typed deterministic policy broker, T0–T3 approvals

**Status:** Accepted
**Date:** 2026-11-14 (master spec v1.0)

## Context

The LLM must never grant its own permissions or execute unrestricted
shell code. Consequential actions need explain/preview/approve/verify
with exact scope binding.

## Decision

A deterministic policy broker, independent of model-generated text,
governs all operations. Risk tiers: T0 Observe (auto within sensors),
T1 Navigate/read (auto within allowed roots), T2 Mutate recoverable
(explain + exact preview + approval + snapshot), T3 High consequence
(dedicated confirmation, may be disallowed). Approval tokens bind
`plan_hash`, enumerated operations, resource versions, expiry, and
trusted UI origin. Silence is never approval; any plan/resource change
invalidates grants. Phase 0 implements deny-by-default only.

## Alternatives considered

Prompt-based safety (rejected: prompting, JSON validation, AST, and
confidence scores alone are insufficient per security requirements).
Blanket trusted sessions (rejected: only enumerated task batches).

## Consequences

- Every new permission needs an ADR + regression tests.
- Performance tuning must never remove approval/audit checks.
- Phase 0 broker always denies; later phases add evaluation + issuance.

## Spec references

R-003, R-004, R-005; Approval lifecycle; Approval-bound mutation protocol.
