# ADR-004: Groq qwen/qwen3.8-27b preferred RSI candidate

**Status:** Candidate — pending account validation (V-02)
**Date:** 2026-11-14 (master spec v1.0)

## Context

If RSI is ever used, one provider/model must be preferred initially for
onboarding simplicity. Groq currently lists `qwen/qwen3.8-27b` with
usage-based pricing and account-dependent limits.

## Decision

Preferred (not guaranteed-free, not permanently selected) initial RSI
candidate: Groq `qwen/qwen3.8-27b`. Price, free eligibility, and data
controls must be checked against the authenticated account at runtime
and before every material policy change. The catalog ID is not a
promise of perpetual availability.

## Alternatives considered

Other providers/models (deferred: provider onboarding is a separate
decision with its own ADR, endpoint policy, and audit receipt).

## Consequences

- **Not fully benchmarked or permanently selected.** V-02 must confirm
  account-level entitlement and data controls before any real use.
- No "always free" promise; no dependency on RSI for core usefulness.
- Rate limits never trigger automatic provider switches.

## Spec references

RSI decision rules; V-02; Risk register (Groq price/quota changes).
