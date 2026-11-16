# ADR-003: RSI optional, explicit, per-task

**Status:** Accepted
**Date:** 2026-11-14 (master spec v1.0)

## Context

A stronger remote model may help with hard reasoning or code review, but
transmission discloses private data and may incur cost/quota. Automatic
escalation would violate privacy and user authority.

## Decision

Remote Specialist Intelligence (RSI) is optional, disabled by default,
and invoked only after: explicit user invocation → provider/model
selection → exact payload preview → per-task approval → send to pinned
endpoint → treat result as untrusted advice → local preview/approval →
local tests. There is no `auto_cloud` route, no automatic provider
fallback, and no covert background traffic. Internet research, token
count, local failure, or low confidence is **not** an RSI invocation.

## Alternatives considered

Automatic cloud escalation on low confidence (rejected: violates R-002).
Silent provider fallback on rate limits (rejected: requires new consent).

## Consequences

- Phase 0 implements only the `RSIDisclosureRequest` contract; no
  provider code, no sending.
- API keys live in OS secret storage, never in YAML/logs/SQLite.
- `SECRET` data is blocked from RSI pending a separate security design.

## Spec references

R-002; RSI decision rules; RSI disclosure security; ADR-004.
