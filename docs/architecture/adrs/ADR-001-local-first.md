# ADR-001: Local-first operation

**Status:** Accepted
**Date:** 2026-11-14 (master spec v1.0)

## Context

AETHER must be dependable under poor connectivity, keep private data local,
and incur no hosted-model charge for the core. Remote services may change
price, quota, or terms without notice.

## Decision

AETHER OS is local-first: the full core (text, memory, approved computer
control) works offline. No hosted inference by default. The local model
runs on the user's machine via llama.cpp. An enforceable Offline switch
disables all outbound HTTP, not merely a prompt instruction.

## Alternatives considered

Cloud-first assistant (rejected: violates privacy, offline, and
independence requirements). Hybrid with automatic cloud fallback
(rejected: violates R-002; RSI is explicit per-task only).

## Consequences

- All core features must be testable air-gapped (E-01).
- Model/runtime are replaceable local components with manifests + hashes.
- RSI, web research, and updates are separate capabilities, each gated.

## Spec references

R-001, R-002, R-009, R-012; Network policy; ADR-003.
