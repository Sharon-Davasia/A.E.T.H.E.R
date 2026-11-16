# ADR-009: Electron + React/TS + Python/FastAPI modular monolith

**Status:** Accepted
**Date:** 2026-11-14 (master spec v1.0)

## Context

AETHER needs a desktop shell, a typed backend, and process isolation
without the operational cost of a microservice cluster.

## Decision

Modular monolith with process isolation: Electron (main/preload +
React/Vite/TS/Tailwind renderer) + Python/FastAPI/Pydantic backend +
llama.cpp server + small workers/adapters. Modules communicate via
typed contracts. Custom typed Python task state machine is the core
orchestrator; LangGraph is optional for bounded specialist flows, never
the policy authority. No managed cloud DB, broker, Kubernetes, or
hosted vector store is required.

## Alternatives considered

Microservices (rejected: premature distribution; one-user/one-machine).
Single-process script collection (rejected: no isolation, no contracts).

## Consequences

- `core/policy` cannot depend on model content; `model_gateway`
  cannot import FS writers/shell/credentials; adapters cannot call
  each other directly.
- Electron hardening (contextIsolation, sandbox, narrow preload) is
  mandatory.
- Phase 0: backend skeleton only; no Electron UI.

## Spec references

Architectural pattern; Process layout; Module dependencies.
