# ADR-011: Skill registry with quarantine, no auto-install

**Status:** Accepted
**Date:** 2026-11-14 (master spec v1.0)

## Context

Skills extend capabilities, but executable extensions are a supply-chain
and privilege-escalation risk. LLM-generated skills must never install
themselves or acquire privileges.

## Decision

Versioned skill registry with manifests (declared effects, max tier,
package hash, trust status). Untrusted skills are quarantined: never
imported or executed automatically. Installation requires review,
hash verification, and broker approval. Two-stage retrieval (FTS5
shortlist + GBNF grammar) keeps the local model fast. MCP adapters
are wrapped in the same Tier gate. Skill Forge (self-coding) is a
later, opt-in phase with Tier 3 review. Phase 0: manifest contract
only.

## Alternatives considered

Drop-in auto-import (rejected: arbitrary code execution).
No skills (rejected: prevents extensibility).

## Consequences

- Every skill needs manifest, integrity, and regression tests.
- Quarantine + signed packages are mandatory for distribution.
- No skill becomes a permission.

## Spec references

Skill system; Skill installation pipeline; R-010.
