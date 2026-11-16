# ADR-012: Versioned installation, encrypted backups

**Status:** Accepted (design direction; implementation deferred to Phase 9)
**Date:** 2026-11-14 (master spec v1.0)

## Context

Upgrades, recovery, and hardware migration must be pain-free, or the
tool will be abandoned. Half-updated codebases are a top failure mode.

## Decision

Versioned layout (`current` pointer → `versions\<x.y.z>`, shared
`models\`, user `data\`), atomic activation with health check before
swap, forward-only migrations with pre-migration backup, one-command
rollback. Encrypted backups (SQLite online backup API), portable
"soul file" export, migration packages (models re-downloaded, not
bundled). Signed/verifiable releases, checksums, staging, rollback.
No automatic antivirus exclusions. Phase 0: no installer/updater code.

## Alternatives considered

`git pull` on live systems (rejected: dependency mismatch risk).
Silent auto-updates (rejected: supply-chain risk).

## Consequences

- Fresh-install, upgrade/rollback, and restore drills are release gates.
- Model manifest tracks source/version/hash/licence.
- Security/lifecycle hygiene (audits, integrity checks) is mandatory.

## Spec references

Distribution model; On-disk layout; Backups; V-07.
