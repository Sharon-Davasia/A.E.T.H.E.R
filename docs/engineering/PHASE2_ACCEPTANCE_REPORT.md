# Phase 2 Acceptance Report

**Date:** 2026-11-15 (report authored) · acceptance run pending
**Branch:** `arena/9ff5f05b-a-e-t-h-e-r` (open PR #14 at `2b60708`, **not merged**)
**Binding specification:** `docs/architecture/MASTER_SPEC.md`
**Acceptance procedure:** `docs/engineering/PHASE2_WINDOWS_ACCEPTANCE.md`
**Verifier:** `scripts/verify_phase2.ps1`

> ## Verdict: **NOT COMPLETE**
>
> Every mandatory item that can be proven on Linux is **PASS**. Every mandatory
> item that requires the target Windows machine, a human operating the trusted
> UI, or a real power-loss/interruption event is **NOT VERIFIED**.
>
> Under the directive, Phase 2 must not be declared complete while any mandatory
> item is `NOT VERIFIED`. **Phase 2 is therefore not complete.** This report does
> not claim otherwise, and no partial result here may be quoted as acceptance.

---

## 1. What is implemented

| Workstream | Deliverable | State |
|---|---|---|
| A (PR #14) | Schema-v2 migration prepared, **not activated**; `ACTIVE_SCHEMA_VERSION=1`, `PENDING_MIGRATION_VERSIONS={2}` | Implemented, tested, awaiting your review; **not merged** |
| B (2C) | Bounded typed read/inspect/search/open + task-level session with durable audit | Implemented, tested |
| C (2B) | Planner, persisted preview authority, signed authorizing gesture, production attestation verifier | Implemented, tested; **production verifier still rejecting by default** |
| D (2D) | Exact edit executor, encrypted Undo Vault, append-only receipts | Implemented, tested; **no live mutation path enabled** |
| E | `scripts/verify_phase2.ps1`, `PHASE2_WINDOWS_ACCEPTANCE.md` | Written; **not yet executed on Windows** |

## 2. Exact test results (Linux, this sandbox)

Command: `uv run pytest` in `backend/`. Full suite: **589 passed, 1 skipped**.

| Suite | Tests | Result |
|---|---|---|
| `test_phase2b_persistence.py` | 53 | PASS |
| `test_phase2b_stage2.py` | 29 | PASS |
| `test_phase2b_stage3.py` | 16 | PASS |
| `test_phase2b_stage3_corrections.py` | — | PASS |
| `test_phase2b_stage4_grants.py` | 114 | PASS |
| `test_phase2b_stage4_migration.py` | 28 | PASS |
| `test_phase2b_trusted_approval.py` | 32 | PASS (new) |
| `test_phase2c_filesystem.py` | 51 | PASS (new) |
| `test_phase2c_session.py` | 11 | PASS (new) |
| `test_phase2d_edits.py` | 33 | PASS (new) |
| `test_phase2_end_to_end.py` | 25 | PASS (new) |
| `test_phase2_workspace_surface.py` | 8 | PASS (new) |
| `test_phase2_policy.py` | 6 | PASS |
| `test_phase2_approval_binding.py` | 15 | PASS |

Other gates:

| Gate | Command | Result |
|---|---|---|
| Backend lint | `ruff check .` | PASS |
| Backend format | `ruff format --check` | PASS |
| Backend types | `mypy` (87 files, strict) | PASS |
| Desktop lint | `npm run lint` (`--max-warnings 0`) | PASS |
| Desktop typecheck | `npm run typecheck` | PASS |
| Desktop Node tests | `npm test` | 54 pass, 7 skipped |
| Desktop Python security tests | `npm run test:python` | 6 pass |
| Electron build | `npm run build:electron` | PASS |

The 7 skipped desktop tests are environment-gated (they need a display or a
packaged Electron binary). They are **skipped, not passed**, and they appear as
`NOT VERIFIED` in the Windows verifier.

## 3. Directive §7 — the 18 mandatory Windows scenarios

| # | Scenario | Implementation | Linux test | Windows evidence |
|---|---|---|---|---|
| 1 | Open a registered project | `fs/session.py` `open` | `test_01_*` PASS | **NOT VERIFIED** |
| 2 | Search + read an allowed file | `fs/search.py`, `fs/content.py` | `test_02_*` PASS | **NOT VERIFIED** |
| 3 | Refuse read outside allowed roots | `resources/registry.py` | `test_03_*` PASS | **NOT VERIFIED** |
| 4 | Refuse `.env` without authorization | `registry.py`, `fs/content.py` | `test_04_*` PASS | **NOT VERIFIED** |
| 5 | Deny junction/symlink escape | `resources/path_safety.py` | `test_05_*` PASS (symlink) | **NOT VERIFIED** (junction needs NTFS) |
| 6 | Show the exact patch pre-approval | `planning/preview_authority.py` | `test_06_*` PASS | **NOT VERIFIED** (needs human-visible UI) |
| 7 | Refuse mutation before approval | `grants/attestation.py` | `test_07_*` PASS | **NOT VERIFIED** |
| 8 | Apply edit, compare hash | `edits/executor.py` | `test_08_*` PASS | **NOT VERIFIED** |
| 9 | Refuse stale post-preview modification | `edits/executor.py` | `test_09_*` PASS | **NOT VERIFIED** |
| 10 | Reject forged/expired/revoked/exhausted/replayed grants | `grants/*`, `planning/authorizing_gesture.py` | `test_10_*` (7 cases) PASS | **NOT VERIFIED** |
| 11 | Exact-action consumption | `grants/authority.py` | `test_11_*` PASS | **NOT VERIFIED** |
| 12 | Receipts across restart | `edits/receipts.py` | `test_12_*` PASS | **NOT VERIFIED** |
| 13 | Undo + verify | `vault/undo_vault.py` | `test_13_*` PASS | **NOT VERIFIED** |
| 14 | Refuse silent overwrite of newer edit | `edits/executor.py` undo | `test_14_*` PASS | **NOT VERIFIED** |
| 15 | Truthful crash/cancel recovery | `edits/executor.py` (UNVERIFIED) | `test_15_*` PASS (simulated) | **NOT VERIFIED** (needs a real kill/power loss) |
| 16 | T3/shell/unsupported denied | `policy/broker.py`, `fs/executor.py` | `test_16_*` PASS | **NOT VERIFIED** |
| 17 | Zero unauthorized mutation | whole stack | `test_17_*` PASS | **NOT VERIFIED** |
| 18 | Offline, no unauthorized cloud traffic | no network client in Phase 2 packages | `test_18_*` PASS | **NOT VERIFIED** (must be observed) |

**Scenario summary: 18 of 18 implemented and covered by a passing Linux test;
0 of 18 carry Windows evidence.**

## 4. Security boundaries — current, verified state

| Boundary | State | Evidence |
|---|---|---|
| `GRANT_ISSUANCE_DISABLED` | **Intact, unchanged** | `test_phase2b_stage4_grants.py`, `test_production_issuance_stays_disabled_after_activation` |
| `PRODUCTION_ATTESTATION_VERIFIER` | Still `NullAttestationVerifier` (rejects everything) | `test_07_*`, `test_phase2b_trusted_approval.py` |
| `PRODUCTION_PREVIEW_AUTHORITY` | Still `NullPreviewAuthority` | same |
| Schema v2 | **Not activated** (`ACTIVE_SCHEMA_VERSION=1`) | 28 migration tests |
| T3 capabilities | Denied | `TIER3_DISABLED` in broker |
| Generic shell | Absent; `open` reports `SHELL_ACCEPTED_REQUEST`, never claims app success | `test_phase2c_filesystem.py` |
| Mutation in the running service | **None.** No adapter wired in `chat_service.py` | `test_workspace_is_not_wired_into_the_running_service` |
| Read-only workspace adapters | Explicit set of four; no wildcard | `test_phase2_workspace_surface.py` |
| Audit metadata | Allow-listed; no paths, content or queries | `test_events_never_contain_file_content`, `EventMetadata` validator |

## 5. Real migration evidence

Executed on Linux against real SQLite files (not simulated persistence):

| Check | Result |
|---|---|
| Migration `0002` bytes match the release pin | PASS — `d2a02f54…64571c` |
| v2 fingerprint independently reproduced | PASS — `dec68c2c…55b788` |
| Migration `0001` not rewritten | PASS |
| Clean install records only v1 | PASS |
| v1 → v2 upgrade preserves existing records (activated in test) | PASS |
| Interrupted migration leaves no half-applied schema | PASS |
| Tampered migration ledger row rejected | PASS |
| Shipped configuration prepares but does not activate v2 | PASS |

**Not verified:** the same migration on NTFS under a real Windows file lock, and
under an actual process kill. Those are in the Windows verifier.

## 6. Unsupported cases (denied and recorded, never silently widened)

- Non-regular files: FIFOs, devices, hard links (`nlink > 1`) — refused.
- Reparse points, junctions, symlinks — refused by canonical re-verification.
- UNC paths, network volumes, removable volumes — refused.
- `.env`, `.git`, `.ssh`, browser profiles, credential stores — refused.
- T2 mutation without a verified exact grant — refused.
- T3 and any generic shell/exec capability — refused.
- A capability with a registered contract but no adapter — `CAPABILITY_EXECUTOR_NOT_AVAILABLE`.

## 7. Release blockers

1. **PR #14 is unmerged** and must be reviewed by you independently before merge.
2. **No Windows evidence exists yet.** Run `scripts/verify_phase2.ps1` on the
   target machine; any exit code other than `0` blocks the phase.
3. **No human-in-the-loop approval has been demonstrated.** The gesture chain is
   tested programmatically; nobody has yet clicked Approve in the real UI.
4. **No real crash has been exercised.** The `UNVERIFIED` path is proven by
   simulation only.
5. **Schema v2 activation is still a separately-approvable change** and has not
   been requested or granted.
6. **`cryptography` is a new runtime dependency** (Apache-2.0/BSD-3-Clause) —
   recorded in `DEPENDENCY_INVENTORY.md`; distribution licence review still open.

## 8. Phase 1 status

Unchanged and still green: Phase 0/1 deny-all policy, offline contract, model
gateway and manifest tests all pass within the 589-test run. `GRANT_ISSUANCE_DISABLED`
and the Phase 1 deny-all broker default were not modified.

## 9. What has NOT been done, deliberately

- Phase 3 was not started.
- Schema v2 was not activated.
- `GRANT_ISSUANCE_DISABLED` was not removed or bypassed.
- No environment flag, model output or renderer message can authorize anything.
- The Stage 3 review button was not turned into an execution approval.
- No acceptance result was fabricated to close a gate.
