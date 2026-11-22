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

Command: `uv run pytest` in `backend/`. Full suite at `a65460c`: **775 passed,
3 skipped** (778 collected). The 3 skips are two native-Windows ACL tests and one
environment-gated test; they are **skipped, not passed**.

This count was produced in a **fresh, isolated interpreter** (`python3.11 -m venv`
with the project installed editable from this checkout), so it is reproducible and
not dependent on the sandbox's shared editable install.

| Suite | Tests | Result |
|---|---|---|
| `test_phase2b_persistence.py` | 53 | PASS |
| `test_phase2b_stage2.py` | 29 | PASS |
| `test_phase2b_stage3.py` | 16 | PASS |
| `test_phase2b_stage3_corrections.py` | — | PASS |
| `test_phase2_approved_bytes.py` | 24 | PASS (S14-1) |
| `test_phase2_grant_consumption.py` | 19 | PASS (S14-2) |
| `test_phase2_undo_authorization.py` | 16 | PASS (S14-3) |
| `test_phase2_mutation_journal.py` | 22 | PASS (S14-4) |
| `test_phase2_vault_key_protection.py` | 18 (2 skipped) | PASS (S14-5) |
| `test_phase2_fixture_safety.py` | 21 | PASS (S14-6) |
| `test_phase2_grant_authority.py` | 20 | PASS (S14-7) |
| `test_phase2_orphan_consumption.py` | 11 | PASS (S14-8) |
| `test_phase2_execution_context.py` | 10 | PASS (S14-9) |
| `test_phase2_windows_acl.py` | 25 | PASS (S14-10) |
| `test_phase2b_stage4_grants.py` | 114 | PASS |
| `test_phase2b_stage4_migration.py` | 28 | PASS |
| `test_phase2b_trusted_approval.py` | 32 | PASS (new) |
| `test_phase2c_filesystem.py` | 51 | PASS (new) |
| `test_phase2c_session.py` | 13 | PASS (new) |
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
gateway and manifest tests all pass within the 712-test run. `GRANT_ISSUANCE_DISABLED`
and the Phase 1 deny-all broker default were not modified.

## 9. What has NOT been done, deliberately

- Phase 3 was not started.
- Schema v2 was not activated.
- `GRANT_ISSUANCE_DISABLED` was not removed or bypassed.
- No environment flag, model output or renderer message can authorize anything.
- The Stage 3 review button was not turned into an execution approval.
- No acceptance result was fabricated to close a gate.

## 10. Independent-review remediation (S14-1 … S14-10)

PR #14's independent review found nine defects, and a post-interruption review of
the correction found four more. All thirteen are corrected here as ten separately
reviewable commits. This section states what changed, what proves it,
and — as importantly — what remains **NOT VERIFIED**.

| Commit | Subject | The defect it corrects | Proof |
|---|---|---|---|
| `36a4063` | S14-1 | The user was asked to approve a patch they had not been shown, and the approved post-image was not bound to the plan or the grant | `test_phase2_approved_bytes.py` (24): real `render_exact_diff`, post-image digest bound into `PlanStep.expected_effect`, verified immediately before mutation, same-pre/different-post substitution refused |
| `fb58b49` | S14-2 | A validated grant was treated as execution authority; consumption was not atomic and a retry could double-spend | `test_phase2_grant_consumption.py` (19): default-deny, one-use-one-action, replay refused, thread race for the last use, use spent before the target is read, `GRANT_VALIDATED_EXECUTOR_NOT_ENABLED` can never authorize |
| `ac0f39c` | S14-3 | Undo was authorized through the forward-edit capability and could overwrite a newer user edit | `test_phase2_undo_authorization.py` (16): distinct `fs.undo_edit`, edit approval refused for undo (`approved_capability_mismatch`), current bytes compared to the receipt's verified post-image, newer edit refused as `undo_conflict_newer_content` |
| `e75264b` | S14-4 | A kill between replacing the file and writing the receipt left a changed file with no durable record | `test_phase2_mutation_journal.py` (22): intent durable before the replace, single intent per step, kill-after-replace re-opened from disk, kill-before-replace distinguished, read-only reconciliation, `COMPLETED_UNVERIFIED` never treated as consistent |
| `fef5592` | S14-5 | The vault key was stored inside the vault directory, and `chmod` was a silent no-op on Windows | `test_phase2_vault_key_protection.py` (16 passed, 2 skipped): key relocated, in-vault key refused, copied vault cannot decrypt, legacy key migrated, real DACL on Windows (skipped here), unprotected key refuses to open |
| `58e271a` | S14-7 | A consumption budget could be created for any approval id, so consumption was a second approval source, and accepting grant doubles hid it | `test_phase2_grant_authority.py` (20): budget requires an authoritative grant, may not exceed or disagree with it, spends re-checked for EXPIRED/REVOKED/EXHAUSTED, invented approval cannot authorize a real file mutation |
| `e399099` | S14-8 | A crash between spending a use and journaling left a pending consumption that reconciliation reported as clean | `test_phase2_orphan_consumption.py` (11): orphan reported `reconcile_consumption_without_intent`, never consistent, never completed, file untouched, never attached to another intent |
| `f5ab233` | S14-9 | `_consumption_id` was shared mutable executor state, and the journal was optional | `test_phase2_execution_context.py` (10): attribute gone, two interleaved operations resolve only their own use, journal-less executor refuses before any state change, journal check precedes consumption |
| `a65460c` | S14-10 | The Windows ACL check accepted any descriptor containing an owner ACE, so owner-plus-Everyone passed | `test_phase2_windows_acl.py` (25): exact ACE inventory; Everyone, Users, Authenticated Users, unrelated SIDs, SYSTEM, Administrators, inherited and deny ACEs all rejected |
| `1b2f9c8` | S14-6 | The Windows verifier deleted fixtures outside its own containment and could report unverifiable checks as passing | `test_phase2_fixture_safety.py` (21): `assert_contained`, `assert_no_redirection`, marker-bound `FixtureLease`, source scan forbidding recursive deletes, PASS/FAIL/NOT VERIFIED only |

### What this remediation does not prove

Every item below is still **NOT VERIFIED** and no commit above changes that:

- No real mutation path is wired into the running application. The executor and
  journal are exercised by tests only; `chat_service.py` still wires nothing, and
  `ConsumptionLedger` is never constructed in shipped code — only the
  `IssuanceDisabledConsumptionLedger` default.
- The Electron approval surface has not been demonstrated by a human clicking
  approve. The automated tests drive the chain programmatically.
- No real process kill, power loss or forced unmount has been performed. The
  crash tests simulate the kill in-process and re-open the stores from disk; the
  *simulation* is honest about its own limits, but it is not a real interruption.
- The native Windows DACL has not been executed on Windows in this session. S14-10
  proves the *verifier* is strict, by parsing SDDL on Linux, but does not prove
  that Windows produces that SDDL or that `SetFileSecurityW` succeeds. The two
  Windows-only tests skip here, and the verifier's gate is written to fail on an
  unprotected or broadly-granted DACL — but that gate has not been observed on NTFS.
- The consumption authority (S14-7) is wired only in tests. No production
  configuration constructs a `ConsumptionLedger` with a real `GrantLedger`
  authority, because issuing those grants requires schema v2 activation and is
  still disabled.
- Schema v2 remains inactive (`ACTIVE_SCHEMA_VERSION = 1`,
  `PENDING_MIGRATION_VERSIONS = {2}`) and production grant issuance remains
  disabled (`GRANT_ISSUANCE_DISABLED`).

**Phase 2 is therefore not complete, and this report does not claim it is.**

### Gates at the time of writing

| Gate | Result |
|---|---|
| Backend suite | 775 passed, 3 skipped (clean isolated interpreter) |
| Ruff / format / mypy | clean / clean / clean (95 files) |
| Desktop typecheck / eslint | pass / pass |
| Desktop Node tests | 54 pass, 7 skipped (environment-gated) |
| Desktop Python security tests | 6 pass |
| Electron build | pass |
| Schema v2 | **still inactive** |
| Production grant issuance | **still disabled** |
| Live mutation path | **still absent** |
| Phase 3 | **not started** |
