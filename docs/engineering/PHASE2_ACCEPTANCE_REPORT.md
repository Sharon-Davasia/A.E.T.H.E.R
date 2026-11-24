# Phase 2 Acceptance Report

**Date:** 2026-11-15 (report authored) · **post-merge update 2026-11-23**
**Repository state:** Phase 2 implementation **merged to `main`** via PR #34
(merge commit `a58bd68843091eb339e3c102b8a2cfa204d355c6`; integrated source
head `3cd5c06281cb1e749ecb9099d0770975ea249009`). At the moment of that integration there were zero open PRs (historical statement as of 2026-11-23; this report's own documentation PR #35 was opened afterwards).
**Binding specification:** `docs/architecture/MASTER_SPEC.md`
**Acceptance procedure:** `docs/engineering/PHASE2_WINDOWS_ACCEPTANCE.md`
**Verifier:** `scripts/verify_phase2.ps1`

> ## Verdicts (kept deliberately separate)
>
> - **Phase 2 code integration: COMPLETE.** The entire implementation
>   (formerly PRs #15–#32, plus the CRLF/EOF and Windows merge-gate
>   corrections) is on `main` through PR #34.
> - **Automated verification: PASS with qualifications** (see §2 — Linux
>   results are Python 3.11.2, not 3.12.10; native Windows results are
>   user-reported and their logs are not archived in this repository).
> - **Formal Phase 2 acceptance: NOT COMPLETE.** Every mandatory scenario
>   that requires the target Windows machine, a human operating the trusted
>   UI, or a real power-loss/interruption event remains **NOT VERIFIED**
>   (see the evidence matrix in `PHASE2_WINDOWS_ACCEPTANCE.md` §8).
>
> Merging the implementation is not acceptance. No partial result here may
> be quoted as acceptance.

## 0. Integration record (verified against GitHub, 2026-11-23)

| Fact | Value |
|---|---|
| Integration PR | #34 — **MERGED** 2026-11-23 |
| Merge commit on `main` | `a58bd68843091eb339e3c102b8a2cfa204d355c6` |
| Integrated source head | `3cd5c06281cb1e749ecb9099d0770975ea249009` |
| Independently verified source commit | `bf08ca9274ed02576ec791ff20781e47a92725a4` |
| Verified source tree | `811c9b75b4a42d81a582beb7f37499eb13a55b2a` |
| Tree equivalence | `3cd5c06^{tree}` == `bf08ca9^{tree}`; GitHub comparison showed zero file differences between the integration head and merged `main` |
| Stack integration | PRs #15–#32 entered through PR #34 exactly once (all split tips A–R are ancestors of the integrated head). GitHub recorded PR #15 as merged; the remaining stacked PRs were closed following integration |
| Superseded PRs | #14 (closed; tree-identical content integrated) and #33 (closed; corrections incorporated via `bf08ca9`). Neither was merged independently, and neither must be reopened for merging |
| Temporary CI | `.github/workflows/phase2-pr34-linux-temporary.yml` (commit `aa91dcb`) was removed in `3cd5c06` before merge; the manual-only `.github/workflows/ci.yml` is unchanged. The temporary workflow never executed — GitHub Actions reported an **account billing restriction**, which is not a source-code test failure |

---

## 1. What is implemented

| Workstream | Deliverable | State (post-merge, verified on `main`) |
|---|---|---|
| A (ex-PR #14) | Schema-v2 migration prepared, **not activated**; `ACTIVE_SCHEMA_VERSION=1`, `PENDING_MIGRATION_VERSIONS={2}` (`backend/aether/core/persistence/sqlite_store.py`) | **Merged via PR #34**; activation still requires separate authorization |
| B (2C) | Bounded typed read/inspect/search/open + task-level session with durable audit | **Merged via PR #34** |
| C (2B) | Planner, persisted preview authority, signed authorizing gesture, production attestation verifier | **Merged via PR #34**; production verifier still `NullAttestationVerifier` (rejects everything) |
| D (2D) | Exact edit executor, encrypted Undo Vault, append-only receipts | **Merged via PR #34**; **no live mutation path enabled** |
| E | `scripts/verify_phase2.ps1`, `PHASE2_WINDOWS_ACCEPTANCE.md` | Merged; see procedure §8 matrix for per-scenario evidence |
| F (post-review correction) | CRLF exact previews, `aether-diff-v2` EOF trailer, legacy-binding fail-closed executor (`aece44c`), Windows merge-gate (`bf08ca9`) | **Merged via PR #34**; renderer/validator traceability: `backend/aether/core/planning/exact_diff.py`, `backend/aether/core/approval_review.py`, `backend/aether/core/edits/executor.py`, `apps/desktop/shared/review.ts` |

## 2. Exact test results

### 2.1 Latest verification (post-integration source, 2026-11-23)

**Linux / Arena — against exact commit `bf08ca9` (isolated worktree):**

| Item | Result |
|---|---|
| Python | **3.11.2** (3.12.10 unavailable in the Arena sandbox — see limitation below) |
| Node.js / npm | v22.22.3 / 10.9.8 (exact) |
| Backend pytest | **847 passed, 5 skipped**, exit 0 |
| Ruff lint / format | PASS / PASS (145 files) |
| mypy (strict) | PASS (95 source files) |
| Desktop `npm run check` (`AETHER_DEV_PYTHON` = backend venv) | ESLint, both typechecks, renderer + Electron builds PASS; **70 Node tests passed, 0 failed, 0 skipped**; 6 Python channel tests passed |

The 5 Linux skips are **skipped, not passed**: environment-gated model
integration (`AETHER_RUN_MODEL_INTEGRATION=1` unset), two native-Windows ACL
vault tests, one Windows access-denial semantics test, and one wheel-packaging
check (hatchling not installed).

> **Limitation:** these Linux results are **Python 3.11.2** results. They must
> not be presented as Linux Python 3.12.10 verification; re-confirmation on
> 3.12.10 remains outstanding.

**Native Windows — user-reported (reported 2026-11-23):** the user reports
native Windows verification with **Python 3.12.10**: full backend suite passed;
desktop 70 Node tests passed; 6 Python channel tests passed; Ruff lint/format
and strict mypy passed; Electron build passed; the native Windows ACL
unreadable-narrative test passed (1 passed, 0 skipped); Windows worktree
validation completed. **These results are user-reported: no execution logs,
exit codes or timestamps are archived in this repository, and they were not
independently re-executed by the report author.** They are recorded as
reported evidence, not as independently verified evidence.

**GitHub Actions:** the temporary Linux workflow added for PR #34 could not
execute — GitHub Actions reported an **account billing restriction**. That is
an account/infrastructure limitation, **not a source-code test failure**. The
temporary workflow was removed before merge (`3cd5c06`); the original
manual-only CI configuration remains intact and unchanged versus `main`.

### 2.2 Historical Linux results (pre-merge, PR #14 era — superseded)

The remainder of this section records the earlier sandbox run. These counts
are **historical evidence**, not the latest results.

Command: `uv run pytest` in `backend/`. Full suite at `eb7e07e`: **819 passed,
3 skipped** (822 collected). At `a65460c` it was 775; S14-11 added 21
and rewrote 2 of the S14-7 tests, S14-12/13 added 15, and the vault concurrency
regression added 1. The 3 skips are two native-Windows ACL
tests and one environment-gated test; they are **skipped, not passed**.

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
| `test_phase2_vault_key_protection.py` | 26 (2 skipped) | PASS (S14-5, S14-14 concurrency) |
| `test_phase2_fixture_safety.py` | 21 | PASS (S14-6) |
| `test_phase2_grant_authority.py` | 18 | PASS (S14-7, rewritten for S14-11) |
| `test_phase2_authoritative_consumption.py` | 21 | PASS (S14-11) |
| `test_phase2_consumption_recovery.py` | 15 | PASS (S14-12, S14-13) |
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

**Scenario summary (updated 2026-11-23): 18 of 18 implemented and covered by
passing automated tests (Linux, `bf08ca9`; the suite is also user-reported
passing on native Windows, logs not archived). 0 of 18 are formally accepted:
the auditable per-scenario evidence matrix — with automated status, native
Windows evidence status, human-demonstration requirement and final verdict
per scenario — is maintained in `PHASE2_WINDOWS_ACCEPTANCE.md` §8. Several
scenarios' *live* demonstrations are currently blocked because production
grant issuance and any live mutation path remain deliberately disabled; that
is recorded as an acceptance blocker there, not worked around.**

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

## 7. Release / acceptance blockers

*Resolved since the pre-merge edition of this report: PR #14's merge review
(integrated via PR #34 and closed as superseded), and the absence of any
native Windows test run (now user-reported — see §2.1).*

1. **No human-in-the-loop approval has been demonstrated.** The gesture chain
   is tested programmatically; nobody has yet clicked Approve in the real UI.
2. **No real crash has been exercised.** The `UNVERIFIED` path is proven by
   simulation only.
3. **Live mutation demonstrations are blocked by design.** Production grant
   issuance remains disabled and no live mutation path is wired, so
   scenarios requiring a real approved edit cannot be demonstrated live
   until a separately authorized, supported workflow exists. This must not
   be bypassed.
4. **Windows evidence is reported, not archived.** Native Windows results
   (§2.1) have no execution logs in this repository; formal acceptance
   requires recorded evidence (see `PHASE2_WINDOWS_ACCEPTANCE.md` §7).
5. **Linux Python 3.12.10 re-confirmation outstanding** (§2.1 limitation).
6. **GitHub Actions could not run** (account billing restriction) — no
   hosted-CI evidence exists; this is not a code failure.
7. **Schema v2 activation is still a separately-approvable change** and has not
   been requested or granted.
8. **`cryptography` is a runtime dependency** (Apache-2.0/BSD-3-Clause) —
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

## 10. Independent-review remediation (S14-1 … S14-14)

PR #14's independent review found nine defects, and a post-interruption review of
the correction found four more. A third source review then found that S14-7's fix
was incomplete: it *checked* the authoritative grant but still spent a separate
local budget. All are corrected here as separately reviewable commits. This section states what changed, what proves it,
and — as importantly — what remains **NOT VERIFIED**.

| Commit | Subject | The defect it corrects | Proof |
|---|---|---|---|
| `36a4063` | S14-1 | The user was asked to approve a patch they had not been shown, and the approved post-image was not bound to the plan or the grant | `test_phase2_approved_bytes.py` (24): real `render_exact_diff`, post-image digest bound into `PlanStep.expected_effect`, verified immediately before mutation, same-pre/different-post substitution refused |
| `fb58b49` | S14-2 | A validated grant was treated as execution authority; consumption was not atomic and a retry could double-spend | `test_phase2_grant_consumption.py` (19): default-deny, one-use-one-action, replay refused, thread race for the last use, use spent before the target is read, `GRANT_VALIDATED_EXECUTOR_NOT_ENABLED` can never authorize |
| `ac0f39c` | S14-3 | Undo was authorized through the forward-edit capability and could overwrite a newer user edit | `test_phase2_undo_authorization.py` (16): distinct `fs.undo_edit`, edit approval refused for undo (`approved_capability_mismatch`), current bytes compared to the receipt's verified post-image, newer edit refused as `undo_conflict_newer_content` |
| `e75264b` | S14-4 | A kill between replacing the file and writing the receipt left a changed file with no durable record | `test_phase2_mutation_journal.py` (22): intent durable before the replace, single intent per step, kill-after-replace re-opened from disk, kill-before-replace distinguished, read-only reconciliation, `COMPLETED_UNVERIFIED` never treated as consistent |
| `fef5592` | S14-5 | The vault key was stored inside the vault directory, and `chmod` was a silent no-op on Windows | `test_phase2_vault_key_protection.py` (16 passed, 2 skipped): key relocated, in-vault key refused, copied vault cannot decrypt, legacy key migrated, real DACL on Windows (skipped here), unprotected key refuses to open |
| `58e271a` | S14-7 | A consumption budget could be created for any approval id, so consumption was a second approval source, and accepting grant doubles hid it | `test_phase2_grant_authority.py` (20): budget requires an authoritative grant, may not exceed or disagree with it, spends re-checked for EXPIRED/REVOKED/EXHAUSTED, invented approval cannot authorize a real file mutation |
| `d1bdd2c` | S14-11 | S14-7 *checked* `GrantLedger.load()/status()` but decremented only a local budget, so the grant stayed unconsumed; two independent consumption databases could each spend the same final use, and revocation between check and spend was escapable | `test_phase2_authoritative_consumption.py` (21): the spend now *is* `GrantLedger.consume`, so the authoritative count moves exactly once; record **and** `CONSUMED` audit event; second consumer cannot report or spend a full allowance; concurrent overspend refused; exhaustion, revocation (incl. mid-flight), expiry, consent and plan binding at consumption time, step binding, replay; invented local budget inert; fake and simulated authorities refused; interrupted execution still journaled, reported as an orphan needing review, and resolvable to `UNVERIFIED` without refunding the use |
| `3d1ade5` | S14-12 | The authoritative commit and the local projection are two SQLite databases, so they cannot commit together; a kill in between left a spend that no local row and no journal intent named, and reconciliation called that clean | `test_phase2_consumption_recovery.py` (8 at this commit): a durable attempt row is committed *before* the spend, so the window is observable from either side; reconciliation asks the authoritative ledger by consumption id and returns `NEEDS_REVIEW` (`reconcile_consumed_without_projection`) for a spend it finds, `NOT_APPLIED` for one it does not, and `NEEDS_REVIEW` (`reconcile_authority_unavailable`) when it cannot ask; the attempt is not an allowance and the simulated ledger is still refused |
| `3149b6c` | S14-13 | The projection used `INSERT OR REPLACE`, so an authoritative replay reset a resolved SUCCEEDED/FAILED/UNVERIFIED row to PENDING, erasing what the first attempt concluded on the path that exists to refuse a duplicate mutation | `test_phase2_consumption_recovery.py` (7 more): replay after each terminal state and across a reopen preserves the state and its detail; a mismatched identity is refused and leaves the row intact; a missing projection recovers as PENDING, never as success; replays remain idempotent and spend nothing |
| `eb7e07e` | S14-14 | The vault lock added with `9194036` protected only `put`'s index update: `cleanup_expired` and `collect_orphan_objects` wrote the same index unlocked, `put` wrote its object outside the critical section (so orphan collection could delete a not-yet-indexed pre-image), two processes could both write, and retention could expire a snapshot a live receipt still needs | `test_phase2_vault_key_protection.py` (26, 8 new): deterministic Event-parked interleavings for put-versus-collection and put-versus-cleanup, a structural guard that every index writer takes the lock, a single-writer ownership lock across instances (`vault_owned_by_another_writer`) released on close with readers unaffected, receipt-linked snapshots excluded from retention, quota refusing rather than evicting them, and all maintenance paths still fail-closed on a corrupt index |
| `9194036` | interim fix | `UndoVault.put` appended to its JSON index with an unsynchronized read-modify-write, so concurrent snapshots could drop an index record — a stored pre-image then reported as `vault_snapshot_unknown` | `test_phase2_vault_key_protection.py` (+1, now 19): 8 concurrent snapshots all readable and all present in the index; 10/10 runs fail without the lock, 8/8 pass with it. Pre-existing since S14-5, surfaced as a ~2-in-12 flake in the interleaved-executor test |
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
- The consumption authority (S14-7/S14-11) is wired only in tests. No production
  configuration constructs a `ConsumptionLedger` with a real `GrantLedger`
  authority, because issuing those grants requires schema v2 activation and is
  still disabled.
- S14-11 makes `GrantLedger.consume` the sole spend, and proves it against a real
  ledger in-process. It has **not** been proven under a real concurrent OS-process
  load or a real crash between the authoritative commit and the projection row:
  the interleaving tests use threads and in-process fault injection. Because the
  spend is atomic and the projection is written after it, a crash in that window
  leaves an authoritative consumption with no local row — reconciliable by
  `consumption_id`, but that recovery path is reasoned about, not exercised.
- Schema v2 remains inactive (`ACTIVE_SCHEMA_VERSION = 1`,
  `PENDING_MIGRATION_VERSIONS = {2}`) and production grant issuance remains
  disabled (`GRANT_ISSUANCE_DISABLED`).

**Phase 2 is therefore not complete, and this report does not claim it is.**

### Gates at the time of writing

| Gate | Result |
|---|---|
| Backend suite | 819 passed, 3 skipped (clean isolated interpreter) |
| Ruff / format / mypy | clean / clean / clean (95 files) |
| Desktop typecheck / eslint | pass / pass |
| Desktop Node tests | 54 pass, 7 skipped (environment-gated) |
| Desktop Python security tests | 6 pass |
| Electron build | pass |
| Schema v2 | **still inactive** |
| Production grant issuance | **still disabled** |
| Live mutation path | **still absent** |
| Phase 3 | **not started** |


---

## 11. Acceptance-readiness checklist (post-merge, 2026-11-23)

This checklist lets a future reviewer complete acceptance without relying on
any prior conversation.

**Implemented and merged** (all on `main` via PR #34, merge commit
`a58bd68`): schema-v2 migration *prepared but inactive*; bounded typed
filesystem session with durable audit; planner + persisted preview authority;
exact-byte approval binding with the `aether-diff-v2` EOF trailer and CRLF
support; exact edit executor with legacy-binding fail-closed verification;
encrypted Undo Vault; append-only receipts; mutation journal and consumption
reconciliation; the Windows acceptance procedure and fixture-safety verifier.

**What automated verification establishes:** the implementation behaves as
specified in-process on Linux (847 passed / 5 skipped at `bf08ca9`, Python
3.11.2) and is user-reported passing on native Windows (Python 3.12.10) —
exact-byte binding, grant accounting, undo authorization, crash-state
reporting, ACL strictness and fail-closed defaults are all covered by named
tests (traceability in §3, §10 and `PHASE2_WINDOWS_ACCEPTANCE.md` §8).

**What remains missing — implementation/wiring prerequisites *and* acceptance evidence (kept distinct):** the merged code is complete, but several mandatory demonstrations cannot run against the shipped product until separately authorized implementation/wiring work exists — a supported live workflow that can issue a real production grant and perform a working approved edit and a verified Undo (production grant issuance and any live mutation path remain deliberately disabled, and schema v2 remains inactive). Those are prerequisites to obtain, not evidence to collect. On top of them, the following evidence is missing:

- [ ] Archived native Windows evidence (logs, exit codes, git SHA, machine
      identity) for the full automated gates, per §7 of the procedure.
- [ ] Machine-identity, OS/build and NTFS details recorded with the Windows run.
- [ ] Evidence matrix in `PHASE2_WINDOWS_ACCEPTANCE.md` §8 filled per scenario.
- [ ] Linux (or hosted-CI) re-confirmation on Python 3.12.10.
- [ ] The mandatory human demonstrations listed in the procedure §4 —
      several are **blocked** until a separately authorized live workflow
      exists (production grant issuance/mutation remain disabled); they must
      not be simulated by bypassing security controls.

**Safe prerequisites for future acceptance testing:** Windows 11, normal
(non-elevated) account, fixture root only under the reviewed containment
rules, clean tree at a recorded commit. **Do not run
`scripts/verify_phase2.ps1` on a machine containing real data until its
fixture safety has been independently reviewed** (see the warning in
`PHASE2_WINDOWS_ACCEPTANCE.md`).

**Actions requiring explicit user authorization:** schema-v2 activation;
enabling production grant issuance or any live mutation path; merging or
reopening superseded PRs; running the Windows verifier on a real machine;
declaring formal acceptance.

**Formal Phase 2 PASS, per the specification and procedure:** every one of
the 18 mandatory scenarios in the evidence matrix is `PASS` with its
required evidence class present (automated result *and*, where required,
archived native Windows evidence *and* a recorded human demonstration),
with the acceptance signed per the procedure §7. Until then:

- Phase 2 code integration: **COMPLETE**
- Automated verification: **PASS with qualifications** (§2.1)
- Formal Phase 2 acceptance: **NOT COMPLETE**
