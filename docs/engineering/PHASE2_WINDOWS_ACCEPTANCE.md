# Phase 2 — Windows Acceptance Procedure

**Audience:** the engineer running the acceptance pass on the target Windows 11 laptop.
**Status authority:** this document defines *how* Phase 2 is accepted. It does not
assert that it has been. Results are recorded in `PHASE2_ACCEPTANCE_REPORT.md`.

> **⚠️ The verifier has not been independently reviewed and must not be run on a
> machine holding real data until it is.** `scripts/verify_phase2.ps1` deletes
> nothing itself — every fixture operation is delegated to
> `aether.core.acceptance.fixture_safety`, which has negative tests proving that
> sibling prefixes, unmarked directories, junctions and arbitrary paths are
> refused. Review those tests first; that is the safety argument.

A Phase 2 claim is only valid when every **mandatory** item below is `PASS`.
`NOT VERIFIED` is not a soft pass: while any mandatory item is `NOT VERIFIED`,
Phase 2 is **incomplete** and must not be announced as complete.

---

## 1. Preconditions

| Requirement | Detail |
|---|---|
| Operating system | Windows 11, fully patched, NTFS system volume |
| Account | **Normal user.** No elevation. The verifier refuses to run elevated. |
| Fixture location | A uniquely named `AETHER-Phase2-Fixture-<token>` directory created under an explicit base (default `D:\Projects`). Created and removed only by the reviewed fixture module, and removed only after its ownership marker proves the harness created it. |
| Forbidden locations | Real documents, Desktop, Downloads, OneDrive, any source repository, any network or removable share |
| Toolchain | `python`, `node`, `npm`, `uv`, `git` on `PATH` |
| Repository | Clean working tree at a known commit (the verifier records the SHA and flags a dirty tree) |

**Never run acceptance against real user data.** Containment is enforced by the
fixture module, not by string comparison: a sibling such as
`D:\Projects\AETHER-Phase2-Fixture-Other` is *outside* the base and is refused.
A pre-existing directory is never adopted, reused or deleted.

## 2. Running it

```powershell
cd <repo>
powershell -File .\scripts\verify_phase2.ps1
```

Useful switches:

| Switch | Effect |
|---|---|
| `-Base <path>` | Override the fixture base directory (default `D:\Projects`); the fixture itself is created as `AETHER-Phase2-Fixture-<token>` under it by the fixture module |
| `-EvidenceRoot <path>` | Where sanitized evidence is written (default `.cache\phase2-evidence`) |
| `-SkipDesktop` | Skip desktop gates — records them as `NOT VERIFIED`, never as `PASS` |
| `-SkipBackend` | Skip backend gates — likewise `NOT VERIFIED` |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every recorded item `PASS` |
| `1` | At least one `FAIL` |
| `2` | No failures, but at least one item `NOT VERIFIED` — **Phase 2 is incomplete** |

## 3. What the verifier does

1. **Environment** — asserts Windows 11, non-elevated account, records git SHA,
   Python, Node and `uv` versions, and flags a dirty working tree.
2. **Fixture containment** — first exercises a *negative control* proving the
   containment rule refuses a sibling prefix path, then creates a fresh uniquely
   named fixture and writes a synthetic project (`README.md`, `src\module.py`).
3. **Backend gates** — `uv sync --locked`, `ruff check`, `ruff format --check`,
   strict `mypy`, the full `pytest` suite, and the Phase 2B/2C/2D/persistence
   suites individually.
4. **Desktop gates** — lint, typecheck, Node tests, Python security tests, and an
   Electron build. Skips are recorded as `NOT VERIFIED`.
5. **Native Windows behaviour** — behaviours that *cannot* be inferred from the
   Linux test run:
   - a directory junction is refused by the reparse-point check;
   - the Undo Vault key file is created **outside** the vault directory and an
     owner-only, non-inherited DACL is read back from the OS for both the key and
     the vault directories (S14-5; the verifier fails the gate if the key sits
     inside the vault or the DACL is not protected);
   - a second store instance cannot open the same database (owner lock);
   - the volume identity prefix is the Windows form.
6. **Evidence** — writes sanitized JSON and Markdown under the evidence root and
   prints the paths.

## 4. What the verifier cannot do

The script itself records these as `NOT VERIFIED` on every run, so its own
output can never be mistaken for acceptance. They require a human demonstration:

- a **real** approval gesture in the running Electron UI (the automated tests
  exercise the chain programmatically, not through a human clicking);
- that approving patch **A** cannot cause patch **B** to be applied;
- refusal before approval and application only after approval, live;
- grant denial for forged, expired, revoked, exhausted and replayed grants
  against the real ledger;
- receipts surviving a real application restart;
- undo restoring the exact original and refusing to overwrite a newer edit;
- an **actual interruption** (power loss, process kill, forced unmount) between
  replacement and receipt — the automated test simulates the crash in-process;
- zero unauthorized mutation and zero unauthorized disclosure across the run;
- no cloud traffic, by observing the machine rather than asserting it in a test;
- the Undo Vault key ACL reviewed on NTFS.

Because these are always present, a fully successful automated run still exits
**2**, never `0`. There is no configuration in which this script prints PASS for
Phase 2 as a whole.

## 5. Sanitization rules

Evidence files may contain: requirement names, pass/fail/skip, exit codes,
git SHA, tool versions, OS caption, and fixture paths.

Evidence files must **never** contain: environment variable dumps, tokens, keys,
credentials, file contents beyond fixture hashes, user directory listings, or
anything from outside the fixture root.

The verifier writes only what it prints in the requirement table, so anything
sensitive must never be passed to `Add-Result`.

## 6. Requirements → results matrix

Fill this in during the acceptance pass. Copy the table structure; do not
pre-fill results.

| # | Directive requirement | Code | Test / evidence | Windows result |
|---|---|---|---|---|
| 1 | Open a registered project | `core/fs/session.py` `open` | `test_01_open_a_registered_project` | |
| 2 | Search and read an allowed file | `core/fs/search.py`, `content.py` | `test_02_search_and_read_an_allowed_file` | |
| 3 | Refuse a read outside allowed roots | `core/resources/registry.py` | `test_03_refuse_a_read_outside_the_allowed_roots` | |
| 4 | Refuse sensitive files without permission | `registry.py`, `content.py` | `test_04_refuse_sensitive_files_without_specific_permission` | |
| 5 | Deny junction/symlink escape | `core/resources/path_safety.py` | `test_05_deny_symlink_and_junction_escape`; native probe | |
| 6 | Show the exact patch before an edit | `core/planning/preview_authority.py` | `test_06_show_the_exact_patch_before_an_edit` | |
| 7 | Refuse mutation before approval | `core/grants/attestation.py` | `test_07_refuse_mutation_before_explicit_trusted_approval` | |
| 8 | Apply the edit and compare bytes | `core/edits/executor.py` | `test_08_apply_approved_edit_and_compare_exact_bytes` | |
| 9 | Refuse after post-preview modification | `core/edits/executor.py` | `test_09_refuse_stale_authorization_after_a_later_edit` | |
| 10 | Reject forged/expired/revoked/exhausted/replayed grants | `core/start.py`, `grants/` | `test_10_*` (7 cases), `test_phase2b_trusted_approval.py` | |
| 11 | Consumption binds the exact action | `grants/authority.py` | `test_11_grant_binding_is_checked_against_the_exact_action` | |
| 12 | Receipts survive a restart | `core/edits/receipts.py` | `test_12_receipts_persist_across_a_restart` | |
| 13 | Undo restores the exact original | `core/vault/undo_vault.py` | `test_13_undo_restores_the_exact_original` | |
| 14 | Refuse silent overwrite of a newer edit | `edits/executor.py` `undo` | `test_14_refuse_silent_overwrite_of_a_newer_user_edit` | |
| 15 | Truthful crash/cancel recovery | `edits/executor.py` (UNVERIFIED) | `test_15_crash_between_replace_and_verification_is_unverified` | |
| 16 | T3 / shell / unsupported denied | `policy/broker.py`, `fs/executor.py` | `test_16_t3_shell_and_unsupported_paths_stay_denied` | |
| 17 | Zero unauthorized mutation | whole stack | `test_17_no_unauthorized_mutation_occurred` | |
| 18 | Offline, no unauthorized cloud traffic | no network client imported | `test_18_no_network_access_during_operations`, observe the machine | |

## 7. Recording the result

Copy `phase2-windows-<stamp>.md` into the acceptance report with the matrix
above filled in, and record each human-required demonstration alongside it with
what was actually observed. Any `FAIL` blocks the phase. Any `NOT VERIFIED`
blocks the phase. There is no "mostly passed", and a green script is not a
substitute for the human evidence.

The person performing acceptance signs the result with: date, machine identity,
git SHA, and their own statement of what they observed with their own eyes
(as distinct from what the script asserted).

---

## 8. Evidence matrix (post-merge reconciliation, 2026-11-23)

Reconciled against merged `main` (`a58bd68`, via PR #34), the automated
results at verified commit `bf08ca9`, and the user-reported native Windows
run. Statuses distinguish four evidence classes: **automated** (test-suite
results), **native Windows** (executed on the target OS), **human
demonstration** (a person operating the shipped application), and the
**final verdict**, which is `PASS` only when every required class is
present. User-reported Windows results have no archived logs in this
repository; they are marked "reported" and do not by themselves satisfy a
verdict.

**Production-wiring fact that bounds several scenarios:** production grant
issuance remains disabled (`GRANT_ISSUANCE_DISABLED`,
`NullAttestationVerifier`, `IssuanceDisabledConsumptionLedger` default).
The final integration (branch `integration/phase2-final-live-workflow`,
see `PHASE2_LIVE_WORKFLOW.md`) now wires a live mutation path into the
running service and the desktop, but it is gated twice: on the shipped
schema v1 the mutation tier is absent (`schema_activation_pending`), and
on schema v2 the production issuer still refuses
(`grant_issuance_disabled`). Scenarios whose *live* form requires issuing
a real grant or mutating a real file therefore remain **blocked as
acceptance demonstrations** until schema activation and production
issuance are enabled by separately approved changes. They must not be
"demonstrated" by bypassing those controls.

| # | Scenario (expected behaviour) | Implementation / test files | Automated | Native Windows evidence | Human demonstration | Final verdict |
|---|---|---|---|---|---|---|
| 1 | Open a registered project; bounded access only | `core/fs/session.py`; `test_phase2_end_to_end.py::test_01_*`, `test_phase2c_session.py` | PASS (Linux 847-suite) | Reported PASS (full suite, Win 3.12.10; logs not archived) | Required — open the shipped app on a registered project | **NOT VERIFIED** |
| 2 | Search + read an allowed file | `core/fs/search.py`, `content.py`; `test_02_*` | PASS | Reported PASS (as above) | Required — live search/read in the app | **NOT VERIFIED** |
| 3 | Refuse reads outside authorized roots | `core/resources/registry.py`; `test_03_*` | PASS | Reported PASS | Required — attempt an outside-root read live | **NOT VERIFIED** |
| 4 | Refuse `.env`/sensitive files without authorization | `registry.py`, `fs/content.py`; `test_04_*` | PASS | Reported PASS | Required — live refusal observation | **NOT VERIFIED** |
| 5 | Deny junction/symlink (reparse-point) escape | `core/resources/path_safety.py`; `test_05_*` (symlink on Linux); native junction probe in verifier step 5 | PASS (symlink); junction NTFS-only | Junction probe is part of `verify_phase2.ps1`; execution/archived output not in repo | Required — create a junction on NTFS and observe refusal | **NOT VERIFIED** |
| 6 | Human-visible exact patch preview before approval | `core/planning/preview_authority.py`, `planning/exact_diff.py` (aether-diff-v2 EOF trailer), `apps/desktop/src/ApprovalReviewSurface.tsx`; `test_06_*`, desktop CRLF/EOF tests | PASS | Desktop suite reported PASS on Windows | Required — a human reads the exact diff (incl. CRLF/EOF summary) in the real UI | **NOT VERIFIED** |
| 7 | Refuse mutation before approval | `core/grants/attestation.py`; `test_07_*` | PASS | Reported PASS | Required live — but **blocked**: production grant issuance disabled, no live mutation path; refusal is the only live-observable half | **NOT VERIFIED** (live demo blocked) |
| 8 | Apply the exact approved edit; hash matches | `core/edits/executor.py`; `test_08_*`, `test_phase2_approved_bytes.py`, `test_phase2d_edits.py` | PASS | Reported PASS | Required live — **blocked** as #7 | **NOT VERIFIED** (live demo blocked) |
| 9 | Refuse stale approval after post-preview modification | `edits/executor.py`; `test_09_*` | PASS | Reported PASS | Required live — **blocked** as #7 | **NOT VERIFIED** (live demo blocked) |
| 10 | Reject forged/expired/revoked/exhausted/replayed grants | `core/grants/*`, `planning/authorizing_gesture.py`; `test_10_*` (7 cases), `test_phase2b_stage4_grants.py`, `test_phase2_authoritative_consumption.py` | PASS | Reported PASS | Required against the real ledger — **blocked** for live issuance as #7 | **NOT VERIFIED** (live demo blocked) |
| 11 | Consumption binds the exact action | `grants/authority.py`, `grants/consumption.py`; `test_11_*` | PASS | Reported PASS | Required live — **blocked** as #7 | **NOT VERIFIED** (live demo blocked) |
| 12 | Receipts durable across restart | `core/edits/receipts.py`; `test_12_*` | PASS | Reported PASS | Required — real application restart with receipts re-read | **NOT VERIFIED** |
| 13 | Undo restores the exact original bytes | `core/vault/undo_vault.py`, `edits/executor.py` undo; `test_13_*`, `test_phase2_undo_authorization.py` | PASS | Reported PASS | Required live — **blocked** as #7 | **NOT VERIFIED** (live demo blocked) |
| 14 | Undo refuses silent overwrite of a newer edit | `edits/executor.py` undo; `test_14_*` | PASS | Reported PASS | Required live — **blocked** as #7 | **NOT VERIFIED** (live demo blocked) |
| 15 | Truthful crash/cancel recovery (UNVERIFIED, never false success) | `edits/executor.py`, `edits/journal.py`; `test_15_*` (simulated kill, re-opened from disk) | PASS (simulated) | No real interruption performed | Required — a genuine interruption (kill/power) on Windows; simulation does not satisfy this | **NOT VERIFIED** |
| 16 | T3/shell/unsupported capabilities denied | `core/policy/broker.py`, `fs/executor.py`; `test_16_*` | PASS | Reported PASS | Required — live denial observation in the app | **NOT VERIFIED** |
| 17 | Zero unauthorized mutation across the run | whole stack; `test_17_*` | PASS | Not observed on a live machine | Required — observed across the acceptance run (fixture hashes before/after) | **NOT VERIFIED** |
| 18 | Offline; zero unauthorized outbound disclosure | no network client in Phase 2 packages; `test_18_*` | PASS (code-level) | Not observed on a live machine | Required — observed offline behaviour on the machine, not inferred from tests | **NOT VERIFIED** |

**Summary:** 18/18 implemented; 18/18 automated PASS on Linux at `bf08ca9`
(user-reported PASS on native Windows, unarchived); 0/18 formally accepted.
Every scenario still lacks at least one required evidence class — archived
native Windows evidence, a human demonstration, a genuine interruption, or
a supported live workflow for the presently disabled mutation path.
**Formal Phase 2 acceptance remains NOT COMPLETE.**

---

## 9. Live-workflow addendum (final integration, 2026-11-24)

The live workflow is now implemented and wired (channel `LiveBridge`,
trusted composition root, main-process native-confirmation approval) and
is exercised end to end in automated tests
(`test_phase2_live_workflow.py`, `test_phase2_live_adversarial.py`,
desktop `live-approval.test.ts`) — including edit → receipt → undo under
the test-scoped ledger configuration. It changes no verdict above:

- the shipped configuration still cannot authorize or mutate
  (`schema_activation_pending` on v1, `grant_issuance_disabled` on v2 —
  both asserted by automated tests against the production classes);
- schema v2 activation and production issuance enablement are separate,
  not-yet-approved proposals (`PHASE2_LIVE_WORKFLOW.md` §5);
- once — and only once — those are approved, §6 of
  `PHASE2_LIVE_WORKFLOW.md` defines the human demonstration procedure
  for the presently blocked scenarios (6–15, 17, 18) on this machine.

**Formal Phase 2 acceptance remains NOT COMPLETE.**
