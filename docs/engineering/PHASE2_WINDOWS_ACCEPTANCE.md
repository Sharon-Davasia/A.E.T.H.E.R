# Phase 2 — Windows Acceptance Procedure

**Audience:** the engineer running the acceptance pass on the target Windows 11 laptop.
**Status authority:** this document defines *how* Phase 2 is accepted. It does not
assert that it has been. Results are recorded in `PHASE2_ACCEPTANCE_REPORT.md`.

A Phase 2 claim is only valid when every **mandatory** item below is `PASS`.
`NOT VERIFIED` is not a soft pass: while any mandatory item is `NOT VERIFIED`,
Phase 2 is **incomplete** and must not be announced as complete.

---

## 1. Preconditions

| Requirement | Detail |
|---|---|
| Operating system | Windows 11, fully patched, NTFS system volume |
| Account | **Normal user.** No elevation. The verifier refuses to run elevated. |
| Fixture location | `D:\Projects\AETHER-Phase2-Fixture` — disposable, created and destroyed by the verifier |
| Forbidden locations | Real documents, Desktop, Downloads, OneDrive, any source repository, any network or removable share |
| Toolchain | `python`, `node`, `npm`, `uv`, `git` on `PATH` |
| Repository | Clean working tree at a known commit (the verifier records the SHA and flags a dirty tree) |

**Never run acceptance against real user data.** The verifier hard-fails unless
the fixture root is under `D:\Projects\AETHER-Phase2-Fixture`.

## 2. Running it

```powershell
cd <repo>
powershell -ExecutionPolicy Bypass -File .\scripts\verify_phase2.ps1
```

Useful switches:

| Switch | Effect |
|---|---|
| `-FixtureRoot <path>` | Override the fixture root (must remain under `D:\Projects\AETHER-Phase2-Fixture`) |
| `-EvidenceRoot <path>` | Where sanitized evidence is written (default `.cache\phase2-evidence`) |
| `-SkipDesktop` | Skip desktop gates — records them as `NOT VERIFIED`, never as `PASS` |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every recorded item `PASS` |
| `1` | At least one `FAIL` |
| `2` | No failures, but at least one item `NOT VERIFIED` — **Phase 2 is incomplete** |

## 3. What the verifier does

1. **Environment** — asserts Windows 11, non-elevated account, records git SHA,
   Python, Node and `uv` versions, and flags a dirty working tree.
2. **Fixture containment** — refuses to run outside the disposable fixture root,
   then builds a synthetic project (`README.md`, `src\module.py`).
3. **Backend gates** — `uv sync --locked`, `ruff check`, `ruff format --check`,
   strict `mypy`, the full `pytest` suite, and the Phase 2B/2C/2D/persistence
   suites individually.
4. **Desktop gates** — lint, typecheck, Node tests, Python security tests, and an
   Electron build. Skips are recorded as `NOT VERIFIED`.
5. **Native Windows behaviour** — behaviours that *cannot* be inferred from the
   Linux test run:
   - a directory junction is refused by the reparse-point check;
   - the Undo Vault key file is created and its ACL is owner-only;
   - a second store instance cannot open the same database (owner lock);
   - the volume identity prefix is the Windows form.
6. **Evidence** — writes sanitized JSON and Markdown under the evidence root and
   prints the paths.

## 4. What the verifier cannot do

These must be performed and evidenced by a human, and remain `NOT VERIFIED`
until then:

- a **real** approval gesture in the running Electron UI (the verifier exercises
  the chain programmatically, not through a human clicking);
- an **actual interruption** (power loss, process kill, forced unmount) during a
  write — the automated test simulates the crash in-process;
- a real `D:\Projects` demo performed on your own checkout with your own eyes on
  the preview;
- confirming that no cloud traffic occurred, by observing the machine rather
  than by asserting it in a test.

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
above filled in. Any `FAIL` blocks the phase. Any `NOT VERIFIED` blocks the
phase. There is no "mostly passed".

The person performing acceptance signs the result with: date, machine identity,
git SHA, and their own statement of what they observed with their own eyes
(as distinct from what the script asserted).
