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

## 8. Evidence matrix (final-integration closeout)

Consolidated against PR #36 at the native-tested implementation head
`35f9bb0e344441ed86878b6b22e8b9d8765de5d8` (closeout commits after it
are documentation and renderer-copy only). Evidence classes are kept
deliberately separate and never merged into a claim stronger than
their source:

- **Source-reviewed** — implementation inspected in review (PR #36).
- **Automated** — test suites on Linux (Python 3.11.2) at the closeout
  head: backend 955 passed / 7 skipped; desktop 126 passed.
- **Native automated** — the same gates executed on the target
  Windows machine (Python 3.12.10): owner-confirmed PASS.
- **Owner-confirmed native demonstration** — a person operating the
  shipped application on the target machine, confirmed by the
  repository owner. The underlying artifacts (evidence directory
  `D:\AETHER-A-Evidence-5b02b5d18c3c4e649c469a7920b63c6a`, including
  the original successful edit receipt
  `9900df8e-9157-43a3-85b0-0e7d0d5203e2`) are held by the owner and are
  **not archived in this repository**; confirmation is recorded here
  as owner-reported evidence, not as archived evidence.
- **Unverified** — no evidence of the required class exists yet.

**Production-wiring fact (current):** schema v2 is active for the
controlled candidate; production grant issuance is enabled *only*
for validated acceptance-fixture launches, bounded to the designated
fixture project subtree (`Activation B`). Ordinary application
launches refuse issuance (`grant_issuance_disabled`) and execution
(`mutation_not_enabled`). Fixture-only mutation, the combined
verifier safety warning and the real-data migration restriction
remain in force.

A final verdict of `PASS` requires every required class, archived.
Owner confirmation without archived artifacts therefore leaves the
verdict **NOT VERIFIED (evidence not archived)** — a bookkeeping
state, not a doubt about the reported observation.

| # | Scenario (expected behaviour) | Automated (Linux) | Native automated (Windows) | Owner-confirmed native demonstration | Final verdict |
|---|---|---|---|---|---|
| 1 | Open a registered project; bounded access only | PASS | PASS (owner-confirmed) | Confirmed — registration and Explorer opening | **NOT VERIFIED** (evidence not archived) |
| 2 | Search + read an allowed file | PASS | PASS (owner-confirmed) | Confirmed — reading and search | **NOT VERIFIED** (evidence not archived) |
| 3 | Refuse reads/registrations outside authorized roots | PASS | PASS (owner-confirmed) | Confirmed — fixture root, storage and outside registration refusals; path traversal refusals | **NOT VERIFIED** (evidence not archived) |
| 4 | Refuse `.env`/sensitive files without authorization | PASS | PASS (owner-confirmed) | Confirmed — secret-file protection observed | **NOT VERIFIED** (evidence not archived) |
| 5 | Deny junction/symlink (reparse-point) escape | PASS | PASS (owner-confirmed; junction variant runs without elevation) | Not separately demonstrated live | **NOT VERIFIED** |
| 6 | Human-visible exact patch preview before approval | PASS | PASS (owner-confirmed) | Confirmed — trusted approval window, acknowledgement gating, CRLF/EOF and long-line scrolling, cancellation incl. Escape | **NOT VERIFIED** (evidence not archived) |
| 7 | Refuse mutation before approval | PASS | PASS (owner-confirmed) | Confirmed — no mutation before approval; cancellations signed nothing (fixture hashes unchanged) | **NOT VERIFIED** (evidence not archived) |
| 8 | Apply the exact approved edit; hash matches | PASS | PASS (owner-confirmed) | Confirmed — actual explicitly approved edit; original receipt `9900df8e-9157-43a3-85b0-0e7d0d5203e2` | **NOT VERIFIED** (evidence not archived) |
| 9 | Refuse stale approval after post-preview modification | PASS | PASS (owner-confirmed) | Confirmed — stale-plan invalidation and stale approval rejection preserving externally modified content | **NOT VERIFIED** (evidence not archived) |
| 10 | Reject forged/expired/revoked/exhausted/replayed grants | PASS | PASS (owner-confirmed) | Not demonstrated live against the fixture ledger | **NOT VERIFIED** |
| 11 | Consumption binds the exact action | PASS | PASS (owner-confirmed) | Not demonstrated live | **NOT VERIFIED** |
| 12 | Receipts durable across restart | PASS | PASS (owner-confirmed) | Confirmed — receipt retrieved across application restart | **NOT VERIFIED** (evidence not archived) |
| 13 | Undo restores the exact original bytes | PASS | PASS (owner-confirmed) | Confirmed — separately approved Undo; all six original fixture SHA-256 hashes restored | **NOT VERIFIED** (evidence not archived) |
| 14 | Undo refuses silent overwrite of a newer edit | PASS | PASS (owner-confirmed) | Confirmed — Undo conflict rejection | **NOT VERIFIED** (evidence not archived) |
| 15 | Truthful crash/cancel recovery (UNVERIFIED, never false success) | PASS (simulated) | No genuine interruption performed | Not demonstrated — simulation does not satisfy this scenario | **NOT VERIFIED** |
| 16 | T3/shell/unsupported capabilities denied | PASS | PASS (owner-confirmed) | Confirmed — absence of arbitrary shell execution | **NOT VERIFIED** (evidence not archived) |
| 17 | Zero unauthorized mutation across the run | PASS | PASS (owner-confirmed) | Confirmed — all six fixture files verified by SHA-256 across the campaign | **NOT VERIFIED** (evidence not archived) |
| 18 | Offline; zero unauthorized outbound disclosure | PASS (code-level) | Not observed live | Not demonstrated — must be observed on the machine, not inferred | **NOT VERIFIED** |

**Summary:** 18/18 implemented and source-reviewed; 18/18 automated
PASS (Linux at closeout head; native Windows gates owner-confirmed
PASS at `35f9bb0`); owner-confirmed native demonstrations for
scenarios 1–4, 6–9, 12–14, 16, 17; **0/18 formally accepted** —
archived evidence and the §10 closeout items remain outstanding.
**Formal Phase 2 acceptance remains NOT COMPLETE.**

---

## 9. Live-workflow addendum (superseded by §8 closeout)

The live workflow (Activation A schema v2 + controlled Activation B
production-trusted issuance for the disposable fixture) is implemented
in PR #36 and natively demonstrated as recorded in §8. The earlier
statement that activation proposals were "not yet approved" is
superseded: both were separately authorized and implemented for the
controlled candidate, with ordinary launches remaining
issuance/execution-disabled. **Formal Phase 2 acceptance remains NOT
COMPLETE.**

---

## 10. Final closeout checklist (remaining mandatory evidence — finite)

Implementation and owner-confirmed demonstrations are complete. The
following, and only the following, remain before formal acceptance
can be declared under §7. No new test cycles are required beyond
these items; existing native automated evidence is reused wherever
the procedure permits.

- [ ] Archive the owner-held native evidence (evidence directory
      `D:\AETHER-A-Evidence-5b02b5d18c3c4e649c469a7920b63c6a`,
      including receipt `9900df8e-9157-43a3-85b0-0e7d0d5203e2` and the
      fixture SHA-256 comparisons) into the repository or an
      owner-signed evidence bundle naming head `35f9bb0`.
- [ ] Record machine identity, Windows OS/build and NTFS details for
      the acceptance machine alongside the archived evidence.
- [ ] Scenario 5: human junction-escape demonstration on NTFS with
      archived output (native automated junction coverage already
      passes without elevation).
- [ ] Scenarios 10–11: live demonstration against the fixture ledger
      (forged/replayed authorization refusal; single-use exact-action
      consumption), or an explicit owner acceptance, recorded per §7,
      of the existing native automated evidence for these scenarios.
- [ ] Scenario 15: one genuine interruption (process kill during an
      approved execution) on Windows, with the resulting UNVERIFIED /
      reconciliation outcome recorded.
- [ ] Scenario 18: offline observation on the acceptance machine
      (no network route; no outbound disclosure), recorded.
- [ ] Owner visual confirmation of the corrected desktop footer text
      (controlled fixture activation vs ordinary-mode denial) in the
      merged build — copy-only change after `35f9bb0`.
- [ ] §7 sign-off: date, machine identity, git SHA (merged head), and
      the owner's own statement of what was personally observed; only
      then may the matrix verdicts be advanced to PASS.

Until every box is checked: **Formal Phase 2 acceptance: NOT
COMPLETE.** Merging PR #36 as a controlled integration checkpoint
does not change that verdict and does not authorize real-data
migration, general mutation enablement, or Phase 3.
