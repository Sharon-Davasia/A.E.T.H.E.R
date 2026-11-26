# Phase 2 native interruption test procedure (reviewable)

Status: **procedure prepared, NOT executed**. Applies to merged main
`14614dcf99c79477dec36e1c25e10e17397cf763`. Formal Phase 2 acceptance
remains NOT COMPLETE and unwaived. Nothing in this document changes
any acceptance status; executing it provides native evidence for
independent review only.

## Purpose

Demonstrate, on the owner's Windows machine, that killing the AETHER
process after a genuine approved filesystem edit mutates an isolated
synthetic file but before the verified receipt is persisted results
in truthful UNVERIFIED/reconciliation on restart — never a silent
success, never automatic replay of the mutation.

## Hard constraints

- Run only on `main` at exactly
  `14614dcf99c79477dec36e1c25e10e17397cf763`, clean tree,
  non-admin PowerShell 5.1 at `D:\A.E.T.H.E.R`.
- Use ONLY isolated synthetic data created for this test (a fresh
  dedicated test directory below the test scratch area). Never point
  the edit at any real-user document or directory.
- The edit must be a genuine approved execution through the normal
  approval flow. **Do not manually insert, edit, or fabricate a
  journal intent** (no direct SQLite writes, no synthetic journal
  rows, no state files edited by hand) as a substitute for an
  approved execution.
- Terminate only the AETHER test process identified ahead of time
  (child/test server process). Never terminate unrelated owner
  processes.
- No elevation, no execution-policy bypass, no Developer Mode, no
  WSL, no new worktrees, no dependency installs for this procedure.
- Never run the historical combined Phase 2 verifier.
- No automatic cleanup: preserve the synthetic file, journal, and
  receipts untouched for inspection after the run.

## Preparation

1. Verify `git rev-parse HEAD` prints the merged-main SHA above and
   `git status --porcelain` is empty.
2. Run the automated gates (these are Linux-evidence-free native
   prerequisites, expected to already pass):
   - `python -m pytest backend/tests -q`
   - `python -m ruff check backend`
   - `mypy` (from `backend/`)
3. Create an isolated synthetic dataset: one small text file with
   known content and hash (record both), inside a fresh directory
   reserved exclusively for this test.
4. Start the application normally (ordinary startup; no Phase 3
   authorization or enablement involved). Note the process ID of the
   AETHER test process you will terminate.

## Execution

5. Through the normal UI/approval flow, approve and execute one
   filesystem edit on the isolated synthetic file (e.g. append one
   line). A genuine approved execution only.
6. At the moment the synthetic file's content has changed on disk
   (mutation applied) but before the verified receipt is persisted,
   terminate the AETHER test process from step 4 (e.g.
   `Stop-Process -Id <pid>`). If exact timing cannot be achieved,
   record that outcome honestly and repeat the attempt; do not
   simulate the interruption any other way.
7. Verify on disk: the synthetic file contains the mutation; the
   persisted receipt set does NOT claim a verified success for the
   interrupted edit (record journal/task state exactly as found).
8. Restart the application normally against the same isolated
   storage.

## Expected result (acceptance-correct behavior)

9. On startup, recovery/reconciliation reports the interrupted edit
   as `COMPLETED_UNVERIFIED` / needing review (the file bytes are
   checked against journal evidence; nothing is reported as a
   verified success).
10. The mutation is **not automatically replayed**: the synthetic
    file's hash after restart equals the hash recorded in step 7
    (single mutation, no duplicate append, no revert either).
11. The only path to resolution is an owner-visible review action
    (accept the observed state or explicitly undo via the normal
    flow). Record the reconciliation output verbatim.

## Evidence to record

- Git SHA, process IDs, timestamps.
- Synthetic file hash before edit, after kill, and after restart.
- Journal entries and task states before kill and after restart
  (queried read-only; never modified by hand).
- Reconciliation report output and final resolution action.

## Non-goals / prohibitions

- No journal fabrication, no direct database edits, no manual state
  repair of any kind.
- No change to formal Phase 2 acceptance status, no Phase 3
  activation, no real-user data.
- If any step cannot be performed exactly as written, stop and
  report; do not improvise a weaker substitute.
