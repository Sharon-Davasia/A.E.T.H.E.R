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

## Runnable harness (deterministic; no manual timing)

Ordinary startup disables mutation, so this procedure is executed
by the standalone harness in
`backend/tests/test_phase2_interruption_harness.py`. It uses the
controlled fixture activation of the Phase 2 acceptance suite
(test-scoped consumption ledger with an explicit budget, persisted
plan with the canonical approval binding, trusted gesture
signature) over an isolated synthetic project, performs a genuine
approved edit through `EditExecutor.apply`, and terminates the
test child from the executor's own `"replaced"` checkpoint —
after the atomic file replacement and the journal's
REPLACED_UNVERIFIED record, before readback verification and
before any verified receipt is persisted. It then restarts over
the same durable files and asserts the reconciliation verdict and
the absence of replay. No journal entry is fabricated and no
timing is manual.

Exact commands (non-admin PowerShell 5.1, repository root
`D:\A.E.T.H.E.R`, HEAD verified first):

```powershell
git rev-parse HEAD   # expect 14614dcf99c79477dec36e1c25e10e17397cf763 on main
git status --porcelain   # expect empty
python -m pytest backend/tests/test_phase2_interruption_harness.py -q
```

Expected: both tests pass — the control run completes a genuine
verified edit (`SUCCEEDED`), and the killed run exits with the
harness kill code, leaves the post-image on disk exactly once,
persists no verified receipt, reconciles on restart as
`COMPLETED_UNVERIFIED` (needs review), and does not replay.

Optional standalone child invocation (what the harness spawns):

```powershell
$env:PYTHONPATH = "backend;backend/tests"
python backend/tests/test_phase2_interruption_harness.py control <isolated-workspace>
python backend/tests/test_phase2_interruption_harness.py kill <isolated-workspace>
```

## Expected result (acceptance-correct behavior)

1. Recovery/reconciliation reports the interrupted edit as
   `COMPLETED_UNVERIFIED` / needing review (the file bytes are
   checked against journal evidence; nothing is reported as a
   verified success).
2. The mutation is **not automatically replayed**: the synthetic
   file's hash after restart equals the hash recorded at the kill
   (single mutation, no duplicate append, no revert either).
3. The only path to resolution is an owner-visible review action
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
