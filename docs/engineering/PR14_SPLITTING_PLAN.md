# PR #14 — Splitting Plan

**Branch:** `arena/9ff5f05b-a-e-t-h-e-r` (base `main` @ `02dff4b`)
**PR:** #14, open, **not merged**, no auto-merge requested
**Scope constraint honoured:** nothing was reverted, reset, force-pushed, deleted or
merged. The branch history is intact and additive.

> Heads-up on figures: every count in this document was produced by running the
> suite, in the environment named beside it. Numbers from earlier revisions of this
> document (589, 655, 709) are superseded and deliberately not carried forward.

---

## 1. Why PR #14 should not land as one review unit

PR #14 carries ten commits across four security boundaries plus two large
pre-existing workstream commits. A reviewer approving it is simultaneously
approving a schema migration, a capability taxonomy, an approval chain, byte-exact
edit binding, grant consumption, undo authorization, a mutation journal, vault key
storage, an ACL verifier and a rewritten Windows acceptance script. Those are
separable decisions with different blast radii, and several are exactly the
"security boundary changes" that standing review rules require to be split.

---

## 2. Proposed review units

Ordered. Each row is one PR. "Depends on" must merge first.

| # | PR | Commit(s) | Files | Depends on |
|---|---|---|---|---|
| A | **Schema-v2 migration, inactive** | `2b60708` | `persistence/sqlite_store.py`, `0002_*.sql`, `stage4_support.py`, `test_phase2b_persistence.py`, `test_phase2b_stage4_migration.py`, `docs/engineering/PHASE2B_STAGE4_*.md`, `STATUS.md`, `TRUST_BOUNDARIES.md` | – (base) |
| B | **Phase 2B–E workstreams** | `470fea9` | `core/fs/*`, `core/edits/*`, `core/planning/*`, `core/vault/*`, `channel/*`, `broker.py`, `registry.py`, `review_contract.py`, `pyproject.toml`, docs | A |
| C | **S14-6 — verifier safety** | `1b2f9c8` | `core/acceptance/fixture_safety.py`, `fs/session.py`, `test_phase2_fixture_safety.py`, `test_phase2c_session.py`, `verify_phase2.ps1`, `PHASE2_WINDOWS_ACCEPTANCE.md` | B |
| D | **S14-5 — vault key + Windows ACL** | `fef5592` | `core/security/file_permissions.py`, `vault/undo_vault.py`, `test_phase2_vault_key_protection.py`, `verify_phase2.ps1`, `PHASE2_WINDOWS_ACCEPTANCE.md` | C — **and it must stay in the chain**: PR L builds on `file_permissions.py`, which D creates |
| E | **S14-1 — approved byte binding** | `36a4063` | `exact_diff.py`, `edit_binding.py`, `planner.py`, `edits/executor.py`, `test_phase2_approved_bytes.py`, 3 adapted suites | C |
| F | **S14-2 — grant consumption** | `fb58b49` | `grants/consumption.py`, `edits/executor.py`, `tests/fs_support.py`, `stage4_support.py`, `test_phase2_grant_consumption.py`, 3 adapted suites | E |
| G | **S14-3 — undo authorization** | `ac0f39c` | `policy/capabilities.py`, `planner.py`, `edits/executor.py`, `test_phase2_undo_authorization.py`, 2 adapted suites | F |
| H | **S14-4 — mutation journal** | `e75264b` | `edits/journal.py`, `edits/reconcile.py`, `edits/executor.py`, `test_phase2_mutation_journal.py` | G |
| I | **S14-7 — single grant authority** | `58e271a` | `grants/consumption.py`, `tests/fs_support.py`, `test_phase2_grant_authority.py`, `test_phase2_grant_consumption.py`, `test_phase2d_edits.py` | H |
| J | **S14-8 — orphan consumption** | `e399099` | `edits/journal.py`, `edits/reconcile.py`, `test_phase2_orphan_consumption.py` | I |
| K | **S14-9 — operation state + mandatory journal** | `f5ab233` | `edits/executor.py`, `edits/journal.py`, `test_phase2_execution_context.py`, 6 adapted suites | J |
| L | **S14-10 — exact Windows ACL** | `a65460c` | `core/security/file_permissions.py`, `test_phase2_windows_acl.py`, `verify_phase2.ps1` | K **and** D — `file_permissions.py` is *created by D*, so L cannot apply to `main` alone |
| M | **Acceptance report** | `9a1334f`, *pending* | `PHASE2_ACCEPTANCE_REPORT.md`, `.gitignore` | L |

---

## 3. Measured dependencies

Measured by cherry-picking onto a scratch worktree; the conflicts are real, not
predicted.

| Applied onto `1b2f9c8` | Result |
|---|---|
| `fef5592` (S14-5) | **clean** |
| `36a4063` (S14-1) | **clean** |
| `fb58b49` (S14-2) | conflict — `executor.py`, `test_phase2_approved_bytes.py`, `test_phase2_end_to_end.py` |
| `ac0f39c` (S14-3) | conflict — `executor.py`, `planner.py`, `test_phase2_end_to_end.py` |
| `e75264b` (S14-4) | conflict — `executor.py` |
| `36a4063 → fb58b49` | **clean** |
| `36a4063 → fb58b49 → ac0f39c` | **clean** |
| `36a4063 → fb58b49 → ac0f39c → e75264b` | **clean** |

Every S14 commit from **S14-2 onward** edits `backend/aether/core/edits/executor.py`
in overlapping regions, so **E → L is a strict chain**. Do not reorder the chain:
the conflicts sit in the authorization and mutation core, where a hand-resolved
split would risk changing security behaviour for a reviewer's convenience.

#### D is *not* independent — it is a chain link (corrected)

An earlier revision of this plan called D (S14-5, `fef5592`) "C only, verified
clean" and branched it off C as a dead end. Both statements are true and
insufficient: `fef5592` applies cleanly onto C, **and** it *creates*
`backend/aether/core/security/file_permissions.py`, which L (S14-10, `a65460c`)
then modifies by 263 lines. A branch that has D but never feeds L, alongside an L
that never sees D, produces a PR L that cannot apply:

```
$ git worktree add /tmp/wt-Lsolo 02dff4b
$ git apply --check <L.patch>
error: backend/aether/core/security/file_permissions.py: No such file or directory
error: scripts/verify_phase2.ps1: No such file or directory
```

**Measured correction.** D is carried *inline* in the E→L chain, immediately after
C, which is where history already has it (`fef5592` sits between `e75264b` and
`9a1334f`). Cherry-picking the whole sequence onto `1b2f9c8` in that order:

```
fef5592 36a4063 fb58b49 ac0f39c e75264b 58e271a e399099 f5ab233 a65460c d1bdd2c
=> every pick clean, no conflicts, including D and L
=> isolated tests: 794 passed, 3 skipped, 0 failed; ruff + mypy clean
```

So the dependency needs no separate integration branch and no rebase of L: **D is
PR D in the main chain, and PR L's base transitively contains it.** The one thing
that must not happen is treating D as a side branch off C while L hangs off K.

### Can the oversized Phase 2 commit (`470fea9`) be split?

**Tested, and the honest answer is: not by file ownership alone.**

Applying only the FS substrate (`core/fs`, `policy`, `resources`, `approval_review`,
`review_contract`, `persistence`, `channel`) plus the tests from `470fea9` onto
`2b60708` fails at collection:

```
ModuleNotFoundError: No module named 'aether.core.edits'
ModuleNotFoundError: No module named 'aether.core.planning'
3 errors during collection
```

The Phase 2 test modules import `core.edits` and `core.planning` unconditionally,
so an FS-only PR cannot carry the suite that proves it. Splitting it further would
require hand-editing `470fea9`'s own tests, which is exactly the kind of
reconstruction that risks losing coverage while looking tidier.

**Recommendation:** keep `470fea9` as **one PR (B)** and review it by reading order
(`fs` → `planning` → `edits` → `vault` → `channel`) rather than by pretending it
divides cleanly. If it must be smaller, the honest split needs a test-only
refactor PR first (making the FS tests independent of `edits`/`planning`), and that
is a separate, reviewable change — not a mechanical `git checkout`.

---

## 4. Every proposed tip was built and tested

Each tip was checked out into its own worktree and run in a **fresh, isolated
interpreter**: a new `python3.11 -m venv` with the project installed editable *from
that checkout*, so `aether` resolves to the code under test rather than to the
sandbox's main checkout.

| PR tip | Result |
|---|---|
| C (`1b2f9c8`) alone | 609 passed, 1 skipped |
| D (C + S14-5) | 627 passed, 3 skipped |
| E (C + S14-1) | 635 passed, 1 skipped |
| F (E + S14-2) | 654 passed, 1 skipped |
| G (F + S14-3) | 670 passed, 1 skipped |
| H (G + S14-4) | 693 passed, 1 skipped |
| I (H + S14-7) | **729 passed, 3 skipped, 0 failed** |
| J (I + S14-8) | **740 passed, 3 skipped, 0 failed** |
| K (J + S14-9) | **750 passed, 3 skipped, 0 failed** |
| L (K + S14-10) | **775 passed, 3 skipped, 0 failed** |
| M (L + S14-11) | **794 passed, 3 skipped, 0 failed** |

**Dependency-correct chain, re-verified (S14-11).** The individual tips above were
measured before the D→L defect was found, and D was measured as a side branch off
C. Rebuilt as one linear sequence carrying D inline, each pick clean:

```
1b2f9c8 -> fef5592 -> 36a4063 -> fb58b49 -> ac0f39c -> e75264b
        -> 58e271a -> e399099 -> f5ab233 -> a65460c -> d1bdd2c
```

Tip of that chain, in a fresh `python3.11 -m venv` installed editable from the
worktree: **794 passed, 3 skipped, 0 failed**, ruff `All checks passed!`,
`ruff format --check` 144 files, `mypy aether` 95 files clean. This is the number
that matters for the split: it proves the linear dependency applies, not just that
each commit is individually plausible.

**No exclusions.** An earlier revision of this plan deselected
`test_hardened_launch_import_origin_comes_from_selected_interpreter` because it
failed in scratch worktrees. That test spawns a subprocess whose `aether` import
resolved through the sandbox's editable install pointing at `/home/user/A.E.T.H.E.R`.
Rather than keep excluding it, a properly isolated interpreter was built; the test
then passes, and it is now included in every count above. Excluding a test to make
a split look green was the wrong answer.

The skips are: two native-Windows ACL tests (need NTFS) and one environment-gated
test; they are skipped, not passed.

**Isolated-environment prerequisite.** A fresh venv must install the declared `dev`
extra *and* `hatchling`, or the numbers shift for reasons unrelated to the code:
`pip install -e ".[dev]" httpx hatchling`. Without `pytest-asyncio` the async model
suites fail outright (8+8+5 failures that look like regressions); without
`hatchling` `test_phase2b_stage4_migration.py:724` skips and reports 4 skips
instead of 3. Neither is a code defect, and neither should be reported as one.

---

## 5. Safe git commands

Run these on **new** branches, never on `arena/9ff5f05b-a-e-t-h-e-r`. The existing
branch must not be rewritten: no `reset --hard` of pushed commits, no
`push --force`, no `filter-repo`/`filter-branch`, no branch deletion, no merging
without explicit approval.

> Corrected: an earlier revision of this document created `split/pr14-schema-v2`
> twice (once as a prerequisite step and once as PR A). That duplicate is removed;
> the commands below assume a clean start and were validated in scratch worktrees.

### 5.1 Start

```bash
cd /home/user/A.E.T.H.E.R
git fetch origin
git switch -c split/pr14-schema-v2 origin/main
```

### 5.2 PR A — schema v2, inactive

```bash
git cherry-pick -x 2b60708
git push -u origin split/pr14-schema-v2
gh pr create --base main --head split/pr14-schema-v2 \
  --title "Schema v2: prepare the Stage 4 grant migration without activating it" \
  --body-file docs/engineering/PHASE2B_STAGE4_MIGRATION.md
```

### 5.3 PR B — Phase 2B–E workstreams

```bash
git switch -c split/pr14-phase2-workstreams split/pr14-schema-v2
git cherry-pick -x 470fea9
git push -u origin split/pr14-phase2-workstreams
gh pr create --base split/pr14-schema-v2 --head split/pr14-phase2-workstreams \
  --title "Phase 2B-E: bounded capabilities, trusted approval, exact edits, vault" --fill
```

### 5.4 PR C — S14-6, verifier safety

```bash
git switch -c split/pr14-s14-6-verifier split/pr14-phase2-workstreams
git cherry-pick -x 1b2f9c8
git push -u origin split/pr14-s14-6-verifier
gh pr create --base split/pr14-phase2-workstreams --head split/pr14-s14-6-verifier \
  --title "S14-6: make the Windows verifier non-destructive and honest" --fill
```

### 5.5 PR D — S14-5, vault key + Windows ACL (first link after C)

D is a normal link in the chain, not a side branch: PR L modifies the
`file_permissions.py` that D creates, so everything from E onward builds on D.
Branching D off C and leaving it there while E also branches off C would make L
unappliable — and it would force the reviewer of L to imagine a file they cannot
see.

```bash
git switch -c split/pr14-s14-5-vault-key split/pr14-s14-6-verifier
git cherry-pick -x fef5592
git push -u origin split/pr14-s14-5-vault-key
gh pr create --base split/pr14-s14-6-verifier --head split/pr14-s14-5-vault-key \
  --title "S14-5: vault key outside the vault, real owner-only ACLs on Windows" --fill
```

### 5.6 PR E — S14-1 (branch from D, not C)

```bash
git switch -c split/pr14-s14-1-approved-bytes split/pr14-s14-5-vault-key
git cherry-pick -x 36a4063
git push -u origin split/pr14-s14-1-approved-bytes
gh pr create --base split/pr14-s14-5-vault-key --head split/pr14-s14-1-approved-bytes \
  --title "S14-1: bind every edited byte to the approved preview" --fill
```

### 5.7 PRs F–M — the strict chain

```bash
# F
git switch -c split/pr14-s14-2-grant-consumption split/pr14-s14-1-approved-bytes
git cherry-pick -x fb58b49 && git push -u origin split/pr14-s14-2-grant-consumption

# G
git switch -c split/pr14-s14-3-undo-auth split/pr14-s14-2-grant-consumption
git cherry-pick -x ac0f39c && git push -u origin split/pr14-s14-3-undo-auth

# H
git switch -c split/pr14-s14-4-mutation-journal split/pr14-s14-3-undo-auth
git cherry-pick -x e75264b && git push -u origin split/pr14-s14-4-mutation-journal

# I
git switch -c split/pr14-s14-7-grant-authority split/pr14-s14-4-mutation-journal
git cherry-pick -x 58e271a && git push -u origin split/pr14-s14-7-grant-authority

# J
git switch -c split/pr14-s14-8-orphan-consumption split/pr14-s14-7-grant-authority
git cherry-pick -x e399099 && git push -u origin split/pr14-s14-8-orphan-consumption

# K
git switch -c split/pr14-s14-9-operation-state split/pr14-s14-8-orphan-consumption
git cherry-pick -x f5ab233 && git push -u origin split/pr14-s14-9-operation-state

# L -- its base (K) transitively contains D, which created file_permissions.py
git switch -c split/pr14-s14-10-windows-acl split/pr14-s14-9-operation-state
git cherry-pick -x a65460c && git push -u origin split/pr14-s14-10-windows-acl

# M -- S14-11, the authoritative-consumption correction (replaces S14-7's model)
git switch -c split/pr14-s14-11-authoritative-consumption split/pr14-s14-10-windows-acl
git cherry-pick -x d1bdd2c && git push -u origin split/pr14-s14-11-authoritative-consumption

# N -- acceptance report
git switch -c split/pr14-acceptance-report split/pr14-s14-11-authoritative-consumption
git cherry-pick -x 03e11e8 && git push -u origin split/pr14-acceptance-report
```

Before opening **L**, confirm its base really carries D:

```bash
git merge-base --is-ancestor fef5592 split/pr14-s14-10-windows-acl && echo "D present"
test -f backend/aether/core/security/file_permissions.py && echo "file present"
```

Open each with `gh pr create --fill` and a base of the previous PR's branch.

### 5.8 Verify before each push

```bash
cd backend
uv run pytest
uv run ruff check . && uv run ruff format --check aether tests
uv run mypy aether
```

Do not stack the next cherry-pick until the previous PR is green; the chain edits
`executor.py` eight times and a red tip invalidates everything above it.

### 5.9 Closing PR #14

Only after the series is merged, and only with explicit human approval:

```bash
gh pr close 14 --comment "Superseded by the split series A-M; content preserved in the branch."
```

Use `gh pr close`, **not** `gh pr merge`. The branch is kept, so nothing is lost if
the split is abandoned partway.

---

## 6. What the split does not change

Splitting is a review convenience and moves no gate:

* schema v2 stays inactive (`ACTIVE_SCHEMA_VERSION = 1`,
  `PENDING_MIGRATION_VERSIONS = {2}`);
* production grant issuance stays disabled (`GRANT_ISSUANCE_DISABLED`);
* no mutation path is wired into the running application;
* no Phase 3 work exists;
* the Windows, Electron-UI and real-interruption acceptance items remain
  **NOT VERIFIED** in every one of the PRs above.

Anyone reading only one PR should still see, in that PR's own description, that
the end-to-end feature it hardens is not enabled and has not been demonstrated on
Windows or through the UI.
