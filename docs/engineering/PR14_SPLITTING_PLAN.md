# PR #14 — Splitting Plan

> **Historical record (updated 2026-11-23).** This plan was executed:
> the stack was split into PRs #15–#32 and integrated, with all later
> corrections, through PR #34 into `main` (merge commit `a58bd68`).
> PR #14 itself was closed as superseded and was never merged. The text
> below is preserved unchanged as the historical planning record; its
> present-tense statements about open PRs and branches no longer describe
> the repository.


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
| M | **S14-11 — one authoritative spend** | `d1bdd2c` | `grants/consumption.py`, `test_phase2_authoritative_consumption.py`, `test_phase2_grant_authority.py` | L |
| N | **S14-12 — unprojected spend discoverable** | `3d1ade5` | `grants/consumption.py`, `edits/reconcile.py`, `test_phase2_consumption_recovery.py` | M |
| O | **S14-13 — replay preserves terminal state** | `3149b6c` | `grants/consumption.py`, `test_phase2_consumption_recovery.py` | N |
| P | **Vault index race (found during S14-12)** | `9194036` | `vault/undo_vault.py`, `test_phase2_vault_key_protection.py` | L (independent of M–O) |
| Q | **S14-14 — complete the vault concurrency invariant** | `eb7e07e` | `vault/undo_vault.py`, `test_phase2_vault_key_protection.py` | P |
| R | **Documentation set** | `1038b1d`, `9a1334f`, `03e11e8`, `ec9452b`, *and the branch HEAD at split time* | `PR14_SPLITTING_PLAN.md`, `PHASE2_ACCEPTANCE_REPORT.md`, `.gitignore` | Q |

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

**Every one of the 17 tips was rebuilt and re-tested** after the D→L and
documentation-chain corrections, as one linear A→Q sequence from a clean `02dff4b`
base. All 20 cherry-picks applied clean, and the A–Q tip is byte-identical to the
branch HEAD, so the split preserves every file exactly.

| PR | Contains | Result (isolated venv) |
|---|---|---|
| A | `2b60708` schema v2 prepared, inert | 429 passed, 1 skipped |
| B | `470fea9` workstreams B–E | 589 passed, 1 skipped |
| C | `1b2f9c8` S14-6 verifier | 612 passed, 1 skipped |
| D | `fef5592` S14-5 vault key | 628 passed, 3 skipped |
| E | `36a4063` S14-1 approved bytes | 652 passed, 3 skipped |
| F | `fb58b49` S14-2 grant consumption | 671 passed, 3 skipped |
| G | `ac0f39c` S14-3 undo authorization | 687 passed, 3 skipped |
| H | `e75264b` S14-4 mutation journal | 709 passed, 3 skipped |
| I | `58e271a` S14-7 grant authority | 729 passed, 3 skipped |
| J | `e399099` S14-8 orphan consumption | 740 passed, 3 skipped |
| K | `f5ab233` S14-9 operation state | 750 passed, 3 skipped |
| L | `a65460c` S14-10 Windows ACL | 775 passed, 3 skipped |
| M | `d1bdd2c` S14-11 authoritative spend | 794 passed, 3 skipped |
| N | `3d1ade5` S14-12 unprojected spend | 802 passed, 3 skipped |
| O | `3149b6c` S14-13 replay terminal state | 809 passed, 3 skipped |
| P | `9194036` vault index race | 810 passed, 3 skipped |
| Q | `eb7e07e` S14-14 vault concurrency | 819 passed, 3 skipped |
| R | `1038b1d` `9a1334f` `03e11e8` `ec9452b` + docs tip | 819 passed, 3 skipped |

**0 failures at every tip.**

One observation worth recording rather than hiding. Tip **N** (`3d1ade5`) failed
`test_two_interleaved_operations_each_resolve_their_own_consumption` in **2 of 6**
full-suite runs. That is expected and is not a split defect: N predates both vault
fixes, so it still carries the pre-existing index race, exactly as the source
branch did at the equivalent commit. Tip **P** (`9194036`, the first vault lock)
showed **2 of 8** failures in one session; 24 subsequent full runs of that tip did
not reproduce it, and I could not capture the error text, so I am not claiming P is
clean -- only that the failure was not reproducible on demand. Tips **Q** and **R**
were **18 of 18** and **10 of 10** clean respectively. The residual at P is
consistent with the incomplete invariant that S14-14 exists to finish (maintenance
paths still unlocked), but without the trace that is an inference, not a
measurement. The count rises monotonically as tests are added, and
never falls, which is the signature of a split that preserves coverage rather than
one that quietly drops it. The earlier per-tip table this replaces was measured
with D as a side branch off C, which is the arrangement the D→L correction exists
to remove; those numbers are superseded, not silently reused.

The 3 skips throughout are the two native-Windows ACL tests and the
environment-gated model-integration test. A, B and C show 1 skip because the
Windows-only tests are added by D.

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

# N -- S14-12
git switch -c split/pr14-s14-12-unprojected-spend split/pr14-s14-11-authoritative-consumption
git cherry-pick -x 3d1ade5 && git push -u origin split/pr14-s14-12-unprojected-spend

# O -- S14-13
git switch -c split/pr14-s14-13-replay-terminal-state split/pr14-s14-12-unprojected-spend
git cherry-pick -x 3149b6c && git push -u origin split/pr14-s14-13-replay-terminal-state

# P -- the vault index race, independent of M-O but stacked on L so the chain stays linear
git switch -c split/pr14-vault-index-race split/pr14-s14-13-replay-terminal-state
git cherry-pick -x 9194036 && git push -u origin split/pr14-vault-index-race

# Q -- S14-14, the vault concurrency invariant
git switch -c split/pr14-s14-14-vault-concurrency split/pr14-vault-index-race
git cherry-pick -x eb7e07e && git push -u origin split/pr14-s14-14-vault-concurrency

# R -- the documentation set, in creation order (see below)
git switch -c split/pr14-docs split/pr14-s14-14-vault-concurrency
git cherry-pick -x 1038b1d   # CREATES PR14_SPLITTING_PLAN.md
git cherry-pick -x 9a1334f   # CREATES the acceptance report, .gitignore
git cherry-pick -x 03e11e8   # modifies both
git cherry-pick -x ec9452b   # modifies both
git cherry-pick -x "$DOCS_TIP"   # final docs commit(s); see the note below
git push -u origin split/pr14-docs
```

#### Why the final docs commit is referenced as a variable

A document cannot contain the hash of the commit that contains it: writing the
hash changes the content, which changes the hash. Making it literal creates an
infinite regress, and any fixed value goes stale the moment the plan is edited
again. So the final documentation commit is resolved at split time:

```bash
SOURCE_HEAD=$(git -C /home/user/A.E.T.H.E.R rev-parse arena/9ff5f05b-a-e-t-h-e-r)
DOCS_TIP=$SOURCE_HEAD     # the last commit that is documentation-only
echo "splitting from $SOURCE_HEAD"
```

Every other hash in this plan is a fixed, already-pushed commit and is quoted
literally, because those are stable. Only the tip moves.

#### Preflight: verify content, not ancestry

**Do not use `git merge-base --is-ancestor` on these branches.** Cherry-picking
rewrites commit ids, so the original SHA is never an ancestor of a split branch
even when the change it carries is present. A check like

```bash
git merge-base --is-ancestor fef5592 split/pr14-s14-10-windows-acl   # WRONG
```

fails on a correct branch and tells you nothing about whether the change landed.
The question is not "is this commit an ancestor" but "does this branch contain the
resulting files and patches, and do they work". So verify content and behaviour:

```bash
# 1. The file D creates must exist on L's base, and must be the version L expects.
git switch split/pr14-s14-10-windows-acl
test -s backend/aether/core/security/file_permissions.py || { echo "MISSING file_permissions.py (D not applied)"; exit 1; }
test -f scripts/verify_phase2.ps1 || { echo "MISSING verify_phase2.ps1"; exit 1; }

# 2. L's own change must be present in that file, not just the file.
grep -q "def parse_sddl_dacl" backend/aether/core/security/file_permissions.py || { echo "S14-10 parser absent"; exit 1; }
grep -q "def evaluate_windows_dacl" backend/aether/core/security/file_permissions.py || { echo "S14-10 evaluator absent"; exit 1; }

# 3. D's contribution must also still be present.
grep -q "restrict_to_owner" backend/aether/core/security/file_permissions.py || { echo "S14-5 absent"; exit 1; }

# 4. Behaviour is the only real proof: the tests that cover both must pass.
cd backend && python -m pytest tests/test_phase2_vault_key_protection.py \
                        tests/test_phase2_windows_acl.py -q
```

The same content-and-behaviour rule replaces the ancestry idea everywhere:

| Question | Wrong check | Correct check |
|---|---|---|
| Does L's base carry D? | `--is-ancestor fef5592` | `test -s .../file_permissions.py` **and** `pytest test_phase2_vault_key_protection.py` |
| Does Q carry both docs? | `--is-ancestor 1038b1d` | both files non-empty **and** `git log --oneline origin/main..HEAD -- <path>` non-empty for each |
| Is the split identical to source? | compare commit ids | `git diff --name-status <split-tip> <source-HEAD>` is **empty** |

That last row is the strongest check available, and it is the one to run before
opening any PR: if the reconstructed tree is byte-identical to the reviewed source
HEAD, no change was lost, dropped or silently altered in the split.

```bash
# Run this on the Q tip. Empty output means the split reproduces source exactly.
git diff --name-status HEAD "$SOURCE_HEAD"
```

Before opening **Q**, confirm the documentation set is complete rather than partial:

```bash
for f in docs/engineering/PR14_SPLITTING_PLAN.md docs/engineering/PHASE2_ACCEPTANCE_REPORT.md; do
  test -s "$f" || { echo "MISSING $f"; exit 1; }
  echo "$f: $(git log --oneline origin/main..HEAD -- "$f" | wc -l) commits"
done
```

Before opening **L**:

```bash
test -s backend/aether/core/security/file_permissions.py || { echo "D missing"; exit 1; }
grep -q "def parse_sddl_dacl" backend/aether/core/security/file_permissions.py || exit 1
cd backend && python -m pytest tests/test_phase2_windows_acl.py -q
```

Open each with `gh pr create --fill` and a base of the previous PR's branch.

#### The documentation commits are a chain too (corrected)

An earlier revision of this plan put a single documentation PR at the end that
cherry-picked `03e11e8` alone. That cannot work either, and for the same reason
the D→L defect could not: a commit that *modifies* a file needs the commit that
*created* it.

```
1038b1d  CREATES docs/engineering/PR14_SPLITTING_PLAN.md
9a1334f  CREATES docs/engineering/PHASE2_ACCEPTANCE_REPORT.md, .gitignore
03e11e8  modifies both
ec9452b  modifies both
```

Cherry-picking `03e11e8` onto a tree with neither file fails outright; onto a tree
with only one of them it half-applies. So the documentation PR carries all four in
creation order, plus the final docs commit. This is why "PR N: acceptance report"
in the previous revision was wrong: it named one commit for a four-commit set.

**Why one PR and not four.** These are review *aids*, not security boundaries.
The security boundary is the code, and the code is already split. Four separate
documentation PRs would add review overhead for edits to prose that is being
corrected as the code under it lands. If a reviewer prefers them separate, the
sequence above is already ordered so each can be its own branch; say so and it
can be split without touching a line of code.

Verify the documentation set as a set, not commit by commit:

```bash
# On the tip of split/pr14-docs:
git log --oneline origin/main..HEAD -- docs/engineering/PR14_SPLITTING_PLAN.md
git log --oneline origin/main..HEAD -- docs/engineering/PHASE2_ACCEPTANCE_REPORT.md
# Both must show every documentation commit, and both files must exist.
test -s docs/engineering/PR14_SPLITTING_PLAN.md
test -s docs/engineering/PHASE2_ACCEPTANCE_REPORT.md
```

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
