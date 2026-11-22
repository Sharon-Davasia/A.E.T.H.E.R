# PR #14 — Splitting Plan

**Branch:** `arena/9ff5f05b-a-e-t-h-e-r` (base `main` @ `02dff4b`)
**PR:** #14, open, **not merged**, no auto-merge requested
**Scope constraint honoured:** everything below is a *plan*. Nothing was reverted,
reset, force-pushed, merged or discarded. The branch as pushed is unchanged and
complete.

---

## 1. Why PR #14 should not land as one review unit

PR #14 currently carries nine commits across four security boundaries plus two
large pre-existing workstream commits. A reviewer approving it is simultaneously
approving:

* a schema migration prepared but not activated;
* a capability taxonomy and policy broker change;
* an approval chain with a new execution authority;
* byte-exact edit binding (S14-1);
* grant consumption accounting (S14-2);
* undo authorization (S14-3);
* a durable mutation journal (S14-4);
* vault key relocation and Windows ACLs (S14-5);
* a rewritten Windows acceptance verifier (S14-6).

Those are separable decisions with different blast radii, and several of them are
exactly the "security boundary changes" that standing review rules require to be
split into their own PRs. The six S14 commits were deliberately structured so
this split is mechanical.

---

## 2. The proposed PR set

Ordered. Each row is one PR. "Depends on" must be merged first.

| # | PR | Commits | Files | Depends on | Reviewer's question |
|---|---|---|---|---|---|
| A | **Schema-v2 migration, inactive** | `2b60708` | `persistence/sqlite_store.py`, `0002_*.sql`, `stage4_support.py`, `test_phase2b_persistence.py`, `test_phase2b_stage4_migration.py`, `docs/engineering/PHASE2B_STAGE4_*.md`, `STATUS.md`, `TRUST_BOUNDARIES.md` | – (base) | Is v2 correct, and is it genuinely inert? |
| B | **Phase 2B–E workstreams** | `470fea9` | `core/fs/*`, `core/edits/*`, `core/planning/*`, `core/vault/undo_vault.py`, `channel/*`, `broker.py`, `registry.py`, `review_contract.py`, `pyproject.toml`, docs | A | Is the Phase 2 substrate sound? |
| C | **S14-6 — verifier safety** | `1b2f9c8` | `core/acceptance/fixture_safety.py`, `fs/session.py`, `test_phase2_fixture_safety.py`, `test_phase2c_session.py`, `verify_phase2.ps1`, `PHASE2_WINDOWS_ACCEPTANCE.md` | B | Does the verifier refuse to destroy data or over-claim? |
| D | **S14-5 — vault key + Windows ACL** | `fef5592` | `core/security/file_permissions.py`, `vault/undo_vault.py`, `test_phase2_vault_key_protection.py`, `verify_phase2.ps1`, `PHASE2_WINDOWS_ACCEPTANCE.md` | **C only** (applies cleanly onto C — verified) | Is the key outside the vault, and is protection enforced rather than assumed? |
| E | **S14-1 — approved byte binding** | `36a4063` | `core/planning/exact_diff.py`, `core/planning/edit_binding.py`, `core/planning/planner.py`, `core/edits/executor.py`, `test_phase2_approved_bytes.py`, 3 adapted suites | B (+C in practice) | Can a user approve one patch and receive another? |
| F | **S14-2 — grant consumption** | `fb58b49` | `core/grants/consumption.py`, `core/edits/executor.py`, `tests/fs_support.py`, `stage4_support.py`, `test_phase2_grant_consumption.py`, 3 adapted suites | E | Can grant authority be treated as execution authority, or double-spent? |
| G | **S14-3 — undo authorization** | `ac0f39c` | `core/policy/capabilities.py`, `core/planning/planner.py`, `core/edits/executor.py`, `test_phase2_undo_authorization.py`, 2 adapted suites | F | Can an edit approval authorize an undo, or an undo clobber a newer edit? |
| H | **S14-4 — mutation journal** | `e75264b` | `core/edits/journal.py`, `core/edits/reconcile.py`, `core/edits/executor.py`, `test_phase2_mutation_journal.py` | G | Is a crash between replace and receipt recoverable and honestly reported? |
| I | **Integration — acceptance report** | `9a1334f` | `PHASE2_ACCEPTANCE_REPORT.md`, `.gitignore` | H (and D) | Does the report match what was actually proven? |

**Nine PRs from one branch.** D is the only one that is genuinely independent of
the S14 chain, and it is deliberately placed early because it is the smallest and
the most self-contained.

---

## 3. Verified dependencies (measured, not assumed)

Each of these was tested by cherry-picking onto a scratch worktree at `1b2f9c8`
and recording the result:

| Applied onto `1b2f9c8` | Result |
|---|---|
| `fef5592` (S14-5) | **clean** |
| `36a4063` (S14-1) | **clean** |
| `fb58b49` (S14-2) | conflict — `executor.py`, `test_phase2_approved_bytes.py`, `test_phase2_end_to_end.py` |
| `ac0f39c` (S14-3) | conflict — `executor.py`, `planner.py`, `test_phase2_end_to_end.py` |
| `e75264b` (S14-4) | conflict — `executor.py` |
| `36a4063` → `fb58b49` | **clean** |
| `36a4063` → `fb58b49` → `ac0f39c` | **clean** |
| `36a4063` → `fb58b49` → `ac0f39c` → `e75264b` | **clean** |

**Conclusion:** S14-1 → S14-2 → S14-3 → S14-4 is a strict chain; they all edit
`executor.py` in overlapping regions and must land in order. S14-5 is independent
of all of them. Do not attempt to reorder the chain — the conflicts are in the
authorization core and hand-resolving them during a split would risk changing
security behaviour for the convenience of a reviewer.

### Every proposed tip was built and tested

| PR tip | Suite result |
|---|---|
| C (`1b2f9c8`) alone | 609 passed, 1 skipped, 1 deselected |
| D (C + S14-5) | 627 passed, 3 skipped |
| E (C + S14-1) | 635 passed, 1 skipped |
| F (E + S14-2) | 654 passed, 1 skipped |
| G (F + S14-3) | 670 passed, 1 skipped |
| H (G + S14-4) | 693 passed, 1 skipped |
| I (current HEAD `9a1334f`) | **709 passed, 3 skipped** |

The `1 deselected` is `test_hardened_launch_import_origin_comes_from_selected_interpreter`.
It is **not** a regression: it fails identically at base `1b2f9c8` with no changes
applied, because it spawns a subprocess whose `aether` import resolves through
this sandbox's editable install (`aether-os 0.1.0 -> /home/user/A.E.T.H.E.R/backend`)
rather than the checkout under test. On a clean CI runner with a proper editable
install of the checkout it is expected to pass; that expectation is **NOT
VERIFIED** here.

---

## 4. Safe git commands

Run these on a *new* branch, never on `arena/9ff5f05b-a-e-t-h-e-r`. The existing
branch must not be rewritten: no `reset --hard` of pushed commits, no
`push --force`, no `filter-repo`/`filter-branch`, no deletion of `main`.

### 4.1 Prerequisite: create the split from the existing commits

```bash
cd /home/user/A.E.T.H.E.R
git fetch origin
git switch -c split/pr14-schema-v2 origin/main
```

### 4.2 PR A — schema v2, inactive

```bash
git switch -c split/pr14-schema-v2 origin/main
git cherry-pick -x 2b60708
git push -u origin split/pr14-schema-v2
gh pr create --base main --head split/pr14-schema-v2 \
  --title "Schema v2: prepare the Stage 4 grant migration without activating it" \
  --body-file docs/engineering/PHASE2B_STAGE4_MIGRATION.md
```

### 4.3 PR B — Phase 2B–E workstreams

```bash
git switch -c split/pr14-phase2-workstreams split/pr14-schema-v2
git cherry-pick -x 470fea9
git push -u origin split/pr14-phase2-workstreams
gh pr create --base split/pr14-schema-v2 --head split/pr14-phase2-workstreams \
  --title "Phase 2B-E: bounded capabilities, trusted approval, exact edits, vault" \
  --fill
```

### 4.4 PR C — S14-6, verifier safety

```bash
git switch -c split/pr14-s14-6-verifier split/pr14-phase2-workstreams
git cherry-pick -x 1b2f9c8
git push -u origin split/pr14-s14-6-verifier
gh pr create --base split/pr14-phase2-workstreams --head split/pr14-s14-6-verifier \
  --title "S14-6: make the Windows verifier non-destructive and honest" --fill
```

### 4.5 PR D — S14-5, vault key + Windows ACL (independent of the S14 chain)

```bash
git switch -c split/pr14-s14-5-vault-key split/pr14-s14-6-verifier
git cherry-pick -x fef5592
git push -u origin split/pr14-s14-5-vault-key
gh pr create --base split/pr14-s14-6-verifier --head split/pr14-s14-5-vault-key \
  --title "S14-5: vault key outside the vault, real owner-only ACLs on Windows" --fill
```

### 4.6 PRs E–H — the strict S14 chain

```bash
# E
git switch -c split/pr14-s14-1-approved-byte-binding split/pr14-s14-6-verifier
git cherry-pick -x 36a4063
git push -u origin split/pr14-s14-1-approved-byte-binding

# F
git switch -c split/pr14-s14-2-grant-consumption split/pr14-s14-1-approved-byte-binding
git cherry-pick -x fb58b49
git push -u origin split/pr14-s14-2-grant-consumption

# G
git switch -c split/pr14-s14-3-undo-auth split/pr14-s14-2-grant-consumption
git cherry-pick -x ac0f39c
git push -u origin split/pr14-s14-3-undo-auth

# H
git switch -c split/pr14-s14-4-mutation-journal split/pr14-s14-3-undo-auth
git cherry-pick -x e75264b
git push -u origin split/pr14-s14-4-mutation-journal
```

Then open each with `--fill` and a base of the previous PR's branch.

### 4.7 PR I — integration and acceptance report

```bash
git switch -c split/pr14-acceptance-report split/pr14-s14-4-mutation-journal
git cherry-pick -x 9a1334f
git push -u origin split/pr14-acceptance-report
gh pr create --base split/pr14-s14-4-mutation-journal --head split/pr14-acceptance-report \
  --title "Acceptance report: reconcile with the S14 remediation" --fill
```

### 4.8 Verify before each push

```bash
cd backend
uv run pytest                                   # or: python -m pytest
uv run ruff check . && uv run ruff format --check aether tests
uv run mypy aether
```

Do not stack the next cherry-pick until the previous PR's CI is green; the chain
edits `executor.py` four times and a red tip invalidates everything above it.

### 4.9 Closing PR #14

Only after the nine PRs are merged, and only with explicit human approval:

```bash
gh pr close 14 --comment "Superseded by the split PR series A-I; content preserved in 9a1334f."
```

`gh pr close` is used rather than `gh pr merge` because PR #14's commit sequence
is intentionally not a merge candidate. **Do not merge it.** The branch itself is
kept, so nothing is lost if the split is abandoned partway.

---

## 5. What the split does not change

Splitting is a review convenience. It does not move any gate:

* schema v2 stays inactive (`ACTIVE_SCHEMA_VERSION = 1`,
  `PENDING_MIGRATION_VERSIONS = {2}`);
* production grant issuance stays disabled (`GRANT_ISSUANCE_DISABLED`);
* no mutation path is wired into the running application;
* no Phase 3 work exists;
* the Windows, Electron-UI and real-interruption acceptance items remain
  **NOT VERIFIED** in every one of the nine PRs.

Anyone reading only PR E, F, G or H should still see, in that PR's own
description, that the end-to-end feature it hardens is not enabled and has not
been demonstrated on Windows or through the UI.
