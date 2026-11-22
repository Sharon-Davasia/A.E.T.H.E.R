# Phase 2B Stage 4 — Schema-v2 Production Migration Preparation

**Status:** prepared on branch `arena/9ff5f05b-a-e-t-h-e-r`, opened from merged `main`
(`02dff4b`, PR #13 merged). **Not merged. Version 2 is not applied and not activated.
Production grant issuance remains `GRANT_ISSUANCE_DISABLED`.**

This document is the readiness record for integrating migration
`0002_phase2b_stage4_grants.sql` into the production migration registry. It exists so an
independent reviewer can decide whether to approve *activation* as a separate, later step.
It describes what was verified, how it was verified, and what remains true after this
change: **a user's database is never altered by this delivery.**

`docs/architecture/MASTER_SPEC.md` remains the binding authority. Nothing here weakens a
Master Specification requirement; the whole point of the split between *registration* and
*activation* is to make the approved migration verifiable without making it effective.

---

## 1. What this delivery changes — and what it deliberately does not

| Area | Before (merged `main`) | After (this branch) |
|---|---|---|
| Migration file | `aether/core/persistence/proposed_migrations/0002_…sql` | `aether/core/persistence/migrations/0002_…sql` (byte-identical, via `git mv`) |
| Registry `_EXPECTED_MIGRATIONS` | version 1 only | versions 1 and 2, each with a SHA-256 pin |
| Fingerprints `_EXPECTED_SCHEMA_SHA256` | version 1 only | versions 1 and 2 |
| Schema requirements | one shared table/trigger set | per-version requirements, version 2 a strict superset of version 1 |
| What a build creates | version 1 | **version 1** |
| What a build accepts | version 1 | **version 1**; a version-2 database is refused as newer |
| What a build verifies | version 1 bytes + fingerprint | **both** versions' bytes and fingerprints, on every open |
| `GrantLedger` | refuses version-1 databases | unchanged — still refuses version-1 databases |

Changed files:

- `backend/aether/core/persistence/migrations/0002_phase2b_stage4_grants.sql` (moved; bytes
  unchanged, SHA-256 unchanged)
- `backend/aether/core/persistence/migrations/` — `proposed_migrations/` directory removed
- `backend/aether/core/persistence/sqlite_store.py` — registry, activation state, per-version
  requirements, commit-time version verification
- `backend/tests/stage4_support.py` — activation helper for tests
- `backend/tests/test_phase2b_persistence.py` — migration-directory helper copies the full
  registered set
- `backend/tests/test_phase2b_stage4_migration.py` — new: 28 tests, this document's evidence
- `docs/engineering/PHASE2B_STAGE4_MIGRATION.md` (this file), `STATUS.md`,
  `PHASE2B_STAGE4_GRANTS.md`, `docs/security/TRUST_BOUNDARIES.md`

Does **not** change: migration `0001` bytes or pins, `GrantLedger` pins or behaviour, any
grant-issuance path, any execution adapter, any renderer IPC or HTTP route, the Stage 3
review interface, or anything in Phase 2C/2D/Phase 3.

---

## 2. The activation model

Three constants in `sqlite_store.py` express the split. Registration is preparation;
activation is authority.

```python
_EXPECTED_MIGRATIONS: dict[int, tuple[str, str]]        # every known version + byte pin
_EXPECTED_SCHEMA_SHA256: dict[int, str]                 # every known version + fingerprint
ACTIVE_SCHEMA_VERSION = 1                               # what this build creates and accepts
PENDING_MIGRATION_VERSIONS = frozenset({2})             # prepared, must never run
```

Consequences, each covered by a test:

1. **Listed but pending ⇒ never applied.** `_apply_migrations` refuses to target a version
   in `PENDING_MIGRATION_VERSIONS`. Bumping `ACTIVE_SCHEMA_VERSION` alone cannot apply an
   unauthorized migration — the gate is checked before any SQL runs.
   (`test_pending_migration_is_refused_even_if_active_version_is_bumped`)
2. **Listed but pending ⇒ still verified.** The packaged bytes of every registered version
   are hashed against the pin on every open, so the file cannot rot or be swapped while it
   waits. (`test_registered_migration_bytes_are_verified_even_while_pending`)
3. **Active version bounds creation.** A clean install runs migrations up to
   `ACTIVE_SCHEMA_VERSION` only. (`test_clean_install_records_only_version_one`)
4. **Active version bounds acceptance.** A database whose `user_version` exceeds the active
   version is refused as "newer than this application" rather than opened on a schema this
   build does not implement. (`test_version_two_database_is_rejected_when_not_activated`)
   > This was a genuine defect found by the new tests, not a pre-existing one: the check
   > previously compared against the registry maximum, so adding version 2 to the registry
   > would have let a not-yet-activated build open a version-2 database.
5. **Refusal is inert.** A refused activation leaves an existing version-1 database
   byte-identical, with `user_version = 1` and a single ledger row.
   (`test_refused_activation_does_not_touch_an_existing_v1_database`)

Activating version 2 is therefore exactly two line changes plus review:

```python
ACTIVE_SCHEMA_VERSION = 2
PENDING_MIGRATION_VERSIONS: frozenset[int] = frozenset()
```

Everything else — pins, fingerprints, trigger inventory, rollback, upgrade tests — is
already in place in this delivery, so the activation PR is small enough to review
completely.

---

## 3. Independently recomputed values

Neither value was copied from documentation. Both were recomputed from the packaged bytes,
with the method validated by first reproducing the already-released version-1 pin.

| Value | Version 1 (released, unchanged) | Version 2 (this delivery) |
|---|---|---|
| Migration SHA-256 | `709077298230c7065c6778b3149f93b679b6e678220e2d1a34d3540a348d741e` | `d2a02f54bc2f0eaee19fe1fd29c58294efbb136565145866d3c4853b8d64571c` |
| Schema fingerprint | `02f3cac7e905dfb4d1f161621c789bd5c437530002dec36202e9b2dfaa5d2e30` | `dec68c2c1ecdd6d7222b5dcff54b877c9895e5cee6329930148c5db97355b788` |
| Objects | 17 | 30 (10 tables, 5 indexes, 15 triggers) |
| `user_version` | 1 | 2 |

Fingerprint method: replay the migrations into a throwaway database, read
`type, name, sql` from `sqlite_master` for tables/indexes/triggers (excluding
`sqlite_%`), normalize whitespace with `re.sub(r"\s+", " ", sql.strip())`, serialize as
canonical JSON (`sort_keys=True`, `separators=(",", ":")`) and SHA-256 the UTF-8 bytes.
This is exactly what `SQLiteTaskStore._verify_schema` does, and the same helper reproduces
`02f3cac7…` for version 1 — so agreement on version 2 is evidence, not a coincidence.
(`test_documented_v2_fingerprint_is_independently_reproduced` asserts all three.)

Version-2 object inventory:

- **New tables (4):** `exact_approval_grants`, `exact_approval_grant_state`,
  `exact_approval_grant_events`, `exact_approval_grant_consumptions`
- **New triggers (7):** `exact_approval_grants_scope_no_update`,
  `exact_approval_grant_events_no_update`, `exact_approval_grant_events_no_delete`,
  `exact_approval_grant_consumptions_no_update`,
  `exact_approval_grant_consumptions_no_delete`,
  `exact_approval_grant_state_guarded_update`, `exact_approval_grant_state_no_delete`
- **Additive only:** every version-1 table, index and trigger still exists. A test asserts
  set containment, so version 2 cannot silently drop or rename released schema.
- Version 2 also adds 2 indexes (`idx_exact_approval_grants_task`,
  `idx_exact_approval_grant_consumptions_grant`) and no new columns on version-1 tables.
- The migration ends with `PRAGMA user_version = 2` and contains no `schema_migrations`
  `INSERT`: the ledger row is written by the store inside the same transaction, which is
  why the digest is authoritative in one place.

`GrantLedger`'s own pins (`_PROPOSED_MIGRATION_SHA256`, `_EXPECTED_SCHEMA_SHA256_V2`,
`_MIGRATION_NAME_V2`) are unchanged and agree with the store registry;
`test_registry_and_grant_ledger_pins_agree` fails if they ever drift.

---

## 4. Requirements → tests

All new tests are in `backend/tests/test_phase2b_stage4_migration.py` unless stated.

### A. Integrity and preparation

| Requirement | Test |
|---|---|
| Migration bytes match the pin; pin matches the registry | `test_documented_migration_checksum_is_independently_reproduced` |
| Fingerprint independently reproduced, method validated on released v1 | `test_documented_v2_fingerprint_is_independently_reproduced` |
| Version 2 is additive over version 1; critical inventory exact | `test_critical_object_inventory_covers_version_two` |
| Released `0001` bytes never rewritten | `test_migration_0001_bytes_are_not_rewritten` |
| Store registry and ledger pins cannot drift | `test_registry_and_grant_ledger_pins_agree` |
| Packaged resources (importlib) are byte-identical to the pins | `test_packaged_migration_bytes_match_the_pin` |
| A real wheel ships the exact pinned bytes, no `proposed_migrations/` residue | `test_built_wheel_contains_the_verified_migration` |

### B. Deny-by-default while pending

| Requirement | Test |
|---|---|
| Shipped state is active v1 with v2 pending | `test_shipped_configuration_prepares_but_does_not_activate_version_two` |
| Clean install writes only version 1 | `test_clean_install_records_only_version_one` |
| Bumping the active version cannot smuggle a pending migration in | `test_pending_migration_is_refused_even_if_active_version_is_bumped` |
| A refused activation does not touch an existing database | `test_refused_activation_does_not_touch_an_existing_v1_database` |
| Pending bytes are still verified | `test_registered_migration_bytes_are_verified_even_while_pending` |
| Unexpected `.sql` file fails closed | `test_unexpected_migration_file_fails_closed` |
| Missing registered migration fails closed | `test_missing_prepared_migration_fails_closed` |
| Prepared v2 does not disturb normal v1 use | `test_v1_database_still_opens_while_v2_is_pending` |

### C. Migration mechanics (gate lifted in test memory only)

| Requirement | Test |
|---|---|
| Clean install reaches the exact version-2 fingerprint | `test_activated_clean_install_creates_the_full_v2_schema` |
| Upgrade from a realistic v1 database preserves persisted rows | `test_activated_v1_upgrade_preserves_existing_data` |
| Reopening a version-2 database is idempotent and writes nothing | `test_activated_upgrade_is_idempotent_on_reopen` |
| The ledger can open the migrated schema; production issuance still denied | `test_activated_v2_database_opens_the_grant_ledger`, `test_production_issuance_stays_disabled_after_activation` |

### D. Failure injection, tampering, rollback

| Requirement | Test |
|---|---|
| A failing `0002` rolls back schema *and* ledger atomically | `test_upgrade_failure_rolls_back_atomically` |
| An interrupted / truncated migration leaves no half-applied schema | `test_interrupted_migration_leaves_no_half_applied_schema` |
| Tampered version-2 ledger checksum is rejected | `test_tampered_v2_migration_ledger_row_is_rejected` |
| Dropped version-2 object is rejected | `test_tampered_v2_schema_object_is_rejected` |
| Rewritten version-2 object is rejected by fingerprint | `test_tampered_v2_schema_sql_is_rejected` |
| Unactivated build refuses a version-2 database | `test_version_two_database_is_rejected_when_not_activated` |
| The issuance gate is still present on the persistence path | `test_forged_permit_is_refused_on_a_migrated_database` |
| The activation boundary is intact in the shipped build | `test_activation_gate_is_the_only_thing_standing_between_pending_and_applied` |

> **Defect found and fixed while writing these tests.** `_apply_migrations` verified the
> `user_version` bump *after* `COMMIT`. A migration script that completed but did not bump
> the version (truncated file, interrupted run) left a committed partial schema while the
> database still reported the old version, so the next open would fail with a confusing
> fingerprint mismatch and the user database would hold half a schema. The check now runs
> inside the transaction, and the `PersistenceIntegrityError` path rolls back explicitly.
> `test_interrupted_migration_leaves_no_half_applied_schema` is the regression test.

---

## 5. Verification record (Linux sandbox only)

| Gate | Command | Result |
|---|---|---|
| Full backend suite | `python -m pytest tests -o addopts=""` | **429 passed, 1 skipped** |
| New migration suite | `python -m pytest tests/test_phase2b_stage4_migration.py` | **28 passed** |
| Persistence suite | `python -m pytest tests/test_phase2b_persistence.py` | 53 passed |
| Stage 4 grants suite | `python -m pytest tests/test_phase2b_stage4_grants.py` | 114 passed |
| Static typing | `python -m mypy aether` | Success, 71 files |
| Lint | `ruff check .` | All checks passed |
| Desktop lint / types | `npm run lint`, `npm run typecheck` | clean |
| Desktop tests | `npm test` | 54 pass, 0 fail, 7 skipped |
| App-layer security tests | `npm run test:python` | 6 passed |
| Wheel packaging | `python -m hatchling build -t wheel` | both migrations present, pins match, no `proposed_migrations/` |

The single skip is `tests/test_model_integration.py`, which requires
`AETHER_RUN_MODEL_INTEGRATION=1` and a real model runtime; it is unrelated to this change
and was skipped before it.

Pre-change baseline for comparison: merged `main` at `02dff4b` ran 401 passed, 1 skipped.
Net new tests: 28, all in the new module.

### Mutation checks (the tests are known to fail when the boundary is removed)

A test that cannot fail is not evidence. Three deliberate mutations were applied, run, and
reverted (byte-identical restore verified):

| Mutation | Result |
|---|---|
| Delete the activation gate (`if target_version in PENDING_MIGRATION_VERSIONS`) | 2 failures |
| Delete the issuance gate (`if self._trust_source_policy != "test_scoped":`) | 2 failures |
| Bump `ACTIVE_SCHEMA_VERSION = 2` while version 2 is still pending | 8 failures |

The third mutation initially appeared to pass — Python had reused a stale
`__pycache__/sqlite_store.cpython-311.pyc` whose source size and mtime matched after the
revert. Clearing `__pycache__` shows the expected 8 failures.

**Linux is not Windows.** Every result above is from the Linux sandbox. POSIX-only paths
(inode-based owner lock, `0600` permissions) are exercised here; the Windows equivalents are
**not** and must not be inferred from these runs. The acceptance checklist in §8 must be
executed on the target machine.

---

## 6. Risks and mitigations

| Risk | Mitigation in this delivery |
|---|---|
| A version-2 migration applied before approval | `ACTIVE_SCHEMA_VERSION = 1` plus the `PENDING_MIGRATION_VERSIONS` gate; a test proves bumping the active version alone is insufficient |
| Prepared bytes drift while waiting for approval | Byte pins verified on every open, even for pending versions |
| Version-2 database opened by a build that does not implement it | Refusal against the *active* version, not the registry maximum (defect fixed here) |
| Partial schema committed on an interrupted migration | Version bump verified inside the transaction with explicit rollback (defect fixed here) |
| A future edit silently widens version 2 | Fingerprint pin plus additivity assertion against version 1 |
| `0001` rewritten by accident | Byte pin plus `test_migration_0001_bytes_are_not_rewritten` |
| Store and ledger pins drifting apart | `test_registry_and_grant_ledger_pins_agree` |
| Packaging omits the SQL file | Wheel test + `importlib.resources` visibility test |
| Migration silently enables authorization | Activation test asserts `AUTHORIZATION_EVIDENCE_REQUIRED` still denies issuance |

Residual risk that this delivery **cannot** remove: the migration grants a durable schema
for approval grants, and correctness of the grant protocol itself rests on the Stage 4
reviews already merged in PR #13. Activation does not create an authorization path — the
production attestation verifier still rejects everything — but a reviewer should confirm
that the Stage 4 boundary is the one they intend to run against before approving
activation.

---

## 7. Dependency-ordered plan

### 7.1 Remaining Phase 2B production-approval integration

Ordered; each step depends on all previous ones. Steps 1–2 are already done.

1. **Schema-v2 migration preparation** — *this PR*. Registry, pins, gate, rollback and
   packaging evidence. No activation.
2. **Independent review of this PR** — reviewer confirms fingerprints, additive schema,
   failure semantics and that activation is genuinely inert.
3. **Explicit activation approval, then activation PR** — reviewer-approved change setting
   `ACTIVE_SCHEMA_VERSION = 2` and `PENDING_MIGRATION_VERSIONS = frozenset()`. Ships with a
   user-facing upgrade note: existing databases migrate on first open, one-way, with
   rollback only to the pre-upgrade file copy. Must include a real upgrade test against a
   database produced by the shipped version 1 build.
4. **Trusted authorizing origin (Phase 2B authorization)** — replace the rejecting
   `AttestationVerifier` with a verifier bound to an authenticated desktop-side approval
   interaction. This is the step that actually creates authority; it needs its own threat
   model update to `docs/security/TRUST_BOUNDARIES.md` and must keep test-only issuance
   isolated from production-capable configuration.
5. **Grant issuance enablement** — flip `GRANT_ISSUANCE_DISABLED` only after step 4 is
   reviewed, with a per-issuance audit trail and a revocation drill.
6. **Executor boundary** — still out of scope for 2B. `GRANT_VALIDATED_EXECUTOR_NOT_ENABLED`
   stays the ceiling until a separate capability-execution phase.

### 7.2 Phase 2C — file read / open / search

Depends on activation (7.1 step 3) for the ledger, and on 7.1 step 4 for any path where a
read is treated as authorized. Suggested order:

1. Read-only capability contracts: canonical path identity, symlink/reparse resolution,
   allow-listed roots, size/time bounds, typed denial reasons. No writes.
2. Read executor adapter behind the existing policy broker, consuming a validated grant;
   deny-by-default when no grant is present.
3. Search: bounded, deterministic, cancellable, with the same path-identity rules; no
   index persistence in the first cut.
4. Open-with-default-app: explicitly deferred until 2C read/search are reviewed, because it
   crosses a process boundary the current boundary does not cover.
5. Windows reparse-point and ACL acceptance on the target machine before any of the above
   is called done.

### 7.3 Phase 2D — verified edits + Undo Vault

Depends on all of 2C, and on 7.1 step 6 for execution authority. Suggested order:

1. Pre-image capture contract: hash, size, mode, timestamp, canonical path; stored before
   any mutation, verified after.
2. Atomic write protocol (temp file + fsync + replace) with crash-recovery semantics defined
   before implementation, and explicit failure injection tests.
3. Undo Vault: append-only, integrity-verified store; every entry bound to the grant, the
   pre-image hash and the post-image hash. Reuse the migration/ledger integrity pattern
   proven here rather than inventing a second one.
4. Undo execution as its own reviewed capability with the same grant requirements — undo is
   an edit and must never be an implicit privilege.
5. Conflict detection for external modification between capture and undo; never overwrite
   silently.

Phase 3 is not started, planned in detail, or implied by any of the above.

---

## 8. Windows acceptance requirements (not yet executed)

These must be run on the target Windows machine after merge. Linux results are not
evidence for any of them.

**Schema and migration**

- [ ] Fresh install on Windows creates `user_version = 1` and exactly one
      `schema_migrations` row; no version-2 table exists.
- [ ] The packaged migration files are readable from the installed wheel on Windows
      (`importlib.resources` resolves inside the app bundle, not just a source checkout).
- [ ] A database created by the shipped build, copied and reopened, still opens at
      version 1 with a valid fingerprint.
- [ ] A version-2 database (produced with the gate lifted in a test harness) is refused with
      "newer than this application" by the shipped build.
- [ ] Migration failure injection on Windows leaves no partial schema and no ledger row.

**Filesystem and locking**

- [ ] `msvcrt` sidecar owner lock: contention, stale-lock recovery, and behaviour when the
      pathname is replaced or the process is killed mid-migration.
- [ ] Windows ACLs (not POSIX `0600`) are applied to the database, the WAL/SHM files, the
      sidecar and any `mode=ro` handle.
- [ ] Junction / reparse-point and volume-identity checks behave as they do on POSIX.

**Application**

- [ ] Desktop app starts, the Stage 3 review interface still authorizes nothing, and no
      grant surface appears in the renderer.
- [ ] Full desktop check (`npm run check`) passes on Windows.
- [ ] Backend suite passes on Windows Python, with the same 1 skipped model-integration test.

---

## 9. What a reviewer must decide

1. Are the recomputed pins acceptable as the approved values (§3)?
2. Is the registration/activation split the right mechanism, and is it genuinely inert
   (§2)?
3. Are the two defects fixed here (acceptance bound, commit-time version check) fixed
   correctly rather than papered over (§4)?
4. Is activation a separate approval, or should it be bundled? **This delivery assumes
   separate** and stops here.
