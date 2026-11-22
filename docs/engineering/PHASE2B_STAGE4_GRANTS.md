# Phase 2B Stage 4 — Trusted Exact Approval-Grant Foundation

**Status:** implemented on branch `arena/2b83b1da-a-e-t-h-e-r`, opened from merged `main`
(`2a6d673`, PR #12 merged). Stage 4 is the durable, fail-closed *foundation* for exact
approval grants. It is **not** authorization and it executes nothing.

`docs/architecture/MASTER_SPEC.md` remains the binding authority. Where the Master
Specification requires a trusted authorizing origin that does not yet exist, Stage 4
implements the contract, the persistence and the test-only simulation, and keeps
**production issuance disabled**.

---

## 1. What Stage 4 adds, and what it deliberately does not

Adds:

| Area | Artifact |
|---|---|
| Authoritative grant binding | `ApprovedOperation.recovery_class` (defaults to the most conservative class) now participates in `exact_approval_scope_digest` |
| Issuance prerequisites | `aether/core/grants/issuance.py` — opaque `AuthorizingProof`, `GrantIssuer`, `TestOnlyAuthorizingProof` |
| Validation | `aether/core/grants/validation.py` — pure, fail-closed `check_grant_scope` with reason codes |
| Durable persistence | `aether/core/grants/ledger.py` — `GrantLedger` (schema v2 only, verifies fingerprints, never migrates) |
| Policy integration | `PolicyBroker(..., grant_authority=...)` — deny-by-default, execution still disabled |
| Proposed schema | `aether/core/persistence/proposed_migrations/0002_phase2b_stage4_grants.sql` (**not applied, not registered**) |
| Tests | `backend/tests/test_phase2b_stage4_grants.py` (46 tests) + `tests/stage4_support.py` |

Does **not** add: any execution adapter, any filesystem mutation, any shell/command
execution, any renderer IPC surface, any HTTP route, any production grant issuer, any
promotion of review evidence to authority, any Phase 2C/2D or Phase 3 code, and no
production schema change.

---

## 2. Requirements → code → tests

Legend: **MS** = Master Specification clause area; **test** = test function in
`backend/tests/test_phase2b_stage4_grants.py` unless another file is named.

### A. Authoritative grant model and validation

| Requirement (MS: exact-grant protocol) | Code | Tests |
|---|---|---|
| Reuse `ExactApprovalGrant`; bind task ID, plan revision **and** plan hash | `contracts/approval.py` (unchanged shape), `grants/issuance.py::GrantIssuer.issue` | `test_grant_binds_exact_scope_and_digest_is_stable`, `test_issuance_rejects_any_operation_wider_or_different_than_the_plan` |
| Bind approved step identities and exact allowed operations (capability, arguments hash, effect hash) | `ApprovedOperation`, `check_grant_scope` | `test_issuance_rejects_any_operation_wider_or_different_than_the_plan`, `test_arguments_substitution_denies` |
| Bind canonical resource IDs and expected versions — no widening | `ApprovedResourceVersion`, `check_grant_scope` resource comparison | `test_resource_substitution_scope_widening_and_stale_versions_deny` |
| Bind risk-tier ceiling and **recovery requirements** | `ExactApprovalGrant.max_tier`, `ApprovedOperation.recovery_class`, `exact_approval_scope_digest` | `test_recovery_class_is_bound_into_the_scope_digest`, `test_phase2_approval_binding.py::test_recovery_class_binding_is_part_of_the_approved_scope` |
| Trusted approval origin | `ExactApprovalGrant.approval_origin` (literal `trusted-electron`), ledger column `approval_origin` with `CHECK`, `issued_by` attestation column | `test_grant_binds_exact_scope_and_digest_is_stable`, `test_ledger_rejects_tampered_migration_ledger_and_schema` |
| Issued/expiry times, bounded use counts, revocation/invalidation state | `GrantIssuer` bounds (≤60 min, 1–8 uses), `exact_approval_grant_state` row | `test_issuance_bounds_lifetime_uses_and_tier`, `test_expiry_denies_consume_and_reports_state` |
| No wildcard permissions, no blanket T2, no future unknown edits, no scope expansion | `ExactApprovalGrant` validators + ledger trigger `exact_approval_grants_scope_no_update` | `test_no_wildcard_or_blanket_tier_grant_can_be_built`, `test_scope_row_and_ledgers_are_immutable`, `test_duplicate_issuance_is_idempotent_and_conflicts_on_scope_change` |

### B. Trustworthy issuance prerequisites

| Requirement | Code | Tests |
|---|---|---|
| `NON_AUTHORIZING_AUDIT_RECORD` is review evidence only | `issuance.py` requires `AuthorizingProof`; ledger never reads `approval_records` | `test_issuance_requires_authorizing_proof_never_review_evidence` |
| A renderer `APPROVE` / client claim of `trusted-electron` never authorizes | no IPC/HTTP issuer exists; proof cannot be constructed directly | `test_authorizing_proof_cannot_be_constructed_by_production_code`, `test_only_test_simulation_subclass_ships` |
| A model proposal never authorizes | `GrantIssuer` only accepts a persisted plan + proof | `test_issuance_requires_current_persisted_plan` |
| A synthetic dev preview never authorizes | dev seams are untouched; no grant path reads them | `test_synthetic_preview_review_cannot_produce_a_grant` |
| Explicit user action authenticated at the Electron-main/backend boundary | `AuthorizingProof` capability contract (documented, **no production subclass**) | `test_only_test_simulation_subclass_ships`, `test_no_production_module_issues_grants_or_exposes_ipc` |
| Production issuance disabled where the mechanism is absent | no production subclass; `GrantIssuer` is unreachable from API/desktop | same two tests |
| No ambiguous second approval; Stage 3 approve button not upgraded | `apps/desktop` unchanged | desktop suite unchanged (55/55 Node, 6/6 Python) |

### C. Durable grant persistence and revocation

| Requirement | Code | Tests |
|---|---|---|
| Transactional persistence on the existing SQLite architecture and its security rules | `GrantLedger` (raw-path validation, safe-storage path, 0600, `synchronous=FULL`, `secure_delete`, `quick_check`, `foreign_key_check`) | `test_grant_file_permissions_are_private`, `test_unsafe_database_paths_fail_closed` |
| Schema versioning; never apply migrations implicitly | `_verify_v2_schema` fail-closed, `GrantUnavailableError` on v1 | `test_ledger_refuses_v1_database_without_the_approved_migration`, `test_grant_ledger_never_applies_migrations` |
| Scope-digest validation of persisted grants | `_grant_from_row` recomputes `exact_approval_scope_digest` and cross-checks every scope column | `test_ledger_rejects_tampered_migration_ledger_and_schema` |
| Grant state, use limits, expiry, revocation | `exact_approval_grant_state` + guarded-update trigger | `test_expiry_denies_consume_and_reports_state`, `test_revocation_blocks_use_and_is_idempotent`, `test_exhaustion_replay_and_duplicate_consumption` |
| Plan changes invalidate grants | plan revision/hash bound in scope and re-validated on every use | `test_grant_binds_exact_scope_and_digest_is_stable`, `test_substitution_of_task_plan_step_or_effect_denies` |
| Replay resistance and duplicate issuance | `UNIQUE(issuance_key)`, `consumption_id` idempotency ledger | `test_duplicate_issuance_is_idempotent_and_conflicts_on_scope_change`, `test_exhaustion_replay_and_duplicate_consumption` |
| Crash/restart integrity | all-or-nothing transactions; committed state survives reopen | `test_crash_restart_preserves_committed_state`, `test_transactional_failure_leaves_no_partial_consumption` |
| Concurrency and transactional failure | `BEGIN IMMEDIATE` + compare-and-decrement | `test_concurrent_consumption_never_overspends` |
| Append-only lifecycle evidence | `exact_approval_grant_events` triggers | `test_scope_row_and_ledgers_are_immutable` |

### D. Fail-closed policy integration

| Requirement | Code | Tests |
|---|---|---|
| Deterministic broker integration, no execution | `PolicyBroker.evaluate(request, grant=..., now=...)` | `test_validated_exact_grant_verifies_scope_but_still_enables_no_executor` |
| Expired/stale/revoked/exhausted/mismatched/forged grants deny | `GrantAuthority.check_action` → `check_grant_scope` | `test_expired_revoked_exhausted_or_absent_grants_deny`, `test_grant_authority_rejects_unknown_and_forged_grant_ids` |
| No resources outside canonical registered scope | `check_grant_scope` set-equality on resource ids/versions; registry checked first by the broker | `test_resource_substitution_scope_widening_and_stale_versions_deny` |
| T3 remains unavailable | `ExactApprovalGrant` rejects `max_tier > MODIFY`; broker denies T3 before grants | `test_t3_requests_remain_denied_even_with_a_maximum_grant` |
| Unconfigured grant authority fails closed | `GrantAuthority(None)` → `GRANT_AUTHORITY_UNAVAILABLE` | `test_grant_authority_fails_closed_without_a_ledger`, `test_broker_without_grant_still_denies_t2` |

---

## 3. Security model of the Stage 4 boundary

**Authorization is still unavailable.** The single strongest outcome this branch can
produce for a T2 request is:

```
allowed=False
reason_code="GRANT_VALIDATED_EXECUTOR_NOT_ENABLED"
```

That code means *the persisted grant exactly matched the proposed action and every
closed check passed*, and nothing was authorized, consumed or executed. Consumption
(`GrantLedger.consume`) exists so the use-accounting, replay and exhaustion semantics
are durable and adversarially tested **before** an executor could rely on them; the
policy broker never consumes.

**Issuance is disabled.** `AuthorizingProof.__init__` refuses direct construction, and
the only subclass shipped is `TestOnlyAuthorizingProof`. A production authorizing
interaction (authenticated user gesture → Electron main → backend attestation) does not
exist, so no production code path can obtain proof. A test in the suite scans the whole
`aether` package to prove nothing outside `core/grants` constructs a proof or an issuer.

**Review evidence is not authority.** The ledger never reads `approval_records`; the
Stage 3 channel, the Stage 2 approve button and the synthetic dev seeds
(`AETHER_REVIEW_*`) are untouched and cannot produce a grant.

**Scope is immutable, state is separate.** Approved scope (digest, JSON, plan binding,
tier, origin, issuance key, issued/expiry) lives in `exact_approval_grants` and is
protected by a no-update trigger. Uses and revocation live in
`exact_approval_grant_state`, whose guarded-update trigger only permits the exact
lifecycle transitions (−1 use / +1 consumption, or a one-way revocation). Spending a use
can therefore never rewrite the hashed scope.

**Integrity is verified, not assumed.** `GrantLedger` refuses to open unless
`user_version = 2`, the exact 30-object schema fingerprint matches, the migration ledger
row for version 2 matches the proposed file's SHA-256, and `quick_check` /
`foreign_key_check` pass. Persisted scope JSON is re-validated through Pydantic and its
digest recomputed on every load; use accounting must agree across the state row, the
consumption table and `CONSUMED` events.

---

## 4. Proposed migration — separate approval required

`backend/aether/core/persistence/proposed_migrations/0002_phase2b_stage4_grants.sql`

- SHA-256: `a91b431cd84ced700b443df8ed0ecce45316f5f9737d768d8f313cc59d1c18cb`
- Full version-2 schema fingerprint (30 objects, computed like
  `SQLiteTaskStore._verify_schema`): `f68447f63fe0c61313a8df30d09b572f74352f6860bcaf1678f06bf6565283f2`
- New objects: `exact_approval_grants`, `exact_approval_grant_state`,
  `exact_approval_grant_events`, `exact_approval_grant_consumptions`, two indexes, and
  seven triggers (append-only events/consumptions, immutable grant scope, no-delete and
  guarded-update on state).
- It lives in `proposed_migrations/`, is **not** in `migrations/`, is **not** in
  `_EXPECTED_MIGRATIONS`, and no production fingerprint references it.

Applying or merging it is a separate change that must also:

1. move the file to `aether/core/persistence/migrations/0002_phase2b_stage4_grants.sql`;
2. add `2: ("0002_phase2b_stage4_grants.sql", "<sha256>")` to `_EXPECTED_MIGRATIONS`;
3. add the version-2 schema fingerprint to `_EXPECTED_SCHEMA_SHA256`;
4. extend `_CRITICAL_TRIGGER_NAMES` with the Stage 4 triggers and the
   `_verify_schema` required-table set with the Stage 4 tables;
5. update `tests/test_phase2b_persistence.py` (version pins, packaged-migration-set
   assertions) and rebuild the backend wheel to confirm packaged bytes;
6. be explicitly approved by the user before it is applied or merged.

**Until that separate approval, `SQLiteTaskStore` stays pinned to version 1 and any
version-2 database is rejected by it.** Tests exercise the ledger against a temporary
migration directory registered through `monkeypatch` (`tests/stage4_support.py::stage4_store`),
which is the only place the proposed migration is ever applied — inside a test process,
on a `tmp_path` database.

---

## 5. Verification (Linux sandbox only)

Environment: `/tmp/aether-stage4-venv` (Python 3.11), editable backend install.

| Check | Result |
|---|---|
| `pytest tests` | **333 passed, 1 skipped** (skip = optional `AETHER_RUN_MODEL_INTEGRATION=1`); Stage 4 adds 47 (46 new + 1 recovery-binding test in `test_phase2_approval_binding.py`) |
| `ruff check .` | passed |
| `ruff format --check` (Stage 4 files) | passed |
| `mypy` (strict) | passed, 71 source files |
| Backend wheel/migration pins | unchanged (`0001` = `70907729…`, schema `02f3cac7…`) |
| Desktop `npm run check` | passed — ESLint clean, both TS projects, renderer build, **61 Node tests** (54 pass / 7 skipped by design), **6/6** Python child tests, Electron build |
| `scripts/generate_stage2_golden.py --check` | up to date |

Pre-existing noise, unchanged by this branch: 13 files repo-wide are not
`ruff format`-clean at baseline (the Stage 4 files are formatted), and a Starlette
`TestClient`/HTTPX deprecation warning remains non-failing.

**No Windows verification was performed.** Nothing here infers Windows filesystem,
ACL, reparse/junction, process or resource security from Linux results. Stage 4 is pure
in-process Python plus SQLite; the Windows acceptance items in
`docs/engineering/PHASE2A_RESOURCE_POLICY.md` remain open.

---

## 6. Adversarial coverage map

| Adversarial scenario (task requirement) | Test |
|---|---|
| Forged approval origin | `test_authorizing_proof_cannot_be_constructed_by_production_code`, `test_ledger_rejects_tampered_migration_ledger_and_schema` |
| Audit-only APPROVE misused as authorization | `test_issuance_requires_authorizing_proof_never_review_evidence` |
| Task / plan / step substitution | `test_substitution_of_task_plan_step_or_effect_denies` |
| Resource substitution | `test_resource_substitution_scope_widening_and_stale_versions_deny` |
| Stale content/state versions | same test (stale `observed_version`, unversioned ref) |
| Scope widening | `test_resource_substitution_scope_widening_and_stale_versions_deny`, `test_no_wildcard_or_blanket_tier_grant_can_be_built`, `test_duplicate_issuance_is_idempotent_and_conflicts_on_scope_change` |
| Grant expiry | `test_expiry_denies_consume_and_reports_state`, `test_expired_revoked_exhausted_or_absent_grants_deny` |
| Exhaustion | `test_exhaustion_replay_and_duplicate_consumption`, `test_concurrent_consumption_never_overspends` |
| Revocation | `test_revocation_blocks_use_and_is_idempotent`, `test_scope_row_and_ledgers_are_immutable` |
| Replay | `test_exhaustion_replay_and_duplicate_consumption` (idempotent replay, conflicting replay) |
| Duplicate issuance | `test_duplicate_issuance_is_idempotent_and_conflicts_on_scope_change` |
| Crash / restart integrity | `test_crash_restart_preserves_committed_state` |
| Concurrency | `test_concurrent_consumption_never_overspends` |
| Transactional failure | `test_transactional_failure_leaves_no_partial_consumption` |
| Unsupported T3 requests | `test_t3_requests_remain_denied_even_with_a_maximum_grant` |
| Synthetic development-source isolation | `test_synthetic_preview_review_cannot_produce_a_grant` |
| No production issuer / no IPC route | `test_no_production_module_issues_grants_or_exposes_ipc`, `test_only_test_simulation_subclass_ships` |
| Ledger never migrates | `test_grant_ledger_never_applies_migrations` |

---

## 7. Disabled capabilities and remaining limitations

- **No execution.** `GRANT_VALIDATED_EXECUTOR_NOT_ENABLED` is the ceiling; there is no
  adapter, no mutation, no shell, no IPC operation that performs work.
- **No production issuance.** The authenticated authorizing interaction (and a
  production planner/narrative source) is still absent.
- **T3 unavailable**, permanently, until a dedicated authorization design and its
  prerequisites are separately approved.
- **Trust boundary:** a same-user local attacker with write access to the database file
  can still tamper with it; the ledger detects schema, digest, accounting and migration
  tampering and fails closed, but SQLite is not a hardware root of trust. No claim is
  made about defeating a compromised local account.
- **Clock:** expiry/validity comparisons trust the machine clock supplied by the caller;
  there is no attested time source.
- **Consumption is not yet wired to a real action**, so "one use = one action" is proven
  only transactionally, not end-to-end.

---

## 8. Next dependency-ordered steps

1. **Separately approved production migration** (Section 4) — move `0002` into
   `migrations/`, update the store's pins/trigger list and its tests, verify packaged
   bytes, then merge.
2. **Trustworthy production plan/preview source + authorizing UI integration** — an
   authenticated authorizing interaction at the Electron-main/backend boundary that can
   mint an `AuthorizingProof`, plus the planner/narrative source that makes previews
   non-synthetic. Until this exists, issuance stays disabled.
3. **Windows-safe read/search/open adapters (Phase 2C)** — T0/T1 execution with receipts
   and Windows path/ACL/reparse validation on the target laptop.
4. **Exact approved recoverable edits (Phase 2D)** — T2 execution bound to a consumed
   grant, then verified receipts.
5. **Undo Vault + authenticated restoration**, then full Phase 2 acceptance on the target
   Windows system.
