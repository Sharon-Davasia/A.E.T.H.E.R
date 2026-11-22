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
| Issuance prerequisites | `aether/core/grants/attestation.py` — `AuthorizationAttestation` data contract + injected `AttestationVerifier`; `aether/core/grants/issuance.py` — `GrantIssuer`. Nothing test-only is exported. |
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
| `NON_AUTHORIZING_AUDIT_RECORD` is review evidence only | `issuance.py` requires a verified `AuthorizationAttestation`; the ledger never reads `approval_records` | `test_issuance_requires_attestation_never_review_evidence`, `test_synthetic_preview_review_cannot_produce_a_grant` |
| A renderer `APPROVE` / client claim of `trusted-electron` never authorizes | no IPC/HTTP issuer exists; proof cannot be constructed directly | `test_authorizing_proof_cannot_be_constructed_by_production_code`, `test_only_test_simulation_subclass_ships` |
| A model proposal never authorizes | `GrantIssuer` only accepts a persisted plan + proof | `test_issuance_requires_current_persisted_plan` |
| A synthetic dev preview never authorizes | dev seams are untouched; no grant path reads them | `test_synthetic_preview_review_cannot_produce_a_grant` |
| Explicit user action authenticated at the Electron-main/backend boundary | `attestation.py` contract + injected verifier; production ships `NullAttestationVerifier` only | `test_production_verifier_denies_all_issuance`, `test_production_package_exports_no_test_only_or_inheritance_path` |
| Attestation binds task / plan revision+hash / preview / scope / issuer / freshness | `issuance.py::_check_attestation` replays every binding field | `test_attestation_must_bind_this_exact_authorization`, `test_attestation_from_another_task_cannot_authorize`, `test_attestation_expiry_must_cover_the_grant`, `test_forged_origin_and_expired_attestation_are_rejected_by_contract` |
| Python class identity is not a trust boundary | trust = validated data + injected verifier; no `isinstance` gate, no shipped subclass | `test_production_package_exports_no_test_only_or_inheritance_path`, `test_attestation_is_validated_data_not_a_duck_typed_object` |
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

**Issuance is disabled.** Authorization is a *data* contract plus an injected verifier,
not an inheritance hierarchy:

* `AuthorizationAttestation` (frozen, `extra="forbid"`, `strict=True`) binds the
  authorization identity, trusted authority id, exact task, plan revision/hash, the preview
  id and digest the user saw, the approved-scope digest, and its own ≤60-minute window.
* `GrantIssuer` re-derives the scope digest from the grant it is about to persist and
  requires the attestation to match task, plan revision, plan hash and scope digest
  exactly, to have been authorized no later than the grant's issue time, and to expire no
  earlier than the grant does.
* The trust decision is `AttestationVerifier.verify(...)`, injected at construction.
  Production ships `NullAttestationVerifier` (`PRODUCTION_ATTESTATION_VERIFIER`), which
  rejects everything, so **production issuance is disabled**. A claim whose
  `authority_id` does not match the configured verifier is refused before verification.
* Nothing test-only is exported: `aether.core.grants.__all__` contains no
  `AuthorizingProof`/`TestOnly*` names, and the test simulation lives only in
  `backend/tests/stage4_support.py`. A source-scan test asserts no module outside
  `core/grants` constructs an issuer or an attestation.

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

- SHA-256: `d2a02f54bc2f0eaee19fe1fd29c58294efbb136565145866d3c4853b8d64571c`
  (supersedes the earlier proposed `a91b431c…`, which is **not** approved and must be
  discarded)
- Full version-2 schema fingerprint (30 objects, computed like
  `SQLiteTaskStore._verify_schema`): `dec68c2c1ecdd6d7222b5dcff54b877c9895e5cee6329930148c5db97355b788`
  (30 objects, unchanged count; supersedes `f68447f6…`)
- New objects: `exact_approval_grants`, `exact_approval_grant_state`,
  `exact_approval_grant_events`, `exact_approval_grant_consumptions`, two indexes, and
  seven triggers (append-only events/consumptions, immutable grant scope, no-delete and
  guarded-update on state).
- Columns added by the review corrections:
  `exact_approval_grants.issuance_digest` (full immutable authorization intent, S4-2) and
  `exact_approval_grants.issued_by` (bounded issuer code, S4-5);
  `exact_approval_grant_consumptions.risk_tier`, `.arguments_sha256`,
  `.expected_effect_sha256`, `.resource_versions_digest`, `.action_digest`,
  `.consumed_by` (complete action binding, S4-3);
  `exact_approval_grant_events.reason_code` and
  `exact_approval_grant_state.revocation_code` replace free-text revocation reasons with
  bounded machine-readable codes (`CHECK … GLOB '[A-Z]*'`), plus
  `CHECK ((revoked_at IS NULL) = (revocation_code IS NULL))` (S4-5).
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
| `pytest tests` | **401 passed, 1 skipped** (skip = optional `AETHER_RUN_MODEL_INTEGRATION=1`); Stage 4 adds 115 (114 in `test_phase2b_stage4_grants.py` + 1 recovery-binding test in `test_phase2_approval_binding.py`) |
| `ruff check .` | passed |
| `ruff format --check` (Stage 4 files) | passed |
| `mypy` (strict) | passed, 73 source files |
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
| Forged approval origin | `test_production_verifier_denies_all_issuance`, `test_attestation_must_bind_this_exact_authorization`, `test_forged_origin_and_expired_attestation_are_rejected_by_contract`, `test_production_package_exports_no_test_only_or_inheritance_path` |
| Audit-only APPROVE misused as authorization | `test_issuance_requires_attestation_never_review_evidence` |
| Task / plan / step substitution | `test_substitution_of_task_plan_step_or_effect_denies`, `test_attestation_from_another_task_cannot_authorize` |
| Resource substitution | `test_resource_substitution_scope_widening_and_stale_versions_deny` |
| Stale content/state versions | same test (stale `observed_version`, unversioned ref) |
| Scope widening | `test_resource_substitution_scope_widening_and_stale_versions_deny`, `test_no_wildcard_or_blanket_tier_grant_can_be_built`, `test_duplicate_issuance_is_idempotent_and_conflicts_on_scope_change` |
| Grant expiry | `test_expiry_denies_consume_and_reports_state`, `test_expired_revoked_exhausted_or_absent_grants_deny` |
| Exhaustion | `test_exhaustion_replay_and_duplicate_consumption`, `test_concurrent_consumption_never_overspends` |
| Revocation | `test_revocation_is_bounded_code_and_idempotent`, `test_scope_rows_and_ledgers_are_immutable` |
| Replay (issuance) | `test_replay_with_changed_authorization_terms_is_a_conflict`, `test_replay_with_changed_issuer_identity_is_a_conflict`, `test_supplied_scope_digest_is_verified_independently`, `test_duplicate_issuance_is_idempotent_only_for_identical_terms` |
| Replay (consumption) | `test_exact_consumption_replay_is_idempotent`, `test_consumption_replay_with_changed_action_terms_fails_closed`, `test_consumption_replay_binding_survives_reopen` |
| Superseded plan / invalidated consent | `test_issued_grant_is_denied_after_the_plan_advances`, `test_use_is_denied_once_the_task_leaves_consent_states`, `test_issuance_refuses_tasks_outside_consent_states_and_invalidated_consent`, `test_issuance_rechecks_the_plan_inside_its_transaction`, `test_current_plan_check_and_decrement_are_atomic_under_concurrency` |
| Ownership / audit privacy | `test_ledger_shares_the_store_connection_and_lock`, `test_ledger_write_is_rolled_back_with_the_task_transaction`, `test_standalone_ledger_cannot_take_ownership_from_a_store`, `test_standalone_ledgers_are_mutually_exclusive`, `test_read_only_handle_verifies_and_cannot_write`, `test_free_text_audit_metadata_is_refused`, `test_consumption_consumer_code_is_bounded` |
| Duplicate issuance | `test_duplicate_issuance_is_idempotent_only_for_identical_terms` |
| Crash / restart integrity | `test_crash_restart_preserves_committed_state` |
| Concurrency | `test_concurrent_consumption_never_overspends`, `test_current_plan_check_and_decrement_are_atomic_under_concurrency` |
| Transactional failure | `test_transactional_failure_leaves_no_partial_consumption` |
| Unsupported T3 requests | `test_t3_requests_remain_denied_even_with_a_maximum_grant` |
| Synthetic development-source isolation | `test_synthetic_preview_review_cannot_produce_a_grant` |
| No production issuer / no IPC route | `test_no_production_module_issues_grants_or_exposes_ipc`, `test_production_package_exports_no_test_only_or_inheritance_path` |
| Ledger never migrates | `test_grant_ledger_never_applies_migrations` |

---

## 6b. Independent-review corrections (S4-1 … S4-5)

The first review of PR #13 requested five corrections. All are implemented on the same
branch; none enables issuance, execution or a migration.

| Finding | Code-level resolution | Tests |
|---|---|---|
| **S4-1** — `AuthorizingProof` accepted arbitrary subclasses and test-only proof was exported; the proof bound no task/plan/preview/scope | Replaced the capability-class hierarchy with `AuthorizationAttestation` (frozen, strict, `extra="forbid"`) binding authorization id, authority id, task, plan revision/hash, preview id + digest, scope digest and a ≤60-min window. Trust is an injected `AttestationVerifier`; production ships only `NullAttestationVerifier`, so issuance is disabled. `issuance.py` re-derives the scope digest and replays every binding field, refusing a mismatched authority label before any verification. No test-only class is exported; the simulation lives in `backend/tests/stage4_support.py`. | `test_production_package_exports_no_test_only_or_inheritance_path`, `test_production_verifier_denies_all_issuance`, `test_attestation_is_validated_data_not_a_duck_typed_object`, `test_attestation_must_bind_this_exact_authorization`, `test_attestation_from_another_task_cannot_authorize`, `test_attestation_expiry_must_cover_the_grant`, `test_forged_origin_and_expired_attestation_are_rejected_by_contract` |
| **S4-2** — issuance replay keyed on a scope digest that excluded immutable authorization terms | `issue()` now verifies the *supplied* digest against the computed one and persists `issuance_digest = issuance_intent_digest(scope_digest, task, plan revision/hash, tier, issued/expiry, initial uses, issuer)`. Replay with any changed term is `GrantConflictError`; identical replay stays idempotent. `_grant_from_row` recomputes the intent digest from persisted columns on every load. | `test_supplied_scope_digest_is_verified_independently`, `test_replay_with_changed_authorization_terms_is_a_conflict`, `test_replay_with_changed_issuer_identity_is_a_conflict`, `test_issuance_intent_digest_covers_every_immutable_term` |
| **S4-3** — consumption replay ignored risk tier, argument/effect hashes and resource versions | Consumptions now persist and compare a complete `action_digest` (plus the individual `risk_tier`, `arguments_sha256`, `expected_effect_sha256`, `resource_versions_digest`, `consumed_by` columns). Identical retry returns the committed consumption; any changed action field raises `GrantConflictError`, including after reopen. | `test_exact_consumption_replay_is_idempotent`, `test_consumption_replay_with_changed_action_terms_fails_closed`, `test_consumption_replay_binding_survives_reopen`, `test_consumption_action_digest_covers_every_action_field` |
| **S4-4** — validation trusted caller-supplied historical plan identities | Issuance requires the task to exist in a consent-bearing state, be free of fresh-consent blockers, and match the **current** persisted plan; it re-checks the task pointer *inside* the issuing transaction. Consumption re-reads the task state/plan pointer inside the decrement transaction (`GRANT_PLAN_SUPERSEDED` / `TASK_STATE_NOT_AUTHORIZABLE`). `GrantAuthority` accepts an optional store and performs the same current-plan check after scope validation. Recovery class is compared with the persisted plan step's trusted value. | `test_issued_grant_is_denied_after_the_plan_advances`, `test_use_is_denied_once_the_task_leaves_consent_states`, `test_issuance_refuses_tasks_outside_consent_states_and_invalidated_consent`, `test_issuance_rechecks_the_plan_inside_its_transaction`, `test_current_plan_check_and_decrement_are_atomic_under_concurrency`, `test_recovery_class_comes_from_the_trusted_plan_step` |
| **S4-5** — second connection risked weakening store ownership; audit text was unrestricted | `GrantLedger.open(store)` **shares** the store's owner lock and single connection and reuses the store's `BEGIN IMMEDIATE` transaction (location verified before/after commit), so ownership, atomicity and recovery invariants are untouched; one ledger per store. `read_only()` is an explicit `mode=ro` verification handle and the path-only constructor refuses while a store owns the database. Event `detail` is restricted to allow-listed keys with boolean/integer/bounded-code/digest/timestamp values; revocation and consumer identity are bounded codes (`REVOCATION_CODES`, `CONSUMED_BY_CODES`) with `CHECK … GLOB` constraints, never free text. | `test_ledger_shares_the_store_connection_and_lock`, `test_ledger_write_is_rolled_back_with_the_task_transaction`, `test_store_still_enforces_single_owner_while_ledger_is_open`, `test_standalone_ledger_cannot_take_ownership_from_a_store`, `test_standalone_ledgers_are_mutually_exclusive`, `test_read_only_handle_verifies_and_cannot_write`, `test_free_text_audit_metadata_is_refused`, `test_consumption_consumer_code_is_bounded` |

## 6c. Second-round corrections (S4-6 … S4-8)

The second review accepted S4-1…S4-5 and required three further corrections. They are
implemented on the same branch; still no issuance, execution, IPC or migration.

| Finding | Code-level resolution | Tests |
|---|---|---|
| **S4-6** — `GrantLedger.issue()` could persist a grant with no verified authorization evidence | Authorization is now established *before* storage and storage is not an authorization path. `GrantLedger.issue()` is removed; the only write primitive is the private `GrantLedger._persist_verified_grant(...)`, whose first argument is a `permit:` keyword that accepts nothing but a single-use `IssuancePermit`. Permits are minted only by the central decision (§6d, S4-9), are bound to the exact scope digest and issuer identity, and are consumed on first use (`ISSUANCE_PERMIT_ALREADY_USED` / `ISSUANCE_PERMIT_MISMATCH`). Anything else — `None`, a plain object, a namespace, a subclass-like stand-in — is refused with `AUTHORIZATION_EVIDENCE_REQUIRED` before a database handle is touched. Preview identity is now verified against **authoritative preview evidence**: new `PreviewAuthority` contract plus `AuthoritativePreview`; `GrantIssuer` requires the attestation's `preview_id`/`preview_digest` to equal what the injected source resolves for this task/revision/hash (`PREVIEW_IDENTITY_MISMATCH`, `PREVIEW_SOURCE_MISMATCH`). The shipped default is `NullPreviewAuthority`, which raises `PREVIEW_SOURCE_UNAVAILABLE`: no production preview source exists in this phase, so that verification is explicitly unavailable and production issuance stays disabled rather than silently skipped. Class identity/inheritance is still never an authentication boundary, and the only simulation (`SimulatedAttestationVerifier`, `SimulatedPreviewAuthority`) lives in `backend/tests/stage4_support.py`. No authorizing IPC was added. | `test_no_ledger_entry_point_can_persist_a_grant_without_authorization`, `test_issuance_permit_is_single_use_and_bound_to_its_scope`, `test_production_default_has_no_preview_source_and_stays_disabled`, `test_permit_subclass_cannot_inherit_authorization_and_override_is_ignored`, `test_forged_preview_identity_is_rejected_against_authoritative_evidence`, `test_verified_preview_identity_is_required_for_successful_issuance`, `test_preview_source_failures_fail_closed`, `test_production_verifier_denies_all_issuance`, `test_no_production_module_issues_grants_or_exposes_ipc` (now also scans for `_persist_verified_grant` / `IssuancePermit`) |
| **S4-7** — revocation/fresh-consent was checked only before the transaction | `GrantLedger._check_fresh_consent()` runs inside the same transaction as the grant insert **and** inside the decrement transaction, delegating to the store's existing Stage 2 predicate `SQLiteTaskStore.is_stage2_preview_blocked()` (the `APPROVAL_PREVIEW_REVOKED` / `requires_fresh_plan_and_consent` event semantics). No second consent system. It additionally refuses if the store's connection is not the transaction's connection (`CONSENT_AUTHORITY_UNAVAILABLE`), so the check cannot silently read outside the write. Denials are `CONSENT_INVALIDATED` with no grant row, no consumption row and no use decrement; a revocation after issuance denies use even when task state and plan identity are unchanged. | `test_revocation_between_issuance_precheck_and_transaction_denies` (asserts the denial came from the in-transaction check), `test_revocation_after_issuance_denies_consumption_without_decrement`, `test_consent_check_is_shared_with_the_store_not_reimplemented`, `test_standalone_ledger_cannot_verify_consent_and_fails_closed` |
| **S4-8** — `GrantAuthority(store=None)` skipped current-plan checks; shared-connection reads were unsynchronized | `GrantAuthority.check_action` fails closed with `GRANT_CURRENT_PLAN_AUTHORITY_REQUIRED` when no current-plan authority is supplied — no success is reportable without checking the authoritative current task/plan. Grant load and the current task/plan/consent reads now happen inside one consistent snapshot guarded by the store's lock, so historical grants deny after supersession and a reader cannot observe uncommitted task/grant state. `GrantLedger.open(store)` adopts the store's `_lock` as its own (`ledger._lock is store._lock`), keeping the single-owner/one-connection design: there is still exactly one connection and one serialization mechanism. | `test_grant_authority_without_store_fails_closed`, `test_historical_grant_denies_after_supersession_without_store`, `test_shared_connection_reads_take_the_store_lock`, `test_reader_cannot_observe_an_uncommitted_grant_write` |

## 6d. Third-round correction (S4-9) — trust provenance, not permit objects

The third review accepted S4-7 and S4-8 and found that S4-6 was still only partially
resolved: `IssuancePermit._mint()` was callable by ordinary Python code, so a permit object
(and the tests that used one) proved nothing about whether a verifier or preview source ever
ran. `IssuancePermit` is therefore no longer treated as authentication at all. Trust is the
outcome of a **single decision procedure**, in one module:

`backend/aether/core/grants/authorization.py` — the only two factories for a permit:

| Factory | Outcome | Accepted by |
|---|---|---|
| `authorize_issuance(attestation, grant=…, scope_digest=…, attestations=…, previews=…)` | `trust_source="trusted_verifier"`, bound to task/plan/scope/issuance identity | any ledger |
| `authorize_test_persistence(...)` | `trust_source="test_simulation"`, records the requesting module | **only** `GrantLedger.open_tests_scoped(store)` **and** an allow-listed test module |

Consequences:

- **One decision.** `authorize_issuance` owns the whole authorization test — attested-field
  replay against the exact grant, the injected `AttestationVerifier`, and the authoritative
  `PreviewAuthority` — and mints a permit only if all of it passes. `GrantIssuer` no longer
  contains attestation or preview checks; it builds the exact grant from persisted state,
  calls the gate, and persists. There is no second copy of the checks to drift and no
  caller-supplied path around it. Operation/plan binding moved to the same module
  (`check_operation_binding`) so the trust-relevant checks live together.
- **Production storage fails closed.** `GrantLedger.open(store)` (the default,
  production-configured entry point) sets `_trust_source_policy = "production"`. As shipped in
  `8570bc1` this rejected permits whose *fields* did not match; re-review correctly showed that
  field validation cannot establish provenance, so §6e replaces it with a configuration-level
  denial of all new issuance (`GRANT_ISSUANCE_DISABLED`) evaluated before the permit is read.
  Grant rows, state rows, events and consumptions all stay at zero on the denied path.
- **Default-deny preserved.** Production still ships `NullAttestationVerifier` +
  `NullPreviewAuthority`, so `authorize_issuance` always raises
  (`AUTHORIZATION_SOURCE_NOT_TRUSTED` / `PREVIEW_SOURCE_UNAVAILABLE`), *and* (§6e) the
  production-configured ledger refuses all new issuance regardless of the permit. No
  production verifier and no production preview source exist; the authenticated Electron
  main → backend interaction remains unimplemented and no authorizing IPC was added.
- **Test simulation isolated.** Low-level ledger semantics (replay, rollback, immutability)
  still use real persistence, via `authorize_test_persistence` + `open_tests_scoped`. Three
  independent conditions are required (test-scoped ledger instance, allow-listed requesting
  module, `test_simulation` permit), none of which exists in a production configuration. The
  allow-list (`TEST_AUTHORIZATION_MODULES`) is canonical in `ledger.py` and asserted at
  import time to contain no `aether.` module; `open_tests_scoped` and
  `authorize_test_persistence` are not exported from `aether.core.grants`.
- **Stated trusted-code assumptions.** This is an in-process Python boundary, not an OS
  capability. Arbitrary code *running inside the backend process* can reach module internals;
  no object, subclass check, private name or module constant is claimed to be unforgeable.
  What is guaranteed is structural: the production-configured storage boundary only accepts
  the output of the central decision, and that decision's only success path requires a
  verifier and preview source that production does not have. The module docstring states this
  explicitly rather than implying stronger guarantees.
- **Opening is serialized too.** `GrantLedger.open(store)` now performs construction *and*
  its initial `quick_check`/`foreign_key_check`/schema-fingerprint reads under the store's
  lock, not only after adopting it, so an opening ledger cannot validate uncommitted
  state from another thread's in-flight transaction.

| Requirement | Tests |
|---|---|
| Direct permit construction cannot create a grant through the default production-configured ledger; zero grant rows, grant events and consumptions | `test_direct_permit_construction_cannot_write_through_the_default_ledger` (also asserts zero `exact_approval_grant_state` rows), `test_permit_minting_is_not_authorization`, `test_permit_subclass_cannot_inherit_authorization_and_override_is_ignored`, `test_no_ledger_entry_point_can_persist_a_grant_without_authorization` |
| The central decision is the only source of a trusted permit; the decision binds the exact authorization | `test_central_decision_is_the_only_source_of_a_trusted_permit`, `test_trusted_decision_permit_is_bound_to_the_exact_authorization` |
| Test-only mechanisms are isolated from production-capable configurations | `test_test_only_configuration_is_isolated_from_the_shipped_package`, `test_production_package_exports_no_test_only_authorization_surface`, `test_no_production_module_issues_grants_or_exposes_ipc` |
| `open()` integrity/schema reads run under the store lock | `test_open_runs_initial_integrity_reads_under_the_store_lock`, `test_open_serializes_with_a_concurrent_store_transaction` |
| Positive synthetic issuance and exact idempotent replay still work | `test_verified_preview_identity_is_required_for_successful_issuance`, `test_issued_grant_is_denied_after_the_plan_advances` (fresh-revision issuance), `test_replay_with_changed_authorization_terms_is_a_conflict`, `test_replay_with_changed_issuer_identity_is_a_conflict`, `test_issuance_permit_is_single_use_and_bound_to_its_scope` |

## 6e. Final boundary closure — production issuance is configurationally denied

Re-review at `8570bc1` accepted the central decision, the test-only separation, the
transactional consent checks and the SQLite synchronization, and found one remaining gap:
`_check_permit_trust` validated a permit's *fields*, but a permit is an ordinary Python
object, so a hand-built permit carrying `trust_source="trusted_verifier"` plus a complete
matching binding was indistinguishable from the real thing. Field validation therefore never
established the claimed provenance.

The boundary is now closed by **configuration, not by credential**:

- `GrantLedger.open(store)` — the default, production-configured entry point — refuses **all
  new grant issuance** with `GRANT_ISSUANCE_DISABLED`. The check runs *before* the permit is
  inspected or spent, so no caller-supplied object (exact-type, correctly labelled, correctly
  bound, or obtained from `authorize_issuance` itself) can enable production issuance.
- Reads, status, revocation and **consumption** of grants that already exist are unaffected:
  the denial is confined to issuance, so the configuration is not a blanket outage.
- The attestation contract, the authoritative-preview contract and the single central
  decision (`authorize_issuance`) are preserved untouched for future integration. They are
  retained and exercised on the test-scoped path; they are not a production capability today.
- `activate` is deliberately not a runtime flag, constructor argument, environment variable
  or permit kind. Enabling production issuance requires the separately reviewed authenticated
  authorizing boundary to be implemented and this gate to be changed in code.
- Test-scoped configuration (`GrantLedger.open_tests_scoped`, allow-listed modules only)
  accepts the central decision's permit as well as the isolated `test_simulation` permit, so
  the real issuance path keeps end-to-end positive coverage plus exact idempotent replay.

No further permit hierarchy, security framework or refactor was introduced. The full denial
surface is a single `if` on the ledger's own configuration.

| Requirement | Tests |
|---|---|
| Production-configured ledger refuses an exact-type permit with `trust_source="trusted_verifier"`, correct task, plan, scope digest, issuer and issuance key — zero grant/state/event/consumption rows | `test_default_production_ledger_refuses_a_perfectly_forged_permit` |
| Even a permit minted by `authorize_issuance()` cannot enable production issuance | `test_default_production_ledger_refuses_the_central_decision_too` |
| The production issuer path denies closed with the same code before storage | `test_production_issuance_fails_closed_without_any_permit` |
| Default-deny is confined to issuance; existing grants still read and consume | `test_production_configuration_can_still_read_and_consume_existing_grants` |
| Positive synthetic issuance, exact replay and ledger semantics still covered | `test_verified_preview_identity_is_required_for_successful_issuance`, `test_issuance_permit_is_single_use_and_bound_to_its_scope`, `test_trusted_decision_permit_is_bound_to_the_exact_authorization`, `test_replay_with_changed_authorization_terms_is_a_conflict`, `test_replay_with_changed_issuer_identity_is_a_conflict`, `test_exact_consumption_replay_is_idempotent` |
| No production module gains an issuance path | `test_no_production_module_issues_grants_or_exposes_ipc`, `test_production_package_exports_no_test_only_authorization_surface`, `test_test_only_configuration_is_isolated_from_the_shipped_package` |

### Remaining limitation (explicit)

Production issuance is **off**, and it is off because the authenticated authorizing boundary
does not exist — not because a Python object is unforgeable. Any code able to run inside the
backend process can reach internals; what it cannot do is make the production-configured
ledger accept a new grant, because that ledger denies issuance by configuration. Turning it on
is future, separately reviewed work that must supply a real attestation verifier and a real
authoritative preview source and change this gate.

### Migration-control outcome (third round)

Unchanged again: no schema delta was required, so the proposed artefacts stand as reported.

### Migration-control outcome (second round)

The proposed migration bytes did **not** change in this round: no column or trigger was
needed, because the authorized-preview binding is derived from existing plan/preview
evidence and the revocation/consent state is already the Stage 2 `task_events` audit
stream. Pins therefore remain:

- proposed migration SHA-256: `d2a02f54bc2f0eaee19fe1fd29c58294efbb136565145866d3c4853b8d64571c`
- complete version-2 schema fingerprint: `dec68c2c1ecdd6d7222b5dcff54b877c9895e5cee6329930148c5db97355b788`
  (30 objects, `user_version = 2`)
- still proposed, inert, unregistered and never applied; production schema pins unchanged
  (v1 `70907729…` / `02f3cac7…`).

### Migration-control outcome (first round, S4-1 … S4-5)

The proposed migration's **bytes changed** for S4-2/S4-3/S4-5 and the artefacts were
regenerated, not carried over:

- proposed migration SHA-256: `d2a02f54bc2f0eaee19fe1fd29c58294efbb136565145866d3c4853b8d64571c`
  (previous, now **unapproved and superseded**: `a91b431c…`)
- complete version-2 schema fingerprint: `dec68c2c1ecdd6d7222b5dcff54b877c9895e5cee6329930148c5db97355b788`
  (previous: `f68447f6…`), still 30 objects
- the file remains in `proposed_migrations/`, unregistered, unfingerprinted by
  `SQLiteTaskStore`, and every test applies it only through a `monkeypatch`-scoped
  temporary migrations directory.

### Windows-specific acceptance items for this design (not Linux-inferred)

- POSIX shares the database inode for the owner lock; Windows uses the `msvcrt` sidecar.
  The shared-ownership design means the ledger never opens a lock of its own in production,
  but the store's Windows sidecar semantics (contention, pathname replacement) still need
  target-machine verification.
- Windows ACLs (rather than POSIX `0600`) must be verified for the database and, in
  standalone/read-only diagnostics, for the sidecar and `mode=ro` handle.
- Junction/reparse and volume-identity checks are exercised on POSIX only here.

## 7. Disabled capabilities and remaining limitations

- **No execution.** `GRANT_VALIDATED_EXECUTOR_NOT_ENABLED` is the ceiling; there is no
  adapter, no mutation, no shell, no IPC operation that performs work.
- **No production issuance.** The authenticated authorizing interaction is still absent,
  and so is a production preview source: `PRODUCTION_PREVIEW_AUTHORITY` is
  `NullPreviewAuthority`, which raises `PREVIEW_SOURCE_UNAVAILABLE`. Preview identity
  therefore cannot be verified in production, and issuance is explicitly disabled rather
  than unverified. Wiring a real preview source is a prerequisite for the production
  verifier, not a substitute for it.
- **T3 unavailable**, permanently, until a dedicated authorization design and its
  prerequisites are separately approved.
- **Attestation trust:** `AuthorizationAttestation` is a *claim*. Its trustworthiness is
  entirely the injected verifier's responsibility; the repair path is a production verifier
  backed by an authenticated channel, not a data-shape check.
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
   assert trust (a production `AttestationVerifier` bound to an authenticated
   Electron-main→backend attestation, plus the planner/narrative source that makes previews
   non-synthetic). Until both exist, issuance stays disabled.
3. **Windows-safe read/search/open adapters (Phase 2C)** — T0/T1 execution with receipts
   and Windows path/ACL/reparse validation on the target laptop.
4. **Exact approved recoverable edits (Phase 2D)** — T2 execution bound to a consumed
   grant, then verified receipts.
5. **Undo Vault + authenticated restoration**, then full Phase 2 acceptance on the target
   Windows system.
