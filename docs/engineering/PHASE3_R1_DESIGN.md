# Phase 3 R1 Design — Execution-State and Evidence Architecture (DESIGN ONLY)

**Status:** Proposal for review before CP3. **No new execution
transition is activated by this document or the CP0–CP2 batch.**
`ACTIVE_SCHEMA_VERSION` remains 2; no schema v3 is authorized. The
existing `_EXECUTION_TRANSITIONS` and Phase 2 grant/consumption/
receipt-hash requirements are unchanged.

## 1. Operation classes and evidence classes

| Class | Operations | Evidence class (proposed) |
|---|---|---|
| T0 observation | observe/discover/resolve/inspect | No execution transition; observations are in-memory WorldState evidence only, never durable success claims |
| T1 navigation | `app.launch`, `window.activate` (later CP3) | **Navigation evidence**: durable attempt record + observed postcondition verification record (below); *no filesystem grant is fabricated* |
| T2 UI mutation | Exactly bound UI operations (CP5+) | Existing Phase 2 exact-grant stack extended only via the separate UI-operation binding (ADR-015); unchanged fs requirements |
| T3 | install/send/delete via UI, elevated launch | Denied; no evidence class can authorize |

The store must derive the applicable evidence class from the
*persisted plan step's registered capability id* (looked up in the
trusted capability registry), never from caller/renderer/model
assertions or caller-selected risk labels. A T1-class capability can
only ever satisfy navigation evidence; it cannot be presented to the
mutation-gated edges, and navigation evidence cannot satisfy them.

## 2. Typed navigation facts (proposed persistence shapes)

- `NavigationAttemptFact`: task_id, step_id, plan_revision, plan_hash,
  app_id (registration identity), expected location digest, launch
  method, recorded_at (durable *before* the native attempt).
- `NavigationVerificationFact`: attempt ref, observed process instance
  token (pid+creation+session), observed window version token (or
  truthful "no window expected/observed"), outcome
  (verified/timeout_before_effect/timeout_after_effect/unverified),
  verified_at.
- `NavigationReceiptFact`: attempt+verification refs, status
  (SUCCEEDED only when verification is affirmative), recovery class
  (`IRREVERSIBLE` for process launch; closing an app is a separate
  operation, never implied rollback).

## 3. Transition / evidence matrix (proposed, not implemented)

| Source | Destination | Class | Authoritative caller | Required durable evidence | Failure behaviour |
|---|---|---|---|---|---|
| RESOLVING_CONTEXT | PLANNING | T0/T1 | planner (backend) | resolved app/window resource id + version bound into plan | stale version → CLARIFICATION_REQUIRED |
| PLANNING | VALIDATING | all | broker | registered capability, typed args validated, kind dispatch matches capability | DENIED |
| VALIDATING | PREVIEW_READY | T1 | broker | plan hash over resolved resources+versions | drift → replan |
| PREVIEW_READY | AWAITING_APPROVAL | T1/T2 | trusted UI channel | T1: explicit user task confirmation recorded; T2: existing exact grant path only | silence = no approval |
| AWAITING_APPROVAL | PRECHECK | T1 | live bridge | live plan hash + resource version re-check | DENIED/stale |
| PRECHECK | EXECUTING | T1 | executor | `NavigationAttemptFact` committed **before** native call | attempt-write failure aborts before effect |
| EXECUTING | POSTCHECK | T1 | executor | native outcome recorded (returned/timeout classes distinguished) | timeout-before-effect→FAILED; timeout-after→UNVERIFIED |
| POSTCHECK | COMPLETED | T1 | verifier | affirmative `NavigationVerificationFact` + receipt fact | verification failure → UNVERIFIED, never COMPLETED |
| EXECUTING | PAUSED | T1 | takeover/pause authority (backend event) | pause recorded pre-effect where known; if effect may have occurred, PAUSED is forbidden → RECOVERING/UNVERIFIED | resume requires fresh observation+revalidation |
| PAUSED | EXECUTING | T1 | trusted resume | fresh observation, resource version re-match, plan still live | mismatch → FAILED/CLARIFICATION_REQUIRED |
| EXECUTING/POSTCHECK | RECOVERING | T1 | reconciler | crash/restart: attempt exists without verification | reconcile from observed state; no replay of non-idempotent launch |
| RECOVERING | COMPLETED/UNVERIFIED/FAILED | T1 | reconciler+verifier | observed identity matches attempt (COMPLETED) or cannot be established (UNVERIFIED) | truthful terminal state |
| any | CANCELLED | T1 | trusted cancel | cancel recorded at safe boundary; committed steps listed | already-verified effects reported, not hidden |

Phase 2 mutation edges (AWAITING_APPROVAL→PRECHECK "grant",
PRECHECK→EXECUTING "consumption", POSTCHECK→COMPLETED "receipt",
etc.) are **not** reused for T1 and remain exactly as implemented.

## 4. App/window audit resource support without widening fs restrictions

Plan steps already persist resources as JSON. Proposed: app/window
steps persist `{resource_id: "app:…"/"window:…", expected_version}`
validated against the Phase 3 resource authority at plan time; the
filesystem `ApprovedResourceVersion` pattern and exact-grant tables
are untouched, and navigation facts live in their own proposed
tables. A forged kind prefix fails kind-dispatch validation because
the store checks the persisted capability's declared kind.

## 5. Persistence / migration implication

Durable navigation evidence requires new tables
(`navigation_attempts`, `navigation_verifications`) referencing
tasks/steps — i.e. **schema v3**. That migration is **not
authorized**; this design is the rationale package for a separate
approval (with the established hash-pinned migration discipline,
backup/compatibility evidence, and no real-user database migration
without separate authorization). Until then CP3 cannot activate.

## 6. PolicyBroker integration

One broker. Proposed: the broker gains an optional app/window
resource authority consulted only when the capability's declared
`resource_kind` is `app`/`window` (dispatch by registered capability,
not caller claims); filesystem capabilities keep the existing
registry path byte-for-byte. Executors remain an explicit allowlist;
policy "allowed" is never proof of execution — postcondition
verification produces the receipt.

## 7. Remaining decisions for CP3 authorization

Approve/reject this evidence model; the T1 confirmation record form;
the v3 migration package; the distinct Phase 3 enablement mechanism
(Decision 4: trusted initialization, app allowlist, lifetime,
revocation); R2 takeover signal design.
