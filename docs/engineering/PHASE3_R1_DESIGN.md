# Phase 3 R1 Design — Execution-State and Evidence Architecture

**Status: REVISED for the foundation-closeout + CP3 batch.** Prepared
schema v3 exists but is **not activated** (`ACTIVE_SCHEMA_VERSION`
remains 2; v3 is `PENDING_MIGRATION_VERSIONS`, exercised only against
explicit isolated synthetic databases). CP3 source and fake-backed
integration are implemented behind default-disabled enablement; no
native capability is enabled and no real application is launched. The
existing `_EXECUTION_TRANSITIONS` and Phase 2 grant/consumption/
receipt-hash requirements are unchanged; Phase 2 acceptance remains
NOT COMPLETE and is not waived.

## 1. Operation classes and evidence classes

| Class | Operations | Evidence class |
|---|---|---|
| T0 observation | observe/discover/resolve/inspect | In-memory WorldState evidence only, never durable success claims |
| T1 navigation | `app.launch` (CP3) | **Navigation evidence**: durable attempt record + observed postcondition verification record; *no filesystem grant is fabricated* |
| T2 UI mutation | Exactly bound UI operations (CP5+, not this batch) | Existing Phase 2 exact-grant stack; unchanged |
| T3 | install/send/delete via UI, elevated launch | Denied; no evidence class can authorize |

The evidence class is derived from the *registered capability* of the
persisted plan step, never from caller/renderer/model assertions or
caller-selected risk labels. T1 navigation evidence cannot satisfy T2
mutation gates (regression-tested: presenting navigation facts to the
Phase 2 mutation path still denies).

## 2. Typed navigation facts (schema v3, prepared-only)

- `navigation_confirmations`: id, task_id, step_id, plan_revision,
  plan_hash, capability_id, arguments digest, app resource id,
  expected app version, integrity-evidence digest, session id,
  activation scope, issuance/expiry. Append-only.
- `navigation_attempts`: confirmation ref + task/step/capability/app
  binding, attempt number unique per confirmation, recorded **before**
  any external effect. Attempt-write failure ⇒ no launch.
- `navigation_verifications`: attempt ref, distinct outcome
  (`verified_new_instance`, `verified_existing_instance`,
  `verified_background_no_window`, accepted-but-unverified classes,
  `failed`, `timeout_before_effect`, timeout-after-effect ⇒
  UNVERIFIED), observed process/window identity tokens, verified_at.
- `navigation_receipts`: attempt + verification refs; `SUCCEEDED` only
  with an affirmative (`verified_*`) verification; recovery class
  `IRREVERSIBLE` — closing an app never "reverses" a launch.

Bindings are enforced in code before insertion and by constraints:
cross-task/cross-step/cross-capability/cross-app evidence is
rejected; an attempt requires its confirmation; a receipt requires
the matching verification; interrupted attempts (attempt without
verification) reconcile as UNVERIFIED and are never replayed. An
existing process alone is never launch proof, and a timeout is never
proof of no effect.

## 3. Transition / evidence matrix

| Source | Destination | Class | Required durable evidence | Failure behaviour |
|---|---|---|---|---|
| RESOLVING_CONTEXT | PLANNING | T0/T1 | resolved app/window resource id + version bound into plan | stale version → CLARIFICATION_REQUIRED |
| PLANNING | VALIDATING | all | registered capability, typed args, kind dispatch matches capability | DENIED |
| VALIDATING | PREVIEW_READY | T1 | plan hash over resolved resources+versions | drift → replan |
| PREVIEW_READY | AWAITING_APPROVAL | T1/T2 | T1: explicit trusted confirmation recorded; T2: existing exact grant path only | silence = no approval |
| AWAITING_APPROVAL | PRECHECK | T1 | live plan hash + resource version + confirmation re-check | DENIED/stale |
| PRECHECK | EXECUTING | T1 | attempt committed **before** native call | attempt-write failure aborts before effect |
| EXECUTING | POSTCHECK | T1 | adapter outcome recorded; timeout classes distinguished | timeout-before→FAILED; timeout-after→UNVERIFIED |
| POSTCHECK | COMPLETED | T1 | affirmative verification + receipt | verification failure → UNVERIFIED, never COMPLETED |
| EXECUTING | PAUSED | T1 | pause only at positively-established safe checkpoints | effect may have occurred → RECOVERING/UNVERIFIED |
| PAUSED | EXECUTING | T1 | never direct: fresh observation + revalidation required first | mismatch → FAILED/CLARIFICATION_REQUIRED |
| EXECUTING/POSTCHECK | RECOVERING | T1 | attempt exists without verification | reconcile from observed state; no replay |
| any | CANCELLED | T1 | only at safe boundaries with effects listed | already-verified effects reported, not hidden |

Phase 2 mutation edges are **not** reused for T1 and remain exactly
as implemented.

## 4. Confirmation binding (R1 refinement)

A navigation confirmation is bound to: task, step, plan
revision+hash, capability, exact normalized arguments digest,
canonical app resource identity, expected app version, trusted
integrity-evidence digest, session id and activation scope. It is
single-use, expires, is revocable, and is minted only by the trusted
confirmer on the trusted side — never by a renderer boolean. It is
not a filesystem edit grant and cannot satisfy mutation gates.

## 5. Launch authority separation

Descriptive discovery fields (caller-settable `integrity_status` /
`launch_authorized`) never establish authority. Authority is a
distinct `LaunchAuthorization` minted by `LaunchAuthority` only when
a trusted `IntegrityVerifier` returns typed evidence (location
digest, content/signer/package identity, verification time) for the
exact registration. Authorization is scoped to app + method +
activation scope, expires, is revocable, single-use, and is
re-validated immediately before the attempt: same-path replacement
(evidence drift), expiry, revocation or scope mismatch denies.
Deterministic ids are not credentials; discovery refresh cannot issue
or restore authorization; unavailable required integrity ⇒ deny.
Real verify-to-create time-of-check races are documented as a
platform limitation — no atomicity is claimed that Windows does not
provide; the native launcher remains disabled in this batch.

## 6. Persistence / migration

Schema v3 (`0003_phase3_navigation.sql`) is prepared and hash-pinned
(migration SHA-256 and schema fingerprint), listed as pending, and
refused by ordinary startup. It is exercised only on explicit
isolated synthetic databases; no real-user database is migrated.
Backup/migration recovery behaviour is unchanged from the established
v1/v2 discipline: a database newer than the active version is refused
rather than downgraded. Production activation remains a separate
owner decision. No window titles, observations or UIA content are
persisted; the app/window registry remains in-memory.

## 7. PolicyBroker integration

One broker. The broker consults the Phase 3 app/window resource
authority only when the capability's declared `resource_kind` is
`app`/`window` (dispatch by registered capability, never caller
claims); filesystem capabilities keep the existing registry path.
Executors remain an explicit allowlist (empty by default); policy
"allowed" is never proof of execution — the postcondition verifier
produces the receipt.

## 8. Cancellation / takeover contracts (R2, fake-backed only)

Launch verification/recovery consume typed cancellation/takeover
events at known safe checkpoints only. There is no native input
monitoring, no key/typed-text/clipboard capture, and no replay of
consumed confirmations or unresolved attempts. UIA worker and
focus-lock design are deferred to CP4/CP5 and are not implemented.

## 9. Remaining decisions

Schema-v3 activation; production enablement wiring (trusted
initialization from owner configuration, exact app scope, lifetime,
revocation — an importable class, issuer string, env flag or caller
boolean is never authorization); native observer/launcher activation
with native Windows evidence; R2 native signal design.
