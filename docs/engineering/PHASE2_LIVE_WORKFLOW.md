# Phase 2 — Live Workflow (Final Integration)

**Status:** implemented and wired end to end; **not activated**. Schema v2
activation and production grant issuance remain disabled in the shipped
configuration and each requires its own separately approved change (see
§5). Nothing in this document claims formal Phase 2 acceptance, which
remains **NOT COMPLETE** (see `PHASE2_ACCEPTANCE_REPORT.md`).

**Branch:** `integration/phase2-final-live-workflow` (for review; not merged).

---

## 1. What was built

Every Phase 2 security component already existed and was individually
tested (planner, exact preview authority, signed authorizing gesture,
production attestation verifier, grant ledger/issuer/consumption, edit
executor, receipts, undo vault, journal). What was missing was the
wiring. This integration adds exactly that, under four workstreams:

| Workstream | Content |
|---|---|
| WS1 — migration safety | `test_phase2_migration_safety.py`: shipped config pinned (`ACTIVE_SCHEMA_VERSION=1`, v2 pending); backup/restore and migration exercised only on disposable copies; corrupted-migration failure is atomic; a shipped build refuses a v2 database it cannot own |
| WS2 — execution states (Decision D) | `ExecutionEvidence` + `advance_execution_state`: PRECHECK→EXECUTING→POSTCHECK→COMPLETED (and →UNVERIFIED) are reachable **only** with evidence re-read from the v2 ledger inside the store transaction (live unrevoked grant bound to the current plan revision/hash, recorded consumption, verified receipt). `transition_task` still refuses these states; grant consent checks are unchanged |
| WS3+4 — composition + gesture key (Decisions C+A) | One `TrustedComposition` owns the single store/connection/lock and constructs every trusted component over it. The schema ≥2 tier adds sibling vault/receipts/journal/consumption databases. Per-launch 32-byte gesture key travels only in the 120-byte private stdin bootstrap; Electron main generates, holds and zeroes it; signing exists only as `BackendClient.signGesture()` in the main process |
| WS5 — live workflow | `LiveBridge` on the authenticated channel, plus the main-process native-confirmation approval path (below) |

## 2. The live approval path

```
renderer ──(IPC: no arguments)──▶ Electron main: live-approval provider
   1. task id from trusted main-process configuration (renderer chooses nothing)
   2. channel gesture.begin ──▶ backend recomputes binding from persisted plan+preview
   3. channel review.get_preview ──▶ main verifies canonical preview digest + derived
      identities, and requires the binding to commit to exactly that preview,
      plan revision and plan hash
   4. native OS confirmation dialog (dismissal = decline; declining signs nothing)
   5. BackendClient.signGesture() (per-launch key, main-process memory only)
   6. channel gesture.submit ──▶ production verifier: authority, preview identity,
      freshness, single-use nonce ──▶ GrantIssuer (refuses while issuance disabled)
   7. main checks returned scope digest == binding scope digest
   8. channel edit.execute ──▶ executor spends the grant, applies exact bytes,
      re-reads and verifies; execution states advance from ledger evidence (WS2)
```

Only a bounded summary (`executed` / `declined` / `unavailable(reason)`)
crosses the preload boundary. A nonce, signature, or binding never
reaches the renderer.

### Channel kinds (live)

| Request | Response | Effect |
|---|---|---|
| `project.register` | `project.registered` | register a project root |
| `project.resolve` | `project.resolved` | resolve a resource inside a root |
| `task.create` | `task.created` | create a persisted task |
| `task.plan` | `task.preview` | plan + exact preview (proposed bytes held server-side, process-local) |
| `fs.execute_read` | `fs.read_result` | bounded inspect/read/search through the capability session |
| `gesture.begin` | `gesture.challenge` | server-computed binding + single-use nonce |
| `gesture.submit` | `gesture.authorized` | verified gesture → exact grant (still gated, §5) |
| `edit.execute` | `edit.executed` | apply the approved edit (or undo, from the vault snapshot) |
| `edit.receipt` | `edit.receipt` | re-read a durable receipt |

Unknown kinds terminate the session. If the composition cannot be built,
live kinds answer `live.error`/`composition_unavailable` and the audit-only
review surface keeps working.

## 3. Trust rules (enforced, tested)

- **Renderer payloads never authorize.** Bindings and scope digests are
  recomputed server-side from the persisted plan and authoritative
  preview; a submitted binding that differs in any field is refused
  (`gesture_binding_mismatch`) before verification.
- **Forged or wrong-key signatures, replayed gestures** (nonces are
  single-use and burned before return), and **execution without a
  gesture** all fail closed with files byte-identical
  (`test_phase2_live_adversarial.py`, 9 tests).
- **Issuance and consumption hash the same bytes:** the persisted
  `approved_effect_digest` and the persisted step arguments verbatim
  (including undo's receipt/snapshot identity) — three seams found by
  the live end-to-end test and fixed in `core/grants/authorization.py`
  and `core/edits/executor.py`.
- **Undo content comes only from the vault snapshot**, never the wire.
- **Execution states advance only from re-read ledger evidence**;
  uncertain outcomes land in `UNVERIFIED` with
  `mutation_may_have_happened=True`, never auto-replayed.
- Every failure is a bounded `{"status": "unavailable", "reason": …}`
  response; nothing throws across the channel.

## 4. Shipped-configuration behaviour (what a user gets today)

| Configuration | Reads/planning/preview | Authorization | Execution |
|---|---|---|---|
| Schema v1 (shipped) | work | mutation tier absent → `schema_activation_pending` | `schema_activation_pending` |
| Schema v2, production ledger | work | valid signed gesture refused → `grant_issuance_disabled` | refused; file untouched |
| Schema v2, test-scoped ledger (tests only) | work | works | works — reachable only from allow-listed test modules |

## 5. Separately reviewable activation proposals (NOT in this PR)

### Proposal A — schema v2 activation

Single reviewed change in `sqlite_store.py`: `ACTIVE_SCHEMA_VERSION = 2`,
remove `2` from `PENDING_MIGRATION_VERSIONS`. Prerequisites: WS1 evidence
(disposable-copy backup → migrate → restore verified; corrupted migration
fails atomically; originals byte-identical), a recorded backup/rollback
procedure for real databases, and the full backend suite green. User data
migration itself remains an operator action with a verified backup first.

### Proposal B — production grant issuance enablement

Give the production ledger a production trust-source policy settable only
from `aether/core/composition.py` (caller-module allowlist, the same
mechanism that isolates the test seam), so `GrantIssuer.issue` accepts
the central `authorize_issuance` permit for gestures verified by
`ProductionAttestationVerifier` against the per-launch gesture authority.
Prerequisites: Proposal A live, full backend + desktop suites green on
the target Windows machine, `verify_phase2.ps1` updated to exercise the
live path, and the §6 demonstration procedure rehearsed on fixtures.

Neither proposal is implemented here. `NullAttestationVerifier` and the
`GRANT_ISSUANCE_DISABLED` default remain exactly as shipped.

## 6. Windows demonstration procedure (after activation is approved)

On the target Windows 11 laptop (normal user, fixtures only — never real
data), with a separately approved activation build:

1. Run `scripts/verify_phase2.ps1` — every recorded item must be `PASS`
   (exit 0). Do not proceed on `NOT VERIFIED`.
2. Start the desktop app pointed at a fixture project (dev configuration:
   `AETHER_REVIEW_DB`, `AETHER_REVIEW_TASK_ID`, fixture root only).
3. Scenario 6: read the exact preview (incl. CRLF/EOF summary) in the UI.
4. Scenario 7→8: click *Approve & execute exact action…*; confirm the
   native dialog names the exact effect; affirm. Verify the file's new
   hash matches the preview's approved bytes and a receipt exists.
5. Scenario 13: plan an undo for that receipt, approve natively, verify
   the original bytes are restored exactly.
6. Scenarios 9/14: modify the file after preview (and after an edit, for
   undo) and confirm both stale-approval and silent-overwrite refusals.
7. Scenario 10: attempt a replayed gesture (restart the app and re-use a
   spent approval) — refused; the file does not change.
8. Scenario 12: restart the app; receipts re-read from disk.
9. Scenario 15: kill the app mid-execution; on restart the task must be
   `UNVERIFIED` or truthfully recovered — never false success.
10. Scenarios 17/18: fixture tree hashes unchanged outside the approved
    edits; machine offline throughout.

Record results in `PHASE2_ACCEPTANCE_REPORT.md`; any `NOT VERIFIED`
keeps formal acceptance **NOT COMPLETE**.

## 7. Evidence for this integration (Linux, Python 3.11.2)

| Gate | Result |
|---|---|
| Backend full suite | **882 passed / 5 skipped** (`pytest backend/tests`) |
| Backend ruff / format / mypy (strict) | PASS (97 files) |
| Desktop suite | **77 passed / 0 failed / 7 skipped** (`npm test`, 84 tests) |
| Desktop typecheck (electron + renderer) + build | PASS |
| Gesture golden interop (Python ↔ TS) | PASS (vectors pinned both sides) |

Python 3.12.10 was unavailable in the Linux sandbox; native Windows
evidence is still required and unarchived. The desktop count includes
`pipe.integration.test.ts`, whose pre-WS3 104-byte bootstrap (fixed in
this integration) previously made the suite hang rather than fail.
