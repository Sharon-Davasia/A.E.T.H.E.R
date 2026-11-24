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

### Supported application storage (FI-02A)

The shipped desktop initializes storage independently of the
development review seed: Electron main passes `AETHER_APP_DB` (an
absolute path inside the OS per-user application-data directory) for
every build, and `aether.channel.app_storage` opens it through
`SQLiteTaskStore` — exclusive owner lock, private permissions, and
only the shipped active schema applied (pending migrations are never
applied implicitly). Misconfiguration fails closed
(`composition_unavailable`) while the ping path keeps working. For the
Windows acceptance campaign, an isolated fixture database is selected
with `AETHER_FIXTURE_DB` (development/fixture launches only, absolute
path inside the fixture root), so acceptance never touches real user
storage.

## 4. Shipped-configuration behaviour (what a user gets today)

| Configuration | Reads/planning/preview | Authorization | Execution |
|---|---|---|---|
| Schema v1 (shipped) | work | mutation tier absent → `schema_activation_pending` | `schema_activation_pending` |
| Schema v2, production ledger | work | valid signed gesture refused → `grant_issuance_disabled` | refused; file untouched |
| Schema v2, test-scoped ledger (tests only) | work | works | works — reachable only via test-scoped construction. These tests are **not** production-enablement evidence: the construction discipline they exercise is not an authorization boundary (see Proposal B correction). |

## 5. Separately reviewable activation proposals (NOT in this PR)

### Proposal A — schema v2 activation

Single reviewed change in `sqlite_store.py`: `ACTIVE_SCHEMA_VERSION = 2`,
remove `2` from `PENDING_MIGRATION_VERSIONS`. Prerequisites: WS1 evidence
(disposable-copy backup → migrate → restore verified; corrupted migration
fails atomically; originals byte-identical), a recorded backup/rollback
procedure for real databases, and the full backend suite green. User data
migration itself remains an operator action with a verified backup first.

### Proposal B — production grant issuance enablement

Give the production ledger a production trust-source policy so
`GrantIssuer.issue` accepts the central `authorize_issuance` permit for
gestures verified by `ProductionAttestationVerifier` against the
per-launch gesture authority, fed by the FI-01 trusted confirmation
(complete exact preview in a main-owned native dialog, shown == signed).

**Correction (independent review, FI): a caller-module allowlist is NOT
an authorization boundary.** The allowlist used to isolate the
test-scoped ledger seam enforces *composition discipline only* — it
shows which module constructed an object. It cannot establish human
consent, and inside a single process it is not unforgeable: any code
running in the process could satisfy it. It must therefore never be
described or relied upon as the mechanism that authorizes production
issuance. The real authorization chain is, and must remain:

1. an independently verified trusted confirmation (FI-01) over the
   complete authoritative exact preview;
2. an authenticated authorizing gesture (per-launch HMAC key, single-use
   nonce, exact binding);
3. the authoritative preview recomputed and matched server-side;
4. an exact grant binding (task, plan, step, scope and result digests);
5. the central issuance decision in the grant authority/ledger.

Prerequisites: Proposal A live, FI-01/FI-02 complete, full backend +
desktop suites green on the target Windows machine, `verify_phase2.ps1`
updated to exercise the live path, and the §6 demonstration procedure
rehearsed on fixtures. Production issuance stays disabled until this
proposal is separately approved and implemented.

Neither proposal is implemented here. `NullAttestationVerifier` and the
`GRANT_ISSUANCE_DISABLED` default remain exactly as shipped. Concrete,
separately reviewable diffs for both proposals (not applied) live in
`docs/engineering/activation-proposals/` (`proposal-a-schema-v2.diff`,
`proposal-b-production-issuance.diff`).

## 6. Windows acceptance procedure (18 scenarios)

Target: Windows 11 laptop, **normal (non-elevated) user**, PowerShell 5.1,
synthetic fixtures only — never real data. Use `npm.cmd` (never bare
`npm`, never an execution-policy bypass: if script policy blocks a step,
stop and have the machine owner set an approved policy; do not work
around it).

### 6.0 Gate semantics — automated success is not formal acceptance

Two different things must not be conflated:

- **Automated gate success**: `scripts/verify_phase2.ps1` records every
  automated item `PASS`. Because the verifier *by design* always records
  the human-demonstration items `NOT VERIFIED`, a fully successful
  automated run exits **2**, not 0. **Exit 2 / NOT VERIFIED does not
  block starting the human demonstrations below** — the demonstrations
  are precisely what can convert those items. Only an automated `FAIL`
  (exit 1) blocks proceeding.
- **Formal acceptance**: complete only when all 18 scenarios below are
  recorded `PASS` with archived evidence on the target machine, *after*
  separately approved schema activation and production-issuance
  enablement. Until then formal Phase 2 acceptance is **NOT COMPLETE**,
  regardless of automated results.

> **Safety warning (preserved):** the verifier has not been
> independently reviewed and must not be run on a machine holding real
> data until it is. Before recommending its execution, independently
> review `aether.core.acceptance.fixture_safety` and its negative tests
> (sibling prefixes, unmarked directories, junctions and arbitrary paths
> are refused). The procedure below uses only fixture directories under
> an explicit fixture base; nothing outside them may be touched.

Setup (once): create the fixture project under the fixture base with two
small text files (`sample.txt` containing `hello world`, `other.txt`),
start the activation-approved build with isolated fixture storage
(`AETHER_FIXTURE_DB` pointing inside the fixture root, FI-02A), and record SHA-256 hashes of the
whole fixture tree as the baseline for scenarios 17–18. Evidence for
every scenario: the verifier evidence JSON/Markdown, plus dated
screenshots or notes naming the scenario, the observed dialog text, and
the before/after file hashes. Record each scenario PASS or FAIL;
cleanup after each scenario restores the fixture from the pristine
synthetic copy (never by editing hashes or deleting receipts).

1. **Open a registered project; bounded access only.**
   Prereq: clean fixture, app started. Actions: *Choose project
   directory…*, select the fixture directory, affirm the native
   grant-access dialog naming that directory. Expected: project
   registered; opening `../` paths or absolute outside paths is refused.
   PASS: registration only after native affirmation; outside reads
   refused. Cleanup: none (session state only).
2. **Search + read an allowed file.** Actions: use the workflow's
   *Search project* for `hello` (results list shows
   `sample.txt:1: hello world`), then open `sample.txt`. Expected:
   exact bytes displayed, hash shown matches `Get-FileHash`. PASS:
   search result listed + byte-identical content. Cleanup: none.
3. **Refuse reads outside authorized roots.** Actions: attempt to open a
   file outside the fixture root. Expected: bounded refusal, no content.
   PASS: refusal observed. Cleanup: none.
4. **Refuse `.env`/sensitive files without authorization.** Actions:
   place a synthetic `.env` in the fixture; attempt to open it.
   Expected: refusal. PASS: no bytes disclosed. Cleanup: delete the
   synthetic `.env`.
5. **Deny junction/symlink escape.** Actions (non-elevated):
   `cmd /c mklink /J fixture\escape <outside-dir>`; attempt to open a
   file through it. Expected: `reparse_point_not_allowed` refusal.
   PASS: no outside bytes read. Cleanup: `cmd /c rmdir fixture\escape`
   (removes the junction only).
6. **Human-visible exact patch preview before approval.** Actions:
   prepare an edit `hello world` → `hello aether`; read the preview in
   the UI and in the native approval dialog. Expected: the dialog names
   the **unambiguous affected path** (full canonical path, not a
   basename) and the complete unified diff including CRLF/EOF notes,
   recovery class and plan hash — not truncated. PASS: dialog text
   contains the full path and the complete changed lines. Cleanup:
   cancel the dialog.
   **Native Windows display check (mandatory, this scenario):**
   (a) repeat with a synthetic file whose diff is long (several
   hundred changed lines): if the preview exceeds the host display
   bound, approval must report `preview_not_displayable_completely`
   and sign nothing — record this; a dialog that silently truncates
   is a FAIL and blocks acceptance until the bound/surface is fixed;
   (b) repeat with a CRLF file whose line endings change: the CRLF/EOF
   summary must be visible in the dialog; (c) cancel via the Cancel
   button, via Escape, and by closing the dialog: each must decline,
   sign nothing and leave the file byte-identical. Evidence:
   screenshots of the dialog for (a)–(c) plus before/after hashes.
7. **Refuse mutation before approval.** Actions: prepare the edit, then
   inspect the file without approving. Expected: file hash unchanged;
   no receipt. PASS: baseline hash intact. Cleanup: none.
8. **Apply the exact approved edit; hash matches.** Actions: affirm the
   native dialog. Expected: executed outcome with a receipt id; file
   hash equals the preview's approved result hash. PASS: hash equality
   + receipt displayed. Cleanup: keep the receipt id for 12–14.
9. **Refuse stale approval after post-preview modification.** Actions:
   prepare an edit; modify `sample.txt` externally; then approve.
   Expected: refusal (stale target/conflict); the external bytes remain.
   PASS: no overwrite. Cleanup: restore fixture file from pristine copy.
10. **Reject forged/expired/revoked/exhausted/replayed grants.**
    Actions: after scenario 8, restart the app and attempt to re-use
    the spent approval; observe refusal. (Forged/expired variants are
    covered by the automated adversarial suites; the live half is the
    replay refusal.) Expected: refusal, file unchanged. PASS: refusal.
    Cleanup: none.
11. **Consumption binds the exact action.** Actions: prepare edit A,
    approve; verify only A's bytes were applied and a second, different
    prepared edit B was not. Expected: file equals A exactly. PASS:
    byte equality with A, B absent. Cleanup: restore pristine fixture.
12. **Receipts durable across restart.** Actions: note scenario 8's
    receipt id; fully restart the app; *Show receipt*. Expected: same
    receipt, `SUCCEEDED`, verified, with snapshot id. PASS: identical
    receipt fields. Cleanup: none.
13. **Undo restores the exact original bytes.** Actions: *Prepare undo
    from receipt* (scenario 8 receipt); affirm the native dialog (the
    preview must show the derived restoration; no content is typed).
    Expected: file hash equals the pre-edit baseline. PASS: hash
    equality. Cleanup: none.
14. **Undo refuses silent overwrite of a newer edit.** Actions: edit the
    file again (scenario 8), then modify it externally, then prepare
    undo of the first receipt. Expected: `undo_conflict_newer_change`
    refusal; newer bytes intact. PASS: refusal + intact bytes. Cleanup:
    restore pristine fixture.
15. **Truthful crash/cancel recovery.** Actions: begin an approved edit
    and kill the app process mid-execution (Task Manager, fixture only);
    restart. Expected: task is `UNVERIFIED` or truthfully reconciled —
    never a false success; on restart, mutation is blocked pending
    reconciliation for unresolved tasks. PASS: no false `COMPLETED`;
    file is either fully old or fully new, hash-verified. Cleanup:
    restore pristine fixture; record the observed state.
16. **T3/shell/unsupported capabilities denied.** Actions: attempt any
    UI path beyond inspect/read/search/approved edit/undo (none should
    exist); confirm no shell or arbitrary-command surface is offered.
    Expected: denial/absence. PASS: no unsupported action possible.
    Cleanup: none.
17. **Zero unauthorized mutation across the run.** Actions: after all
    scenarios, re-hash the fixture tree. Expected: only the approved
    edits (8, 13, 14's approved half) differ from baseline; receipts
    account for each difference. PASS: every changed hash maps to a
    receipt. Cleanup: remove the fixture via the reviewed fixture
    procedure only.
18. **Offline; zero unauthorized outbound disclosure.** Actions: run
    the whole procedure with the machine offline (airplane mode);
    observe no network dependency or failure, and no outbound traffic
    in the OS network view. Expected: full workflow works offline.
    PASS: completed offline. Cleanup: restore network settings.

Record results in `PHASE2_ACCEPTANCE_REPORT.md`; any scenario not run or
`FAIL` keeps formal acceptance **NOT COMPLETE**.

## 7. Evidence for this integration (Linux, Python 3.11.2)

Corrected head (FI-01…FI-08) results, this sandbox:

| Gate | Result |
|---|---|
| Backend full suite | **933 passed / 5 skipped** (`pytest backend/tests`) |
| Backend ruff / format / mypy (strict) | PASS (99 files) |
| Desktop suite (`npm test`, no Python env) | 7 Python-child integration tests skip (environment-gated) |
| Desktop suite with `AETHER_DEV_PYTHON` set | **99 passed / 0 failed / 0 skipped** (real Python child, production-shaped channel; includes FI-01/FI-02B/workflow and native-confirmation tests) |
| Desktop full gate (`npm run check`: lint, typecheck, tests, Python tests, electron build) | PASS |
| Gesture golden interop (Python ↔ TS) | PASS (vectors pinned both sides) |

Skip inventory (nothing is silently skipped):

- Backend (5): model-integration test requires
  `AETHER_RUN_MODEL_INTEGRATION=1` (needs a local model runtime);
  two vault-key tests are native-Windows-ACL-only; one stage-3 test
  requires Windows access-denial semantics; one migration test requires
  `hatchling` (wheel packaging check) which is not installed here.
- Desktop (7, only when `AETHER_DEV_PYTHON` is unset): all seven are
  Python-child integration tests in `stage3-review-channel.test.ts`
  gated on an interpreter with the backend installed; with the venv
  interpreter provided they run and pass (90/90 above). They are
  environment-gated, not disabled.

Test-scoped ledger runs (all live-workflow tests above) are **not**
production-enablement evidence: production issuance remains
`GRANT_ISSUANCE_DISABLED` and schema v2 remains pending.

### Cryptography dependency review (`cryptography`)

The only third-party cryptographic dependency is PyPI `cryptography`
(`backend/pyproject.toml`: `>=43,<47`; 46.0.7 in this venv), used
solely for AES-256-GCM snapshot encryption in the Undo Vault. Licence:
Apache-2.0 OR BSD-3-Clause (dual-licensed; either is permissive and
compatible with this project's pending licence decision — see
`DEPENDENCY_INVENTORY.md`). It links OpenSSL on most wheels; the
licence notice obligations travel with redistribution, which is a
release-packaging concern, not a code concern. It never authorizes an
action; HMAC gesture signing uses the standard library. No other
component performs cryptography beyond stdlib `hashlib`/`hmac` and the
desktop's Node `crypto`.

### Python runtime limitations (honest statement)

- All Linux evidence here is **Python 3.11.2**. The target runtime is
  Python 3.12.10 on native Windows; 3.11.2 results must never be
  presented as 3.12.10 evidence.
- The desktop launches the backend with `-P -I -B -u`; `-P`
  (safe_path) requires Python ≥ 3.11. Anything older is unsupported.
- Owner-lock, DACL and junction behaviour are Windows-specific and are
  only verifiable on the target machine (verifier steps; several
  backend tests skip elsewhere by design, listed above).
- The backend is a single-process stdio channel service; it has no
  network listener, no concurrency beyond one child session, and file
  bounds (4 MiB edit/read caps) are deliberate product limits.
