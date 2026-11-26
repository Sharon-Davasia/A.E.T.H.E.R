# Phase 3 CP4–CP5: UIA snapshots, focus coordination, exact fixture interaction

Status: implemented fake-backed on Linux; **no native Windows evidence**;
native activation still disabled; schema v3 still inactive
(`ACTIVE_SCHEMA_VERSION = 2`, `PENDING_MIGRATION_VERSIONS = {3}`);
Phase 2 acceptance remains NOT COMPLETE and unwaived.

## CP3 prerequisites (R01–R05)

- **R01** `SQLiteTaskStore.commit_navigation_attempt()` consumes the
  confirmation, records the attempt and transitions PRECHECK→EXECUTING
  in one transaction. `reconcile_navigation_tasks()` now also recovers
  PRECHECK tasks with a committed attempt → FAILED (the adapter is
  gated on EXECUTING, so no effect was possible), idempotently, never
  replaying. PRECHECK without an attempt stays cancellable.
- **R02** The coordinator's execution lock spans commitment through the
  terminal advance: cancellation confirmed before commitment prevents
  the adapter call; afterwards it reports the verified/uncertain
  terminal truth. Enablement is rechecked after commitment. This is an
  in-process lock only — no Windows operation is claimed atomic.
- **R03** `NativeIntegrityProvider` binds content hash to the same
  opened file handle whose OS identity is recorded, revalidates
  identity after inspection, restricts approved targets to canonical
  local `.exe` identities (UNC/drive-relative/symlink/unsupported
  denied), and requires a platform package query (full identity +
  version) for packaged apps; a repeated registry string is no longer
  evidence. COM activation handles RPC_E_CHANGED_MODE without
  uninitializing an apartment it does not own. The documented
  verify-to-create race remains.
- **R04** `LaunchCallResult.process_token` carries the returned PID
  identity (CreateProcessW and activation paths) into
  `VerificationExpectation`: with a returned identity only that exact
  instance verifies; without one a *complete* baseline is required and
  `started_after_attempt` is mandatory. Incomplete baseline ⇒ never
  verified-new.
- **R05** `ObserverService` accepts a `snapshot_handler` and publishes
  reconciliations atomically through `WorldState.apply_snapshot()`;
  uncertainty clears only on successful publication. Window version
  tokens are now `process_token#instance_generation` (the actual
  window instance); unchanged live windows keep stable references;
  destroy/recreate (incl. same-process HWND reuse) mints a new
  reference and invalidates the old; per-HWND generation bookkeeping
  is bounded (4096).

## CP4 — bounded UIA snapshots

Architecture unchanged: Electron trusted main → authenticated channel
→ trusted Python policy/planning → supervised adapter worker → bounded
UIA provider. Contracts in `core/contracts/uia.py` (schema 0.1.0):
snapshot bound to session, app resource, window resource, window
instance version, process identity, generation, timestamps, expiry,
provenance, privacy classification, completeness/truncation. Elements
carry only transient refs (`el:N` within one snapshot), UIA runtime
ids, control types, patterns, enabled/offscreen, privacy-permitted
names, parent/ancestor refs and optional bounds. No raw HWND/COM or
executable selectors reach the model.

Provisional limits: depth 8, 300 elements, 32 KiB retained text, 5 s
budget, 64 KiB requests / 256 KiB responses, 16 retained snapshots,
60 s snapshot TTL. Truncation is explicit and never proves absence.

Privacy: inspection requires a positively permitted context
classification (unknown/elevated fail closed); content-bearing
inspection additionally requires the caller's content permission;
password values are never read or retained and password names are
dropped; snapshots live in memory only and are never persisted; UI
text is untrusted data, never instructions. No OCR, screenshots or
clipboard access exists.

Native source (real, disabled): `adapters/windows/native_uia.py`
(pywinauto UIA backend: root resolution, bounded tree walk, typed
stale/unavailable errors, COM cleanup via element cache release),
`adapters/windows/uia.py` (`NativeUiaAdapter`, activation-gated),
`adapters/windows/uia_worker_main.py` (bounded typed ops over stdio).
Worker reliability (`core/workers/uia_worker.py`): protocol/version
and request-id binding, size bounds, forbidden payload fields
(code/shell/pattern names/keys/mouse), deadlines; inspection timeout →
TIMED_OUT, post-side-effect timeout → UNCERTAIN (never replayed);
crash/malformed/stale responses classified. pywinauto 0.6.9 (BSD
3-clause; transitives pywin32, comtypes, six — Windows markers only)
added to `backend/pyproject.toml` + `uv.lock`; see
`PHASE3_DEPENDENCY_REPORT.md`. Python 3.12.10 compatibility rests on
package metadata (no `requires_python` cap; deps support it), not on a
local install — the sandbox runs 3.11.2.

Capabilities (`CapabilityRegistry.phase3_with_uia()`): `window.activate`
(T1 NAVIGATE), `uia.inspect_snapshot` / `uia.inspect_element`
(OBSERVE), `uia.invoke_fixture` (MODIFY/T2, exact-binding only). No
generic invoke/set-value/keyboard/mouse capability exists anywhere.

## CP5 — focus coordination, takeover, exact interaction

`core/apps/focus.py`: per-window locks + one shared foreground lock,
deterministic ordering (window → foreground), bounded 30 s duration,
same-owner re-entry, stale-owner release denial, expiry/crash
reconciliation. Locks never prove target validity; identity/focus are
revalidated at operation boundaries. Manual takeover consumes only
content-free activity signals (foreground change / same-window manual
activity / focus lost): automation stops, locks release, snapshots
invalidate, resumption needs a fresh precheck. No key/text/pointer/
clipboard recording exists; native activity monitoring is absent and
remains a separate decision.

`core/apps/ui_binding.py` + store `ui_operation_*` evidence (separate
class from navigation): bindings bind task/step, plan revision+hash,
capability, canonical arguments digest, app, window instance version,
snapshot id+generation, exact element (ref + runtime id), approved
pattern, declared intended effect, session, activation scope,
issuance/expiry, single-use consumption. Unknown intended effects are
denied; inspection approval never authorizes interaction; T1
navigation evidence cannot authorize this T2 interaction and vice
versa (both directions tested).

`core/apps/ui_executor.py`: persisted plan → fresh precheck → combined
durable commitment (`commit_ui_attempt`) → focus locks → one bounded
adapter invoke → independent verification from a fresh snapshot →
truthful receipt. Adapter success claims without the observed
postcondition are FAILED (`no_effect`); replaced elements are
`stale_target`; post-effect timeout is UNVERIFIED. `WindowActivator`
provides the bounded T1 activation with foreground verification.

Fixture (`core/apps/fixture.py`): synthetic window with Increment
button (deterministic Count+1), status text, disabled control,
simulated password control, modal trigger, controlled element
replacement and delayed response. No real files/apps/settings.

## Persistence / migration

Migration `0003_phase3_navigation.sql` extended with
`ui_operation_bindings/attempts/verifications/receipts` (append-only,
binding-immutability triggers, SUCCEEDED requires `verified_effect`
with an observed postcondition token; only identity digests/tokens
stored, never UI content). New SHA-256:
`36c93e8348cd6d58aba77af4f07572988b2d570815f253cb631f2c7c70c23e7a`;
v3 fingerprint:
`5e69f75d1eee2857fd96edb9183aa8e5b2480ee18c95a6ee6035a24b6c19ac24`.
Activation status unchanged: v3 is prepared only.

## Remaining native verification (owner-side, later)

Build the small native fixture app per `PHASE3_NATIVE_TESTS.md`, run
the native UIA/activation checks on Windows under a dedicated test
session, and review pywinauto against Python 3.12.10. Until then every
result above is simulated evidence only.

## Proposed CP6–CP7 sequence

CP6: general dialog recovery + full pause/resume and takeover UX on
top of these locks/signals; production desktop integration decision;
owner native-verification pass. CP7: enumerated additional verified
interactions beyond the fixture (each with its own exact binding,
intended-effect classification and independent verification), still
no generic UI automation.

## Final consolidated batch (F09–F14, CP6, CP7)

Owner-authorized final implementation batch on this branch. Native
activation remains disabled; schema v3 remains prepared-but-inactive;
no native evidence was produced (Linux, Python 3.11.2, fake providers
and real subprocess workers only).

- **F09** The persisted UI-operation binding is now fully
  authoritative: migration 0003 adds precondition/postcondition digest
  columns protected by the immutability trigger; execution re-derives
  and compares every field against the persisted plan and trusted
  observations; read-only observation capabilities never enter the T2
  path and failed binding checks consume nothing. Focus ownership
  tokens are task+session-bound UUIDs with deterministic lock order;
  outcome classes are truthful — a missing post-Invoke snapshot is
  `uncertain`, never `no_effect`.
- **F10** `UiOperationExecutor` integrates the existing `PolicyBroker`
  (new `ui_authorizer` limited to `uia.invoke_fixture`; no second
  broker, no widened filesystem grants) and `Phase3Enablement`;
  fixture identity comes only from trusted launch/process/executable
  evidence; `window.activate` ships as a T1 service; observation stays
  under privacy/access policy.
- **F11** Production UIA inspection routes through the real
  `SubprocessWorkerSupervisor`: parent-owned startup, allowlisted
  bounded schemas, worker-session identity, parent deadlines,
  termination/cleanup, no replay of uncertain effects. Real-child
  tests cover success, startup failure, hang/timeout, oversized/
  malformed frames, crash, stale responses and cancellation cleanup.
- **F12** Privacy governs collection: password controls are
  classified before any content read and their names suppressed in
  the native walk; metadata-only mode collects no unrestricted text;
  snapshots are lifecycle-bound (session/window/process/privacy
  generation/permission/expiry) and purge on privacy change, pause,
  replacement, takeover, dialog and worker restart; traversal work is
  budget-bounded.
- **F13/F14** `tools/windows-fixture/aether_fixture.py` provides the
  native Win32 fixture source (stable control ids, `Count: N`,
  disabled/password/modal/replacement/delayed modes, deterministic
  reset). It is source only — never executed here; fake ids
  (`fixture-increment`/`fixture-status`) are contract ids, not native
  runtime ids.
- **CP6** Current-project detection inside registered roots only
  (registered/Explorer/recent-focus evidence, deterministic ranking,
  ambiguity clarification, no permission expansion);
  unexpected-dialog handling that halts dispatch and never
  auto-dismisses; manual-takeover signals scoped to active operations;
  pause/resume only through the persistent task authority with fresh
  revalidation; restart reconciliation without activating v3.
- **CP7** Electron Phase 3 verification surface over the existing
  authenticated channel (`phase3.*` kinds): observer state, privacy
  modes, registry search, bounded snapshot inspection, fixture
  preview + trusted approval (native dialog visibly binds
  app/window/operation/effect; main signs; backend verifies;
  exactly-once), task state and pause. Ordinary launches construct
  the disabled surface and report `phase3_native_disabled`
  truthfully. No generic execute/invoke/click/python IPC exists.

Native acceptance campaign P3-01–P3-25 is prepared in
`docs/engineering/PHASE3_NATIVE_ACCEPTANCE.md` (not run); the
activation proposal is `docs/security/PHASE3_ACTIVATION_PROPOSAL.md`
(not approved). Implementation-present ≠ platform-verified ≠
native-verified ≠ formally accepted: everything above is
implementation-present with fake/Linux evidence only.

## Integration and activation-readiness gate (G01–G06)

On top of the final consolidated batch, the readiness gate added:

- **G01** `core/apps/composition.py`: one controlled composition
  factory (disabled / simulated / native-prepared-never-startable)
  wiring observer policy, registry+resolver, app/window authority,
  integrity, launch authority, confirmer, PolicyBroker, planner,
  TrustedLaunchCoordinator, WindowActivationService, UIA supervisor
  + snapshot service, FocusCoordinator, fixture executor,
  ProjectDetector, dialog guard, takeover source, RecoveryService
  and Phase3Bridge over shared authorities, with revoke/shutdown
  lifecycle and initialization-failure cleanup. The native worker
  now requires a parent-owned first-line bootstrap on its private
  stdin pipe (no env/CLI/importable-token enablement).
- **G02** Complete desktop workflow (apps discovery + ambiguous
  selection, observed windows with human identities, persisted
  launch/activation/fixture preparation, trusted approval binding
  app+window+operation+verified precondition+postcondition, durable
  receipts, pause/cancel/resume) over narrow `phase3.*` kinds.
  Ordinary startup still constructs the disabled surface.
- **G03** Scoped schema selection: dedicated marker-bound synthetic
  acceptance storage opens v3 only with an owner authorization
  object; ordinary storage stays v2; real-user storage is rejected.
- **G04** Takeover mapping relative to the active operation; native
  activity source resolves foreground HWND→authorized window id and
  owns its hook thread/pump/cleanup; dialog stops dispatch and is
  never dismissed; integrated (not isolated) tests.
- **G05** Native fixture contract (automation-id control contract,
  strict counter, script launches rejected) plus a reproducibly
  built `AETHERFixture.exe` (in-box `csc.exe`, delay as an on-window
  toggle, no arbitrary arguments).
- **G06** Authoritative privacy authority in composition (worker
  enforces collection mode before name access; `read_value` removed
  from the worker contract; bounded request values; explicit worker
  completeness; privacy-change-in-flight rejection), project
  detection without unregistered probing and with root-resource
  binding, and window-activation confirmation binding validation.

Evidence at the gate head: backend + desktop gates (see STATUS).
Simulated/Linux evidence only — not native evidence, not formal
acceptance. The runnable campaign is
`docs/engineering/PHASE3_NATIVE_ACCEPTANCE.md`; the decision package
is `docs/security/PHASE3_ACTIVATION_PROPOSAL.md` (not approved).
