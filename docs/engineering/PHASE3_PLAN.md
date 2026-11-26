# AETHER OS — Phase 3 Plan: Windows State, Application Discovery and Generic Application Control

**Status:** CP0–CP2 foundation implemented on
`integration/phase3-windows-state-app-control` (from merged baseline
`14614dcf99c79477dec36e1c25e10e17397cf763`). **Phase 3 is not
complete. No native observation, application launching or UI
interaction is enabled. CP3+ require separate authorization.**
Formal Phase 2 acceptance remains **NOT COMPLETE**
(`PHASE2_WINDOWS_ACCEPTANCE.md` §10 outstanding); this plan does not
waive it. Parallel CP0–CP2 development was explicitly authorized as
foundation-only work.

Authority: `docs/architecture/MASTER_SPEC.md`. Where this plan and
the spec's illustrative repository blueprint differ (folder names),
the merged repository layout governs; the spec's behaviour governs.

## 0. Implementation-status vocabulary (F-scope correction)

| Term | Meaning here |
|---|---|
| Contract defined | Typed shapes exist and are tested |
| Platform-independent behaviour implemented | Logic runs and is tested on Linux with fake sources |
| Native implementation source written | Real Win32 source exists behind guards (F01/F02), verified only via injected API fakes |
| Native activation disabled | No production path can start it (current state) |
| Native behaviour verified | Requires future native Windows runs — **not achieved** |
| Formal acceptance | Requires the future acceptance campaign — **not achieved** |

After the F01–F08 correction batch: contracts and platform-independent
behaviour are implemented; the native observer (SetWinEventHook +
message pump) and bounded stdlib discovery sources are *written* and
fake-verified; AppsFolder COM enumeration remains truthfully
`unavailable` until the pywin32 checkpoint. Native activation is
disabled and nothing native is verified.

## 1. Traceability

| Requirement (spec) | Existing at baseline | CP0–CP2 implementation | Later checkpoint |
|---|---|---|---|
| Event-driven observer (Windows control; ADR-007) | `WorldStateObservation` contract only | `world_state/observer.py`: bounded queue, overflow→uncertainty+reconciliation, lifecycle; fake source; guarded inert native source (`adapters/windows/native_observer.py`) | Native activation (separate auth) |
| Privacy modes (State observation privacy policy) | `DataClass` only | `world_state/privacy.py`: modes `off/metadata_only/active_app_only/workspace_context/content_on_demand`, opt-in gate, collection-boundary filtering, sensitive/elevated/unclassifiable exclusion, pause+invalidation | Foreground content path (not in Phase 3 scope yet) |
| WorldState service | Contract only | `world_state/service.py`: in-memory only, TTL expiry, HWND/PID-reuse replacement, destroyed/exit invalidation | Model-context summary wiring |
| App discovery/registry (Control ladder) | Nothing | `core/apps/registry.py`: in-memory registry, provenance, freshness, executable-drift staleness; guarded inert Windows sources (`adapters/windows/discovery.py`) | Native discovery activation |
| Fuzzy aliases (FTS5 + RapidFuzz) | Nothing | `core/apps/resolution.py`: exact→alias→normalized→FTS5 retrieval→real RapidFuzz ranking; margin ambiguity → clarification | Native tuning with measured data |
| Typed app/window resources (R3) | `ResourceRef` kinds existed; concrete registry filesystem-only | `core/contracts/app_window.py` identities; `CapabilityRegistry.phase3_foundation()` with disjoint `app:`/`window:` argument patterns; filesystem patterns unchanged | Broker-integrated app/window authority (CP3 design below) |
| Adapter contract `prepare()` | Interface lacked `prepare` | Non-abstract default (`PREPARE_NOT_SUPPORTED`) preserving Phase 0 adapters; `FakeWindowsAdapter` implements it | Real adapter conformance |
| Launcher (CP3) | Nothing | **Not implemented** (no `app.launch` capability exists) | CP3 proposal §4 |
| UIA snapshot/interaction (CP4/CP5) | Nothing | **Not implemented** | Proposal required before CP5 |
| Active project (3H), dialogs/takeover (3I) | Fs roots; task PAUSED/UNVERIFIED states | Design only (§5, R1/R2) | CP6 |

## 2. Architecture (CP0–CP2)

- **Processes:** unchanged (Electron main ↔ authenticated channel ↔
  Python backend). The observer core is platform-independent; the
  native source is not imported by composition or the channel service.
- **Collection flow (R5):** enabled sensor policy → permitted
  collection → normalization → bounded in-memory WorldState → output
  filtering. Titles are bounded (256 chars), treated as untrusted
  data, and never retained for sensitive/elevated/unclassifiable apps.
- **Identities (R4):** registration identity (durable `app:<uuid5>`)
  ≠ executable identity (digest evidence; drift → stale) ≠ process
  instance (pid + creation time) ≠ window instance (broker `window:`
  id binding HWND+process instance+UIA runtime id). Discovery confers
  no launch trust.
- **Overflow (R6):** queue capacity 256 (provisional default, not a
  measured guarantee); drops increment a counter, mark state
  uncertain, and force reconciliation that clears retained windows.
- **Retention (Decision 8):** in-memory only. No persisted titles,
  snapshots, or activity history.

## 3. Refined designs requiring review before CP3+

### R1 — Execution-state and evidence architecture (design only in CP0–CP2)
The persistent store's `_EXECUTION_TRANSITIONS` are evidence-gated by
filesystem grant/consumption/receipt facts, and `EXECUTING → PAUSED`
is not permitted. **No transition was changed.** Before CP3, a
separate reviewed design must define, per operation class: T0/T1
navigation evidence (resolution + launch-attempt + observed
postcondition facts, *without* fabricating a filesystem grant), T2
mutation evidence (existing grant stack, unchanged), how pre-effect
pause differs from post-effect interruption (`PAUSED` vs
`RECOVERING`/`UNVERIFIED`), and durable attempt/verification records.
Renderer/model claims must never drive execution states. No third
task-state machine will be introduced.

### R2 — Manual takeover (design only; no input monitoring in CP0–CP2)
Foreground events are insufficient (same-HWND intervention exists).
Proposed for later review: during an active controlled operation
only, a bounded activity signal (foreground change; automation-vs-user
input discrimination via injected-event flags where Windows reports
them reliably; input-activity *presence* — never key values, text, or
histories) pauses automation, releases locks, and requires fresh
observation before resume. Where discrimination is unreliable, the
affected capability must be denied/limited. No atomicity or fixed
latency is claimed.

### R7/R8 — Worker and focus locks (design only)
The UIA worker (later) is a reliability boundary, not a security
sandbox; post-begin timeouts yield uncertain outcomes, never replay.
Focus locks (CP5 design) need per-window identity, `desktop:foreground`
coordination, task ownership, ordering, expiry, cancellation, crash
recovery via persistent task state, and stale-lock reconciliation; a
lock never proves a window is safe to interact with.

## 4. CP3 proposal (requires separate authorization)

Verified application launching: planner goal `launch_application`
→ `app.launch` (T1) against a registry-issued `app:` resource only;
identity+availability re-verification at execution; declared launch
method only (AppsFolder activation or explicitly approved executable;
no arbitrary paths/args/shell); single-instance detection; bounded
postcondition verification (intended process/window observed, or
truthful uncertainty); enablement via a distinct default-disabled
Phase 3 mechanism (Decision 4) with trusted initialization, scoped
app allowlist, lifetime and revocation. Depends on the R1 evidence
design being approved first.

## 5. Acceptance (proposed, not yet run natively)

Scenarios P3-01…P3-25 from the Phase 3 directive, mapped to spec
E-01/E-02/E-05/E-06/E-07/E-08/E-15, will be specified with
setup/action/expected/denial/evidence/cleanup/class/pass-criterion in
the native acceptance procedure at the CP7 checkpoint. Foundation
tests in this batch are platform-independent (fake sources) plus real
RapidFuzz ranking; **they are not native Windows evidence.**

## 6. Performance defaults (provisional, unmeasured)

Queue 256 events; observation TTL 30 s; reconciliation on demand /
overflow (5 s sweep proposed for native activation); registry cap
2048 records. All must be measured on the target machine before being
stated as guarantees.
