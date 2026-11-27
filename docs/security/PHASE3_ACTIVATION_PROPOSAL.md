# Phase 3 activation decision package (requires separate owner approval)

Status: **PROPOSAL ONLY — not authorized.** Ordinary operation is
default-denied (`Phase3Surface.disabled()`, `phase3_native_disabled`);
the native composition factory raises until a separately approved
owner activation exists; schema v3 opens only through the scoped
acceptance-storage mechanism below. This package separates *native
acceptance authorization* (a finite campaign on synthetic storage)
from *production enablement* (not proposed here).

## Candidate

- Branch/PR: `integration/phase3-windows-state-app-control`, PR #37.
- Final candidate SHA: recorded by the reviewer at approval time from
  the PR head (the gate report names the exact SHA; approval must
  name that same SHA — any later commit invalidates approval).
- Pinned dependencies: backend lockfile (RapidFuzz, pywin32,
  pywinauto + comtypes, Windows markers) and desktop
  `package-lock.json` (Node 22.22.3 / npm 10.9.8) — no new installs
  beyond the already-pinned sets.

## What approval would authorize (and nothing else)

1. **Safe isolated storage creation**: one dedicated directory named
   `aether-phase3-acceptance-<campaign>` at an owner-chosen location,
   created by `open_acceptance_store` with an
   `OwnerAcceptanceAuthorization` (decision reference = this
   approval, expiry ≤ campaign window). It rejects symlinked
   components, pre-existing unrelated storage and expired decisions.
2. **Schema selection**: that storage only opens at schema v3 through
   the scoped mechanism; ordinary storage remains v2
   (`ACTIVE_SCHEMA_VERSION=2` unchanged); Phase 2 migration hashes
   and execution protections are verified by the normal store path;
   interrupted navigation/UI operations are reconciled on open. No
   real-user database is migrated, opened at v3, or downgraded.
   Rollback = close the app and remove/archive the verified
   acceptance directory; there is no schema downgrade.
3. **Trusted startup configuration**: the reviewed controlled
   composition (G01) constructed in trusted main/host code from this
   approval; the worker receives its activation only via the
   parent-owned first-line bootstrap on its private stdin pipe.
   Renderer IPC, environment flags and importable tokens are not
   authority (the `AETHER_PHASE3_SIMULATED` harness flag builds only
   the *simulated* composition for automated tests and is never set
   by the desktop app).
4. **Authorized app identities**: Notepad, Calculator, File Explorer,
   VS Code (if installed), Windows Settings (read/navigation scope),
   and the preserved compiled `AETHERFixture.exe` (hash-verified
   only; no rebuild in this campaign; the Python fixture is never
   launched as a script). Fixture identity is the approved executable identity +
   verified process/window instance tokens — never title text.
5. **Exact capability allowlist**: `app.launch` (registered apps
   only), `window.activate`, read-only UIA observation under
   `metadata_only` (fixture counter read is a narrow fixture-specific
   authorization), and `uia.invoke_fixture` restricted to the
   approved fixture app + identity token. Nothing else: no SetValue,
   text entry, selection, navigation, file dialogs, Explorer
   mutation, or arbitrary applications.
6. **Session lifetime/expiry**: one desktop session, one activation
   epoch ≤ 4 hours; bindings, snapshots, nonces and confirmations
   die with it; authorization expiry is enforced by the storage
   factory and enablement.
7. **Privacy controls**: observation starts off; explicit
   `metadata_only` opt-in; pause/opt-out revokes collection, purges
   snapshots and voids outstanding approvals; password values are
   never queried; unknown/elevated contexts fail closed; the worker
   enforces the collection mode before reading accessible names.
8. **Worker lifecycle**: parent-owned subprocess, bounded framing,
   health-checked startup, parent deadlines, confirmed termination,
   restart-after-uncertainty without replay; no replacement worker
   while an earlier one may still issue effects.
9. **Revocation**: privacy pause/opt-out, session end, window/process
   replacement, manual takeover, or an unexpected dialog revokes
   outstanding bindings immediately; consumed approvals/gestures are
   single-use and never replayable; dialogs are never auto-dismissed.
10. **Shutdown**: worker terminated and COM released, activity hooks
    removed on their owning thread, snapshots purged, storage closed.
11. **Crash recovery**: restart reconciles through the persistent
    authority before any new execution; uncertain outcomes remain
    uncertain; nothing auto-resumes into EXECUTING.
12. **Default-denied ordinary operation**: without this approval,
    ordinary launches expose no Phase 3 execution (verified by
    automated tests at the gate head).

## Exact owner-side acceptance commands (after approval only)

Run in non-administrator PowerShell 5.1 at `D:\A.E.T.H.E.R`. All
tool paths are explicit; the global PATH is never relied on for
Python, Node or Git. Nothing is reinstalled or rebuilt: the
preserved venv, `node_modules`, portable Node and compiled fixture
are verified, and any absence is a stop-and-report condition.

```powershell
git rev-parse HEAD            # must match the approved candidate SHA
$Python = "D:\A.E.T.H.E.R\backend\.venv\Scripts\python.exe"
& $Python --version           # Python 3.12.10 (preserved backend venv)
$EvidenceRoot = "D:\AETHER-A-Evidence-5b02b5d18c3c4e649c469a7920b63c6a"
$Npm = Join-Path $EvidenceRoot "phase3-final-desktop-a26d2da4a9c54f3cad582ec0be6861a0\node-v22.22.3-win-x64\npm.cmd"
# Fresh, never-reused pytest scratch under the evidence root:
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$BaseTemp = Join-Path $EvidenceRoot "phase3-pytest-$Stamp"
if (Test-Path $BaseTemp) { throw "basetemp already exists; choose a new name" }
New-Item -ItemType Directory -Path $BaseTemp | Out-Null
if ((Get-Item $BaseTemp).Attributes -match "ReparsePoint") { throw "basetemp must not be a reparse point" }
& $Python -m pytest backend/tests -q --basetemp $BaseTemp
& $Python -m ruff check backend tools
& $Python -m ruff format --check backend tools
cd backend; & $Python -m mypy; cd ..
cd apps\desktop; $env:AETHER_DEV_PYTHON = $Python; & $Npm run check; & $Npm test; cd ..\..
# Fixture: verify the preserved build by hash; do NOT rebuild.
(Get-FileHash tools\windows-fixture\AETHERFixture.exe -Algorithm SHA256).Hash
# must equal E0F51AAA58372DB0EB54CF4D29F750D0D49FCA9BEDB4226D0EAE5963497F569D
```

Then execute `docs/engineering/PHASE3_NATIVE_ACCEPTANCE.md`
(P3-01…P3-25) exactly as written. **Do not start until this package
has been independently reviewed and explicitly approved.**

## Evidence collection and cleanup

Per-row evidence (receipts, outcome tokens, snapshot summaries,
screenshots) is recorded in the campaign register with digests;
artifacts stay owner-held unless the owner chooses to archive them.
Cleanup is the campaign's standard cleanup: pause observation, close
test windows, verify no fixture/worker processes remain, and remove
only the exact verified acceptance storage directory. The real
application database is never opened by the campaign.

## Explicitly not authorized by this package

Production enablement in ordinary launches; schema v3 for any
real-user storage; Phase 4 capabilities; running the historical
combined Phase 2 verifier. (Phase 2 owner acceptance is complete
and locally archived; nothing here reopens it.)

---

## Implemented controlled startup (A01–A05, this branch)

Status: **IMPLEMENTED — owner execution still NOT authorized.**
The mechanism below exists in source and is covered by simulated/
fake-platform tests (`backend/tests/test_phase3_controlled_native.py`).
It has never run natively. Do not execute this procedure until an
independent review accepts the implementing commit and the owner
explicitly approves that exact SHA.

What is implemented:

- `Phase3Composition.native(...)` is a real factory. It validates a
  `ControlledAcceptanceAuthorization` (approved commit, owner
  decision reference, campaign, storage id/path, app allowlist,
  capability allowlist within the build ceiling, session, activation
  epoch, expiry, `metadata_only` privacy mode, fixture identity
  token) against the live commit and the acceptance-storage marker
  **before** opening storage or constructing native components.
- Acceptance storage (schema v3) is containment-checked: fixed local
  volume, no symlink/junction/reparse components, exclusive
  creation, marker bound to storage/decision/campaign/directory
  identity, hard-link and unrelated-content rejection. Ordinary
  storage remains v2; the pending-v3 flag alone opens nothing.
- The UIA worker receives session/epoch/scope/operations/expiry in
  its parent-owned bootstrap and enforces them per request; failed
  startup is terminated, effectful malformed/stale responses are
  uncertain and never replayed, shutdown confirms process exit.
- The native UIA provider takes its collection mode before reading
  any accessible name (fixture status control only, under the narrow
  fixture authorization); password classification precedes content;
  elements without a real UIA runtime id are refused. Same-window
  takeover uses content-free low-level activity hooks in addition to
  focus events; unavailable monitoring denies effectful execution.
- One continuous authenticated workflow test runs startup → opt-in →
  discovery → resolution → launch → verification → window
  registration → activation → snapshot → fixture approval →
  single-use commitment → verified effect → receipt → shutdown over
  the real composition, store, broker, planner and gesture authority.

### Exact owner-side procedure (after future approval only)

Non-administrator PowerShell 5.1 at `D:\A.E.T.H.E.R`, Python
3.12.10, Node 22.22.3, `npm.cmd` 10.9.8. No elevation, no new
worktrees, no execution-policy changes.

```powershell
# 1. Candidate verification — HEAD must equal the approved SHA.
git rev-parse HEAD
git status --porcelain        # must be empty

# 2. Environment checks (verify only; never reinstall/rebuild).
$Python = "D:\A.E.T.H.E.R\backend\.venv\Scripts\python.exe"
& $Python --version           # 3.12.10 (preserved backend venv)
$EvidenceRoot = "D:\AETHER-A-Evidence-5b02b5d18c3c4e649c469a7920b63c6a"
$NodeDir = Join-Path $EvidenceRoot "phase3-final-desktop-a26d2da4a9c54f3cad582ec0be6861a0\node-v22.22.3-win-x64"
& (Join-Path $NodeDir "node.exe") --version   # v22.22.3
& (Join-Path $NodeDir "npm.cmd") --version    # 10.9.8

# 3. Gates at the candidate: see "Exact owner-side acceptance
#    commands" above (pinned Python, fresh basetemp, no npm ci,
#    no fixture rebuild - hash verification only).

# 4. Fixture integrity evidence (verify ONLY; never rebuild here -
#    a mismatch is a stop-and-report condition).
(Get-FileHash tools\windows-fixture\AETHERFixture.exe -Algorithm SHA256).Hash
#    must equal E0F51AAA58372DB0EB54CF4D29F750D0D49FCA9BEDB4226D0EAE5963497F569D

# 5-7. Authorization artifact + isolated storage (one tool run).
#     First verify the campaign root and freshness (nothing from an
#     earlier campaign is overwritten or reused):
if ((Get-Item D:\AETHER-acceptance).Attributes -match "ReparsePoint") { throw "acceptance root must not be reparse" }
#     The tool discovers the approved apps, derives the fixture
#     identity and token, generates session/epoch/storage identity,
#     initializes the isolated v3 database directory
#     aether-phase3-acceptance-<campaign> FIRST, then creates the
#     SEPARATE sibling synthetic workspace
#     aether-phase3-workspace-<campaign>, and only then writes
#     D:\AETHER-acceptance\authorization-<campaign>.json
#     (exclusively), so a failed run leaves no usable-looking
#     authorization. The synthetic project is created by the owner
#     inside the workspace (never inside the database directory).
#     The tool reads the candidate commit via git: put the trusted
#     Git directory on this shell's PATH explicitly first.
$env:PATH = "C:\Program Files\Git\cmd;$NodeDir;$env:PATH"
#     Each campaign uses a NEW --campaign name. No internal
#     identifier is constructed by hand. If discovery reports a
#     requested name as ambiguous, re-run with exact --app-ids
#     values instead of names.
cd backend
& $Python -m aether.core.apps.authorization_artifact --decision-reference "<owner decision reference>" --campaign campaign-<unique-name> --apps "Notepad,Calculator,File Explorer" --acceptance-root D:\AETHER-acceptance
cd ..

# 8. Controlled startup (trusted main selects the controlled entry
#    point only from this owner-set main-process environment value).
#    The trusted Git executable is pinned absolutely (the sanitized
#    backend PATH cannot resolve git by name).
$env:AETHER_PHASE3_AUTHORIZATION = "D:\AETHER-acceptance\authorization-<campaign>.json"   # the exact file written in step 5-7
$env:AETHER_GIT_EXECUTABLE = "C:\Program Files\Git\cmd\git.exe"
if (-not (Test-Path $env:AETHER_GIT_EXECUTABLE)) { throw "trusted Git executable not found; stop and report" }
$env:AETHER_DEV_PYTHON = $Python
$env:PATH = "$NodeDir;$env:PATH"   # portable Node resolves for Electron/backend subprocesses
cd apps\desktop; & $Npm run start   # builds the bundles, then launches Electron
# Expected indication: Phase 3 surface reports nativeAvailable=true,
# privacy mode "off" until explicit metadata_only opt-in in the UI.

# 9. Campaign: run docs/engineering/PHASE3_NATIVE_ACCEPTANCE.md
#    P3-01...P3-25 within the authorization expiry; capture receipts.

# 10. Revocation + safe shutdown: opt out of observation in the UI,
#     close the app (composition revokes, stops observer/activity,
#     terminates and confirms the worker, purges snapshots, closes
#     storage). Remove the env var afterwards:
Remove-Item Env:AETHER_PHASE3_AUTHORIZATION
```

Any mismatch — wrong commit, expired artifact, substituted storage,
missing marker — refuses startup with no fallback to ordinary
storage. Native results remain **unverified** until this campaign is
actually run and independently reviewed.
