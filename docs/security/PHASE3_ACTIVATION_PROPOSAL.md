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
   and `AETHERFixture.exe` built by `tools/windows-fixture/build_fixture.cmd`
   (in-box `csc.exe`; the Python fixture is never launched as a
   script). Fixture identity is the approved executable identity +
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

Run in non-administrator PowerShell 5.1 at `D:\A.E.T.H.E.R`:

```powershell
git rev-parse HEAD            # must match the approved candidate SHA
cd apps\desktop
npm.cmd ci                    # pinned lockfile; skip if node_modules already matches
npm.cmd run check
$env:AETHER_DEV_PYTHON = "<python 3.12.10 path>"
npm.cmd test
cd ..\..\backend
python -m pytest              # full backend gates at the candidate
python -m ruff check .
python -m mypy
cd ..\tools\windows-fixture
.\build_fixture.cmd           # builds AETHERFixture.exe (in-box csc)
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
real-user storage; Phase 4 capabilities; any change to the formal
Phase 2 acceptance verdict (NOT COMPLETE, unwaived); running the
historical combined Phase 2 verifier.
