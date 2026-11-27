# Phase 3 native acceptance campaign (PREPARED — do not run yet)

Status: **PREPARED ONLY.** Nothing here is a request to run anything on
the owner's machine until the activation decision package in
`docs/security/PHASE3_ACTIVATION_PROPOSAL.md` is independently
reviewed and explicitly approved. Phase 3 native activation remains
disabled in ordinary operation; schema v3 is selectable only for
dedicated isolated acceptance storage (G03). Phase 2 owner
acceptance is complete and locally archived (owner record, incl.
the independently executed native interruption harness); this
campaign does not reopen Phase 2. The historical combined Phase 2
verifier must NOT be run.

## Environment (exact)

- Windows 11, non-administrator PowerShell 5.1 (no execution-policy
  bypass, no elevation, no Developer Mode, no WSL, no new worktrees).
- Permanent repository `D:\A.E.T.H.E.R`.
- Owner evidence root (preserved; never recreated):
  `D:\AETHER-A-Evidence-5b02b5d18c3c4e649c469a7920b63c6a`.
- Backend interpreter (preserved venv, Python 3.12.10):
  `D:\A.E.T.H.E.R\backend\.venv\Scripts\python.exe`. Do not rely
  on the global PATH for Python, Node or Git.
- Portable Node.js 22.22.3 / npm 10.9.8 (preserved):
  `D:\AETHER-A-Evidence-5b02b5d18c3c4e649c469a7920b63c6a\phase3-final-desktop-a26d2da4a9c54f3cad582ec0be6861a0\node-v22.22.3-win-x64`
  (use its `npm.cmd` by full path or prepend that directory to the
  session PATH explicitly).
- Compiled fixture (preserved; hash-verify only — a rebuild is NOT
  part of this campaign, and a hash mismatch is a stop-and-report
  condition, not a rebuild trigger): `tools\windows-fixture\AETHERFixture.exe`,
  SHA256 `E0F51AAA58372DB0EB54CF4D29F750D0D49FCA9BEDB4226D0EAE5963497F569D`.
- Trusted Git executable for controlled startup: record the actual
  installed absolute path once (e.g. `C:\Program Files\Git\cmd\git.exe`)
  and set it explicitly (see the controlled-startup step). If it
  cannot be verified, stop and report — the backend denies
  controlled startup without it.
- Representative suite: Notepad, Calculator, File Explorer, VS Code
  if installed, Windows Settings (permitted read/navigation only),
  and the native synthetic fixture (the preserved compiled
  `AETHERFixture.exe`; the fixture is the ONLY
  approved effectful UI operation target).
- No unnecessary duplicate dependency installs; no recursive cleanup
  of unverified paths; offline operation expected (observe and record
  any outbound-network behavior; none is required or permitted for
  the fixture).

## Windows verification commands (exact)

Run from non-admin PowerShell 5.1 at `D:\A.E.T.H.E.R`, HEAD equal to
the approved candidate SHA, clean tree — with exactly one known
allowed exception: `git status --porcelain` may show ONLY the exact
known untracked fixture `?? tools/windows-fixture/AETHERFixture.exe`
(it is owner-held build output, hash-verified below; any *other*
porcelain output is a stop condition). pytest scratch MUST be a
new, non-reparse, non-protected directory under the existing owner
evidence root — synthetic projects under protected AppData paths
fail resource registration by design, and those protections must
not be weakened. **Never reuse an existing `--basetemp` path.**

```powershell
$Python = "D:\A.E.T.H.E.R\backend\.venv\Scripts\python.exe"
$EvidenceRoot = "D:\AETHER-A-Evidence-5b02b5d18c3c4e649c469a7920b63c6a"   # existing owner evidence root
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$BaseTemp = Join-Path $EvidenceRoot "phase3-pytest-$Stamp"
if (Test-Path $BaseTemp) { throw "basetemp already exists; choose a new name" }
New-Item -ItemType Directory -Path $BaseTemp | Out-Null
if ((Get-Item $BaseTemp).Attributes -match "ReparsePoint") { throw "basetemp must not be a reparse point" }
& $Python --version            # must print Python 3.12.10
& $Python -m pytest backend/tests -q --basetemp $BaseTemp
& $Python -m ruff check backend tools
& $Python -m ruff format --check backend tools
# strict mypy, from backend\
cd backend; & $Python -m mypy; cd ..
# desktop gates (portable npm by full path; node_modules preserved -
# if it is missing, stop and report instead of reinstalling)
$NodeDir = Join-Path $EvidenceRoot "phase3-final-desktop-a26d2da4a9c54f3cad582ec0be6861a0\node-v22.22.3-win-x64"
$Npm = Join-Path $NodeDir "npm.cmd"
# Subprocesses (node/tsx/tsc/electron) resolve the portable Node
# from the session PATH - never from any global installation.
# NOTE: `npm run check` already includes the desktop test suite;
# no duplicate `npm test` run is required or wanted.
$env:PATH = "D:\A.E.T.H.E.R\backend\.venv\Scripts;$NodeDir;$env:PATH"   # pinned venv + portable Node
cd apps/desktop; $env:AETHER_DEV_PYTHON = $Python; & $Npm run check; cd ..\..
# fixture integrity (verify only; rebuild is NOT part of verification)
(Get-FileHash tools\windows-fixture\AETHERFixture.exe -Algorithm SHA256).Hash
# must equal E0F51AAA58372DB0EB54CF4D29F750D0D49FCA9BEDB4226D0EAE5963497F569D
```

Record the exact basetemp used with the campaign evidence; a rerun
always creates a fresh one.

## Standard setup (unless a row says otherwise)

S1. Start from the exact candidate SHA recorded in the activation
    decision package; verify `git rev-parse HEAD` matches.
S2. Campaign layout. Use ONLY the existing owner evidence root
    `D:\AETHER-A-Evidence-5b02b5d18c3c4e649c469a7920b63c6a`. Inside
    it, create ONE fresh campaign directory
    `phase3-campaign-<stamp>` — exclusively created, verified
    non-reparse, never reusing or renaming any historical evidence.
    All campaign paths are siblings INSIDE that campaign directory:
    the schema-v3 database directory
    `aether-phase3-acceptance-<campaign>`, the synthetic workspace
    `aether-phase3-workspace-<campaign>`, and the artifact
    `authorization-<campaign>.json` (this directory is the tool's
    `--acceptance-root`). Do NOT pre-create any of the three: the
    authorization tool initializes storage exclusively first, then
    creates the workspace, then writes the artifact exclusively (an
    existing campaign artifact is never overwritten — choose a
    fresh campaign name; never delete campaign evidence). The
    database directory refuses unrelated content, so NOTHING is
    ever created inside it. After the tool run, create the
    synthetic project at
    `aether-phase3-workspace-<campaign>\synthetic-project` inside
    the *workspace* (never inside the database directory), with a
    synthetic `pyproject.toml` marker. The real AETHER repository
    is never registered (P3-23).
S3. Start the desktop app in the reviewed controlled-acceptance
    configuration (decision package §"Exact owner-side commands").
    Confirm the Phase 3 panel shows observation **off** before opt-in.
S4. Record: candidate SHA, storage path, app identities offered by
    discovery, and the session's capability list.

## Standard cleanup (every row)

C1. Pause/disable observation from the Phase 3 panel.
C2. Close any fixture/test application windows opened by the row.
C3. Record outcome + evidence digests in the campaign register.
C4. At campaign end: shut the app down (worker must exit; verify no
    `AETHERFixture.exe` or worker process remains), then — only after
    verifying the exact storage directory created in S2 — archive or
    remove that directory. Never touch the real task database.

## Campaign

| ID | Scenario | Steps | Expected | Pass criteria | Evidence |
|---|---|---|---|---|---|
| P3-01 | Sensors disabled before opt-in | Launch ordinarily; open Phase 3 panel before opt-in | Observation off; native disabled or no collection; capabilities truthful | No window/app data collected before opt-in | Panel screenshot/notes |
| P3-02 | Event-driven active-window observation | Opt in (metadata_only); switch between two allowed apps | Active window identity updates event-driven; no polling artifacts | Correct app/window identity each switch | State log |
| P3-03 | Closure and identity invalidation | Close the observed window; reopen the app | Old window identity invalid; new instance gets a new identity | Stale identity cannot be inspected/used | State log |
| P3-04 | Privacy changes | Opt out, then pause, mid-session | Collection stops; retained snapshots void; approvals on old snapshots refused | Old snapshot/approval unusable | Denial reasons |
| P3-05 | Application discovery | Open app search (empty query) | Discovered apps listed with discovery availability and launch-method support shown separately | No discovered app presented as launch-eligible; eligibility is decided only at preparation | Search results |
| P3-06 | Exact and fuzzy resolution | Search exact name, then a near-miss fuzzy name, then a partial name | Exact resolves uniquely; fuzzy shows the best match for confirmation; partial names show retrieval-only candidates, never a resolution | No silent wrong-app selection | Candidate list + resolution label |
| P3-07 | Ambiguous candidate clarification | Search a name matching two apps | "Ambiguous match" shown; no launch prepared until the exact application is selected | Selection is explicit; changing the search clears a stale selection | Panel state |
| P3-08 | Verified application launching | Prepare launch of Notepad; approve in trusted window | One process; verified window; durable receipt SUCCEEDED | Exactly one instance; receipt matches | Receipt id |
| P3-09 | Single-instance application activation | With Notepad open, prepare window activation; approve | Same instance foreground-verified once | No second process; no keystrokes/clicks | Activation receipt |
| P3-10 | Native UIA snapshot bounds | Inspect Calculator window | Bounded snapshot; completeness stated; no silent truncation | Sizes within limits; truncation flagged if present | Snapshot summary |
| P3-11 | Sensitive control exclusion | Inspect fixture window with password field | Password name/value absent everywhere | No password content in snapshot/logs | Snapshot summary |
| P3-12 | Metadata-only collection | Inspect fixture in metadata_only mode | No unrestricted accessible names retained | Worker enforced mode at collection | Snapshot summary |
| P3-13 | Worker interruption | During a long fixture inspection, terminate worker (reviewed test harness) | TIMED_OUT/unavailable truthfully; worker cleaned up; no replay | No hung process; no duplicate request | Outcome + process list |
| P3-14 | Verified fixture interaction | Hash-verify the preserved fixture (no rebuild); launch via approved identity; prepare Increment; approve | Count 0→1 exactly; independent verification; SUCCEEDED receipt | Exactly +1 | Receipt + final Count |
| P3-15 | Stale element rejection | Prepare Increment; click fixture Replace; approve the old plan | Refused pre-dispatch; no invocation on the replacement | Count unchanged | Denial outcome |
| P3-16 | Disabled/hidden control rejection | Prepare against the disabled fixture button (diagnostic plan) or hide Increment | Denied (`element_disabled`/not dispatchable) | No effect | Denial |
| P3-17 | Delayed effect truthfulness | Enable fixture delay toggle; approve Increment | Timeout/uncertain truthfully; never auto-replayed; final count read independently | No duplicate increment | Outcome + Count |
| P3-18 | Manual takeover within the same window | Arm a fixture op; click inside the fixture window manually | Takeover detected; op denied/uncertain; ownership released safely | No SUCCEEDED without verification | Takeover indication |
| P3-19 | Alt-Tab takeover | Arm a fixture op; Alt-Tab to another app | Foreground takeover detected; dispatch stopped | No effect dispatched | Indication + Count |
| P3-20 | Unexpected dialog | Open fixture modal; attempt an op | Dispatch halted; dialog never auto-dismissed; fresh observation+approval required to resume | No effect behind dialog | Dialog indication |
| P3-21 | Safe pause/resume | Pause an armed task; resume | PAUSED holds nothing live; resume goes to fresh planning/precheck; consumed approvals never replay | No PAUSED→EXECUTING jump | Task states |
| P3-22 | Restart reconciliation | Restart the app (controlled config) with an armed/paused task; then re-register the same synthetic project in the workspace and ask for the current project | States reconciled truthfully; uncertain never auto-succeeded; acceptance storage reopens cleanly and workspace project evidence is untouched | No replay after restart; no storage/evidence loss | Task state after restart + project candidate |
| P3-23 | Project reference resolution | Create the synthetic project inside the synthetic workspace (S2); register it via the panel's trusted directory dialog; in the panel click **Begin Explorer project check** (the trusted main process establishes the one-shot 60-second authorization; nothing is read yet); switch to the Explorer window showing the project folder so that Explorer window itself becomes foreground; return to AETHER and click **Complete project check** within the 60 s window (clicking AETHER never supplies evidence — only the verified Explorer foreground change does); **Cancel project check** voids the attempt | Deterministic candidate (the synthetic project) resting on actual fresh Explorer evidence, or truthful `explorer_evidence_unavailable` when no Explorer foreground evidence was captured (foreground mismatch, unrelated windows and expiry never produce a candidate from mere registration) | Registered roots only (synthetic-workspace boundary — never the database directory); generic state refreshes read no Explorer path; no continuous polling and no arbitrary path collection; out-of-scope folders are neither retained nor shown; pausing/opting out, privacy change, expiry or revocation voids the check; no permission expansion; no executor enabled | Candidate/limitations |
| P3-24 | Real-app read-only navigation suite | For Explorer and VS Code (if installed) and Settings (read/navigation scope): activate window + snapshot only | Verified activation; bounded snapshot; zero interactions sent | No clicks/keys; limitations reported truthfully for missing apps | Receipts |
| P3-25 | Boundaries preserved | Ordinary relaunch per §"Ordinary-mode verification" below; attempt Phase 3 actions without acceptance config; confirm offline behavior | Ordinary mode default-denied (`phase3_native_disabled`); Phase 2 surfaces unchanged; no outbound network required/observed beyond OS noise recorded | No ordinary-mode execution; no real-user database opened, migrated or modified | Panel + synthetic-DB schema check (`PRAGMA user_version` = 2 on the *synthetic* database) + real-storage fingerprint comparison only when its verified actual path is known (never opened through SQLite; an unverifiable path is reported, not assumed) |

## Recording and verdict

Record PASS/FAIL per row with evidence digests; update
`docs/engineering/STATUS.md`. A FAIL in P3-01, P3-04, P3-11, P3-14,
P3-20 or P3-25 stops the campaign. This campaign, even if fully
passed, is *native acceptance evidence for review* — it does not by
itself formally accept Phase 3. (Phase 2 owner acceptance is
complete and archived; this campaign neither reopens nor alters
it.)

## Representative application support matrix

| Application | Discovery identity | Integrity evidence | Launch | Notes |
|---|---|---|---|---|
| AETHER Fixture | explicit portable registration (.exe) | SHA-256 of the opened file + file identity | `CreateProcessW` | Only approved effectful UI target; full workflow |
| Notepad | AppsFolder (AUMID) | platform package query (family → full name + version, exact AUMID membership) | `IApplicationActivationManager` | Single-instance: success is declared only for an independently attributed process/window; otherwise truthfully uncertain |
| Calculator | AppsFolder (AUMID) | same packaged route | same | P3-10 inspects an already-open window |
| File Explorer | AppsFolder (AUMID), when enumerated | same packaged route | same, else truthfully refused | Shell-hosted windows may lack an attributable AUMID; existing-window activation/inspection uses observer bindings |
| Windows Settings | AppsFolder (AUMID) | same packaged route | read/navigation scope only | Activate + snapshot; no interactions |
| VS Code | uninstall / Start Menu listing | none (no approved launch method) | **unsupported in this campaign** | Search/listing and existing-window activation/inspection only; launch would require a separately approved portable-registration decision |

Discovery never confers authorization: every launch re-verifies
fresh, method-appropriate integrity evidence, and unverifiable
records are refused before any trusted approval is requested.

## Ordinary-mode verification (P3-01 / P3-25)

Run from non-admin PowerShell 5.1 at `D:\A.E.T.H.E.R`. This uses a
fresh isolated synthetic schema-v2 database; Phase 3 authorization
and Phase 2 Activation B stay disabled; ordinary mutation issuance
and execution stay disabled; real-user storage is never opened.

```powershell
$Python = "D:\A.E.T.H.E.R\backend\.venv\Scripts\python.exe"
$EvidenceRoot = "D:\AETHER-A-Evidence-5b02b5d18c3c4e649c469a7920b63c6a"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OrdRoot = Join-Path $EvidenceRoot "ordinary-v2-$Stamp"
if (Test-Path $OrdRoot) { throw "fresh path required" }
New-Item -ItemType Directory -Path $OrdRoot | Out-Null
if ((Get-Item $OrdRoot).Attributes -match "ReparsePoint") { throw "must not be reparse" }
$SyntheticDb = Join-Path $OrdRoot "tasks.sqlite3"

# Pin the interpreter; select ONLY the synthetic database; make
# sure no acceptance/review configuration leaks into this launch.
$env:AETHER_DEV_PYTHON = $Python
$env:AETHER_DEV_PYTHON_VERSION = "3.12.10"
$env:AETHER_FIXTURE_DB = $SyntheticDb
Remove-Item Env:AETHER_ACCEPTANCE_MODE, Env:AETHER_PHASE3_AUTHORIZATION, Env:AETHER_PHASE3_SIMULATED, Env:AETHER_REVIEW_DB, Env:AETHER_REVIEW_NARRATIVE, Env:AETHER_REVIEW_DEV_SEED -ErrorAction SilentlyContinue

# `npm.cmd run start` builds the renderer/Electron bundles and then
# launches Electron (it is not a no-rebuild command). node_modules
# is preserved; if it is missing, stop and report.
$Npm = Join-Path $EvidenceRoot "phase3-final-desktop-a26d2da4a9c54f3cad582ec0be6861a0\node-v22.22.3-win-x64\npm.cmd"
$env:PATH = "D:\A.E.T.H.E.R\backend\.venv\Scripts;$((Split-Path $Npm));$env:PATH"   # pinned venv + portable Node for all subprocesses
cd apps\desktop; & $Npm run start; cd ..\..

# In the app: the Phase 3 panel shows observation off /
# phase3_native_disabled (P3-01). Attempt one Phase 3 action and
# one Phase 2 approved-edit in a synthetic project: expect
# phase3_native_disabled and grant_issuance_disabled /
# mutation_not_enabled respectively. Record any network observation.
# Close the app, RESTART it once with the same ordinary-mode
# environment, and confirm the panel still shows
# phase3_native_disabled and no Phase 3 action becomes available.
# Then close the app and verify the SYNTHETIC database only:
& $Python -c "import sqlite3,sys; print(sqlite3.connect('file:' + sys.argv[1].replace('\\','/') + '?mode=ro', uri=True).execute('PRAGMA user_version').fetchone()[0])" $SyntheticDb
# Expected: 2 (schema v2). If the verified actual path of real-user
# storage is known from the machine record, compare Get-FileHash +
# LastWriteTimeUtc before/after WITHOUT opening it in SQLite; if it
# cannot be verified, record it as unverifiable rather than assuming
# an Electron userData location.
```
