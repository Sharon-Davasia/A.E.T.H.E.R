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
- Python 3.12.10; Node 22.22.3; npm 10.9.8 via `npm.cmd`.
- Permanent repository `D:\A.E.T.H.E.R`.
- Representative suite: Notepad, Calculator, File Explorer, VS Code
  if installed, Windows Settings (permitted read/navigation only),
  and the native synthetic fixture (`AETHERFixture.exe`, built by
  `tools/windows-fixture/build_fixture.cmd`; the fixture is the ONLY
  approved effectful UI operation target).
- No unnecessary duplicate dependency installs; no recursive cleanup
  of unverified paths; offline operation expected (observe and record
  any outbound-network behavior; none is required or permitted for
  the fixture).

## Windows verification commands (exact)

Run from non-admin PowerShell 5.1 at `D:\A.E.T.H.E.R`, HEAD equal to
the approved candidate SHA, clean tree. pytest scratch MUST be a
new, non-reparse, non-protected directory under the existing owner
evidence root — synthetic projects under protected AppData paths
fail resource registration by design, and those protections must
not be weakened. **Never reuse an existing `--basetemp` path.**

```powershell
$EvidenceRoot = "D:\AETHER-evidence"          # existing owner evidence root
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$BaseTemp = Join-Path $EvidenceRoot "phase3-pytest-$Stamp"
if (Test-Path $BaseTemp) { throw "basetemp already exists; choose a new name" }
New-Item -ItemType Directory -Path $BaseTemp | Out-Null
if ((Get-Item $BaseTemp).Attributes -match "ReparsePoint") { throw "basetemp must not be a reparse point" }
python -m pytest backend/tests -q --basetemp $BaseTemp
python -m ruff check backend tools
python -m ruff format --check backend tools
# strict mypy, from backend\
cd backend; python -m mypy; cd ..
# desktop gates
cd apps/desktop; npm.cmd run check; npm.cmd test; cd ../..
```

Record the exact basetemp used with the campaign evidence; a rerun
always creates a fresh one.

## Standard setup (unless a row says otherwise)

S1. Start from the exact candidate SHA recorded in the activation
    decision package; verify `git rev-parse HEAD` matches.
S2. Create the dedicated synthetic storage directory named
    `aether-phase3-acceptance-<campaign>` in the location recorded in
    the decision package; confirm it is new/empty and not a link.
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
| P3-05 | Application discovery | Open app search | Registered/discovered apps listed with availability | No unregistered app presented as launchable | Search results |
| P3-06 | Exact and fuzzy resolution | Search exact name, then a near-miss fuzzy name | Exact resolves uniquely; fuzzy offers candidates without auto-select | No silent wrong-app selection | Candidate list |
| P3-07 | Ambiguous candidate clarification | Search a name matching two apps | Clarification required; no launch prepared until selection | Selection is explicit | Panel state |
| P3-08 | Verified application launching | Prepare launch of Notepad; approve in trusted window | One process; verified window; durable receipt SUCCEEDED | Exactly one instance; receipt matches | Receipt id |
| P3-09 | Single-instance application activation | With Notepad open, prepare window activation; approve | Same instance foreground-verified once | No second process; no keystrokes/clicks | Activation receipt |
| P3-10 | Native UIA snapshot bounds | Inspect Calculator window | Bounded snapshot; completeness stated; no silent truncation | Sizes within limits; truncation flagged if present | Snapshot summary |
| P3-11 | Sensitive control exclusion | Inspect fixture window with password field | Password name/value absent everywhere | No password content in snapshot/logs | Snapshot summary |
| P3-12 | Metadata-only collection | Inspect fixture in metadata_only mode | No unrestricted accessible names retained | Worker enforced mode at collection | Snapshot summary |
| P3-13 | Worker interruption | During a long fixture inspection, terminate worker (reviewed test harness) | TIMED_OUT/unavailable truthfully; worker cleaned up; no replay | No hung process; no duplicate request | Outcome + process list |
| P3-14 | Verified fixture interaction | Build fixture; launch via approved identity; prepare Increment; approve | Count 0→1 exactly; independent verification; SUCCEEDED receipt | Exactly +1 | Receipt + final Count |
| P3-15 | Stale element rejection | Prepare Increment; click fixture Replace; approve the old plan | Refused pre-dispatch; no invocation on the replacement | Count unchanged | Denial outcome |
| P3-16 | Disabled/hidden control rejection | Prepare against the disabled fixture button (diagnostic plan) or hide Increment | Denied (`element_disabled`/not dispatchable) | No effect | Denial |
| P3-17 | Delayed effect truthfulness | Enable fixture delay toggle; approve Increment | Timeout/uncertain truthfully; never auto-replayed; final count read independently | No duplicate increment | Outcome + Count |
| P3-18 | Manual takeover within the same window | Arm a fixture op; click inside the fixture window manually | Takeover detected; op denied/uncertain; ownership released safely | No SUCCEEDED without verification | Takeover indication |
| P3-19 | Alt-Tab takeover | Arm a fixture op; Alt-Tab to another app | Foreground takeover detected; dispatch stopped | No effect dispatched | Indication + Count |
| P3-20 | Unexpected dialog | Open fixture modal; attempt an op | Dispatch halted; dialog never auto-dismissed; fresh observation+approval required to resume | No effect behind dialog | Dialog indication |
| P3-21 | Safe pause/resume | Pause an armed task; resume | PAUSED holds nothing live; resume goes to fresh planning/precheck; consumed approvals never replay | No PAUSED→EXECUTING jump | Task states |
| P3-22 | Restart reconciliation | Restart the app with an armed/paused task | States reconciled truthfully; uncertain never auto-succeeded | No replay after restart | Task state after restart |
| P3-23 | Project reference resolution | Register the repo root; focus Explorer there; ask for current project | Deterministic candidate (this repo) or clarification if ambiguous | Registered roots only; no permission expansion | Candidate/limitations |
| P3-24 | Real-app read-only navigation suite | For Explorer and VS Code (if installed) and Settings (read/navigation scope): activate window + snapshot only | Verified activation; bounded snapshot; zero interactions sent | No clicks/keys; limitations reported truthfully for missing apps | Receipts |
| P3-25 | Boundaries preserved | Ordinary relaunch; attempt Phase 3 actions without acceptance config; confirm offline behavior | Ordinary mode default-denied (`phase3_native_disabled`); Phase 2 surfaces unchanged; no outbound network required/observed beyond OS noise recorded | No ordinary-mode execution; no real DB migration (schema stays v2) | Panel + DB schema check (`PRAGMA user_version` = 2 on the real DB, untouched) |

## Recording and verdict

Record PASS/FAIL per row with evidence digests; update
`docs/engineering/STATUS.md`. A FAIL in P3-01, P3-04, P3-11, P3-14,
P3-20 or P3-25 stops the campaign. This campaign, even if fully
passed, is *native acceptance evidence for review* — it does not by
itself change the Phase 2 verdict or formally accept Phase 3.
