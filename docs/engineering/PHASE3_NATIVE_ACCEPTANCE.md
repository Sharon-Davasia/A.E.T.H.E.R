# Phase 3 native acceptance campaign (PREPARED — do not run yet)

Status: **PREPARED ONLY.** Nothing in this document is a request to run
anything on the owner's Windows machine. Phase 3 native activation
remains disabled; schema v3 remains prepared-but-inactive
(`ACTIVE_SCHEMA_VERSION=2`, `PENDING_MIGRATION_VERSIONS={3}`); Phase 2
acceptance remains NOT COMPLETE and unwaived. No result recorded here
may be treated as acceptance until the owner runs the campaign in a
dedicated, separately authorized session after the activation proposal
(below) is independently reviewed and approved.

Environment (owner machine): Windows 11, non-administrator
PowerShell 5.1, Python 3.12.10, Node 22.22.3, npm 10.9.8 via `npm.cmd`.
No execution-policy bypass, no elevation, no Developer Mode, no WSL,
no new git worktrees. Reconciliation: each row maps to its Master Spec
Phase 3 scenario (app activation, window activation, application
launch, UIA snapshot, UI operation lifecycle, interactive operation,
independent effect verification, focus/precondition, stale element,
app/window replacement, disabled element, timeout/crash, processed-
but-unverified, dialog interruption, manual takeover, privacy change,
pause, restart, process/application/window recovery, project
detection, dialog handling, project reference clarification,
ambiguous project evidence, unexpected dialog, worker isolation and
desktop command surface rows of the Master Spec Phase 3 test table).

Setup for every row unless stated otherwise: separately reviewed
activation per the proposal; isolated synthetic storage directory
outside the real task database; fixture executable
`tools/windows-fixture/aether_fixture.py` packaged per its README
(synthetic data only); applications limited to the allowlist
(Notepad, Calculator, Explorer, VS Code if installed, Settings
read-only navigation, the native fixture).

| ID | Scenario (Master Spec row) | Action | Expected | Evidence to record | Cleanup | Pass criteria |
|---|---|---|---|---|---|---|
| P3-01 | Verifiably launch a registered app | Launch fixture via registered record | One new process; launch receipt bound to version token | Receipt id + process token digest | Close fixture | Exactly one process; no second launch on retry |
| P3-02 | Unknown app never resolves | Search unregistered name | `app_not_found`; nothing launched | Outcome token | — | No process; denial logged |
| P3-03 | Launch never types/runs path | Attempt path-shaped app query | Treated as search text; no execution | Outcome token | — | No process; no shell used |
| P3-04 | Ambiguity clarifies | Register two similar apps, search | Candidates returned; no auto-launch | Candidate ids | Unregister test app | No launch before selection |
| P3-05 | Updated/missing exe blocks | Change exe identity after registration | `executable_changed`/`app_unavailable` | Outcome token | Restore registry | No launch |
| P3-06 | Unavailable protocol alias | Request `steam:`/invalid alias | Denied; no shell URI invoked | Denial reason | — | No process |
| P3-07 | window.activate (T1) | Activate fixture window | Foreground verified exactly once | Activation receipt | — | One activation; no keystrokes/clicks |
| P3-08 | UIA snapshot privacy | Snapshot fixture with password field | Password name/value absent; counts bounded | Snapshot summary | Delete snapshot (auto-expires) | No password content anywhere |
| P3-09 | Snapshot limits | Enable fixture overflow mode if present; otherwise standard window | Truncation reported, never silent | Truncated flag | — | Bounded size; deterministic order |
| P3-10 | Read-only metadata snapshot | Metadata-only privacy mode snapshot | No unrestricted text retained | Privacy mode + summary | — | No names/text beyond contract |
| P3-11 | Interactive op happy path | Approve fixture Increment via desktop surface | Count 0→1 exactly; verified receipt | Attempt + receipt ids | Fixture reset | Exactly +1; receipt SUCCEEDED |
| P3-12 | Decline executes nothing | Decline confirmation dialog | No invocation | Attempt count 0 | — | Count unchanged |
| P3-13 | Forged/replayed approval | Reuse a consumed nonce/signature | Refused | Denial reason | — | Count unchanged |
| P3-14 | Stale plan/element | Start fixture, plan, click Replace in fixture, approve | Denied pre-dispatch (stale) | Outcome UNVERIFIED/stale, not SUCCEEDED | Reset | No invocation on new element |
| P3-15 | Disabled element | Plan against disabled button | Binding/execution denied `element_disabled` | Denial | — | No effect |
| P3-16 | Provider timeout | Launch fixture with `--delayed`; approve | TIMED_OUT; no replay; state not SUCCEEDED | Outcome | Close delayed fixture | No second invoke |
| P3-17 | Worker crash mid-op | Kill worker during invoke (test harness) | Uncertain/manual-recovery; no replay | Outcome token | Restart worker | No duplicate effect |
| P3-18 | Unexpected dialog | Open fixture modal mid-task; attempt op | Dispatch halted; refs invalidated; fresh approval required | Dialog indication + denial | Close modal manually | No auto-dismiss; no effect behind dialog |
| P3-19 | Manual takeover | Alt-Tab/click fixture during armed op | Ownership lost; op denied/uncertain truthfully | Takeover indication | — | No SUCCEEDED without verification |
| P3-20 | Privacy change mid-task | Opt out / pause during armed op | Snapshots purged; op cannot proceed on old snapshot | Purge + denial | — | Old snapshot unusable |
| P3-21 | Safe pause/resume discipline | Pause during AWAITING_APPROVAL; attempt resume | PAUSED holds zero live bindings; resume needs fresh plan/approval | Task state | — | No PAUSED→EXECUTING jump; consumed approvals never replay |
| P3-22 | Restart reconciliation | Restart app mid-task (armed op) | State reconciled; uncertain never auto-succeeded; navigation reconcilable | Task state after restart | — | No replay; truthful state |
| P3-23 | Project detection | Focus Explorer in a registered project root; ask "this project" | Deterministic candidate or clarification if ambiguous | Candidate id/limitations | — | No permission expansion; registered roots only |
| P3-24 | Real-app read-only nav | Activate Notepad/Calculator window; snapshot only | Activation verified; snapshot bounded; zero interactions | Receipts | Close app | No clicks/keys sent |
| P3-25 | Desktop surface truthfulness | Ordinary launch (activation off) | Phase 3 panel shows disabled + reason; approvals unavailable | Screenshot/notes | — | No fake available state; no generic execute IPC |

After the campaign: record per-row PASS/FAIL with evidence digests in
the Phase 3 acceptance register; update `docs/dev/STATUS.md`; do not
flip schema v3 or enablement defaults as part of evidence recording.
