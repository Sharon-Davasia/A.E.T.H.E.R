# AETHER OS — Phase 2 native Windows acceptance verifier
#
# *** DO NOT RUN THIS ON A MACHINE HOLDING REAL DATA UNTIL ITS SAFETY HAS BEEN
# *** INDEPENDENTLY REVIEWED. See docs/engineering/PHASE2_WINDOWS_ACCEPTANCE.md
#
# Run from the repository root on the target Windows 11 machine
# (PowerShell 5.1, normal user; NO execution-policy bypass — if the
# machine policy blocks scripts, the machine owner sets an approved
# policy; do not work around it):
#     powershell.exe -NoProfile -File .\scripts\verify_phase2.ps1
#
# Safety contract enforced by construction (not by convention):
#   * Never elevated. Refuses to run as Administrator.
#   * Deletes nothing itself. All fixture creation, ownership proof and deletion
#     is delegated to aether.core.acceptance.fixture_safety, which is covered by
#     negative tests proving sibling prefixes, unmarked directories, junctions
#     and arbitrary paths are refused.
#   * A pre-existing directory is never adopted, reused or deleted.
#   * Skips and unexecuted mandatory scenarios are recorded NOT VERIFIED.
#     Exit code 2 means "incomplete", and incomplete is not a pass.
#
# What this script can and cannot establish:
#   It CAN establish that the automated gates pass on Windows and that the
#   native safety probes behave correctly.
#   It CANNOT establish that a human approved an edit in the live Electron UI,
#   that a real power loss was survived, or that no cloud traffic occurred.
#   Those stay NOT VERIFIED until a human demonstrates them.

[CmdletBinding()]
param(
    [string]$Base = 'D:\Projects',
    [string]$EvidenceRoot = '.cache\phase2-evidence',
    [switch]$SkipDesktop,
    [switch]$SkipBackend
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$script:Results = @()
$script:Failures = 0
$script:NotVerified = 0

function Write-Section {
    param([string]$Name)
    Write-Host "`n== $Name ==" -ForegroundColor Cyan
}

# Record one outcome. PASS / FAIL / NOT VERIFIED only. Never inferred.
function Add-Result {
    param(
        [Parameter(Mandatory = $true)][string]$Requirement,
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'NOT VERIFIED')][string]$Status,
        [string]$Evidence = ''
    )
    $script:Results += [pscustomobject]@{
        Requirement = $Requirement
        Status      = $Status
        Evidence    = $Evidence
    }
    switch ($Status) {
        'PASS' { Write-Host ("  [PASS]        {0}" -f $Requirement) -ForegroundColor Green }
        'FAIL' { Write-Host ("  [FAIL]        {0} :: {1}" -f $Requirement, $Evidence) -ForegroundColor Red; $script:Failures++ }
        default { Write-Host ("  [NOT VERIFIED] {0} :: {1}" -f $Requirement, $Evidence) -ForegroundColor Yellow; $script:NotVerified++ }
    }
}

function Invoke-Mandatory {
    param(
        [Parameter(Mandatory = $true)][string]$Requirement,
        [Parameter(Mandatory = $true)][scriptblock]$Command,
        [string]$WorkingDirectory = $root
    )
    Push-Location $WorkingDirectory
    try {
        & $Command 2>&1 | Out-Host
        $code = $LASTEXITCODE
    }
    catch {
        Push-Location $root
        Add-Result -Requirement $Requirement -Status 'FAIL' -Evidence "threw: $($_.Exception.Message)"
        Pop-Location
        return
    }
    finally {
        Pop-Location
    }
    if ($code -ne 0) {
        Add-Result -Requirement $Requirement -Status 'FAIL' -Evidence "exit code $code"
    }
    else {
        Add-Result -Requirement $Requirement -Status 'PASS' -Evidence 'exit code 0'
    }
}

# Run the reviewed fixture module and return its parsed JSON, or $null on refusal.
function Invoke-FixtureModule {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    Push-Location (Join-Path $root 'backend')
    try {
        $raw = & uv run python -m aether.core.acceptance.fixture_safety @Arguments 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($code -ne 0) { return $null }
    try { return $raw | ConvertFrom-Json } catch { return $null }
}

function Assert-Environment {
    Write-Section 'Environment'
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Result -Requirement 'Target OS is Windows 11' `
        -Status $(if ($os.Caption -match 'Windows 11') { 'PASS' } else { 'FAIL' }) `
        -Evidence $os.Caption

    $elevated = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($elevated) {
        Add-Result -Requirement 'Runs as a normal (non-elevated) user' -Status 'FAIL' `
            -Evidence 'administrator token detected'
        throw 'Refusing to run elevated: acceptance must reflect a normal user session.'
    }
    Add-Result -Requirement 'Runs as a normal (non-elevated) user' -Status 'PASS'

    $gitSha = (& git rev-parse HEAD) 2>$null
    Add-Result -Requirement 'Exact git revision recorded' `
        -Status $(if ($gitSha) { 'PASS' } else { 'FAIL' }) -Evidence $gitSha
    $dirty = (& git status --porcelain) 2>$null
    Add-Result -Requirement 'Working tree clean at verification time' `
        -Status $(if ([string]::IsNullOrWhiteSpace($dirty)) { 'PASS' } else { 'FAIL' }) `
        -Evidence $(if ([string]::IsNullOrWhiteSpace($dirty)) { 'clean' } else { 'DIRTY' })

    foreach ($tool in @(
            @{ Name = 'Python'; Cmd = 'python' },
            @{ Name = 'Node'; Cmd = 'node' },
            @{ Name = 'npm'; Cmd = 'npm.cmd' },
            @{ Name = 'uv'; Cmd = 'uv' })) {
        $version = (& $tool.Cmd --version) 2>$null
        Add-Result -Requirement "$($tool.Name) available" `
            -Status $(if ($version) { 'PASS' } else { 'FAIL' }) -Evidence $version
    }
}

function New-SafeFixture {
    Write-Section 'Disposable fixture (owned, provable containment)'
    if (-not (Test-Path -LiteralPath $Base -PathType Container)) {
        Add-Result -Requirement 'Fixture base directory exists' -Status 'FAIL' -Evidence $Base
        throw "Base directory $Base does not exist. Choose an explicit disposable base."
    }
    Add-Result -Requirement 'Fixture base directory exists' -Status 'PASS' -Evidence $Base

    # Negative control: prove the containment rule refuses a sibling prefix
    # before trusting it with a real creation.
    $sibling = "$Base-Other"
    $refusal = Invoke-FixtureModule -Arguments @('cleanup', '--base', $Base, '--dir', $sibling, '--token', 'probe')
    if ($null -eq $refusal) {
        Add-Result -Requirement 'Containment refuses a sibling prefix path' -Status 'PASS' `
            -Evidence 'refused as designed'
    }
    else {
        Add-Result -Requirement 'Containment refuses a sibling prefix path' -Status 'FAIL' `
            -Evidence 'the containment module accepted a sibling path'
    }

    $created = Invoke-FixtureModule -Arguments @('create', '--base', $Base)
    if ($null -eq $created -or -not $created.directory) {
        Add-Result -Requirement 'Disposable fixture created' -Status 'FAIL' -Evidence 'creation refused'
        throw 'Fixture creation failed; no destructive action will be attempted.'
    }
    $script:FixtureDirectory = $created.directory
    $script:FixtureToken = $created.token
    Add-Result -Requirement 'Disposable fixture created' -Status 'PASS' -Evidence $script:FixtureDirectory

    New-Item -ItemType Directory -Path (Join-Path $script:FixtureDirectory 'src') -Force | Out-Null
    Set-Content -Path (Join-Path $script:FixtureDirectory 'README.md') -Value "# Fixture`n`nThe quick brown fox.`n" -Encoding utf8
    Set-Content -Path (Join-Path $script:FixtureDirectory 'src\module.py') -Value "def f(): return 1`n" -Encoding utf8
    Add-Result -Requirement 'Fixture content written' -Status 'PASS'
}

function Assert-Backend {
    if ($SkipBackend) {
        Add-Result -Requirement 'Backend gates' -Status 'NOT VERIFIED' -Evidence '-SkipBackend'
        return
    }
    Write-Section 'Backend gates (native Windows)'
    $backend = Join-Path $root 'backend'
    $temp = Join-Path $script:FixtureDirectory 'pytest-tmp'
    Invoke-Mandatory -Requirement 'uv sync (locked)' -WorkingDirectory $backend -Command { uv sync --all-extras --locked }
    Invoke-Mandatory -Requirement 'Ruff lint' -WorkingDirectory $backend -Command { uv run ruff check . }
    Invoke-Mandatory -Requirement 'Ruff formatting' -WorkingDirectory $backend -Command { uv run ruff format --check . }
    Invoke-Mandatory -Requirement 'Strict mypy' -WorkingDirectory $backend -Command { uv run mypy }
    Invoke-Mandatory -Requirement 'Full pytest suite' -WorkingDirectory $backend -Command { uv run pytest --basetemp $temp }
    foreach ($suite in @(
            @{ Name = '2C filesystem capabilities'; Path = 'tests/test_phase2c_filesystem.py' },
            @{ Name = '2C capability session'; Path = 'tests/test_phase2c_session.py' },
            @{ Name = '2D edits, receipts, undo'; Path = 'tests/test_phase2d_edits.py' },
            @{ Name = '2B trusted approval chain'; Path = 'tests/test_phase2b_trusted_approval.py' },
            @{ Name = 'Persistence and migration'; Path = 'tests/test_phase2b_persistence.py' },
            @{ Name = 'Fixture safety (S14-6)'; Path = 'tests/test_phase2_fixture_safety.py' })) {
        Invoke-Mandatory -Requirement $suite.Name -WorkingDirectory $backend `
            -Command ([scriptblock]::Create("uv run pytest $($suite.Path) --basetemp `"$temp`""))
    }
}

function Assert-Desktop {
    if ($SkipDesktop) {
        Add-Result -Requirement 'Desktop gates' -Status 'NOT VERIFIED' -Evidence '-SkipDesktop'
        return
    }
    Write-Section 'Desktop application gates'
    $desktop = Join-Path $root 'apps\desktop'
    Invoke-Mandatory -Requirement 'Desktop lint' -WorkingDirectory $desktop -Command { npm.cmd run lint }
    Invoke-Mandatory -Requirement 'Desktop typecheck' -WorkingDirectory $desktop -Command { npm.cmd run typecheck }
    Invoke-Mandatory -Requirement 'Desktop Node tests' -WorkingDirectory $desktop -Command { npm.cmd test }
    Invoke-Mandatory -Requirement 'Desktop Python security tests' -WorkingDirectory $desktop -Command { npm.cmd run test:python }
    Invoke-Mandatory -Requirement 'Electron build' -WorkingDirectory $desktop -Command { npm.cmd run build:electron }
}

function Assert-NativeProbes {
    Write-Section 'Native Windows safety probes'
    $backend = Join-Path $root 'backend'
    $probePath = Join-Path $backend 'windows_phase2_probe.py'
    $fixture = $script:FixtureDirectory

    $probe = @'
import json, os, sys
from pathlib import Path

fixture = Path(sys.argv[1])
report = {"checks": []}

def check(name, fn):
    try:
        report["checks"].append({"name": name, "status": "PASS", "detail": str(fn() or "")})
    except Exception as exc:
        report["checks"].append({"name": name, "status": "FAIL", "detail": f"{type(exc).__name__}: {exc}"})

def junction_refused():
    from aether.core.resources.path_safety import PathSafetyError, reject_reparse_components
    target = fixture / "junction-target"
    target.mkdir(exist_ok=True)
    (target / "leak.txt").write_text("outside", encoding="utf-8")
    link = fixture / "junction-link"
    if link.exists() or link.is_symlink():
        os.rmdir(link)
    os.system(f'mklink /J "{link}" "{target}" >nul 2>&1')
    if not link.exists():
        raise RuntimeError("could not create a junction for the test")
    try:
        reject_reparse_components(link)
    except PathSafetyError:
        return "junction refused"
    raise AssertionError("a junction was NOT refused")

def volume_identity():
    from aether.core.resources.path_safety import inspect_volume
    info = inspect_volume(fixture)
    if not info.volume_id.startswith("win-volume:"):
        raise AssertionError(f"unexpected volume identity {info.volume_id}")
    return info.volume_id

def owner_lock():
    from aether.core.persistence.sqlite_store import SQLiteTaskStore
    db = fixture / "lock-probe.sqlite3"
    first = SQLiteTaskStore(db)
    try:
        try:
            SQLiteTaskStore(db)
        except Exception:
            return "second owner correctly refused"
        raise AssertionError("a second owner acquired the same database")
    finally:
        first.close()

def acl_owner_only():
    # S14-5: the key must live OUTSIDE the vault directory, and its protection
    # must be read back from the OS rather than assumed. Both are asserted here
    # because both were previously wrong.
    from aether.core.security.file_permissions import verify_owner_only
    from aether.core.vault.undo_vault import UndoVault
    vault = UndoVault(fixture / "vault").open()
    try:
        key = vault.key_path
        if not key.exists():
            raise AssertionError("vault key was not created")
        inside = key.resolve().is_relative_to((fixture / "vault").resolve())
        if inside:
            raise AssertionError("vault key is stored inside the vault directory")
        key_report = verify_owner_only(key, directory=False)
        if not key_report.enforced:
            # S14-10: this is now an exact ACE-inventory check, so the message
            # names the offending principal or ACE rather than just failing.
            raise AssertionError("vault key ACL is not owner-only: " + key_report.detail)
        if key_report.platform != "windows":
            raise AssertionError("expected the native Windows DACL mechanism")
        if not key_report.detail.startswith("D:P"):
            raise AssertionError("vault key DACL is not protected (inherited ACEs apply)")
        for unexpected in (";;WD)", ";;BU)", ";;AU)", ";;SY)", ";;BA)"):
            if unexpected in key_report.detail:
                raise AssertionError(
                    "vault key DACL grants access to an unauthorized principal: " + unexpected
                )
        for directory in (fixture / "vault", fixture / "vault" / "objects"):
            report = verify_owner_only(directory, directory=True)
            if not report.enforced:
                raise AssertionError("vault directory ACL is not owner-only: " + report.detail)
        return "key outside vault; owner-only DACL verified for key and vault directories"
    finally:
        vault.close()

check("junction escape refused", junction_refused)
check("volume identity", volume_identity)
check("database owner lock", owner_lock)
check("vault key location and ACL", acl_owner_only)
print(json.dumps(report))
'@
    Set-Content -Path $probePath -Value $probe -Encoding utf8
    try {
        Push-Location $backend
        $raw = & uv run python $probePath $fixture 2>&1
        $code = $LASTEXITCODE
        Pop-Location
        $parsed = $null
        try { $parsed = $raw | ConvertFrom-Json } catch { $parsed = $null }
        if ($code -ne 0 -or $null -eq $parsed) {
            Add-Result -Requirement 'Native probe executed' -Status 'FAIL' -Evidence "exit $code"
        }
        else {
            foreach ($check in $parsed.checks) {
                Add-Result -Requirement ("Native: " + $check.name) `
                    -Status $(if ($check.status -eq 'PASS') { 'PASS' } else { 'FAIL' }) `
                    -Evidence $check.detail
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
    }
}

function Assert-HumanRequired {
    Write-Section 'Scenarios this script CANNOT verify'
    # These are mandatory and are NOT satisfied by any automated check.
    $human = @(
        'Live Electron UI approval: a human clicking Approve and the backend verifying that gesture',
        'Exact patch shown to the human before approval, and that approving patch A cannot apply patch B',
        'T2 mutation refused before approval, then applied only after that approval (live, not synthetic)',
        'Grant denial for forged, expired, revoked, exhausted and replayed grants (live ledger)',
        'Receipts survive a real application restart',
        'Undo restores the exact original, and refuses to overwrite a newer user edit',
        'Truthful crash recovery: a real process kill or power loss between replace and receipt',
        'Zero unauthorized mutation and zero unauthorized disclosure observed across the whole run',
        'No unauthorized cloud traffic, observed on the machine (not asserted by a test)',
        'Undo Vault key ACL protection reviewed on NTFS'
    )
    foreach ($item in $human) {
        Add-Result -Requirement $item -Status 'NOT VERIFIED' `
            -Evidence 'requires a human demo / real interruption; not automatable here'
    }
}

function Write-Evidence {
    Write-Section 'Evidence'
    New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
    $stamp = Get-Date -Format 'yyyyMMddTHHmmssZ'
    $jsonPath = Join-Path $EvidenceRoot "phase2-windows-$stamp.json"
    $mdPath = Join-Path $EvidenceRoot "phase2-windows-$stamp.md"

    $summary = [pscustomobject]@{
        generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        git_sha          = (& git rev-parse HEAD)
        os_caption       = (Get-CimInstance Win32_OperatingSystem).Caption
        python_version   = (& python --version)
        node_version     = (& node --version)
        fixture          = $script:FixtureDirectory
        results          = $script:Results
        failures         = $script:Failures
        not_verified     = $script:NotVerified
        verifier_reviewed = $false
    }
    $summary | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding utf8

    $lines = @(
        '# AETHER OS Phase 2 - native Windows evidence',
        '',
        "Generated (UTC): $($summary.generated_at_utc)",
        "Git SHA: $($summary.git_sha)",
        "OS: $($summary.os_caption)",
        "Python: $($summary.python_version)",
        "Node: $($summary.node_version)",
        "Fixture: $($summary.fixture)",
        '',
        '| Requirement | Status | Evidence |',
        '|---|---|---|'
    )
    foreach ($row in $script:Results) {
        $lines += "| $($row.Requirement) | $($row.Status) | $($row.Evidence) |"
    }
    $lines += ''
    $lines += "Failures: $($script:Failures); Not verified: $($script:NotVerified)"
    $lines += ''
    $lines += 'This file records WHAT RAN and WHAT DID NOT. It is evidence, not acceptance.'
    $lines += 'Score it against docs/engineering/PHASE2_WINDOWS_ACCEPTANCE.md.'
    Set-Content -Path $mdPath -Value $lines -Encoding utf8

    Write-Host "`nEvidence written:" -ForegroundColor Yellow
    Write-Host "  $jsonPath"
    Write-Host "  $mdPath"
}

function Remove-SafeFixture {
    Write-Section 'Fixture cleanup (ownership proven)'
    if (-not $script:FixtureDirectory -or -not $script:FixtureToken) {
        Add-Result -Requirement 'Fixture cleanup' -Status 'NOT VERIFIED' -Evidence 'no owned fixture'
        return
    }
    $removed = Invoke-FixtureModule -Arguments @(
        'cleanup', '--base', $Base, '--dir', $script:FixtureDirectory, '--token', $script:FixtureToken
    )
    if ($null -eq $removed) {
        Add-Result -Requirement 'Fixture cleanup' -Status 'FAIL' `
            -Evidence 'ownership verification refused cleanup; the directory was left in place'
        return
    }
    Add-Result -Requirement 'Fixture cleanup' -Status 'PASS' -Evidence $script:FixtureDirectory
}

Write-Host '== AETHER OS Phase 2 native Windows acceptance ==' -ForegroundColor Cyan
Write-Host 'NOTE: this script records evidence. It does not declare acceptance.' -ForegroundColor Yellow
$script:FixtureDirectory = $null
$script:FixtureToken = $null

try {
    Assert-Environment
    New-SafeFixture
    Assert-Backend
    Assert-Desktop
    Assert-NativeProbes
    Assert-HumanRequired
}
finally {
    Remove-SafeFixture
    Write-Evidence
}

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host "PHASE 2 WINDOWS EVIDENCE: FAILED ($($script:Failures) failure(s))" -ForegroundColor Red
    exit 1
}
if ($script:NotVerified -gt 0) {
    Write-Host "PHASE 2 WINDOWS EVIDENCE: INCOMPLETE ($($script:NotVerified) NOT VERIFIED)" -ForegroundColor Yellow
    Write-Host 'Phase 2 must not be declared complete while any mandatory item is NOT VERIFIED.'
    exit 2
}
Write-Host 'PHASE 2 WINDOWS EVIDENCE: all automated items passed' -ForegroundColor Green
Write-Host 'This is still not acceptance unless the human-required items were demonstrated separately.'
exit 0
