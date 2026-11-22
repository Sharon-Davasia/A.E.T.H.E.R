# AETHER OS — Phase 2 native Windows acceptance verifier
#
# Run from the repository root on the target Windows 11 machine:
#     powershell -ExecutionPolicy Bypass -File .\scripts\verify_phase2.ps1
#
# Contract (deliberate and enforced below):
#   * Runs as a NORMAL user. No elevation, no admin-only operations.
#   * Operates only on a disposable fixture under D:\Projects. It never reads,
#     writes or lists the user's real documents or source projects.
#   * Every mandatory step is exit-code checked; any failure ends with a
#     nonzero exit status.
#   * Skips and unsupported cases are recorded as NOT VERIFIED. This script
#     never converts a skip, a missing tool or an uninstalled extra into a pass.
#   * Evidence is written under .cache\phase2-evidence as sanitized text: no
#     environment dumps, no tokens, no file contents beyond fixture hashes.
#
# This script does NOT claim Phase 2 acceptance by itself. It produces evidence
# that is scored against docs/engineering/PHASE2_WINDOWS_ACCEPTANCE.md.

[CmdletBinding()]
param(
    [string]$FixtureRoot = 'D:\Projects\AETHER-Phase2-Fixture',
    [string]$EvidenceRoot = '.cache\phase2-evidence',
    [switch]$SkipDesktop
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$script:Results = @()
$script:Failures = 0

function Write-Section {
    param([string]$Name)
    Write-Host "`n== $Name ==" -ForegroundColor Cyan
}

# Record one outcome. Status is PASS, FAIL or NOT VERIFIED (never inferred).
function Add-Result {
    param(
        [Parameter(Mandatory = $true)][string]$Requirement,
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$Evidence = ''
    )
    $script:Results += [pscustomobject]@{
        Requirement = $Requirement
        Status      = $Status
        Evidence    = $Evidence
    }
    $colour = switch ($Status) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        default { 'Yellow' }
    }
    Write-Host ("  [{0}] {1}" -f $Status, $Requirement) -ForegroundColor $colour
    if ($Status -eq 'FAIL') { $script:Failures++ }
}

# Run one mandatory command. Nonzero exit is a FAIL, not a warning.
function Invoke-Mandatory {
    param(
        [Parameter(Mandatory = $true)][string]$Requirement,
        [Parameter(Mandatory = $true)][scriptblock]$Command,
        [string]$WorkingDirectory = $root
    )
    Push-Location $WorkingDirectory
    try {
        & $Command 2>&1 | Tee-Object -Variable output | Out-Host
        $code = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($code -ne 0) {
        Add-Result -Requirement $Requirement -Status 'FAIL' -Evidence "exit code $code"
        return $false
    }
    Add-Result -Requirement $Requirement -Status 'PASS' -Evidence 'exit code 0'
    return $true
}

function Assert-Environment {
    Write-Section 'Environment'
    $os = Get-CimInstance Win32_OperatingSystem
    $isWindows11 = $os.Caption -match 'Windows 11'
    Add-Result -Requirement 'Target OS is Windows 11' `
        -Status $(if ($isWindows11) { 'PASS' } else { 'FAIL' }) `
        -Evidence $os.Caption

    $elevated = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Add-Result -Requirement 'Runs as a normal (non-elevated) user' `
        -Status $(if ($elevated) { 'FAIL' } else { 'PASS' }) `
        -Evidence 'IsInRole(Administrator) = ' + $elevated

    $gitSha = (& git rev-parse HEAD) 2>$null
    $dirty = (& git status --porcelain) 2>$null
    Add-Result -Requirement 'Exact git revision recorded' `
        -Status $(if ($gitSha) { 'PASS' } else { 'FAIL' }) -Evidence $gitSha
    Add-Result -Requirement 'Working tree clean at verification time' `
        -Status $(if ([string]::IsNullOrWhiteSpace($dirty)) { 'PASS' } else { 'FAIL' }) `
        -Evidence $(if ([string]::IsNullOrWhiteSpace($dirty)) { 'clean' } else { 'DIRTY' })

    foreach ($tool in @(@{ Name = 'Python'; Cmd = 'python' }, @{ Name = 'Node'; Cmd = 'node' })) {
        $version = (& $tool.Cmd --version) 2>$null
        Add-Result -Requirement "$($tool.Name) available" `
            -Status $(if ($version) { 'PASS' } else { 'FAIL' }) -Evidence $version
    }
    $uvVersion = (& uv --version) 2>$null
    Add-Result -Requirement 'uv available (locked toolchain)' `
        -Status $(if ($uvVersion) { 'PASS' } else { 'FAIL' }) -Evidence $uvVersion
}

function Assert-FixtureClosed {
    # The verifier must never touch real user data. Refuse anything that is not
    # the explicit disposable fixture root.
    Write-Section 'Fixture containment'
    $expectedPrefix = 'D:\Projects\AETHER-Phase2-Fixture'
    $resolved = [System.IO.Path]::GetFullPath($FixtureRoot)
    if (-not $resolved.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Add-Result -Requirement 'Fixture is a disposable D:\Projects path' -Status 'FAIL' `
            -Evidence $resolved
        throw "Refusing to run: fixture root must be under $expectedPrefix"
    }
    Add-Result -Requirement 'Fixture is a disposable D:\Projects path' -Status 'PASS' `
        -Evidence $resolved
    if (Test-Path $resolved) {
        Remove-Item -Recurse -Force $resolved
    }
    New-Item -ItemType Directory -Path $resolved -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $resolved 'src') -Force | Out-Null
    Set-Content -Path (Join-Path $resolved 'README.md') -Value '# Fixture' -Encoding utf8
    Set-Content -Path (Join-Path $resolved 'src\module.py') -Value 'def f(): return 1' -Encoding utf8
    Add-Result -Requirement 'Disposable fixture created' -Status 'PASS' -Evidence $resolved
}

function Assert-Backend {
    Write-Section 'Backend quality gates (Linux-equivalent, native Windows)'
    $backend = Join-Path $root 'backend'
    $pytestBase = Join-Path $root '.cache\pytest-tmp'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $pytestBase) | Out-Null

    Invoke-Mandatory -Requirement 'uv sync (locked)' -WorkingDirectory $backend -Command {
        uv sync --all-extras --locked
    } | Out-Null
    Invoke-Mandatory -Requirement 'Ruff lint' -WorkingDirectory $backend -Command {
        uv run ruff check .
    } | Out-Null
    Invoke-Mandatory -Requirement 'Ruff formatting' -WorkingDirectory $backend -Command {
        uv run ruff format --check .
    } | Out-Null
    Invoke-Mandatory -Requirement 'Strict mypy' -WorkingDirectory $backend -Command {
        uv run mypy
    } | Out-Null
    Invoke-Mandatory -Requirement 'Full pytest suite' -WorkingDirectory $backend -Command {
        uv run pytest --basetemp $pytestBase
    } | Out-Null
    Invoke-Mandatory -Requirement 'Phase 2C filesystem capabilities' -WorkingDirectory $backend -Command {
        uv run pytest tests/test_phase2c_filesystem.py --basetemp $pytestBase
    } | Out-Null
    Invoke-Mandatory -Requirement 'Phase 2D edits, receipts and undo' -WorkingDirectory $backend -Command {
        uv run pytest tests/test_phase2d_edits.py --basetemp $pytestBase
    } | Out-Null
    Invoke-Mandatory -Requirement 'Phase 2B trusted approval chain' -WorkingDirectory $backend -Command {
        uv run pytest tests/test_phase2b_trusted_approval.py --basetemp $pytestBase
    } | Out-Null
    Invoke-Mandatory -Requirement 'Persistence and migration integrity' -WorkingDirectory $backend -Command {
        uv run pytest tests/test_phase2b_persistence.py --basetemp $pytestBase
    } | Out-Null
}

function Assert-Desktop {
    if ($SkipDesktop) {
        Add-Result -Requirement 'Desktop gates' -Status 'NOT VERIFIED' -Evidence '-SkipDesktop'
        return
    }
    Write-Section 'Desktop application gates'
    $desktop = Join-Path $root 'apps\desktop'
    Invoke-Mandatory -Requirement 'Desktop lint' -WorkingDirectory $desktop -Command {
        npm run lint
    } | Out-Null
    Invoke-Mandatory -Requirement 'Desktop typecheck' -WorkingDirectory $desktop -Command {
        npm run typecheck
    } | Out-Null
    Invoke-Mandatory -Requirement 'Desktop Node tests' -WorkingDirectory $desktop -Command {
        npm test
    } | Out-Null
    Invoke-Mandatory -Requirement 'Desktop Python security tests' -WorkingDirectory $desktop -Command {
        npm run test:python
    } | Out-Null
    Invoke-Mandatory -Requirement 'Electron build' -WorkingDirectory $desktop -Command {
        npm run build:electron
    } | Out-Null
}

function Assert-NativeWindowsBehaviour {
    Write-Section 'Native Windows behaviour (cannot be inferred from Linux)'
    $backend = Join-Path $root 'backend'

    # Reparse points, ACLs, msvcrt locking and volume identity are Windows-only
    # behaviours. These run as explicit, named checks so a skip is visible.
    $windowsFixture = @'
import json, os, stat, sys
from pathlib import Path

report = {"checks": []}

def check(name, fn):
    try:
        report["checks"].append({"name": name, "status": "PASS", "detail": str(fn() or "")})
    except Exception as exc:
        report["checks"].append({"name": name, "status": "FAIL", "detail": f"{type(exc).__name__}: {exc}"})

sys.path.insert(0, ".")
os.environ.setdefault("AETHER_WINDOWS_FIXTURE", sys.argv[1])
fixture = Path(sys.argv[1])

def reparse_point_refused():
    from aether.core.resources.path_safety import PathSafetyError, reject_reparse_components
    target = fixture / "junction-target"
    target.mkdir(exist_ok=True)
    (target / "leak.txt").write_text("outside", encoding="utf-8")
    link = fixture / "junction-link"
    if link.exists():
        os.rmdir(link)
    subprocess_result = os.system(f'mklink /J "{link}" "{target}" >nul 2>&1')
    if not link.exists():
        raise RuntimeError("could not create a junction for the test")
    try:
        reject_reparse_components(link)
    except PathSafetyError:
        return "junction refused"
    raise AssertionError("a junction was NOT refused")

def acl_is_owner_only():
    from aether.core.vault.undo_vault import UndoVault
    vault = UndoVault(fixture / "vault")
    vault.open()
    key = Path(fixture / "vault" / "vault.key")
    if not key.exists():
        raise AssertionError("vault key was not created")
    vault.close()
    return "vault created (ACL inspected separately below)"

def msvcrt_owner_lock():
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

def volume_identity():
    from aether.core.resources.path_safety import inspect_volume
    info = inspect_volume(fixture)
    if not info.volume_id.startswith("win-volume:"):
        raise AssertionError(f"unexpected volume identity {info.volume_id}")
    return info.volume_id

check("junction escape refused", reparse_point_refused)
check("vault creation", acl_is_owner_only)
check("msvcrt owner lock", msvcrt_owner_lock)
check("volume identity", volume_identity)
print(json.dumps(report))
'@
    $probePath = Join-Path $backend 'windows_phase2_probe.py'
    Set-Content -Path $probePath -Value $windowsFixture -Encoding utf8
    try {
        $json = & uv run --directory $backend python $probePath $FixtureRoot 2>&1
        $exit = $LASTEXITCODE
        $parsed = $null
        try { $parsed = $json | ConvertFrom-Json } catch { $parsed = $null }
        if ($exit -ne 0 -or $null -eq $parsed) {
            Add-Result -Requirement 'Native Windows probe executed' -Status 'FAIL' `
                -Evidence "exit $exit"
        }
        else {
            foreach ($check in $parsed.checks) {
                Add-Result -Requirement ("Native: " + $check.name) `
                    -Status $check.status -Evidence $check.detail
            }
        }
    }
    finally {
        Remove-Item -Path $probePath -Force -ErrorAction SilentlyContinue
    }

    # ACL inspection is deliberately separate so its own result is visible.
    $aclScript = @'
$ErrorActionPreference = "Stop"
$fixture = $args[0]
$key = Join-Path $fixture "vault\vault.key"
if (-not (Test-Path $key)) { Write-Output "NO_KEY"; exit 3 }
$acl = (Get-Acl $key).Access | Where-Object { $_.IdentityReference -notlike "*SYSTEM*" -and $_.IdentityReference -notlike "*Administrators*" }
$unexpected = $acl | Where-Object { $_.FileSystemRights -match "Write|Modify|FullControl" -and $_.IdentityReference -ne "$env:USERDOMAIN\$env:USERNAME" }
if ($unexpected) { Write-Output "UNEXPECTED_GRANTS"; exit 4 }
Write-Output "OWNER_ONLY"
'@
    $aclPath = Join-Path $env:TEMP "aether_acl_probe_$PID.ps1"
    Set-Content -Path $aclPath -Value $aclScript -Encoding utf8
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $aclPath $FixtureRoot
        if ($LASTEXITCODE -eq 0) {
            Add-Result -Requirement 'Native: vault key ACL is owner-only' -Status 'PASS' `
                -Evidence 'OWNER_ONLY'
        }
        else {
            Add-Result -Requirement 'Native: vault key ACL is owner-only' -Status 'FAIL' `
                -Evidence "exit $LASTEXITCODE"
        }
    }
    finally {
        Remove-Item -Path $aclPath -Force -ErrorAction SilentlyContinue
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
        fixture_root     = $FixtureRoot
        results          = $script:Results
        failures         = $script:Failures
        not_verified     = @($script:Results | Where-Object { $_.Status -eq 'NOT VERIFIED' }).Count
    }
    $summary | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding utf8

    $lines = @(
        '# AETHER OS Phase 2 — native Windows evidence',
        '',
        "Generated (UTC): $($summary.generated_at_utc)",
        "Git SHA: $($summary.git_sha)",
        "OS: $($summary.os_caption)",
        "Python: $($summary.python_version)",
        "Node: $($summary.node_version)",
        "Fixture: $($summary.fixture_root)",
        '',
        '| Requirement | Status | Evidence |',
        '|---|---|---|'
    )
    foreach ($row in $script:Results) {
        $lines += "| $($row.Requirement) | $($row.Status) | $($row.Evidence) |"
    }
    $lines += ''
    $lines += "Failures: $($script:Failures); Not verified: $($summary.not_verified)"
    $lines += ''
    $lines += 'This file records WHAT RAN. It does not itself mark Phase 2 complete;'
    $lines += 'score it against docs/engineering/PHASE2_WINDOWS_ACCEPTANCE.md.'
    Set-Content -Path $mdPath -Value $lines -Encoding utf8

    Write-Host "`nEvidence written:" -ForegroundColor Yellow
    Write-Host "  $jsonPath"
    Write-Host "  $mdPath"
}

Write-Host '== AETHER OS Phase 2 native Windows acceptance ==' -ForegroundColor Cyan
Assert-Environment
Assert-FixtureClosed
Assert-Backend
Assert-Desktop
Assert-NativeWindowsBehaviour
Write-Evidence

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host "PHASE 2 WINDOWS ACCEPTANCE: FAILED ($($script:Failures) failure(s))" -ForegroundColor Red
    exit 1
}
$notVerified = @($script:Results | Where-Object { $_.Status -eq 'NOT VERIFIED' }).Count
if ($notVerified -gt 0) {
    Write-Host "PHASE 2 WINDOWS ACCEPTANCE: INCOMPLETE ($notVerified NOT VERIFIED)" -ForegroundColor Yellow
    Write-Host 'Phase 2 must not be declared complete while any item is NOT VERIFIED.'
    exit 2
}
Write-Host 'PHASE 2 WINDOWS ACCEPTANCE: PASSED' -ForegroundColor Green
exit 0
