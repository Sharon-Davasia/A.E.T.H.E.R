# AETHER OS — Phase 1 local verification (Windows PowerShell)
# Run from the repository root: .\scripts\verify.ps1
# No model downloads, model startup, remote inference, or OS automation.
# Every native command exit code is checked; failure aborts immediately.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $root "backend")

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$StepName,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    Write-Host "`n$StepName" -ForegroundColor Yellow
    & $Command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`nFAILED: $StepName (exit code $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Write-Host "== AETHER OS Phase 1 verification ==" -ForegroundColor Cyan

Invoke-Checked "[1/7] uv sync (locked)..." { uv sync --all-extras --locked }

Invoke-Checked "[2/7] Import check..." {
    uv run python -c "import aether; from aether.api.app import create_app; print('imports ok:', aether.__version__, aether.__phase__)"
}

Invoke-Checked "[3/7] Ruff lint..." { uv run ruff check . }

Invoke-Checked "[4/7] Ruff formatting..." { uv run ruff format --check . }

Invoke-Checked "[5/7] mypy typecheck..." { uv run mypy }

# Keep tmp_path fixtures on the D: checkout; registry roots under AppData are denied.
$pytestBase = Join-Path $root ".cache\pytest-tmp"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $pytestBase) | Out-Null
Invoke-Checked "[6/7] pytest (D: repository-local synthetic fixtures)..." {
    uv run pytest --basetemp $pytestBase
}

Invoke-Checked "[7/7] Authenticated health endpoint (TestClient)..." {
    uv run python -c "from fastapi.testclient import TestClient; from aether.api.app import create_app; app=create_app(); c=TestClient(app, client=('127.0.0.1', 43000)); r=c.get('/v1/health', headers={'Authorization': 'Bearer ' + app.state.session_token}); print(r.status_code, r.json()); assert r.status_code==200"
}

Write-Host "`n== Phase 1 foundation verification complete ==" -ForegroundColor Green
Write-Host "Next: .\scripts\run_backend.ps1 (loopback only; model loads only when its verified manifest/runtime are configured)"
