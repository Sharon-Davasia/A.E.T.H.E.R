# AETHER OS — Phase 0 local verification (Windows PowerShell)
# Run from the repository root: .\scripts\verify.ps1
# Verifies: deps, imports, lint, typecheck, tests, health endpoint.
# No model downloads, no OS automation, no network inference.
#
# Every native command's exit code is checked. Any failure aborts
# immediately with a non-zero exit; the success message is printed
# only if every step passes.

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

Write-Host "== AETHER OS Phase 0 verification ==" -ForegroundColor Cyan

Invoke-Checked "[1/6] uv sync (locked)..." { uv sync --all-extras --locked }

Invoke-Checked "[2/6] Import check..." {
    uv run python -c "import aether; from aether.api.app import create_app; print('imports ok:', aether.__version__)"
}

Invoke-Checked "[3/6] Ruff lint..." { uv run ruff check . }

Invoke-Checked "[4/6] mypy typecheck..." { uv run mypy }

Invoke-Checked "[5/6] pytest..." { uv run pytest }

Invoke-Checked "[6/6] Health endpoint (TestClient)..." {
    uv run python -c "from fastapi.testclient import TestClient; from aether.api.app import create_app; c=TestClient(create_app()); r=c.get('/v1/health'); print(r.status_code, r.json()); assert r.status_code==200"
}

Write-Host "`n== Phase 0 verification complete ==" -ForegroundColor Green
Write-Host "Next: uv run uvicorn aether.api.app:app --host 127.0.0.1 --port 9931"
