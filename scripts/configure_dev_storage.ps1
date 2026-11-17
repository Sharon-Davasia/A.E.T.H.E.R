# Configure AETHER development storage relative to this clone for this PowerShell process.
# Dot-source from the repository root to keep these values in the current shell only:
#   . .\scripts\configure_dev_storage.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$uvCache = Join-Path $root ".cache\uv"
$projectEnvironment = Join-Path $root "backend\.venv"
$modelRoot = Join-Path $root "models"
New-Item -ItemType Directory -Force $uvCache | Out-Null
New-Item -ItemType Directory -Force $projectEnvironment | Out-Null
New-Item -ItemType Directory -Force $modelRoot | Out-Null

# These are process-scoped. Do not persist UV settings at Windows User scope:
# unrelated repositories must retain uv's normal project-local .venv behavior.
$env:UV_CACHE_DIR = $uvCache
$env:AETHER_MODEL_ROOT = $modelRoot
# Deliberately do not set UV_PROJECT_ENVIRONMENT. From backend/, uv's default
# project environment is backend\.venv, already on this clone's drive. If the
# caller has an existing override, leave it untouched rather than changing it.
if ($env:UV_PROJECT_ENVIRONMENT) {
    Write-Warning "Existing UV_PROJECT_ENVIRONMENT is left unchanged: $env:UV_PROJECT_ENVIRONMENT"
}

Write-Host "uv cache configured for this PowerShell process: $uvCache"
Write-Host "uv project environment: $projectEnvironment (uv project-local default)"
Write-Host "Model root configured for this PowerShell process: $modelRoot"
Write-Host "No model files were downloaded. Set manifest/runtime only after verification and approval."
