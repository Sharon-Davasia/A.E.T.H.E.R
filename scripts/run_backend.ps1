# AETHER Phase 1 developer API launcher.
# Generates a fresh bearer token in memory and binds both API access and listener to loopback.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $root "backend")
uv run python -m aether.api.dev_server
exit $LASTEXITCODE
