# Developer Setup and Testing (Phase 1)

## Prerequisites

- Windows 11 target; Python 3.12 target (`>=3.11` supported for development), `uv`, Git, Cursor optional.
- Model weights and llama.cpp binaries are not prerequisites for the deterministic test suite.
- A compatible model/runtime is not yet configured: see `MODEL_INSTALLATION.md` and `models/README.md`.

## Setup (Windows PowerShell)

Install uv using its official installation instructions (do not execute downloaded scripts through a shell pipe). From the repository root, configure uv cache, project environment and model storage relative to this clone (so all follow the D: clone without embedding a user path in source). Dot-source the helper to set process-scoped values in this PowerShell session; it does not persist environment values at Windows User scope. `UV_PROJECT_ENVIRONMENT` stays unset so uv uses the backend project's normal `backend\.venv`:

```powershell
. .\scripts\configure_dev_storage.ps1
cd .\backend
uv python install 3.12
uv sync --all-extras --locked
uv run python --version
cd ..
.\scripts\verify.ps1
```

The verifier runs Ruff lint/format, strict mypy, pytest, imports and authenticated FastAPI health checks. No model, network inference or GPU is needed. One optional actual-runtime integration test is skipped unless explicitly enabled and configured; a skip is not a model validation pass.

## Start authenticated local API

From the repository root:

```powershell
.\scripts\run_backend.ps1
```

It binds Uvicorn to `127.0.0.1` on port 9931. At startup it generates a fresh random bearer token, shown once in the terminal. Do not paste it into source, command history, issue reports or logs. The API enforces a loopback peer check, bearer auth, and rejects `Origin` headers not in the exact configured loopback-only set. This is an Origin rejection/CSRF boundary only: no CORS middleware or CORS response headers are configured, so browser-based cross-origin clients are not supported in Phase 1. Without a configured verified model, API health remains live but reports model-not-ready; chat returns an explicit unavailable response.

To call the backend from another local PowerShell terminal without saving the token to command history, enter it through the secure prompt:

```powershell
$secure = Read-Host 'Paste the AETHER session token' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $env:AETHER_SESSION_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
$headers = @{ Authorization = "Bearer $env:AETHER_SESSION_TOKEN" }
Invoke-RestMethod 'http://127.0.0.1:9931/v1/health' -Headers $headers
```

For a text turn after the model is installed and ready:

```powershell
$body = @{ message = 'Give a brief greeting.'; max_output_tokens = 128 } | ConvertTo-Json
Invoke-RestMethod 'http://127.0.0.1:9931/v1/chat/turns' -Method Post -Headers $headers -ContentType 'application/json' -Body $body
```

Press Ctrl+C in the server terminal to stop the backend and supervised model process. The inference server's API key is generated in memory and sent through a restricted child environment, not command-line arguments. llama.cpp's minimal `/health` endpoint is not API-key protected by the upstream server; it is loopback-only and contains no model path/credential data. Protected generation and tokenization routes require the key.

## Optional real-model configuration

Only after the user reviews verified immutable asset/build metadata and separately approves downloads, set `AETHER_MODEL_ROOT`, `AETHER_MODEL_MANIFEST`, `AETHER_LLAMA_SERVER`, `AETHER_MODEL_PORT` (default 9932), `AETHER_CONTEXT_TOKENS` (default 4096), and `AETHER_GPU_LAYERS` in the server terminal before running the launcher. All paths are configurable. No model downloader exists. Details and pending evidence are in `MODEL_INSTALLATION.md`.

The supervisor checks every declared model asset hash/size and exact directory contents, verifies the runtime executable against the manifest SHA-256 and checks its version/build string, passes the manifest model ID through llama.cpp `--alias`, binds to numeric loopback and disables llama.cpp agent/MCP proxy flags. Exact runtime checksum and pinned Windows build metadata remain pending independent verification. Unsupported runtime flags/version mismatch fail closed. The server receives no inherited proxy, HF token, or `LLAMA_ARG_*` overrides. Context starts at 4,096; default GPU layers are zero as a safe troubleshooting baseline. Set a nonzero value only for local RTX 4050 benchmark trials; no offload count is pre-validated.

## Testing and quality

```powershell
cd .\backend
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

Tests use fake gateways, fake processes and synthetic bytes; they do not require model downloads, CUDA or external API calls. The optional test `tests/test_model_integration.py` requires `AETHER_RUN_MODEL_INTEGRATION=1` plus explicit local asset/runtime configuration. It is not part of routine acceptance unless deliberately enabled.

## Benchmarking

After assets are verified and local chat works, set `AETHER_SESSION_TOKEN` (do not put it on command lines), `AETHER_MODEL_ROOT`, `AETHER_MODEL_MANIFEST`, and `AETHER_BENCHMARK_DIR` to a separate report location. Then run `uv run python -m aether.benchmarks.run_benchmark`. It uses fixed synthetic prompts, excludes prompt contents and credentials from reports, and records missing/unavailable metrics as null. See `BENCHMARK_METHODOLOGY.md`.

## CI and offline limitations

`.github/workflows/ci.yml` remains **manual-only** (`workflow_dispatch`), Windows and Python 3.12. Automated secret scanning remains pending. Unit tests that use HTTPX mocks or loopback-only transport checks are not proof of Windows firewall-level offline enforcement. Actual offline chat and V-01 performance need target-laptop validation.
