# Phase 1 — Windows acceptance runbook

This is a staged handoff for `D:\A.E.T.H.E.R`. It does not authorize model downloads. The exact GGUF and llama.cpp build remain pending verification; stop before acquisition until their manifest is reviewed and you separately approve the download.

## A. Pull and run regression checks

```powershell
Set-Location 'D:\A.E.T.H.E.R'
git status --short
git pull --ff-only
. .\scripts\configure_dev_storage.ps1
Set-Location 'D:\A.E.T.H.E.R\backend'
uv sync --all-extras --locked
uv run python --version
Set-Location 'D:\A.E.T.H.E.R'
.\scripts\verify.ps1
```

Expected Python target is 3.12. The verifier runs locked dependency sync, imports, Ruff, formatting, mypy, tests and an authenticated health check. It does not download models or invoke a model runtime.

## B. Review model/runtime requirements (no download yet)

Read `docs/engineering/MODEL_INSTALLATION.md` and `models/README.md`. Confirm the final manifest is present and reviewed. If revision, full hashes, exact size, license, template/projector details or pinned build compatibility is missing, stop here and report the missing evidence.

## C. Install only after explicit download approval

After the separate approval and verified instructions are available:

- Obtain the exact model and runtime artifacts from the documented sources.
- Keep runtime binaries and model files on D: outside Git.
- Set `AETHER_MODEL_ROOT`, `AETHER_MODEL_MANIFEST`, `AETHER_LLAMA_SERVER`, `AETHER_MODEL_PORT=9932`, `AETHER_CONTEXT_TOKENS=4096`, and `AETHER_GPU_LAYERS` as documented.
- Do not change the model-server bind address from `127.0.0.1`; do not enable agent tools, MCP or shell features.
- Run `scripts\run_backend.ps1` from a Cursor PowerShell terminal. It prints a newly generated AETHER API bearer token once to that terminal. Do not paste it into files, source control, issue reports or logs.
- In another PowerShell terminal, set `$env:AETHER_SESSION_TOKEN` to the token for the session, then issue authenticated loopback requests. Never place the token in a command-line argument or saved script.

Example request after the model is verified and installed:

```powershell
$headers = @{ Authorization = "Bearer $env:AETHER_SESSION_TOKEN" }
Invoke-RestMethod 'http://127.0.0.1:9931/v1/health' -Headers $headers
$body = @{ message = 'Give a brief greeting.'; max_output_tokens = 128 } | ConvertTo-Json
Invoke-RestMethod 'http://127.0.0.1:9931/v1/chat/turns' -Method Post -Headers $headers -ContentType 'application/json' -Body $body
```

A `request_tool` result is a proposal only. There is no Windows action, approval or real tool-execution endpoint in Phase 1.

## D. Offline and benchmark checks

1. After normal chat works, disconnect Wi-Fi/Ethernet using Windows controls and submit a synthetic local chat request. Record any error and verify no cloud route is available. Do not treat unit tests as proof of firewall-level offline enforcement.
2. Set `AETHER_BENCHMARK_DIR` to a separate D: report directory, for example `D:\A.E.T.H.E.R\data\benchmarks` (ignored by Git). Run `uv run python -m aether.benchmarks.run_benchmark` from `backend`.
3. Review `docs/engineering/BENCHMARK_METHODOLOGY.md`. Save the report without user prompts or secrets.
4. Inspect `/v1/health` readiness before and after testing. If the model process exits, do not attempt automatic restart; capture the safe error code and sanitized system/runtime version details.
5. Stop the backend with Ctrl+C. Its lifespan shuts down the supervised model process. Confirm the server process has exited in Task Manager or PowerShell. If it remains, preserve diagnostics and report it; do not use force-kill as the normal procedure.

## Evidence to share for acceptance

- Output of the verifier and Python version.
- Model manifest ID and hashes (no weight files).
- llama.cpp version/build ID and CUDA driver/GPU details.
- Sanitized benchmark JSON and offline-test result.
- Whether shutdown left any model process alive.

Phase 1 remains **ready for Windows acceptance—not complete** until the actual model/runtime, offline operation and V-01 measurements pass on the target RTX 4050 laptop.
