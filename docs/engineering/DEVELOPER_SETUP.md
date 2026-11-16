# Developer Setup and Testing (Phase 0)

## Prerequisites

- Windows 11 (target). Development may occur on any OS; Windows CI validates.
- Python 3.12 target (3.11+ supported for dev). `uv` for dependency management.
- Git.

## Setup (Windows PowerShell)

```powershell
# Install uv (once)
irm https://astral.sh/uv/install.ps1 | iex

# Clone and enter backend
git clone <repo-url> AETHER-OS
cd AETHER-OS\backend

# Sync locked dependencies
uv sync --all-extras --locked

# Verify
uv run pytest
uv run ruff check .
uv run mypy
```

## One-command verification (repo root)

```powershell
.\scripts\verify.ps1
```

## Running the health server

```powershell
cd AETHER-OS\backend
uv run uvicorn aether.api.app:app --host 127.0.0.1 --port 9931
# Health: http://127.0.0.1:9931/v1/health
```

Only `GET /v1/health` exists in Phase 0. No chat, task, approval, memory, RSI, or OS-control endpoints.

**Loopback binding is controlled by the launch command** (`--host 127.0.0.1`), not by the FastAPI application object. The app does not independently enforce loopback; operators must always launch with an explicit loopback host. Session authentication arrives in Phase 1.

## Testing

```powershell
cd AETHER-OS\backend
uv run pytest          # all Phase 0 tests (synthetic data, no network)
uv run pytest -v       # verbose
```

Tests cover: schema validation, default-deny policy, invalid requests, task-state transitions, fake adapters, redaction, structured logging (creation, JSON output, redaction), module boundaries, health endpoint.

## Lint and typecheck

```powershell
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

## CI

`.github/workflows/ci.yml` is **manual-only** (`workflow_dispatch`). It runs on `windows-latest` with Python 3.12: `uv sync --locked`, Ruff, mypy, pytest. Do not enable automatic execution until the user explicitly authorises CI activation.

## Environment notes

- Python 3.12 is pinned for development via `backend/.python-version` (uv mechanism). Supported-version policy is `>=3.11` in `pyproject.toml`. Windows CI explicitly installs, pins, and verifies Python 3.12.
- This sandbox (Linux, Python 3.11) cannot install Python 3.12 via `uv` (release-assets host blocked + cert failure). Sandbox verification therefore runs with `uv run --python 3.11` override; Python 3.12 is validated in Windows CI and on the user's laptop. See `STATUS.md`.
- Never commit secrets, model weights, databases, or personal data. `.gitignore` protects `.env`, `*.gguf`, `*.db`, `data/`, `.venv/`, logs.
- Structured logging redacts secrets for structlog events only (`aether.core.security.redaction`). Standard-library logging that bypasses structlog is NOT automatically redacted — use `get_logger()` for redacted output.
