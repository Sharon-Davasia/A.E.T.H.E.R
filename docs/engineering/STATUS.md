# AETHER OS — Implementation Status

**What has actually been implemented and verified.**
The master specification (`docs/architecture/MASTER_SPEC.md`) describes what AETHER must eventually become. This file describes what exists now.

## Current phase

**Phase 0 — Architecture repository, threat model and CI (foundation only).**

## Implemented (Phase 0)

- Monorepo scaffold: `docs/`, `apps/`, `backend/`, `workers/`, `schemas/`, `scripts/`, `models/`, `assets/`, `tests/`, `.github/workflows/`.
- Canonical master spec at `docs/architecture/MASTER_SPEC.md` (v1.0, 14 Nov 2026, verbatim copy of provided source).
- ADRs ADR-001 … ADR-013 + template. Accepted vs candidate vs pending distinguished (see `docs/architecture/adrs/`).
- Threat model + trust boundaries (`docs/security/`).
- Python backend foundation: installable `aether` package, FastAPI app with `GET /v1/health` only (loopback via launch config), Pydantic v2 contracts (10 boundaries), deny-by-default `PolicyBroker`, fake adapters (in-memory), structured logging with redaction (structlog events only).
- Tests: contracts, policy deny, fake adapters, task states, redaction, structured logging, module boundaries, health (43 tests).
- Quality: Ruff config, pytest config, mypy strict, `scripts/verify.ps1` (exit-code checked), `.gitignore`, Windows CI workflow (manual-only, Python 3.12 pinned + verified).
- Dependency lockfile: `backend/uv.lock` (generated via `uv sync`). Python 3.12 pinned via `backend/.python-version`; supported policy `>=3.11` in `pyproject.toml`.
- Hardening pass: fixed `verify.ps1` exit-code handling, fixed `get_logger()` lazy-proxy + redaction processor, corrected CI secret-scan labelling (manual/pending), removed placeholder licence from `pyproject.toml`, clarified localhost/security claims.

## Verified (in this sandbox, Linux / Python 3.11 via `--python 3.11` override)

- `uv sync --python 3.11 --all-extras --locked` — **verified**.
- `uv run --python 3.11 pytest` — **verified** (43 passed).
- `uv run --python 3.11 ruff check .` + `ruff format --check .` — **verified**.
- `uv run --python 3.11 mypy` — **verified** (strict, 24 files).
- Health endpoint via TestClient — **verified**.
- Default-deny: every `PolicyBroker.evaluate()` denies; RSI send denies — **verified by tests**.
- Fake adapters: in-memory only, no filesystem writes — **verified by tests**.
- Structured logging: creation, JSON output, redaction (structlog only) — **verified by tests**.
- `verify.ps1` exit-code logic — **code generated, not executed here** (requires Windows PowerShell).

## NOT yet verified (requires Windows / Python 3.12)

- Python 3.12 runtime: sandbox cannot download 3.12 (release-assets blocked + cert failure). **Unverified here; must run on Windows laptop / CI.** `.python-version` pins 3.12; sandbox uses `--python 3.11` override.
- Windows CI workflow: file created, **manual-only, not enabled**. Must be manually dispatched on GitHub after user authorisation. Automated secret scanning is pending (manual review only).
- PowerShell `verify.ps1`: **code generated, not executed here** (requires Windows). Exit-code logic must be validated on the laptop.
- Windows-specific paths, Electron, llama.cpp, Qwen benchmarks (V-01), Groq account validation (V-02): **not implemented / not verified** (later phases).
- Public-distribution licence and AETHER name search (V-06): **pending user decision** (no placeholder licence in `pyproject.toml`).

## Phase 0 completion checklist

| Requirement | Status |
|---|---|
| Agreed modular structure | ✅ Implemented |
| Reproducible Python backend environment | ✅ Implemented (lockfile); Python 3.12 unverified in sandbox |
| Documentation + initial ADRs | ✅ Implemented |
| Typed core contracts | ✅ Implemented (10 contracts) |
| Security policy denies all real OS actions | ✅ Implemented + tested |
| Fake adapters + synthetic fixtures | ✅ Implemented |
| Local linting + automated tests pass | ✅ Verified (sandbox, Python 3.11) |
| Windows CI configuration exists | ✅ Implemented (manual-only, not enabled) |
| No secrets/weights/personal data | ✅ Verified (git status clean of secrets) |
| No later-phase features | ✅ Verified (health only, no inference/OS/voice/memory) |
| Reproducible startup + verification documented | ✅ Implemented (`DEVELOPER_SETUP.md`, `verify.ps1`) |

## Known limitations

- Sandbox is Linux/Python 3.11; target is Windows/Python 3.12. Windows validation pending.
- Health endpoint is unauthenticated; loopback binding is via launch config (`--host 127.0.0.1`), not enforced by the app. Session auth arrives in Phase 1.
- Phase 0 security is foundational contracts + deny-by-default broker, not full runtime enforcement.
- No `LICENSE`, `SECURITY.md`, or `CONTRIBUTING.md` yet (deferred; licence pending).
- CI is manual-only and not pushed/enabled. Secret scanning is manual/pending.

## Next phase (Phase 1, not started)

Local intelligence and task scaffolding: llama.cpp supervisor, model manifest, chat endpoint, context assembler, mock tool registry, benchmarks. Requires V-01 benchmark gate.
