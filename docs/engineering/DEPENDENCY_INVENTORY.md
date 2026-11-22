# Dependency and Licence Inventory (Phase 1)

**Status:** Development inventory; verify exact released versions and binaries before distribution.
**Public-distribution project licence:** **PENDING user decision** (no `LICENSE` file).

## Current Python runtime dependencies

| Component | Role | Licence / attention |
|---|---|---|
| Python 3.12 (target) | Runtime | PSF; supported-version policy `>=3.11` |
| FastAPI | Authenticated local backend API | MIT; verify exact lockfile version |
| Uvicorn | ASGI server | BSD; developer launcher binds 127.0.0.1 |
| Pydantic v2 | Typed requests, decisions and manifest validation | MIT |
| Structlog | Structured diagnostics | Apache-2.0; prompts/responses are not logged |
| HTTPX | Async local llama.cpp transport | BSD; `trust_env=False`, numeric loopback-only URL |
| cryptography | AES-256-GCM for the Phase 2 Undo Vault (`core/vault/undo_vault.py`) | Apache-2.0 OR BSD-3-Clause; OpenSSL-backed. Used **only** for snapshot encryption at rest. It never authorizes an action, and no key material is logged or stored in the task database. |

## Development and benchmark extras

| Component | Role | Licence / attention |
|---|---|---|
| pytest | Unit and API tests | MIT |
| pytest-asyncio | Deterministic async unit tests | Apache-2.0 |
| Ruff | Lint/format | MIT |
| mypy | Strict type checks | MIT |
| psutil (benchmark extra) | Optional model-process RSS samples | BSD; not used to authorize actions |
| uv | Dependency manager | Apache-2.0/MIT |

Exact Python package versions are pinned in `backend/uv.lock`. CI remains manual-only.

## Model/runtime candidates — not yet verified or installed

| Component | Role | Status / required evidence |
|---|---|---|
| `ggml-org/Qwen3.5-4B-GGUF`, `Qwen3.5-4B-Q4_K_M.gguf` | Preferred user-identified local text model candidate | **Pending independent verification:** immutable repo revision, exact artifact/hash/size, architecture/quantisation, chat template, text capability, projector requirements and exact licence. No download. |
| llama.cpp Windows CUDA build | Local inference process | Upstream server protocol inspected; exact immutable release/build and CUDA compatibility with candidate GGUF **pending**. No binary downloaded. |
| NVIDIA CUDA driver/runtime | Target GPU inference | Laptop version and compatibility unverified until Windows acceptance. |

The master spec states the upstream Qwen checkpoint is Apache-2.0. That is not treated as verification of the specific candidate repository, conversion or redistribution rights. Do not distribute the GGUF until its exact license/terms are checked.

## Later-phase components (not in Phase 1)

| Component | Role | Licence / attention |
|---|---|---|
| Electron/React/Vite | Desktop trusted review surface | In use (Phase 2B Stage 3+). The Electron main process is the trusted UI boundary; the renderer is untrusted and has no Node integration. Audit release notices before distribution. |
| Gemma 4 E4B | Possible model challenger | Deferred; exact checkpoint terms and benchmark review |
| pywinauto / pywin32 | Windows controls | Not present; no generic OS control. Phase 2 filesystem capability is bounded and typed instead. |
| Playwright, Office/PDF tools | App integrations | Deferred |
| SQLite (stdlib `sqlite3`) | Phase 2 task/plan/grant/receipt persistence, schema v1 | In use since Phase 2B. v2 migrations exist but are **not active** (`ACTIVE_SCHEMA_VERSION=1`). |
| Groq/RSI providers | Remote inference | Prohibited in Phase 1; no integration or fallback |

## Supply-chain controls

- Locked Python packages; no model/runtime auto-download code.
- Model files are outside Git, declared in a manifest and checked by exact file inventory, size and streaming SHA-256 before process launch.
- Runtime receives a generated API key through its child environment, not command-line arguments; no proxy or HF credentials are inherited.
- No real model, CUDA binary, cloud provider SDK or personal data is included in the sandbox tests.
- Automated secret scanner remains pending; manual review only.
