# Dependency and Licence Inventory (Phase 0)

**Status:** Initial check; verify per exact released version before distribution.
**Public-distribution licence:** **PENDING user decision** (no `LICENSE` file yet).

## Phase 0 runtime dependencies

| Component | Role | Licence / attention |
|---|---|---|
| Python 3.12 (target) | Runtime | PSF; 3.11+ supported for dev |
| FastAPI | Backend API | Open-source (MIT); verify version/lockfile |
| Uvicorn | ASGI server | Open-source (BSD); localhost only |
| Pydantic v2 | Typed contracts | Open-source (MIT) |
| Structlog | Structured logging | Open-source (Apache-2.0) |

## Phase 0 dev dependencies

| Component | Role | Licence / attention |
|---|---|---|
| pytest | Testing | Open-source (MIT) |
| httpx | TestClient transport | Open-source (BSD) |
| Ruff | Lint/format | Open-source (MIT) |
| mypy | Typecheck | Open-source (MIT) |
| uv | Dependency manager | Open-source (Apache-2.0/MIT) |

All Phase 0 dependencies are OSI-approved open-source. Exact versions are pinned in `backend/uv.lock`.

## Later-phase components (not in Phase 0; licence review required)

| Component | Role | Licence / attention |
|---|---|---|
| Electron | Desktop shell | MIT; security config + Chromium footprint |
| React/Vite/TS/Tailwind | Frontend | Open-source; audit release notices |
| llama.cpp | Local inference | MIT; check distributed builds |
| Qwen3.5-4B upstream | Core model | Apache-2.0 per official repo; GGUF conversion separately verified; **candidate, pending V-01** |
| Gemma 4 E4B | Alternative benchmark | Check exact checkpoint terms; **candidate** |
| pywinauto / pywin32 | Windows controls | Audit packages + platform constraints |
| Playwright | Browser adapter | Apache-2.0; browser binaries + profile handling |
| pdfplumber | PDF parsing | MIT; no OCR/full editing |
| PyMuPDF | Optional PDF engine | AGPLv3 or commercial — review before distribution |
| openWakeWord | Wake word code | Apache-2.0 code; weights CC BY-NC-SA 4.0 |
| whisper.cpp | Local STT | MIT; verify weights/usage |
| Kokoro-82M | TTS candidate | Check model card + voice terms |
| Piper/OHF fork | TTS alternative | GPL-3.0; audit voice packages |
| SQLite/FTS5 | Storage | Public-domain SQLite; build-specific checks |
| VS Code | Editor integration | Check Microsoft distribution vs Code-OSS |
| Groq API | Optional RSI | Commercial hosted service; quotas/terms; **candidate, pending V-02** |

Avoid silently mixing GPL/AGPL binaries or weights into incompatible redistribution. Legal/licensing review required before public distribution (V-06).

## Supply-chain controls (Phase 0)

- Pinned versions + `uv.lock`; no floating installs.
- No model weights, API keys, or personal data in Git.
- CI runs on `windows-latest` with locked deps; manual-only until authorised.
- SBOM generation deferred to Phase 9 (release packaging).
