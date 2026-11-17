# AETHER OS

**A dependable, private, context-aware personal computer operating assistant.**

AETHER OS is a local-first, security-conscious desktop intelligence platform for Windows. Its long-term specification describes broader capabilities; implemented status is recorded separately below.

> **Current status: Phase 1 foundation implemented in the current development branch; target acceptance is pending.** Authenticated text-chat scaffolding, local model interfaces, manifest integrity checks, process supervision, context/decision contracts, task tracking and mock tools are present and tested with fakes. The exact Qwen GGUF metadata and pinned CUDA runtime remain pending verification. No model is bundled or downloaded. **No real Windows actions, approvals, cloud inference, voice or persistent memory are implemented. Real OS actions remain denied by default.**

## Core principles

1. The user understands and approves consequential changes before execution (later-phase capability).
2. The local AI never grants its own permissions or executes unrestricted arbitrary shell code.
3. Private information stays local; Phase 1 has no hosted inference or cloud fallback.
4. Tool responses, web pages, repository files and model outputs are data, not authority.
5. AETHER reports verified outcomes and uncertainty truthfully; it stops rather than bluffing or exceeding scope.

## Target hardware

Intel Core i7-14650HX · 16 GB RAM · RTX 4050 Laptop GPU (6 GB VRAM) · Windows 11 first. CUDA compatibility, GPU offload, VRAM and performance are **unverified until local Windows testing**.

## Quickstart (Windows)

```powershell
# Install uv using the official instructions: https://docs.astral.sh/uv/getting-started/installation/
# Python 3.12 is the project target.

# From the repository root, place uv cache/model storage on the clone's drive.
. .\scripts\configure_dev_storage.ps1

# Sync the locked environment and run verification.
cd .\backend
uv python install 3.12
uv sync --all-extras --locked
cd ..
.\scripts\verify.ps1
```

The verifier uses fake gateways and synthetic fixtures; it does not require model weights, CUDA or network inference. To start the authenticated API in loopback-only developer mode:

```powershell
.\scripts\run_backend.ps1
```

The launcher generates a temporary bearer token and displays it once in that terminal. Health and chat require the token, and the API rejects non-loopback peers. Without a verified model manifest/runtime, health reports `model_ready: false` and chat returns a typed unavailable error. See `docs/engineering/WINDOWS_PHASE1_VALIDATION.md` before any model installation; the candidate download remains pending separate approval.

## Documentation

| Document | Purpose |
|---|---|
| `docs/architecture/MASTER_SPEC.md` | What AETHER must eventually become (authoritative v1.0 baseline) |
| `docs/engineering/STATUS.md` | What has actually been implemented and verified |
| `docs/architecture/adrs/` | Why architectural decisions were made; candidate vs accepted status |
| `docs/security/THREAT_MODEL.md` | Trust hierarchy, adversaries and boundaries |
| `docs/engineering/DEVELOPER_SETUP.md` | Setup, testing and verification |
| `docs/engineering/MODEL_INSTALLATION.md` | Pending model verification and later manual installation |
| `docs/engineering/WINDOWS_PHASE1_VALIDATION.md` | Target-laptop acceptance procedure |
| `docs/engineering/BENCHMARK_METHODOLOGY.md` | Synthetic V-01 benchmark methodology |

The master specification does not change to accommodate implementation shortcuts. Implementation changes are documented in `STATUS.md`; consequential architecture changes require an ADR and user review before the specification is amended.

## Repository layout

```text
AETHER-OS/
├── docs/          # architecture, ADRs, security, engineering and validation
├── apps/          # desktop and extensions (later phases)
├── backend/       # Python FastAPI backend (aether package)
├── workers/       # future workers; model process supervised by backend
├── schemas/       # language-neutral contracts
├── scripts/       # verify.ps1 and run_backend.ps1
├── models/        # manifests only; weights never in Git
├── assets/        # licensed assets (later phases)
└── tests/         # synthetic fixtures and benchmark procedures
```

## Licence

Project public-distribution licence: **pending user decision**. The model/runtime licences are separate and must be verified before any asset download or redistribution.

## Security

Phase 1 adds authenticated loopback API access and a supervised local-inference boundary. The model server receives no OS-action privileges; its inference/tokenization routes require a fresh API key held in process memory and supplied through its environment, not command-line arguments. The llama.cpp health endpoint is a minimal public liveness route, restricted by loopback binding. The FastAPI app also checks the connecting peer, requires a bearer session and rejects non-allowlisted `Origin` headers. This does not enable CORS; browser-based cross-origin clients are unsupported in Phase 1. The supervisor verifies a declared executable SHA-256 and authenticates model readiness. Built-in agent/tools/MCP options are disabled. None of this constitutes Phase 2 authorization or real OS-action enforcement; `PolicyBroker` continues to deny real actions. Never commit secrets, model weights, local databases, benchmark reports or personal data.
