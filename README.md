# AETHER OS

**A dependable, private, context-aware personal computer operating assistant.**

AETHER OS is a local-first, security-conscious, agentic desktop intelligence platform for Windows. It interprets natural language and voice, understands the current Windows workspace, uses local AI, manages authorised files and applications, performs structured coding and document workflows, remembers relevant facts with provenance, and explains what it is doing.

> **Current status: Phase 0 — Architecture repository, threat model and CI (foundation only).**
> No inference, computer control, voice, memory engine, or remote services are implemented yet. All real OS actions are denied by default.

## Core principles

1. The user understands and approves consequential changes **before** AETHER executes them.
2. The local AI never grants its own permissions or executes unrestricted arbitrary shell code.
3. Private information stays local unless the user approves the exact outbound disclosure and destination.
4. Tool responses, web pages, PDFs, repository files, skills, and remote answers are **data**, not instruction sources.
5. AETHER reports verified outcomes and uncertainty truthfully; it stops rather than bluffs or exceeds scope.

## Target hardware

Intel Core i7-14650HX · 16 GB RAM · RTX 4050 Laptop GPU (6 GB VRAM) · 450 GB–1 TB free SSD · Windows 11 first.

## Quickstart (Windows)

```powershell
# 1. Install uv (if not present) — https://docs.astral.sh/uv/getting-started/installation/
irm https://astral.sh/uv/install.ps1 | iex

# 2. Clone and enter the backend
git clone <repo-url> AETHER-OS
cd AETHER-OS\backend

# 3. Sync dependencies (Python 3.12 target; 3.11+ supported for dev)
uv sync --all-extras

# 4. Run tests, lint, typecheck
uv run pytest
uv run ruff check .
uv run mypy

# 5. Run the Phase 0 health server (loopback via launch config)
uv run uvicorn aether.api.app:app --host 127.0.0.1 --port 9931
# Health: http://127.0.0.1:9931/v1/health
# NOTE: Loopback binding is controlled by the launch command above,
# not by the FastAPI application itself. Always launch with --host 127.0.0.1.
```

Or run the one-command verifier (from repo root):

```powershell
.\scripts\verify.ps1
```

## Documentation

| Document | Purpose |
|---|---|
| `docs/architecture/MASTER_SPEC.md` | **What AETHER must eventually become** (authoritative v1.0 baseline) |
| `docs/engineering/STATUS.md` | **What has actually been implemented and verified** |
| `docs/architecture/adrs/` | **Why architectural decisions were made** |
| `docs/security/THREAT_MODEL.md` | Trust hierarchy, adversaries, boundaries |
| `docs/engineering/DEVELOPER_SETUP.md` | Full setup, testing, and verification guide |
| `docs/engineering/DEPENDENCY_INVENTORY.md` | Dependency and licence register |

The master specification does not change when a coding agent proposes a shortcut. Implementation changes are documented in `STATUS.md`; consequential architecture changes require an ADR and user review before the specification is amended.

## Repository layout

```
AETHER-OS/
├── docs/          # architecture, ADRs, security, engineering
├── apps/          # desktop, vscode-extension, browser-extension (later phases)
├── backend/       # Python FastAPI backend (aether package)
├── workers/       # restricted-executor, model-host (later phases)
├── schemas/       # language-neutral JSON Schema (later)
├── scripts/       # verify.ps1 and build/release helpers
├── models/        # model manifests only, never weights in Git
├── assets/        # icons, audio cues, licensed art
├── tests/         # synthetic fixtures, e2e, benchmarks (later)
└── .github/       # Windows CI workflow (manual-only until authorised)
```

## Licence

**Pending user decision.** No public-distribution licence has been selected yet. See `docs/engineering/DEPENDENCY_INVENTORY.md`.

## Security

Phase 0 provides **foundational security contracts and a deny-by-default broker**: every real OS action is denied until permission and execution systems are implemented in later phases. This is not yet full runtime enforcement (no session auth, approval issuance, or resource resolution). See `docs/security/THREAT_MODEL.md`. Never commit secrets, model weights, local databases, or personal data.
