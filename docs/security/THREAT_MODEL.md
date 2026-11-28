# AETHER OS — Threat Model (Phase 1 local-intelligence foundation)

**Authority:** `docs/architecture/MASTER_SPEC.md` v1.0. This document describes implemented Phase 1 boundaries separately from later design requirements.

## Assets and trust hierarchy

- Local model files and runtime identity/integrity metadata; model weights are never Git content.
- Ephemeral AETHER session bearer token and separate llama.cpp API key; neither belongs in source, reports, prompts, command-line arguments or logs.
- Chat prompts/responses are sensitive local data: do not log their contents or export them in benchmark reports.
- The policy broker, not the model, controls any future operation. Phase 1 has no real OS operations and the broker continues to deny them.
- User-provided model output is untrusted. User text and evidence may contain prompt-injection instructions; trust labels are defense in depth, not authority control.
- A local attacker with access to the same Windows user account can inspect or alter same-user software and memory; no hard isolation claim is made against that adversary.

## Phase 1 threat/defense table

| Boundary | Threat | Phase 1 control and limitation |
|---|---|---|
| LAN/local client → FastAPI | Unauthenticated chat, cross-origin use, request flood | Launcher binds numeric loopback; app checks peer IP; bearer token generated each start; rejects non-allowlisted Origin headers; no CORS middleware or browser cross-origin support; bounded request/output and one active generation |
| Local caller → llama.cpp | Bypass FastAPI session and invoke inference | Server binds `127.0.0.1`; protected inference/tokenization routes use a fresh API key kept in process memory and child environment; upstream minimal `/health` remains public and returns readiness only |
| Model output → tool capability | Invented tool/invalid arguments or claims of execution | Pydantic decision schema + registered typed mock schemas; chat never invokes handlers; real OS broker still always denies |
| User/evidence text → prompt | Instruction-like text changes system guidance | Separate system role, server-managed bounded history, explicit untrusted labels and token limits; no external/private context; prompt design is not treated as a security boundary |
| Backend → model runtime | Injection through paths/flags, proxies, credentials, remote fallback | Configured executable and model path; strict manifest/inventory/hash check; `shell=False`; fixed argument list; no runtime auto-download; loopback-only HTTP client with `trust_env=False`; no cloud provider implementation |
| Model process → host | OS control, built-in file/shell/MCP tool | Ordinary user process; tool/agent/MCP features disabled; model gateway imports no filesystem writers, shell runners, credential stores or Windows automation; Windows Job Object code requires target validation |
| Model asset → inference | Missing, unexpected, tampered asset or incompatible runtime | Strict manifest schema, exact file set, size and streaming SHA-256; runtime executable SHA-256 plus version/build check; no final Qwen manifest until source facts are verified |
| Local path → report/log | Prompt, credentials or absolute path disclosure | Prompt text not logged; error codes only; benchmark includes synthetic cases and no prompts/token; report location is configured separately |

## Phase 1 security invariant

**No real Windows action can be performed by this phase.** `PolicyBroker.evaluate()` always denies. Chat returns typed answer/clarification/proposal only. A valid mock tool is not run by the chat service, and model confidence or valid JSON never grants permission.

The `request_tool`, `propose_plan` and `offer_rsi` decision categories are proposals. No approval endpoint, action executor, memory, cloud inference, RSI provider, real file API, shell, process launcher for user programs, UI automation or application control is included.

## Offline boundary

The ordinary chat request path has only the authenticated FastAPI-to-loopback llama.cpp route. The client refuses non-numeric-loopback targets and ambient proxies; the supervisor strips inherited proxy and model-hub credentials and sets hub-offline mode. No HTTP API for model download or cloud inference exists. Automated tests use mocks/loopback constraints; they **do not prove Windows firewall-level offline enforcement**. Laptop airplane-mode/network-disconnected validation remains required.

## Known limitations and validation

- Candidate GGUF repository/file is user-identified; exact revision, SHA-256, size, license, template/projector needs and compatible pinned Windows CUDA build remain unverified. No model has been downloaded.
- llama.cpp upstream health is unauthenticated but loopback-only/minimal; its protected inference routes use an API key.
- The Windows Job Object implementation, job assignment under Cursor/Windows process policies, CUDA loading, shutdown and process-tree cleanup require Windows testing.
- A valid schema does not prove semantic correctness; one bounded repair is allowed, then malformed output fails closed.
- No unit test establishes GPU/VRAM fit, model quality, host firewall enforcement, or V-01 performance.
- Automated secret scanning remains pending; CI is manual-only.

## Phase 3 extension (CP0–CP2 foundation; native control not enabled)

Scope of this extension: typed app/window contracts, privacy-gated
in-memory observation with fake sources, guarded inert native source,
and in-memory app discovery/alias resolution. Launching, UIA
interaction and native sensors remain disabled; residual threats
below are design requirements for later checkpoints, not claims of
implemented native protection.

| Threat | Control in foundation | Fail-closed behaviour / later requirement |
|---|---|---|
| HWND/PID reuse, stale/substituted window | Window identity binds HWND+pid+creation time+UIA runtime id; TTL expiry; destruction/exit invalidation | Re-resolution at execution (CP3+); version mismatch denies |
| Malicious titles/aliases, prompt injection in UI text | Titles bounded, `UNTRUSTED`-grade data, never authority; exact-name precedence over aliases; ambiguity → clarification | Redaction before model context; never instructions |
| Forged `app:`/`window:` resource ids | Disjoint argument patterns vs `file:`/`directory:`; registry-issued ids only; fabricated ids refused in tests | Broker kind dispatch by registered capability (CP3 design) |
| Executable substitution / stale registration | Executable-digest evidence; drift marks record unavailable | Re-verification before any launch trust (CP3) |
| Sensitive collection (password managers, private browsing, elevated, credential UI) | Collection-boundary exclusion; unclassifiable = sensitive; opt-in + mode gating; pause invalidates | Native classifier review before activation |
| Queue overflow losing destruction/privacy events | Overflow counter, uncertainty marking, reconciliation clears retained state | Measured native budgets; never present uncertain as verified |
| Manual takeover (incl. same-HWND) | Not implemented in CP0–CP2 (design R2 in PHASE3_PLAN) | Capability denied/limited where detection unreliable |
| Hung UIA provider / worker death | No UIA worker in this batch (R7 design) | Timeout post-begin = UNVERIFIED, no replay |
| False success | Fake adapter execution returns FAILED; no launch capability exists | Postcondition-verified receipts only (CP3+) |
| Privacy retention creep | In-memory observations only; no persisted titles/snapshots/history | Any persistence requires new approval + migration review |

A subprocess worker (future) is a reliability boundary, not an OS
security sandbox; no same-user isolation claim is made.
