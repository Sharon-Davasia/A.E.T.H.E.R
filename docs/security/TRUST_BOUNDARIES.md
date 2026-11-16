# AETHER OS — Trust Boundaries (Phase 0)

**Status:** Accepted baseline (master spec v1.0)

## Process layout and trust

| Process | Runs as / trust | Allowed responsibilities |
|---|---|---|
| Electron main + preload | Normal interactive user | Trusted windows, approval UI, restricted IPC bridge |
| React renderer | Chromium sandbox, no Node | Presentation only; escaped strings |
| FastAPI orchestrator | Normal user, loopback bound | Plans, policies, task state, model routing, memory |
| llama.cpp server | Normal user, loopback only | Inference; **no independent OS permissions** |
| Adapter workers | Separate processes where useful | Named commands under broker policy |
| Restricted script worker | Low-privilege isolated identity | Only approved code, constrained resources |
| Voice service | Normal user, mic-consent controlled | Wake, VAD, transcription, synthesis |
| Updater/recovery helper | Separately approved privilege if needed | Verified packages, atomic activation, rollback |

Phase 0 implements only the FastAPI health endpoint. All other processes are deferred.

## Network policy

- Default local-only inference; model server binds loopback, not LAN.
- `WEB_PUBLIC` (research/downloads), `RSI_REMOTE` (disabled by default), and `UPDATE_FETCH` are separate capabilities.
- Reject arbitrary model-produced URLs for credential-bearing requests; enforce redirect chains, TLS, hostname allowlists, response size limits.
- Enforceable Offline switch (not merely a prompt).

## Module boundaries (enforced in Phase 0 tests)

- `core/policy` cannot depend on model content.
- `core/orchestration` calls `policy`, `world_state`, `adapters`, `memory` via interfaces (later phases).
- Adapters cannot call other adapters' privileged methods directly.
- `model_gateway` cannot import filesystem writers, shell runners, or credential stores (later phases; boundary test asserts no model/shell imports in policy/adapters).
- `desktop` invokes a narrow backend API, receives events (not raw Python objects).
- `voice` produces intent with transcription evidence; it cannot apply changes.
- `provider_connectors` can only send broker-approved payload hashes.

## Windows path and resource security

`SafePath` is useful but **not a sandbox**. It resolves aliases to canonical trusted resources, identifies volume/file identity, rejects reparse-point/junction escapes, and validates near execution time. Directory zones: Trusted workspace (write only under approved plan), Reference roots (read-only until granted), Protected OS/secret paths (excluded from model context), Removable/network volumes (by identity, unknown = read-only/no-execute).

## Script execution

Prefer typed commands (`run_tests`, `git_status`) over arbitrary shell. AST scan is inspection only; Job Objects are resource management, not isolation. Stronger isolation (restricted token, AppContainer, disposable environment) is required for untrusted code; if unavailable, the path stays disabled. Phase 0: no script execution at all.
