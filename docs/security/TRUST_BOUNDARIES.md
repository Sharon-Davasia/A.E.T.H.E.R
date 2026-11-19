# AETHER OS — Trust Boundaries (Phase 1 foundation)

**Status:** Phase 1 boundaries plus the unmerged Phase 2A resource/policy contract foundation; no Phase 2 filesystem execution, trusted approvals or mutations.

## Phase 1 process and module layout

| Process/module | Trust and allowed responsibility |
|---|---|
| FastAPI backend | Normal user, developer launcher binds `127.0.0.1`; peer-loopback check, ephemeral bearer session, exact-origin allowlist; typed chat/status only |
| `model_gateway` | Internal HTTP client constrained to numeric loopback, requires model-server key for inference/tokenization; no filesystem writers, shell, credentials or Windows automation imports |
| llama.cpp server | Separate ordinary-user process, `127.0.0.1`, authenticated protected routes; no tools/agent/MCP; no independent OS-action privileges |
| `model_runtime` supervisor | Verifies manifest and files, launches an exact configured executable with fixed arguments and `shell=False`, starts one server, no automatic restart; Windows Job Object containment is generated but needs target Windows validation |
| Mock tool registry | In-memory deterministic synthetic handlers only; proposals are validated but never dispatched from chat |
| `PolicyBroker` | Continues to deny every real OS action, independent of model output |

The llama.cpp server exposes an upstream minimal `/health` endpoint without API-key authentication. It is loopback-only and contains no paths or secrets. Chat and tokenization routes require a random in-memory API key passed via child environment, never command-line arguments. Loopback is not treated as authentication: backend routes separately require a bearer token. The local API token is generated at developer-server startup and displayed once in the interactive terminal, not logged or stored in the repository.

## Trust hierarchy and untrusted content

- The user is the sole authorizing principal for future consequential actions; Phase 1 does not implement approvals or actions.
- Trusted system guidance is assembled separately from user content. Only server-created user/assistant history is accepted. External evidence, if provided internally for tests, is explicitly labelled `UNTRUSTED_SOURCE`.
- Labels, system prompts, constrained JSON and Pydantic validation are not security boundaries by themselves. Security derives from module separation, authenticated loopback transport, deterministic registry validation and the deny-all real-OS broker.
- No real world-state, memory, browser, file or Windows context is available. The implementation says so rather than inventing observations.
- A local logged-in user with Windows-level access can inspect or modify same-user processes/files; AETHER does not claim to defeat a compromised local account.

## Phase 1 network and process policy

- The FastAPI developer launcher binds to `127.0.0.1`; middleware rejects non-loopback peers. Non-allowlisted `Origin` values are rejected as a request boundary. No CORS middleware or CORS response headers are present; browser-based cross-origin clients are not supported.
- The gateway accepts only numeric loopback HTTP URLs and disables ambient proxy configuration. No cloud model/provider classes or fallback exist.
- The model server binds only to `127.0.0.1` on a configurable port distinct from backend port 9931. Its protected routes use an ephemeral API key. The model server health route is public but minimal and loopback-restricted.
- Supervisor passes no user/model-generated CLI flags, does not invoke a shell, removes inherited proxy/model-hub credentials and `LLAMA_ARG_*` overrides, and sets model-hub offline mode. Built-in tools, agent and MCP proxy options are explicitly disabled.
- A model can suggest `request_tool` or `offer_rsi`; these are typed proposals only. Unknown tool IDs, invalid mock arguments and malformed structures are rejected. No output runs a command or changes policy.
- The offline unit tests constrain code paths and mock transports; they do not prove Windows firewall-level egress policy.

## Existing broader-phase risks

## Phase 2A security foundation (not executable)

The current feature branch adds `ResourceRegistry`, typed capability contracts, a configured deterministic policy path and exact approval grant contracts; details, limitations and target-Windows validation guidance are in `docs/engineering/PHASE2A_RESOURCE_POLICY.md`. This code is not yet reviewed or merged. The no-argument broker still denies all, built-in filesystem capabilities have no executor, T2 is denied because no trusted approval issuer exists, and T3 is always denied. A client-supplied approval ID or the contract's `trusted-electron` label is never authorization. No filesystem API/action or mutation surface is exposed by Phase 2A.

The resource resolver rejects unsupported path syntax, registered-root escape, protected names, reparse points and volume/device identity changes. Its stat-derived version token is only a freshness indicator, not a content hash or a protection against post-check races. These broker-side checks are not an OS sandbox. No target Windows execution has been performed here, so Windows path/reparse/volume safety remains unverified. PR 2B must operationalize trusted persistent Electron approvals; PR 2C may add only verified read-only adapters; PR 2D may add only exact approved mutations and recovery after 2B/Windows security tests pass. RSI disclosure, script-worker isolation and unrelated higher-phase capabilities remain outside this milestone.
