# AETHER OS — Implementation Status

**What exists and what has actually been verified.** The authoritative future architecture remains `docs/architecture/MASTER_SPEC.md`; this file distinguishes source changes from local and hardware verification.

## Current phase

**Phase 2B-1 — durable persistence (PR #7 merged; approved Windows hotfix PR #8 open for independent review).** Phase 2B-2 trusted Electron integration is not started. All Phase 2A filesystem capabilities remain non-executable; no T2 grant issuer, executor, Phase 2C/2D work, or response-quality work is included. Phase 1 model-asset/build gates and target-hardware checks remain unresolved in this sandbox. User-reported Windows checks are recorded separately and are not independently verified here.

## Phase 0 baseline

- Phase 0 repository, contracts, deny-by-default policy, fakes, docs and manual-only Windows CI are merged in `main`.
- The user reports target Windows acceptance: 43 tests passed and the backend health endpoint succeeded. This browser-based environment cannot independently inspect the target laptop. The original Phase 0 status recorded Python 3.12/PowerShell checks as pending before that user report.

## Phase 1 implementation inventory (merged through PR #4)

- `backend/aether/model_gateway/`: replaceable gateway protocol/errors, local llama.cpp HTTP transport, schema-constrained generation, tokenization, protected readiness check, one-generation semaphore, token/time metrics, model capability discovery. No remote gateway or image generation is exposed.
- `backend/aether/model_runtime/`: manifest parsing, strict local path and file-inventory checks, streaming SHA-256/size validation for model assets and the configured llama-server executable, version/build gate, direct-child process supervisor with fixed arguments and manifest ID passed as `--alias`, loopback port preflight, authenticated tokenizer readiness using the fresh child API key, no proxy/HF token/`LLAMA_ARG_*` inheritance, offline hub mode, cancellation cleanup, no restart loop, shutdown and Windows Job Object source. Concrete runtime checksum/build values remain unverified and are not fabricated.
- `backend/aether/core/contracts/`: typed chat request/response, decision/proposal and model-manifest/readiness contracts. Manifest requires immutable 40-hex source/conversion revisions, asset hashes/sizes, runtime build ID and safe relative install path.
- `backend/aether/api/`: authenticated `GET /v1/health`, typed `POST /v1/chat/turns`, per-start bearer session, numeric loopback peer check, reject-only exact loopback Origin policy, request bounds, sanitized errors/logs, and runtime-process-aware readiness. No CORS middleware/headers or browser-based cross-origin support are provided. Built-in docs/OpenAPI are disabled in this local development surface.
- `backend/aether/context/`: fixed trusted guidance, bounded server-managed conversation context, token counter with conservative fallback, explicit truncation, no invented world state/memory, and untrusted evidence labels.
- `backend/aether/core/chat_service.py`: typed decision parsing, exactly one bounded repair, registered mock schema validation, IDs, bounded in-memory task/conversation records, no model-triggered tool execution, no cloud fallback.
- `backend/aether/core/tasks/` and `core/tools/`: deterministic Phase 1 state transitions (execution/verification states cannot be entered), synthetic mock registry, no-argument `PolicyBroker` denies all real OS actions, and Phase 2A registered contracts also deny until an executor and trusted approval flow exist. Stale `AWAITING_APPROVAL` mock proposals expire to `CANCELLED` after one hour and become reclaimable; capacity exhaustion is a typed 503. `propose_plan` and `offer_rsi` are completed discussion-only text turns, not approval flows.
- `backend/aether/benchmarks/`: synthetic benchmark runner and redacted JSON report; reports require a configured separate directory. It leaves unavailable metrics null and does not infer TTFT from full-response latency.
- `scripts/configure_dev_storage.ps1`: derives uv cache (`.cache/uv`), uv's default project-local environment (`backend/.venv`) and model root (`models/`) from this clone, placing them on the clone’s drive. Cache/model variables are process-scoped; it does not set or persist `UV_PROJECT_ENVIRONMENT` at User scope, avoiding unrelated-project effects.
- `scripts/run_backend.ps1`, expanded exit-checked `scripts/verify.ps1`, manual-only Windows CI, model manifest schema and Phase 1 setup/install/benchmark/Windows runbooks.
- Removed the untracked synthetic `backend/manifest.json`; `models/manifests/` contains the generated schema only, with no selected production model/runtime manifest.
- No model weights, llama.cpp executable, network inference, real OS action, Phase 2 executor or cloud provider was downloaded or introduced.

## Phase 2A implementation in the baseline (PR #5 and hotfix PR #6 merged)

- Added explicit trusted-directory registration, Windows-aware relative path rejection, canonical broker-issued resource IDs, protected-path checks, reparse/symlink checks, fixed-volume/device identity enforcement and version-drift revalidation in `backend/aether/core/resources/`.
- Added strict typed capability schemas, explicit T0–T3 metadata, unknown-operation denial and exact scoped resource checks. T3 always denies; all built-in filesystem capability contracts are non-executable; T2 mutation is denied pending a real trusted approval channel. The no-registry broker preserves Phase 0/1 deny-all behavior.
- Added versioned exact task/plan/step/capability/arguments/effect/resource-version grant contracts with immutable tuple-based operation/resource collections and deterministic matching foundations. `ExactApprovalGrant` is the intended authoritative Phase 2B persistence contract; the legacy Phase 0 `ApprovalGrant` is not Phase 2 authorization. No trusted issuer, durable store, Electron IPC approval, bearer-token privilege, mutation endpoint or executor is implemented.
- Windows reserved-name checks include superscript COM/LPT digits and `CONIN$`/`CONOUT$`. Case-folded resource-ID collisions between different physical entries at different canonical relative paths fail closed; atomic replacement at the same path refreshes the mapping/version and makes older references stale. `fs.inspect_file` means metadata-only (no file bytes), hence T0.
- Added synthetic adversarial tests for lexical traversal/Windows device names, sibling-prefix escape, symlink escape, unknown roots/volumes, secret paths, stale/forged references, atomic `os.replace()` refresh/stale-ref denial, case-collision preservation, unknown capabilities, immutable approval operation/resource collections, exact approval drift, replay/expiry/revocation and T3/T2 deny.
- `scripts/verify.ps1` runs pytest with `--basetemp` under ignored `<repo>/.cache/pytest-tmp` on the D: checkout, keeping synthetic `tmp_path` roots outside protected `%LOCALAPPDATA%` while leaving protected-path rules unchanged.
- Security boundaries, limitations and exact Windows validation checklist are in `docs/engineering/PHASE2A_RESOURCE_POLICY.md` and `docs/security/TRUST_BOUNDARIES.md`. No new ADR was needed; existing deny-all architecture remains unchanged.
- This is broker-side protection, not a sandbox; stat-derived version tokens do not eliminate TOCTOU. The user reports Windows 11 validation after PR #6, but the NTFS case-sensitive fixture and symlink test were skipped/blocked and junction/reparse, volume-boundary, and root-replacement validation remain pending. Arena has not independently verified Windows security acceptance.

## Phase 2B-1 implementation (PR #7 merged; hotfix PR #8 open, Windows validation pending)

- Added versioned SQLite migration and `SQLiteTaskStore` for persistent task state, immutable canonical plan revisions and normalized steps, append-only audit events, and immutable approval-decision audit records.
- Task/plan/step schemas use the Master Specification state vocabulary and typed dependency DAG, resource versions, expected state/effect, risk, retry/idempotency, postcondition, and recovery metadata. Explicit state adapters preserve the Phase 1 `TaskState` contract and reject states that cannot be mapped.
- Startup verifies exact packaged migration-byte checksums and a code-pinned schema fingerprint, checks SQLite/foreign-key integrity, rejects missing/changed/future schema state, and pauses in-flight work only after acquiring the single-owner lock. POSIX locks the database inode directly, so replacing the historical `.owner.lock` pathname cannot give a second process authority; Windows retains the one-byte `msvcrt.locking` sidecar and its pathname-replacement/open-file semantics still require target-machine verification. A second live store fails closed; OS lock release permits crash recovery. Fresh planning/consent is required after restart.
- Database paths are absolute, component-checked for symlink/junction/reparse, hardlink, unsafe Windows names, fixed-volume changes, and parent identity substitutions. The intended LocalAppData-shaped location is not blocked by Phase 2A protected-user-file policy.
- Audit metadata is allow-listed and plan/user-goal redaction is conservative. SQL plan/step/event/approval-audit records are immutable/append-only. Approval decisions are non-authorizing; no trusted-root rehydration, grant loader/issuer, action consumption, executor, or filesystem mutation route exists.
- POSIX database permissions are owner-only; the POSIX lock is the database inode. Windows ACL, junction/reparse, actual `msvcrt` contention, and `.owner.lock` pathname replacement behavior remain target-laptop verification requirements.
- Hotfix findings: Windows strict-mypy portability is covered with POSIX-only APIs dynamically resolved; database input spelling is rejected before `pathlib` normalization; deterministic parent-identity drift is tested on every host. Native rename of an open SQLite parent returned WinError 5 on the reported Windows target, so the native substitution remains explicitly unverified if that test is skipped. Keep the two Windows-skipped symlink cases and their exact skip reasons in the validation register.
- Target Windows checklist remains open in `docs/engineering/PHASE2A_RESOURCE_POLICY.md`; no Windows security or desktop acceptance is inferred from Linux tests.

## Verified in this sandbox (Linux, Python 3.11 override)

- `uv sync --directory backend --python /usr/bin/python3.11 --all-extras --locked` — passed; dependencies remained locked.
- Hotfix Ruff lint and format checks passed; strict mypy passed for 56 source files on Linux and with `--platform win32` (type-target simulation only, not Windows execution).
- Persistence adversarial tests (`tests/test_phase2b_persistence.py`) — **53 passed**.
- Full pytest — **216 passed, 1 skipped**. The skip is optional model integration (`AETHER_RUN_MODEL_INTEGRATION=1` is not configured); the non-failing warning is Starlette/HTTPX deprecation. Existing Phase 0/1 regressions remain in the current suite.
- Linux parent-path tests passed: native substitution and deterministic identity drift. No Windows native parent-replacement behavior is inferred; WinError 5 and symlink skips remain in the target validation register.
- Built the backend wheel and confirmed its packaged migration bytes match pinned SHA-256 `709077298230c7065c6778b3149f93b679b6e678220e2d1a34d3540a348d741e`; migration SQL and schema pins were unchanged.
- Locked workflow import check and authenticated health `TestClient` check both passed (health returned HTTP 200).
- A Starlette `TestClient`/HTTPX deprecation warning remains non-failing; no actual Windows or model compatibility is inferred from it.
- Added exact checked-in JSON-schema drift enforcement; runtime executable checksum, startup cancellation/cleanup, port conflict, authenticated readiness, post-start process exit, task TTL/capacity and controlled API-health failure tests use synthetic bytes, fake processes, and `httpx.MockTransport`.
- FastAPI tests cover authenticated health/chat with fake gateways, sanitized health timeout and dead-child status, typed errors, prompt/context limits, no auto tool execution, mock-only behavior, non-loopback/origin rejection (without CORS support), and unavailable model status.
- No real external API, model, runtime executable or Windows process operation was contacted.

A Starlette deprecation warning remains in the test environment: its TestClient currently warns about the selected HTTPX transport. It does not fail tests; no actual Windows or model compatibility is inferred from it.

## Model source and configuration — pending, no fabricated metadata

Preferred candidate supplied by the user: `https://huggingface.co/ggml-org/Qwen3.5-4B-GGUF`, file `Qwen3.5-4B-Q4_K_M.gguf`. The exact immutable revisions, size, complete SHA-256, exact license, GGUF metadata, chat template, projector needs and compatible pinned Windows CUDA build remain unverified. This environment cannot access Hugging Face. The current runtime code is generic and consumes a manifest, but **no concrete Qwen manifest is present**, and startup will fail closed without one. No weights or runtime binaries were downloaded.

The official llama.cpp server README was inspected on GitHub for its HTTP API/authentication/tool flags and documents `--alias` as the model name used by REST APIs ([server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)). The supervisor now passes the manifest ID as that alias, but compatibility with the eventual pinned runtime is **not live-tested**. Exact compatible version/commit, executable SHA-256, Windows CUDA build metadata and model artifact facts remain **not pinned or verified**. Upstream `/health` is unauthenticated and loopback-restricted; readiness additionally requires the supervised child to remain alive and a bearer-authenticated tokenizer response using its fresh API key.

## Not yet verified (requires the target Windows laptop)

- `scripts/verify.ps1`, `scripts/configure_dev_storage.ps1`, and `scripts/run_backend.ps1` PowerShell execution.
- Python 3.12 on Windows (sandbox verification used 3.11 override).
- Windows Job Object struct/API behavior, interaction with Cursor’s process containment, process cleanup after backend crash, and orphan-free shutdown.
- Exact Qwen GGUF provenance/license/hash/size/template/projector facts; compatible pinned llama.cpp Windows CUDA build; no-download manual install procedure.
- RTX 4050 CUDA loading, GPU-layer sweep, VRAM/RAM, thermals, throughput, actual text/chat-template and structured JSON quality, process startup and V-01.
- Actual disconnected-network operation and firewall-level egress behavior.
- No benchmark was run here; no performance figure is claimed.

## Phase 1 acceptance status

**Phase 1 implementation ready for Windows foundation checks — not yet fully complete.** Model-specific manifest/install instructions and V-01 remain blocked on artifact/runtime verification; all actual model, CUDA, offline and hardware acceptance remains pending. The final sign-off criteria in the user directive are not yet met.

| Requirement | Status |
|---|---|
| Authenticated local chat API | Implemented; fake-gateway tests pass; target Windows API launch unverified |
| Model gateway/supervisor | Implemented generically; runtime flags/build unverified against selected artifact |
| Manifest/integrity enforcement | Implemented and tested on synthetic fixtures; no concrete Qwen manifest |
| Context/structured decision validation | Implemented; tests pass using fake gateway; model quality unverified |
| Deterministic task lifecycle | Implemented; execution transitions blocked; tests pass |
| Mock tools and deny-by-default OS policy | Implemented; synthetic-only; tests pass |
| Offline behavior | Code path constrained and mocked tests pass; real Windows offline test pending |
| Benchmark tooling | Implemented; not run against real model/hardware |
| Windows PowerShell / Python 3.12 | Pending user laptop execution |
| V-01 RTX 4050 benchmark | Pending verified assets and target laptop |

CI remains manual-only. Phase 2A is in the baseline after PR #5 and hotfix PR #6 were merged. PR #7 remains open with the requested persistence corrections submitted from `arena/6a6f42f3-a-e-t-h-e-r`; `main` has not been modified. Automated secret scanning remains pending.
