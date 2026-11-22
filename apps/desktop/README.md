# AETHER Desktop — Phase 2B-2 Stages 1–3

This is a deliberately minimal Electron + React + TypeScript + Vite + Tailwind foundation. Stage 1 demonstrates a synthetic authenticated parent/child control message. Stage 2 adds a dedicated non-authorizing approval-review presentation surface. **Stage 3 wires the authenticated channel to the trusted backend-hosted review service: the exact preview is delivered over the Stage 1 bootstrap/HMAC transport, verified byte-for-byte in the trusted main process before presentation and again before recording, and review outcomes are persisted as non-authorizing audit records. There is still no grant, authority, execution, persistence of user data, or filesystem capability anywhere in the desktop.** Existing Phase 2B-1 approval records remain `NON_AUTHORIZING_AUDIT_RECORD` and are unchanged; Stage 2 review outcomes are likewise non-authorizing audit evidence only.

## Pinned toolchain

Node/npm are pinned by `.nvmrc`, `packageManager`, strict `engines`, and `.npmrc`; direct dependencies are exact in `package.json` and transitive npm dependencies are captured in `package-lock.json` (lockfile v3):

- Electron **44.11.5** is the pinned runtime. Electron's bundled Node.js is **v24.22.3** ([Electron 44.11.5 `DEPS`](https://github.com/electron/electron/blob/v44.11.5/DEPS), `node_version`); this is distinct from the pinned external development CLI, Node.js **22.22.3** with npm **10.9.8**. Electron's [official support policy](https://github.com/electron/electron/blob/main/docs/tutorial/electron-timelines.md#version-support-policy) covers the latest three stable major versions; Electron 44 is within the supported release window as of the target review date. Recheck the Electron release schedule before each release.
- React / React DOM 19.2.0, TypeScript 5.9.3, PostCSS **8.5.33**, Vite **7.3.8**, Tailwind CSS 3.4.18.
- Linux parent/child protocol tests ran with Python 3.11.2. The app handshake intentionally accepts only the target runtime, Python **3.12.10**, which must be verified on Windows.

Install npm dependencies with `npm ci`. Electron 44's package lazily downloads its platform binary the first time its launcher is invoked; a successful `npm ci` alone does not establish that Electron can run. Invoke the Electron launcher or `npx install-electron` only where the verified Electron distribution endpoint is reachable. This sandbox installed the locked npm tree, but its Electron binary fetch failed, so no Electron runtime was launched here.

## Visual system baseline

The default desktop appearance is the Master Spec's light baseline; no dark-mode switch or dashboard is included in this Stage 1 shell. `src/style.css` defines these exact tokens:

| Token | Value |
|:--|:--|
| Background | `#F8FAFC` |
| Surface | `#FFFFFF` |
| Border | `#E2E8F0` |
| Primary accent | `#2563EB` |
| Secondary accent | `#6366F1` |
| Primary text | `#0F172A` |
| Secondary text | `#64748B` |
| Success | `#059669` |
| Warning | `#D97706` |
| Danger | `#DC2626` |

Status/result wording stays textual; color is only supplemental. The theme regression verifies the emitted production CSS retains every token, tests WCAG AA normal-text contrast for primary/secondary text and the primary button label, checks at least 3:1 contrast for semantic status markers, and verifies visible keyboard focus, a narrow-screen layout, and accessible status announcements.

## Commands

From this directory:

```text
npm ci
npm run lint
npm run typecheck
npm test
python -m unittest discover -s tests -p "test_*.py" -v
npm run build
npm run check
```

`npm run check` runs ESLint, TypeScript checks, Python child unit tests, `npm test` (which first builds the actual Vite renderer and then runs Node unit, Node/Python pipe-integration, generated-asset, light-theme and lifecycle-race tests), and Electron main/preload compilation. The lifecycle regressions cover stop during handshake, failed startup, stale child events, repeated shutdown, request rejection, fresh-session sequence reset, and waiting for graceful/forced child exit. Python tests exercise the actual child script with real stdin/stdout/stderr pipes. Existing FastAPI bearer-token, Origin and loopback protections are unchanged; Stage 1 adds no HTTP endpoint. These Linux checks do **not** establish Windows acceptance. `npm start` builds and starts Electron. For a development run, set `AETHER_DEV_PYTHON` to an absolute Python executable path before `npm start`, for example a local Python 3.12 venv's executable; the value selects the parent-side executable and is not forwarded to the child environment. The child service imports the backend package, so that interpreter must be able to import `aether.channel.service` (dependencies installed); `PYTHONPATH` is set to the backend source automatically. The hello-frame Python version is pinned to 3.12.10 by default — if your development interpreter reports a different version (for example 3.11 on Linux), set `AETHER_DEV_PYTHON_VERSION` to its exact version (e.g. `3.11.2`); it is honored in development builds only and never in packaged ones. For local end-to-end review evidence without manufacturing user data, set `AETHER_REVIEW_DB` (absolute path in a development location) and `AETHER_REVIEW_DEV_SEED=synthetic-review` before `npm start`; the built-in synthetic scenario is created in that development database and the review surface then presents it. Without these, the review surface reports unavailable by design. Production expects the bundled runtime at `resources/backend/python[.exe]`.

`npm run dev` starts only the unprivileged Vite renderer development server on loopback; it does not create an Electron window or expose a backend channel.

## Trust boundaries and channel

- Electron main creates the only application window with `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, `webSecurity: true`, no webview and no insecure content. The renderer is local built content; navigation and new windows are denied unless they are the exact loaded local file. A restrictive CSP is present as both a meta policy and response header. No remote/privileged content is loaded.
- Preload exposes exactly four promise-returning calls (`getBackendStatus`, `demoPing`, `getApprovalReview`, `recordReviewOutcome`) using fixed IPC channel names. Main validates the exact `WebContents`, main frame, local file URL, live window, and focused/active window on each invocation. No generic send/invoke API is exposed. `recordReviewOutcome` arguments are re-parsed and bounded in main before reaching the provider; the provider is interface-bound, replaceable, and fail-closed by default.
- Main launches one fixed Python script with fixed `-I -S -B -u` arguments, an absolute runtime executable, explicit script working directory, `shell: false`, and only a small environment allowlist. Child stdin carries bootstrap/channel frames; stdout is exclusively framed protocol; stderr is a separate pipe and discarded. On Windows, Node's `stdio: ['pipe','pipe','pipe']` creates anonymous child-process pipes: the backend receives stdin's read handle and stdout/stderr write handles; the parent retains the reciprocal endpoints. Python uses binary standard streams, and no other application handles are intentionally passed. Exact Electron/Node/Python handle-inheritance behavior remains a Windows gate. No key or session material is put in argv, child environment, logs, or renderer state.
- For every launch, main creates a 256-bit random HMAC key, 128-bit session identifier and 256-bit challenge. It writes a fixed-size bootstrap to the child's private stdin pipe. The child proves possession of that key and challenge in a signed startup hello over stdout before main declares the channel ready. This one-way bootstrap is not itself a general-purpose framed application message.
- Application frames use a 4-byte big-endian length and bounded (64 KiB) canonical UTF-8 JSON envelope with protocol version, session, direction, monotonic per-direction sequence, cryptographic nonce, timestamp, request ID, kind, payload and HMAC-SHA-256. Both sides reject bad MAC, wrong direction/session, stale timestamps, replay/out-of-order sequence, duplicate request IDs/nonces, malformed/oversized frames and unsupported message kinds. The protocol permits the synthetic ping/pong and the two narrow typed review operations described below; no generic privileged operation exists.
- Each child has an isolated session object containing its handshake, decoder, request map, send chain, sequence, key and exit completion. Every stdout/stderr/exit/error/close callback captures that child/session and checks it is still the active generation before changing client state. A stale event can only settle its own retired-process completion. `stop()` rejects a pending handshake and all requests, clears secrets/timers, closes stdin, waits 1.5 seconds, then kills and waits for the actual process exit. Concurrent stops share one promise; failed children are tracked until exit; a fresh start waits for prior retirements and creates a new key/session and fresh sequence/send chain. No automatic restart is attempted. If Electron itself is terminated abruptly, Windows handle closure/child EOF is expected to stop the child; verify this on the target Windows build.
- HMAC is message integrity/authentication, not a boundary against a compromised parent/child or a hostile process with same-user process-memory/handle access. The pipe's local handle inheritance and launch relationship are part of the trust assumptions.

## Stage 2 — non-authorizing approval review

Stage 2 (in review on branch `arena/ac46d51a-a-e-t-h-e-r`) adds the trusted-review presentation path only:

- `shared/review.ts`: strict shared types/parsers for the canonical `ExactPreview` (authority pinned to `REVIEW_EVIDENCE_ONLY`), `ReviewOutcomeRequest` (no authority field; carries `reviewRequestId`, task/plan identity, digest, outcome and the full-diff acknowledgement flag) and `ReviewAcknowledgement` (`NON_AUTHORIZING_AUDIT_RECORD`, `granted: false`, `executionAvailable: false`). Parsers reject authority confusion, extra fields, control characters, secret-like text, absolute paths, non-canonical ordering/JSON and mismatched risk/recovery metadata.
- `electron/review.ts`: `TrustedReviewProvider` interface and a fail-closed default (`createFailClosedReviewProvider`) that reports the review as unavailable, cannot render a preview, cannot record an outcome, and cannot grant anything. `electron/channel-review-provider.ts` implements the interface over the authenticated channel; when the backend is not ready, no trusted task is configured, or any verification fails, every control degrades to the same unavailable state.
- `src/ApprovalReviewSurface.tsx`: accessible review-evidence UI — exact-preview sections (intent, why/how, preconditions, exact resource scope with expected versions, expected state/effect digests, risk classification, recovery class, verification strategy, external effects), full-diff inspection with an explicit "I inspected this exact full diff" acknowledgement, Approve/Revise/Reject/Cancel controls, and explicit wording that approval is not authorization and no grant/execution path exists. **Only Approve requires the diff acknowledgement**; Revise, Reject and Cancel stay enabled so a proposal can be refused without inspecting or accepting it (mirrored backend rule). If the provider is unavailable, the surface fails closed.
- `shared/review-integrity.ts` (Node-only; imported by the trusted main-process provider and tests — **never the renderer**): recomputes the Python canonical digest payload, SHA-256 digest, preview ID (uuid5) and review request ID (uuid5) from a parsed preview and compares them to the supplied identity values. The renderer is never treated as the verification or approval authority; its parsers are hygiene, not verification.
- `tests/fixtures/stage2-exact-preview.golden.json` + `tests/stage2-integrity.test.ts` + `backend/tests/test_phase2b_stage2_golden.py` + `scripts/generate_stage2_golden.py`: checked-in Python-generated golden fixture pinning the complete Python-to-Electron preview representation. The fixture holds the camelCase renderer contract, the exact `digest_payload_canonical_json` bytes Python digests, the digest, and both uuid5 identities. The backend test re-derives the fixture from the code and fails on drift; the Node test recomputes the payload/digest/IDs byte-for-byte. Regenerate with `python3 scripts/generate_stage2_golden.py` only after intentional backend changes, and commit fixture + generator together.
- Two new narrow IPC channels (`desktop:review-preview`, `desktop:record-review-outcome`) behind the same sender/frame/file-URL/live-focus validation as the Stage 1 channels. No new privilege, host, or filesystem reach.
- Non-goals preserved: no `ExactApprovalGrant` issuance/storage/consumption, no T2/T3 capability, no filesystem access, no Phase 2C/2D, no Phase 3.

**Digest verification ownership (implemented Stage 3 behavior):** the trusted main-process provider (`electron/channel-review-provider.ts`) over the authenticated channel re-parses the wire payloads, then (1) verifies `verifyExactPreviewDigest(preview)`, `previewIdForDigest` and `reviewRequestIdForDigest` against the backend-supplied values **before returning a preview to the renderer**, checks the delivered `taskId` against the trusted main-process-configured task, and (2) re-fetches and re-verifies the current persisted preview in `recordOutcome`, requiring the submitted request to match it field-for-field before anything is sent, and validates the acknowledgement (schema, `requestedOutcome` match, non-granting semantics) before any success is shown. Any failure — offline channel, unconfigured or mismatched task, digest/identity mismatch, malformed payload, oversized preview (`preview_too_large`), drift between presentation and recording — fails closed; no success receipt is produced. The renderer must never be the authority; it renders exactly what main returned. There is no code path in this build that bypasses this verification.

Stage 2 adds **15** Node tests (parsers, cross-resource/diff rejection, risk drift, renderer-facing forged-payload rejection, fail-closed provider, channel wiring, S2-1 outcome policy, digest integrity vs. the Python golden fixture, renderer-never-imports-verifier guard). No Windows run of Stage 2 has been performed; the Windows Stage 1 procedure below still applies before any Windows claim is made.

## Stage 3 — authenticated exact-preview delivery over the channel

Stage 3 (in review on branch `arena/bff0ea7b-a-e-t-h-e-r`) wires the review surface to the real trusted backend over the authenticated channel. It is delivery and audit transport only; it grants nothing.

- Backend: `backend/aether/channel/service.py` (`python -m aether.channel.service`) serves the Stage 1 bootstrap/hello plus exactly two narrow, typed operations — `review.get_preview` and `review.record_outcome` — backed by the real persisted task/plan store through `aether.channel.review_bridge.ReviewBridge`. All payload validation lives in the bridge's defensive entry points: malformed, unknown, extra-keyed, oversized or replay-conflicted requests return bounded typed failures (`review_unavailable`, `invalid_review_request`, `review_conflict`, `preview_too_large`); unknown kinds terminate the session; the service never issues or implies an `ExactApprovalGrant`. `backend/aether/channel/dev_seed.py` (activated only by `AETHER_REVIEW_DEV_SEED=synthetic-review`) creates one fixed synthetic reviewable scenario in a development database for end-to-end evidence; packaged builds never set it, and it writes only audit rows, never user files.
- Client: `electron/backend-client.ts` gains `reviewGetPreview(taskId)` (UUID-checked) and `reviewRecordOutcome(request)` over the same authenticated pending-request/timeout path as the ping, with per-request expected kinds enforced in `handleFrame` (`demo.pong` | `review.preview`, `review.outcome` | `review.error`). A `review.error` frame rejects with a typed `ReviewChannelError` carrying a bounded machine-readable reason; anything else (wrong kind, missing pending entry) is a protocol violation and tears the session down. No new IPC privilege is added: the only renderer-facing calls remain the four fixed preload functions with main-process sender/frame/focus validation.
- Trusted provider: `electron/channel-review-provider.ts` implements `TrustedReviewProvider` with the full Stage 2 digest verification (see "Digest verification ownership" above), plus a trusted, main-process-configured review task id (`AETHER_REVIEW_TASK_ID` in development; the fixed synthetic id when `AETHER_REVIEW_DEV_SEED=synthetic-review`; unset in packaged builds — the renderer can never choose or influence it). It re-fetches and re-verifies the persisted preview immediately before recording and refuses drift field-for-field.
- Launch wiring: main launches the service with `PYTHONPATH` set to the backend source (development) or the bundled backend directory (packaged, future), and forwards only absolute-path development review configuration (`AETHER_REVIEW_DB`, `AETHER_REVIEW_NARRATIVE`, `AETHER_REVIEW_DEV_SEED`). The hello-frame Python version assertion is now per-session and overridable only via `AETHER_DEV_PYTHON_VERSION` in development; the win32 pin to 3.12.10 remains in the tests.
- Verification on Linux: backend — Ruff, strict mypy (62 files), full pytest **266 passed, 1 skipped** (optional model integration); Stage 3 adds 16 tests (`backend/tests/test_phase2b_stage3.py`) covering subprocess wire behavior (exact preview round trip, approve-with-diff-ack, reject, stale revision, malformed/unknown/extra-keyed requests, 64 KiB frame-bound `preview_too_large` fallback, unavailable-without-config) and in-process bridge semantics. Desktop — `npm run check` passes: lint, both TypeScript projects, **44/44 Node tests** (12 Stage 3 trusted-provider unit tests incl. forged digest/identity/task/ack rejection and drift refusal, plus 3 live-channel integration tests spawning the real `aether.channel.service` against a development database — digest verified in TypeScript against the Python canonical bytes, idempotent replay confirmed, missing-database fail-closed) and **6/6 Python child tests**. The integration tests need a Python with backend dependencies importable; set `AETHER_DEV_PYTHON` (or use a repo-local `backend/.venv`), otherwise they skip explicitly. No Windows run of Stage 3 has been performed; the Windows Stage 1 procedure below still applies before any Windows claim is made.
- Requirements → evidence map: authenticated delivery → `pipe.integration.test.ts`/`stage3-review-channel.test.ts` (real bootstrap + HMAC round trips); Python canonical digest verified in the trusted provider → `stage3-review-provider.test.ts`, `review-integrity.test.ts`, live integration assertions; non-authorizing persistence → backend Stage 2/3 suites and acknowledgement assertions (`granted:false`, `executionAvailable:false`, `NON_AUTHORIZING_AUDIT_RECORD`); drift-before-record refusal → provider unit tests; oversized-preview fail-closed → backend `preview_too_large` test + `parseReviewGetResponse` handling; no new privilege → IPC surface unchanged (four fixed preload calls), `channel-review-provider.ts` never imported by the renderer; replay idempotence → backend replay tests + integration replay assertion.
- **Not implemented by design:** no grant issuance/storage/consumption, no T2/T3 capability, no filesystem adapter, no user-file mutation, no automatic planner, no production schema migration, no Phase 2C/2D or Phase 3 work. The `AETHER_REVIEW_*` development seams exist only for local end-to-end evidence; packaged builds ignore them. A production review narrative source (the future Phase 2 planner) and production packaging of the backend remain future, separately reviewed work.

## Stage 1 closeout evidence ledger

### Completed in this Linux workspace

- `npm ci` completed from the committed lockfile; `npm audit` reports zero vulnerabilities and `npm ls --all` reports no dependency problems.
- `npm run check` passes lint, renderer/Electron typechecks and compilation, production renderer asset regression, light-theme regression, **14/14 Node tests**, and **6/6 Python child tests** (no skips). Node coverage includes authenticated Node–Python ping/cleanup and IPC trust positive/negative cases.
- The light-theme test checks all specified tokens in production CSS, text/button contrast thresholds, responsive styling, keyboard focus, and accessible textual status.

### Windows results reported by the user (not independently reproduced here)

For the pre-light-theme PR state, the user reports Windows 11 results of 13/13 Node tests, 6/6 Python tests, zero npm audit findings, successful real Electron GUI launch and authenticated synthetic ping, and one normal plus one controlled forced termination with no AETHER Python children remaining. These are useful reported results, not an independent Windows run by this workspace; they do not cover the new light-theme regression.

### Still unverified / future phase gates

- Secret non-disclosure across actual Windows process command lines, child environment, logs, and renderer-visible state has not been fully verified. Repeatable abnormal-termination cleanup across multiple fault points/runs also remains outstanding; one controlled forced-termination pass is not a repeatability gate.
- The latest light theme, its generated CSS, and the new theme regression have only been checked on Linux. Re-run the complete `npm ci` / `npm run check` sequence on Windows and launch the actual Electron 44.11.5 app before treating the visual correction as Windows-verified.
- Preserve these Windows filesystem gaps for their applicable future file/approval phase gates: verify production data-directory ACLs at creation; symlink tests were blocked by WinError 1314; NTFS case-sensitive sibling identity and native cross-volume traversal are unverified; native open-database parent replacement was denied by Windows; sidecar rename denial applies only to the tested handle configuration. No filesystem capability is authorized by this Stage 1 work.

Electron's platform binary fetch failed in this Linux sandbox, so its GUI was not launched here. Source compilation does not establish Electron runtime startup or Windows acceptance. The following procedure supplements the user's reported Windows checks; record only pass/fail counts and never actual session-secret values.

### Exact Windows 11 verification procedure (Python 3.12.10)

Use a clean Windows 11 x64 test account and a fresh checkout. Install Node.js 22.22.3, npm 10.9.8, and CPython 3.12.10 x64; verify with `node --version`, `npm --version`, and `py -3.12 --version` (must report 3.12.10). Create an isolated venv and install dependencies:

```powershell
cd apps\desktop
py -3.12 -m venv .venv
$python = (Resolve-Path .\.venv\Scripts\python.exe).Path
& $python --version
& .\.venv\Scripts\Activate.ps1
$env:AETHER_DEV_PYTHON = $python
npm ci
npm run check
& $python -m unittest discover -s tests -p "test_*.py" -v
npm start
```

Use a disposable Windows account and non-sensitive test profile. Record OS build, architecture, external Node/npm/Python versions, and Electron's `process.versions.node` separately; capture only test outcomes and non-secret runtime versions. Confirm `npm test`'s generated-file regression passes, then launch Electron and confirm `BrowserWindow.loadFile()` renders the built UI without missing `file://` assets or CSP/navigation errors. Verify the UI reports `ready: Authenticated synthetic channel ready`, send **Send synthetic ping**, and confirm the synthetic-only result.

Use Process Explorer (or an equivalent signed local inspection tool) to inspect the AETHER parent/child tree. In memory, verify the child's executable, fixed `-I -S -B -u` arguments, backend script, working directory, and stdin/stdout/stderr pipe handles against the launch policy. Inspect the child Environment tab against the explicit environment allowlist. Do not export environment blocks, copy raw command lines into logs, or capture screenshots of those panes. Do not record pipe contents; stdout carries protocol data and must remain private to the process channel.

For exact-value non-disclosure checks, use only a disposable, untracked test harness that observes generated key/session/challenge values in volatile memory at creation. Have it compare those values (and their defined encodings) against in-memory copies of the child's command line/environment, captured application logs, and renderer-visible DOM/window/storage state. Obtain renderer state through a test-only in-process inspection call; do not add a production IPC method or expose values through DevTools. The observer must report only surface names, match counts, and pass/fail; it must never print, serialize, hash, screenshot, or persist secret values or raw scanned surfaces. Zero its buffers in a `finally` block and terminate the harness after each run. Keep the observer out of the shipped build. Confirm the renderer exposes only the intended status/ping text and no unexpected global, storage, or diagnostic entries.

Run the Windows child transport/security tests above: require the test suite to pass authenticated handshake and synthetic ping; reject malformed and oversized frames, bad MAC, wrong direction, stale session, stale timestamp, replayed sequence/nonce and duplicate request ID; close stdin and prove graceful child exit. For additional runtime-failure checks, use a test-only harness outside the shipped renderer to terminate the child unexpectedly, close stdout, send a truncated frame, and send an invalid-MAC frame. Confirm main changes to `offline`, pending ping rejects, no synthetic success is displayed, child is terminated/reaped, and restarting the desktop makes a fresh authenticated session rather than accepting old frames.

For cleanup repeatability, run at least 10 fresh trials per condition in the disposable profile: normal desktop close, child crash/pipe closure, and forced Electron-main termination from a separate controller. Include malformed/truncated-frame and bad-MAC failure tests. After each trial, poll for up to 5 seconds for Python processes matching both the isolated runtime executable and the exact AETHER child script; require zero matches before proceeding. The controller may retain PIDs and pass/fail counts, but must not print or persist raw environment, logs, pipe data, or session-secret values. Report only aggregate runs/passes/failures and any remaining matching-child count. A failure blocks acceptance and requires a reviewed transport/lifecycle correction; do not substitute environment variables, command-line secrets, or an unauthenticated localhost service.

**Windows results currently reported by the user cover one normal and one controlled forced-termination trial only.** The repeated fault matrix and secret-hygiene procedure above remain to be completed and independently reviewed. Do not claim complete Windows security acceptance or enable approval authority, grant issuance, filesystem execution, Phase 2C, or Phase 2D based on the current Stage 1 scaffold.
