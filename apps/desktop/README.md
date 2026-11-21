# AETHER Desktop — Phase 2B-2 Stage 1

This is a deliberately minimal Electron + React + TypeScript + Vite + Tailwind foundation. It demonstrates a synthetic authenticated parent/child control message only. **There is no approval submission, authority, grant, persistence, or filesystem capability.** Existing Phase 2B-1 approval records remain `NON_AUTHORIZING_AUDIT_RECORD` and are unchanged.

## Pinned toolchain

Node/npm are pinned by `.nvmrc`, `packageManager`, strict `engines`, and `.npmrc`; direct dependencies are exact in `package.json` and transitive npm dependencies are captured in `package-lock.json` (lockfile v3):

- Electron 39.2.3; Node.js 22.22.3 is the pinned development CLI. Electron uses its bundled Node runtime; record its actual version during the Windows gate.
- React / React DOM 19.2.0, TypeScript 5.9.3, Vite 7.2.2, Tailwind CSS 3.4.18.
- Linux parent/child protocol tests ran with Python 3.11.2. The app handshake intentionally accepts only the target runtime, Python **3.12.10**, which must be verified on Windows.

Install with `npm ci`. Electron's postinstall downloads its platform binary; use the normal verified Electron distribution setup in environments where that download is available. `npm install --ignore-scripts` is only useful for static checking and does not install a runnable Electron binary.

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

`npm run check` runs ESLint, TypeScript checks, Python child unit tests, `npm test` (which first builds the actual Vite renderer and then runs Node unit, Node/Python pipe-integration, generated-asset and lifecycle-race tests), and Electron main/preload compilation. The lifecycle regressions cover stop during handshake, failed startup, stale child events, repeated shutdown, request rejection, fresh-session sequence reset, and waiting for graceful/forced child exit. Python tests exercise the actual child script with real stdin/stdout/stderr pipes. Existing FastAPI bearer-token, Origin and loopback protections are unchanged; Stage 1 adds no HTTP endpoint. These Linux checks do **not** establish Windows acceptance. `npm start` builds and starts Electron. For a development run, set `AETHER_DEV_PYTHON` to an absolute Python executable path before `npm start`, for example a local Python 3.12 venv's executable; the value selects the parent-side executable and is not forwarded to the child environment. Production expects the bundled runtime at `resources/backend/python[.exe]`.

`npm run dev` starts only the unprivileged Vite renderer development server on loopback; it does not create an Electron window or expose a backend channel.

## Trust boundaries and channel

- Electron main creates the only application window with `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, `webSecurity: true`, no webview and no insecure content. The renderer is local built content; navigation and new windows are denied unless they are the exact loaded local file. A restrictive CSP is present as both a meta policy and response header. No remote/privileged content is loaded.
- Preload exposes exactly two promise-returning calls (`getBackendStatus`, `demoPing`) using fixed IPC channel names. Main validates the exact `WebContents`, main frame, local file URL, live window, and focused/active window on each invocation. No generic send/invoke API is exposed.
- Main launches one fixed Python script with fixed `-I -S -B -u` arguments, an absolute runtime executable, explicit script working directory, `shell: false`, and only a small environment allowlist. Child stdin carries bootstrap/channel frames; stdout is exclusively framed protocol; stderr is a separate pipe and discarded. On Windows, Node's `stdio: ['pipe','pipe','pipe']` creates anonymous child-process pipes: the backend receives stdin's read handle and stdout/stderr write handles; the parent retains the reciprocal endpoints. Python uses binary standard streams, and no other application handles are intentionally passed. Exact Electron/Node/Python handle-inheritance behavior remains a Windows gate. No key or session material is put in argv, child environment, logs, or renderer state.
- For every launch, main creates a 256-bit random HMAC key, 128-bit session identifier and 256-bit challenge. It writes a fixed-size bootstrap to the child's private stdin pipe. The child proves possession of that key and challenge in a signed startup hello over stdout before main declares the channel ready. This one-way bootstrap is not itself a general-purpose framed application message.
- Application frames use a 4-byte big-endian length and bounded (64 KiB) canonical UTF-8 JSON envelope with protocol version, session, direction, monotonic per-direction sequence, cryptographic nonce, timestamp, request ID, kind, payload and HMAC-SHA-256. Both sides reject bad MAC, wrong direction/session, stale timestamps, replay/out-of-order sequence, duplicate request IDs/nonces, malformed/oversized frames and unsupported message kinds. The protocol currently permits only a synthetic ping/pong.
- Each child has an isolated session object containing its handshake, decoder, request map, send chain, sequence, key and exit completion. Every stdout/stderr/exit/error/close callback captures that child/session and checks it is still the active generation before changing client state. A stale event can only settle its own retired-process completion. `stop()` rejects a pending handshake and all requests, clears secrets/timers, closes stdin, waits 1.5 seconds, then kills and waits for the actual process exit. Concurrent stops share one promise; failed children are tracked until exit; a fresh start waits for prior retirements and creates a new key/session and fresh sequence/send chain. No automatic restart is attempted. If Electron itself is terminated abruptly, Windows handle closure/child EOF is expected to stop the child; verify this on the target Windows build.
- HMAC is message integrity/authentication, not a boundary against a compromised parent/child or a hostile process with same-user process-memory/handle access. The pipe's local handle inheritance and launch relationship are part of the trust assumptions.

## Linux evidence vs target-Windows gate

The generated-renderer regression checks `dist/index.html` and verifies that its script/CSS references are relative, exist under `dist`, and retain CSP. Linux static/unit/build tests exercise the protocol, IPC guard and file-asset layout but cannot prove actual Electron `loadFile()` rendering on Windows, `CreatePipe`/inheritable-handle behavior, Electron's exact Node runtime behavior, ACLs, or process cleanup. Electron's platform binary download was not available in the implementation sandbox due certificate verification failure; source compilation is not Electron runtime startup evidence. The following exact procedure is required on a clean Windows 11 x64 machine before Stage 1 can be called Windows-verified or any later trusted approval/grant/filesystem stage is enabled.

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

Record OS build, architecture, Node/Electron/Python versions, command output and process IDs. Confirm `npm test`'s generated-file regression passes, then launch the actual Electron app: confirm `BrowserWindow.loadFile()` renders the built UI with no missing `file://` JS/CSS assets or CSP/navigation errors in the renderer console. In the UI confirm `ready: Authenticated synthetic channel ready`; click **Send synthetic ping** and confirm the synthetic-only result. Use Process Explorer or an equivalent signed local inspection tool to verify the child command line contains only the fixed Python flags and script path, has the explicit desktop backend working directory, has only stdin/stdout/stderr redirected as intended, and that the key/session/challenge are absent from argv and environment. Confirm stdout carries only protocol frames and stderr remains separate.

Run the Windows child transport/security tests above: require the test suite to pass authenticated handshake and synthetic ping; reject malformed and oversized frames, bad MAC, wrong direction, stale session, stale timestamp, replayed sequence/nonce and duplicate request ID; close stdin and prove graceful child exit. For additional runtime-failure checks, use a test-only harness outside the shipped renderer to terminate the child unexpectedly, close stdout, send a truncated frame, and send an invalid-MAC frame. Confirm main changes to `offline`, pending ping rejects, no synthetic success is displayed, child is terminated/reaped, and restarting the desktop makes a fresh authenticated session rather than accepting old frames.

Finally, close the desktop normally and verify the backend exits within the bounded shutdown interval; force-terminate the Electron main process in Task Manager/Process Explorer and verify inherited pipe closure causes the Python child to exit, with no orphan remaining after 5 seconds. Capture process listings before and after. Search the child command line, environment, Electron/child logs, renderer devtools state, and application output for the generated key/session/challenge (they must not appear). Repeat with an incorrect bootstrap, bad HMAC, replay, child crash and parent termination at least three times each. A failed assertion blocks acceptance and requires a reviewed transport/lifecycle correction; do not substitute environment variables, command-line secrets or an unauthenticated localhost service.

**Until this evidence is recorded and independently reviewed, Windows inherited-pipe feasibility and cleanup remain unverified.** Do not claim Windows acceptance from the Linux results; do not enable approval authority, grant issuance, filesystem execution, Phase 2C, or Phase 2D based on this Stage 1 scaffold.
