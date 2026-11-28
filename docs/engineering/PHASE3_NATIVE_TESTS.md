# Phase 3 native test instructions (PREPARED — do not run yet)

These instructions are prepared for a later owner review. Nothing here
is requested in the current batch, and no result may be recorded as
acceptance until the owner runs them in a dedicated Windows test
session with Phase 3 native activation still disabled by default.

## Fixture application contract

Build the smallest standard-controls Windows app (Win32/WPF/WinForms
stdlib-class tooling only) exposing:

1. Title/identity: window titled `AETHER Fixture` from a signed-off
   test executable identity recorded in the registry.
2. A status text control reading `Count: N` (starts `Count: 0`).
3. An `Increment` button (Invoke) that deterministically sets
   `Count: N+1`.
4. A disabled button.
5. A password edit control (value must never be readable via the
   snapshot contract).
6. An `Open dialog` button producing a modal dialog.
7. A control that replaces the Increment button (new runtime id) on
   demand, and a 10 s delayed-response mode.

## Checks (each mapped to a Linux fake-backed test)

- Authorized snapshot of the fixture window binds the current window
  instance version; password value/name absent; limits/truncation
  behave as in `test_phase3_cp4_uia.py`.
- `window.activate` (T1) foreground-verifies once, without focus
  stealing loops.
- The exact-bound Increment interaction succeeds only with independent
  postcondition `Count: 1`; stale element after replacement fails;
  replay, wrong window, expired/revoked binding all fail closed.
- Manual interaction in the fixture window during a pending operation
  stops automation (takeover), releases focus ownership and requires a
  fresh precheck.
- Native UIA worker survives kill/timeout with TIMED_OUT/UNCERTAIN
  classification and no replay.

Record build identity, Windows build, Python 3.12.10, pywinauto 0.6.9
and outcomes with the evidence; file it under the Phase 3 evidence —
never in this repository's test suite.
