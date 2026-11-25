# Verifier and fixture-safety review (controlled Activation A)

Reviewer: this PR's author (self-review — **not** independent review).
Scope: `scripts/verify_phase2.ps1` (459 lines) and
`backend/aether/core/acceptance/fixture_safety.py` (387 lines), read in
full on the Linux candidate at the Activation A head, plus their test
suite `backend/tests/test_phase2_fixture_safety.py` (21 tests, passing
in the full backend gate). The verifier was **not executed** by the
reviewer (no Windows machine in this environment); the safety warning
in `PHASE2_WINDOWS_ACCEPTANCE.md` stands until the items under
"Requires independent confirmation" are closed by someone other than
the author on the target machine.

## What was reviewed (code inspection)

Fixture safety module — guarantees verified in source:

1. **Exact containment**: canonical `commonpath` comparison, base
   itself refused (`fixture_is_base`), sibling prefixes refused,
   cross-drive refused.
2. **No redirection**: every path component from base to candidate is
   `lstat`-checked for symlink/Windows reparse attributes before
   creation and again before deletion (`assert_no_redirection`,
   `_is_reparse_point` incl. `FILE_ATTRIBUTE_REPARSE_POINT`).
3. **Ownership proven, not assumed**: deletion requires the marker
   file with matching per-lease random token and version
   (`verify_ownership`); unmarked, wrong-token, corrupted-marker and
   replaced directories all refuse, and each has a negative test.
4. **Creation never adopts**: existing target path (even with the
   generated name) fails creation; base must exist, be absolute and
   not a reparse point.
5. **Deletion never follows links**: tree walk unlinks links in place,
   caps entries at 50 000, finishes with `rmdir` (refuses non-empty).
6. **CLI**: exit codes 0/3/4 distinguish success, safety refusal and
   usage error; JSON-only stdout.

Verifier script — behaviour verified in source:

- Refuses elevated tokens before doing anything (throws).
- Deletes nothing itself: fixture creation/deletion go exclusively
  through the fixture module CLI; it first runs the sibling-prefix
  **negative control** and records FAIL if containment ever accepts.
- Records PASS/FAIL/NOT VERIFIED per requirement; skips are
  NOT VERIFIED, human scenarios are always NOT VERIFIED, exit 2 =
  incomplete (never a pass) — consistent with §6 gate semantics.
- Evidence is limited to requirement names, statuses, versions, git
  SHA and fixture paths (no environment dumps or file contents).
- Native probes (junction refusal, volume identity, owner lock,
  vault-key DACL) run against the fixture only; the probe file the
  script generates inside the repo is removed in a `finally`.

Changes made by this review (narrow, in `verify_phase2.ps1`):

- Removed the header instruction to use `-ExecutionPolicy Bypass`
  (contradicted the standing no-bypass rule); replaced with the
  approved-policy instruction.
- Desktop gates and the tool check now invoke `npm.cmd` (the bare
  `npm` PowerShell shim is execution-policy-sensitive and the
  acceptance standard is `npm.cmd`).

## Requires independent confirmation (not closed by this review)

1. **Independent reviewer** (not the author) re-reads both files and
   the negative tests, and records agreement — the standing warning
   is lifted only then.
2. **Native execution**: the verifier has never been run on Windows
   by this project with archived output. Junction creation
   (`mklink /J` via `os.system` in the probe), DACL read-back, WAL
   and owner-lock behaviour, and PowerShell 5.1 quirks
   (`[scriptblock]::Create`, `2>&1` capture) must be confirmed on the
   target machine.
3. **Toolchain pinning**: the verifier records tool versions but does
   not enforce Python 3.12.10 / Node 22.22.3 / npm 10.9.8; the
   operator must verify the recorded versions match before accepting
   any result (tightening the script to enforce them is recommended
   as a follow-up, not done here).
4. **Fixture-base choice**: `$Base` default `D:\Projects` must be a
   real, non-reparse, disposable location on the target machine;
   confirming that is an operator decision the script cannot make.
5. **Script-to-module trust**: `Invoke-FixtureModule` trusts
   `uv run python -m aether.core.acceptance.fixture_safety` from the
   checkout under test; a tampered checkout invalidates the argument
   (clean-tree check mitigates, does not eliminate).
6. **Human scenarios**: by design always NOT VERIFIED after the
   script; they close only through the §6 demonstrations.
