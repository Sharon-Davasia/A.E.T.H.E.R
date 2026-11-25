# Activation proposals — concrete diffs, NOT APPLIED

These two diffs are the complete, separately reviewable activation
changes for Proposals A and B. Status in this PR: Proposal A is
APPLIED (controlled Activation A candidate, schema v2 active for
disposable fixture storage). Proposal B is APPLIED as adapted for
the controlled Activation B fixture candidate: production-trusted
issuance is enabled only under a validated acceptance-fixture scope
and bounded to the fixture root; ordinary launches keep the
`GRANT_ISSUANCE_DISABLED` default. The diffs below remain the
reviewable record of what was applied.

Apply order is mandatory: **A first** (schema), then **B** (issuance),
each in its own reviewed commit, each followed by the full backend +
desktop gates on the target Windows machine and then the 18-scenario
acceptance procedure (`PHASE2_LIVE_WORKFLOW.md` §6). Re-verify line
context at application time; if the context has drifted, the proposal
must be re-reviewed, not force-applied.

- `proposal-a-schema-v2.diff` — single-file flip in
  `backend/aether/core/persistence/sqlite_store.py`.
- `proposal-b-production-issuance.diff` — production trust policy in
  `backend/aether/core/grants/ledger.py` plus the composition opt-in.
  Per the FI review correction: the composition opt-in is a deliberate
  code change reviewed as a whole; the caller-module allowlist plays
  no part in it. The authorization chain it enables is the FI-01
  trusted confirmation + authenticated gesture + authoritative
  preview + exact grant binding + central issuance decision.
