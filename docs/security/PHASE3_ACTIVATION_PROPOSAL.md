# Phase 3 native activation proposal (requires separate owner approval)

Status: **PROPOSAL ONLY — not authorized, not implemented as a switch.**
Today there is no environment variable, caller boolean or importable
token that enables Phase 3 native execution: `Phase3Enablement` admits
a capability only when a trusted, non-forgeable activation context
(window/session/activation-epoch bound) exists, and ordinary launches
construct none. This document describes what an activation would have
to contain before the owner considers approving one.

## Required contents of any activation

1. **Operator authorization**: a recorded owner decision naming the
   campaign (e.g. P3-01…P3-25), the machine, and an expiry.
2. **Trusted initialization**: activation constructed only inside the
   trusted host at startup from owner-reviewed configuration; never
   from renderer IPC, environment flags or task content.
3. **Isolated synthetic storage**: a dedicated database directory
   outside the real task store; the campaign never touches real tasks.
4. **Exact fixture/app identities**: fixture executable identity token
   and allowlisted application version tokens recorded before launch;
   title/name/status text is never identity evidence.
5. **Capability allowlist**: `app.launch` (registered apps only),
   `window.activate`, read-only observation, and
   `uia.invoke_fixture` restricted to the approved fixture app id +
   identity token. No other window-effect capability; no text entry,
   no selection, no navigation, no value setting.
6. **Privacy opt-in**: explicit `metadata_only` (or stricter) opt-in
   with pause control; content modes off; password values never
   queried; unknown/elevated contexts fail closed.
7. **Session scope**: one desktop session, one activation epoch;
   bindings, snapshots and gestures die with it.
8. **Revocation**: privacy pause/opt-out, session end, window/process
   replacement, takeover or unexpected dialog revokes outstanding
   bindings immediately; consumed approvals are never replayable.
9. **Shutdown**: worker terminated and COM released; snapshots purged;
   no background monitoring remains.
10. **Recovery**: restart reconciles through the persistent authority;
    uncertain outcomes stay uncertain; schema stays v2
    (`ACTIVE_SCHEMA_VERSION=2`) unless a separately reviewed migration
    activation is approved — migration is out of scope here.
11. **Default-denied posture**: any missing element above means the
    surface reports `phase3_native_disabled` and nothing executes.

## Explicitly not proposed

Schema v3 activation; Phase 4 capabilities (SetValue, text entry,
selection, file dialogs, Explorer mutation, arbitrary applications);
any change to Phase 2 acceptance status, which remains NOT COMPLETE.
