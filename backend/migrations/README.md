# SQLite migrations

Phase 2B-1 introduces the first versioned schema migration. Packaged SQL files
live at `aether/core/persistence/migrations/NNNN_name.sql` so the same migration
runner works from a source checkout and an installed backend wheel. Migration
files are immutable once released; schema evolution is additive and uses a new
sequence number.

`SQLiteTaskStore` verifies each migration's exact packaged bytes against a
code-pinned SHA-256 before touching the database, and stores that checksum in
the migration ledger from the migration runner (the SQL file does not checksum
itself). Startup also verifies a code-pinned deterministic fingerprint of the
complete user schema, including exact critical immutability-trigger definitions.
It enables foreign keys, WAL, `synchronous=FULL`, and `secure_delete`, checks
SQLite and foreign-key integrity before and after migration, and rejects missing,
changed, or newer migration/schema state.

A nonblocking OS-level lock file grants one active process ownership of each
database. It is held for the store lifetime; POSIX uses `flock`, Windows uses a
one-byte `msvcrt.locking` lock. The OS releases it on process termination. A
second live owner fails before opening the database or running restart recovery.
Startup pauses active tasks only after acquiring ownership; a paused task must
be replanned and receive fresh consent.

The selected absolute database path is checked component-by-component for
symlinks, junctions/reparse points, hard-linked database/lock files, and fixed
volume identity before/after directory creation and database open, and again
before reads and transactions. No Phase 2A protected-user-file path policy is
applied to the intended private `%LOCALAPPDATA%\AetherOS\data` location.
Windows ACL enforcement and actual junction/reparse/file-lock behavior remain
target-machine verification gates.

The 2B-1 schema stores task state, canonical immutable plan revisions,
normalized immutable step rows, append-only allow-listed audit metadata, and
immutable approval-decision audit records. Common credential patterns in task
goals are redacted and plan JSON rejects sensitive/document-content field names;
these are data-minimization safeguards, not a guarantee that arbitrary user text
can be classified perfectly. Approval records are explicitly
`NON_AUTHORIZING_AUDIT_RECORD`; this milestone has no grant issuer, grant
loader, operation-consumption path, executor, or filesystem mutation API.

The caller must choose the local database location. Desktop integration should
use the ignored `.cache/phase2b-data` development location until the packaged
per-user data location and Windows ACL policy are reviewed in Phase 2B-2. On
POSIX the store enforces owner-only directory and file permissions. Windows
ACL behavior requires target-machine verification; Python mode bits are not
claimed as an equivalent ACL guarantee.

Databases from superseded pre-checksum PR #7 development builds have no verified
migration ledger and intentionally fail closed; there is no unsafe in-place
upgrade for those unreleased test databases. Recreate only disposable data after
reviewing retention needs.

No down-migration is provided: irreversible schema rollback could discard audit
history. Back up the database before a future migration that requires data
rewrites, and keep migrations forward-only, transactional, and covered by
upgrade/corruption tests.
