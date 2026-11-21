# SQLite migrations

Phase 2B-1 introduces the first versioned schema migration. Packaged SQL files
live at `aether/core/persistence/migrations/NNNN_name.sql` so the same migration
runner works from a source checkout and an installed backend wheel. Migration
files are immutable once released; schema evolution is additive and uses a new
sequence number.

`SQLiteTaskStore` enables foreign keys, WAL, `synchronous=FULL`, and
`secure_delete`, checks SQLite and foreign-key integrity before and after
migration, rejects newer/unknown schema versions, and pauses active tasks at
startup. A paused task must be replanned and receive fresh consent; stored
records are never rehydrated into trusted resource roots or grants.

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

No down-migration is provided: irreversible schema rollback could discard audit
history. Back up the database before a future migration that requires data
rewrites, and keep migrations forward-only, transactional, and covered by
upgrade/corruption tests.
