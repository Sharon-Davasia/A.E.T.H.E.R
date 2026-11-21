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

A nonblocking OS-level lock grants one active process ownership of each
database. On POSIX, `flock` is held on the database file descriptor itself for
the store lifetime, so unlinking/replacing a historical `.owner.lock` sidecar
cannot create a second lockable inode. On Windows, the existing one-byte
`msvcrt.locking` lock remains on the `.owner.lock` sidecar. The implementation
seeks to offset zero and requests `LK_NBLCK` for one byte; open-file
rename/unlink and replacement-lock behavior has not been established here and
requires target-machine verification. The OS releases the held lock on process termination. A second
live owner fails before startup recovery; active tasks are paused only after
ownership is acquired and must be replanned with fresh consent. This does not
claim protection from a malicious same-OS-user actor able to replace database
paths or otherwise tamper with the private storage directory.

The original caller-provided database-path spelling is checked before
`pathlib` normalization or filesystem access, then checked again component by
component for symlinks, junctions/reparse points, hard-linked database files
(and the Windows lock sidecar), and fixed volume identity before/after directory
creation and database open, and again before reads and transactions. Raw
trailing dots/spaces, reserved device names, alternate data streams and invalid
Windows components are rejected. No Phase 2A protected-user-file path policy is
applied to the intended private `%LOCALAPPDATA%\AetherOS\data` location.
Windows ACL enforcement and actual junction/reparse/file-lock behavior remain
target-machine verification gates.

Parent-identity drift is checked independently of native directory replacement.
The deterministic drift regression runs on every OS. Renaming a parent that
contains an open SQLite database may be denied by Windows sharing rules
(WinError 5); that native substitution remains unverified if blocked, and the
test records the block as a skip rather than counting it as acceptance.

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
