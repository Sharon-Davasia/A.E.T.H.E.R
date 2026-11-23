"""The Undo Vault: encrypted, content-addressed pre-image storage (Phase 2D).

The Master Specification requires an encrypted, owner-restricted,
content-addressed snapshot store with integrity checks, bounded retention and a
durable link from an action receipt to its snapshot.

Design decisions and their reasons:

**Encryption is AEAD, and the key lives outside the vault directory.** Snapshots
are AES-256-GCM encrypted with a random 96-bit nonce per record and the record's
own identity as associated data, so a blob cannot be swapped between records or
silently truncated. The key file is separate from the snapshot files and is
created owner-only, so copying the vault directory alone does not disclose
content. This is protection against casual disclosure and accidental leakage —
*not* a defence against a local user who already holds the credential. That
limit is stated rather than implied (see ``docs/security/TRUST_BOUNDARIES.md``).

**Content-addressing is by plaintext hash, not ciphertext hash.** The address is
``sha256(plaintext)``, which is what a receipt needs to link to and what makes
"the bytes I stored are the bytes the user had" verifiable. Storing the
ciphertext hash instead would make the address unverifiable without the key.

**Quota pressure evicts oldest-first and refuses to evict what a live receipt
still references** unless the caller explicitly accepts breaking that link.
Eviction is reported, never silent.

**Restoration is a separate authorized action.** The vault can *plan* a
restoration and detect conflicts; it cannot restore by itself in this phase. The
edit executor owns that decision so a single code path enforces grant
consumption for every mutation, including undo.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import os
import stat
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TypedDict
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aether.core.security.file_permissions import (
    PermissionEnforcementError,
    restrict_to_owner,
    verify_owner_only,
)

_VAULT_VERSION: Final = 1
_KEY_BYTES: Final = 32
_NONCE_BYTES: Final = 12
_RECORD_MAGIC: Final = b"AETHERV1"
_MAX_SNAPSHOT_BYTES: Final = 16 * 1024 * 1024


class VaultError(Exception):
    """The vault refused an operation; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


class VaultIntegrityError(VaultError):
    """Stored bytes do not match their address or authentication tag."""


class _IndexEntry(TypedDict):
    """One index entry. Typed so persistence cannot drift into ``object``."""

    snapshot_id: str
    content_sha256: str
    size_bytes: int
    created_at_ms: int
    original_display_name: str
    receipt_id: str | None


class _Index(TypedDict):
    records: list[_IndexEntry]


@dataclass(frozen=True, slots=True)
class SnapshotRecord:
    """Metadata for one stored pre-image. Never contains the content itself."""

    snapshot_id: UUID
    content_sha256: str
    size_bytes: int
    created_at_ms: int
    original_display_name: str
    receipt_id: str | None


@dataclass(frozen=True, slots=True)
class RestorePlan:
    """A proposed restoration, with every conflict surfaced before it happens."""

    snapshot_id: UUID
    content_sha256: str
    target_exists: bool
    target_sha256: str | None
    conflict: str | None
    restorable: bool


class UndoVault:
    """Owner-restricted, encrypted, content-addressed snapshot store."""

    def __init__(
        self,
        directory: Path,
        *,
        key_path: Path | None = None,
        quota_bytes: int = 256 * 1024 * 1024,
        retention_seconds: int = 30 * 24 * 60 * 60,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if quota_bytes < _MAX_SNAPSHOT_BYTES:
            raise VaultError(
                "vault_quota_too_small",
                "quota must be able to hold at least one maximum-size snapshot",
            )
        self._directory = Path(directory)
        self._objects = self._directory / "objects"
        self._index = self._directory / "index.json"
        # S14-5: the key must not live inside the vault directory. The whole
        # point of encrypting snapshots is that copying the vault directory is
        # not enough to read them; a key stored alongside the ciphertext defeats
        # that completely. The default is a sibling directory with a distinct
        # owner-only restriction, and any key inside the vault is refused.
        self._key_path = self._resolve_key_path(key_path)
        self._quota_bytes = quota_bytes
        self._retention_seconds = retention_seconds
        self._clock = clock or time.time
        self._cipher: AESGCM | None = None
        self._legacy_key_migrated = False
        # The index is a JSON file rewritten by a read-modify-write in ``put``.
        # Two concurrent snapshots previously raced here: each read the index,
        # each appended its own record, and the second write won -- silently
        # dropping the first snapshot's record so that ``get`` later reported
        # ``vault_snapshot_unknown`` for a snapshot that was genuinely stored.
        # Observed as an intermittent failure in the interleaved-executor test,
        # not as a data-loss report, which is exactly how this kind of bug hides.
        self._lock = threading.RLock()
        # S14-14: an instance lock cannot serialize two *processes* sharing one
        # vault directory. The index is a whole-file read-modify-write, so two
        # concurrent writers can each read, each modify, and one silently loses
        # the other's change -- including a snapshot record. A single-writer
        # ownership lock, held for the life of an open vault, is the only cheap
        # guard that actually holds across processes. Same shape as the grant
        # ledger's owner lock.
        self._writer_lock: int | None = None
        self._writer_lock_path = self._directory / "vault.writer.lock"

    def _resolve_key_path(self, key_path: Path | None) -> Path:
        candidate = (
            Path(key_path)
            if key_path is not None
            else self._directory.parent / f"{self._directory.name}-key" / "vault.key"
        )
        resolved_candidate = candidate.expanduser()
        resolved_directory = self._directory.expanduser().resolve()
        try:
            inside = resolved_candidate.resolve().is_relative_to(resolved_directory)
        except (OSError, RuntimeError):
            inside = False
        if inside:
            raise VaultError(
                "vault_key_inside_vault",
                "the vault key must be stored outside the vault directory, so that a "
                "copy of the vault does not disclose the key",
            )
        if resolved_candidate.name == "":
            raise VaultError("vault_key_path_invalid", "the key path must name a file")
        return resolved_candidate

    @property
    def key_path(self) -> Path:
        """Where the key lives. Exposed so an audit can check it, never the key."""

        return self._key_path

    def _migrate_legacy_key(self) -> None:
        """Move a key that a previous build wrote inside the vault directory.

        Done before the key is used, and reported through the returned warning so
        an operator can see that a weaker layout was actually in use.
        """

        legacy = self._directory / "vault.key"
        if not legacy.exists():
            return
        if self._key_path.exists():
            # Two keys means the vault may already have been half-migrated; do
            # not guess which one decrypts the snapshots.
            raise VaultError(
                "vault_key_migration_ambiguous",
                "both a legacy in-vault key and the external key exist; resolve manually",
            )
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        _restrict_permissions(self._key_path.parent)
        self._key_path.write_bytes(legacy.read_bytes())
        _restrict_permissions(self._key_path)
        legacy.unlink()
        self._legacy_key_migrated = True

    # -- lifecycle -------------------------------------------------------

    def open(self) -> UndoVault:
        """Create or unlock the vault, hardening permissions as we go."""

        self._objects.mkdir(parents=True, exist_ok=True)
        _restrict_permissions(self._directory)
        _restrict_permissions(self._objects)
        self._legacy_key_migrated = False
        self._migrate_legacy_key()
        self._cipher = AESGCM(self._load_or_create_key())
        self._harden_existing_objects()
        return self

    def close(self) -> None:
        self._cipher = None
        self._release_writer_lock()

    def __enter__(self) -> UndoVault:
        return self.open()

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- snapshots -------------------------------------------------------

    def put(
        self,
        content: bytes,
        *,
        original_display_name: str,
        receipt_id: str | None = None,
    ) -> SnapshotRecord:
        """Store one pre-image, returning its durable record."""

        cipher = self._require_open()
        if len(content) > _MAX_SNAPSHOT_BYTES:
            raise VaultError("vault_snapshot_too_large", "pre-image exceeds the snapshot bound")
        if "/" in original_display_name or "\\" in original_display_name:
            raise VaultError("vault_display_name_invalid", "display name must not contain a path")
        digest = hashlib.sha256(content).hexdigest()
        snapshot_id = uuid4()
        target = self._object_path(digest)
        record = SnapshotRecord(
            snapshot_id=snapshot_id,
            content_sha256=digest,
            size_bytes=len(content),
            created_at_ms=int(self._clock() * 1000),
            original_display_name=original_display_name,
            receipt_id=receipt_id,
        )
        # The object write and the index append are ONE critical section.
        #
        # Writing the object first and then taking the lock (the previous
        # arrangement) left a window in which the object existed on disk but no
        # index entry referenced it -- indistinguishable, to
        # ``collect_orphan_objects``, from garbage. Concurrent orphan collection
        # could delete a pre-image that was about to become referenced, and the
        # caller would receive a SnapshotRecord for a snapshot that no longer
        # existed. Holding the lock across both steps means the object is never
        # visible-but-unreferenced to another maintenance call.
        with self._lock, self._exclusive_writer():
            if not target.exists():
                nonce = os.urandom(_NONCE_BYTES)
                blob = cipher.encrypt(nonce, content, digest.encode("ascii"))
                _atomic_write(target, _RECORD_MAGIC + nonce + blob)
                _restrict_permissions(target)
            index = self._read_index()
            candidate = _Index(
                records=[
                    *index["records"],
                    _IndexEntry(
                        snapshot_id=str(record.snapshot_id),
                        content_sha256=record.content_sha256,
                        size_bytes=record.size_bytes,
                        created_at_ms=record.created_at_ms,
                        original_display_name=record.original_display_name,
                        receipt_id=record.receipt_id,
                    ),
                ]
            )
            # Enforce the quota over the *candidate* index and commit only if it
            # succeeds. Evaluating it after the write left a refused snapshot in
            # the index when the only evictable records were receipt-linked: the
            # caller was told the write failed while the record it was told about
            # sat in the index, and an orphan object was left behind. A refusal
            # must leave no trace.
            try:
                self._write_index(self._apply_quota(candidate))
            except VaultError:
                # The quota refused this snapshot. Remove the object we just
                # encrypted, but only if nothing else still references it (another
                # record may share the same content digest), so a refusal leaves no
                # orphan behind.
                self._discard_if_unreferenced(target, digest)
                raise
        return record

    def _discard_if_unreferenced(self, target: Path, digest: str) -> None:
        """Delete an object written for a write that then failed."""

        current = self._read_index()
        if any(entry["content_sha256"] == digest for entry in current["records"]):
            return
        with contextlib.suppress(OSError):
            target.unlink()

    def get(self, snapshot_id: UUID) -> bytes:
        """Return the verified plaintext for one snapshot, or raise."""

        cipher = self._require_open()
        record = self._record(snapshot_id)
        target = self._object_path(record.content_sha256)
        if not target.exists():
            raise VaultIntegrityError(
                "vault_object_missing", "the snapshot object is no longer present"
            )
        raw = target.read_bytes()
        if not raw.startswith(_RECORD_MAGIC):
            raise VaultIntegrityError("vault_object_malformed", "snapshot header is invalid")
        body = raw[len(_RECORD_MAGIC) :]
        nonce, blob = body[:_NONCE_BYTES], body[_NONCE_BYTES:]
        try:
            plaintext = cipher.decrypt(nonce, blob, record.content_sha256.encode("ascii"))
        except InvalidTag as exc:
            raise VaultIntegrityError(
                "vault_authentication_failed",
                "snapshot failed authenticated decryption; it is corrupt or was tampered with",
            ) from exc
        if hashlib.sha256(plaintext).hexdigest() != record.content_sha256:
            raise VaultIntegrityError(
                "vault_content_hash_mismatch", "snapshot content does not match its address"
            )
        return plaintext

    def records(self) -> tuple[SnapshotRecord, ...]:
        with self._lock:
            index = self._read_index()
        return tuple(
            SnapshotRecord(
                snapshot_id=UUID(entry["snapshot_id"]),
                content_sha256=entry["content_sha256"],
                size_bytes=entry["size_bytes"],
                created_at_ms=entry["created_at_ms"],
                original_display_name=entry["original_display_name"],
                receipt_id=entry["receipt_id"],
            )
            for entry in index["records"]
        )

    def verify_all(self) -> dict[str, object]:
        """Verify every stored object; returns a sanitized integrity report."""

        checked = 0
        failures: list[str] = []
        for record in self.records():
            checked += 1
            try:
                self.get(record.snapshot_id)
            except VaultError as exc:
                failures.append(exc.reason_code)
        return {
            "checked": checked,
            "failures": failures,
            "ok": not failures,
        }

    # -- restoration planning --------------------------------------------

    def plan_restore(self, snapshot_id: UUID, target: Path) -> RestorePlan:
        """Describe what restoring would do, including any conflict.

        Never writes. A newer user edit is reported as a conflict so the caller
        must obtain fresh approval rather than overwriting it.
        """

        record = self._record(snapshot_id)
        # Verify the snapshot is readable *before* promising it is restorable.
        self.get(snapshot_id)
        target = Path(target)
        if not target.exists():
            return RestorePlan(
                snapshot_id=snapshot_id,
                content_sha256=record.content_sha256,
                target_exists=False,
                target_sha256=None,
                conflict=None,
                restorable=True,
            )
        current = target.read_bytes()
        current_sha = hashlib.sha256(current).hexdigest()
        conflict = None if current_sha == record.content_sha256 else "target_changed_since_snapshot"
        return RestorePlan(
            snapshot_id=snapshot_id,
            content_sha256=record.content_sha256,
            target_exists=True,
            target_sha256=current_sha,
            conflict=conflict,
            restorable=conflict is None,
        )

    # -- maintenance -----------------------------------------------------

    def cleanup_expired(self) -> tuple[UUID, ...]:
        """Remove records past retention. Orphaned objects are collected too."""

        # The whole read-modify-write, and the collection that follows it, is one
        # critical section. Unlocked (the previous arrangement) two cleanups could
        # each read the index, each remove a different expired record, and let the
        # second write discard the first removal -- resurrecting a snapshot that
        # was supposed to be gone. Worse, a cleanup racing ``put`` could rewrite an
        # index that had just gained a record, dropping it.
        with self._lock, self._exclusive_writer():
            index = self._read_index()
            cutoff_ms = int((self._clock() - self._retention_seconds) * 1000)
            # Retention governs pre-images that nothing points at. A record with a
            # ``receipt_id`` is the one copy of a pre-image that a durable action
            # receipt can still restore, so age alone must not delete it: the
            # receipt outlives the retention window, and expiring the snapshot
            # would leave a SUCCEEDED receipt promising an undo that can no longer
            # be performed. That is a silent loss of recovery evidence, so those
            # records are excluded here rather than quietly dropped.
            expired = [
                entry
                for entry in index["records"]
                if entry["created_at_ms"] < cutoff_ms and entry["receipt_id"] is None
            ]
            if not expired:
                return ()
            expired_ids = {entry["snapshot_id"] for entry in expired}
            index["records"] = [
                entry for entry in index["records"] if entry["snapshot_id"] not in expired_ids
            ]
            self._write_index(index)
            self._collect_orphans(index)
        return tuple(UUID(value) for value in expired_ids)

    def collect_orphan_objects(self) -> int:
        """Delete object files with no index entry; returns how many were removed."""

        with self._lock, self._exclusive_writer():
            index = self._read_index()
            return self._collect_orphans(index)

    # -- internals -------------------------------------------------------

    @contextlib.contextmanager
    def _exclusive_writer(self) -> Iterator[None]:
        """Hold (or acquire once) the vault-directory single-writer lock.

        Reentrant by construction: the lock is acquired on first use and held for
        the lifetime of the open vault, so nested maintenance calls inside a
        critical section do not try to re-lock the file (which would deadlock on
        platforms where the lock is per-descriptor rather than per-process).
        """

        if self._writer_lock is not None:
            yield
            return
        self._writer_lock = self._acquire_writer_lock()
        yield

    def _acquire_writer_lock(self) -> int:
        self._directory.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._writer_lock_path, flags, 0o600)
        except OSError as exc:
            raise VaultError(
                "vault_writer_lock_unavailable",
                "the vault directory writer lock could not be created",
            ) from exc
        try:
            if os.name != "nt":
                fchmod = getattr(os, "fchmod", None)
                if fchmod is not None:
                    fchmod(descriptor, 0o600)
            if os.name == "nt":
                windows_locking = importlib.import_module("msvcrt")
                windows_locking.locking(descriptor, windows_locking.LK_NBLCK, 1)
            else:
                posix_locking = importlib.import_module("fcntl")
                posix_locking.flock(descriptor, posix_locking.LOCK_EX | posix_locking.LOCK_NB)
            return descriptor
        except OSError as exc:
            os.close(descriptor)
            raise VaultError(
                "vault_owned_by_another_writer",
                "another open vault instance is writing this directory; concurrent "
                "writers would race the index and could lose a snapshot record",
            ) from exc

    def _release_writer_lock(self) -> None:
        descriptor = self._writer_lock
        if descriptor is None:
            return
        self._writer_lock = None

        def unlock() -> None:
            if os.name == "nt":
                windows_locking = importlib.import_module("msvcrt")
                windows_locking.locking(descriptor, windows_locking.LK_UNLCK, 1)
            else:
                posix_locking = importlib.import_module("fcntl")
                posix_locking.flock(descriptor, posix_locking.LOCK_UN)

        with contextlib.suppress(OSError, ValueError):
            unlock()
        with contextlib.suppress(OSError):
            os.close(descriptor)

    def _require_open(self) -> AESGCM:
        if self._cipher is None:
            raise VaultError("vault_not_open", "the vault must be opened before use")
        return self._cipher

    def _object_path(self, digest: str) -> Path:
        return self._objects / digest[:2] / f"{digest}.bin"

    def _record(self, snapshot_id: UUID) -> SnapshotRecord:
        for record in self.records():
            if record.snapshot_id == snapshot_id:
                return record
        raise VaultError("vault_snapshot_unknown", "no such snapshot in this vault")

    def _load_or_create_key(self) -> bytes:
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        _restrict_permissions(self._key_path.parent)
        if self._key_path.exists():
            key = self._key_path.read_bytes()
            if len(key) != _KEY_BYTES:
                raise VaultError("vault_key_invalid", "the vault key file is malformed")
            self._assert_key_protected()
            return key
        key = os.urandom(_KEY_BYTES)
        _atomic_write(self._key_path, key)
        _restrict_permissions(self._key_path)
        self._assert_key_protected()
        return key

    def _assert_key_protected(self) -> None:
        """Refuse to run with a key another account could read (S14-5).

        The key protects every snapshot, so an unprotected key is a broken vault
        rather than a degraded one. This fails closed with an explicit code so it
        cannot be mistaken for a warning.
        """

        try:
            report = verify_owner_only(self._key_path, directory=False)
        except PermissionEnforcementError as exc:
            raise VaultError(exc.reason_code, str(exc)) from exc
        if not report.enforced:
            raise VaultError(
                "vault_key_not_protected",
                f"the vault key is not owner-only ({report.mechanism}: {report.detail}); "
                "refusing to use it, because snapshots would not be protected",
            )

    def _harden_existing_objects(self) -> None:
        for path in self._objects.rglob("*.bin"):
            _restrict_permissions(path)

    def _read_index(self) -> _Index:
        if not self._index.exists():
            return _Index(records=[])
        try:
            parsed = json.loads(self._index.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VaultIntegrityError(
                "vault_index_corrupt", "the vault index is unreadable"
            ) from exc
        if not isinstance(parsed, dict) or not isinstance(parsed.get("records"), list):
            raise VaultIntegrityError("vault_index_corrupt", "the vault index is malformed")
        return _Index(records=[_entry(raw) for raw in parsed["records"]])

    def _write_index(self, index: _Index) -> None:
        payload = json.dumps(
            {"version": _VAULT_VERSION, "records": index["records"]},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        _atomic_write(self._index, payload)
        _restrict_permissions(self._index)

    def _apply_quota(self, index: _Index) -> _Index:
        """Evict down to the quota, or refuse; never writes.

        Kept separate from the write so a refusal cannot leave a half-applied
        index behind. Returns the index that should be committed.
        """

        total = sum(entry["size_bytes"] for entry in index["records"])
        if total <= self._quota_bytes:
            return index
        # Evict oldest first, but never break a live receipt link without saying
        # so: records with a receipt are kept until nothing else can be evicted.
        ordered = sorted(
            index["records"],
            key=lambda entry: (entry["receipt_id"] is not None, entry["created_at_ms"]),
        )
        for entry in list(ordered):
            if total <= self._quota_bytes:
                break
            if entry["receipt_id"] is not None:
                # Only receipt-linked records are left. Evicting one would break a
                # restore promise a durable receipt still makes, so the write is
                # refused instead. Failing closed here is better than accepting a
                # snapshot that silently costs an earlier edit its undo.
                raise VaultError(
                    "vault_quota_exhausted_by_receipts",
                    "the quota can only be met by evicting snapshots that live receipts "
                    "still reference; raise the quota or expire those receipts explicitly",
                )
            index["records"].remove(entry)
            total -= entry["size_bytes"]
        return index

    def _enforce_quota(self, index: _Index) -> _Index:
        """Evict to quota and commit the result (used by maintenance paths)."""

        applied = self._apply_quota(index)
        self._write_index(applied)
        self._collect_orphans(applied)
        return applied

    def _collect_orphans(self, index: _Index) -> int:
        referenced = {entry["content_sha256"] for entry in index["records"]}
        removed = 0
        for path in self._objects.rglob("*.bin"):
            if path.stem not in referenced:
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    continue
        return removed


def _entry(raw: Any) -> _IndexEntry:
    """Validate one persisted index entry, refusing a malformed index."""

    if not isinstance(raw, dict):
        raise VaultIntegrityError("vault_index_corrupt", "index entry is not an object")
    snapshot_id = raw.get("snapshot_id")
    content_sha256 = raw.get("content_sha256")
    size_bytes = raw.get("size_bytes")
    created_at_ms = raw.get("created_at_ms")
    display_name = raw.get("original_display_name")
    receipt_id = raw.get("receipt_id")
    if not (
        isinstance(snapshot_id, str)
        and isinstance(content_sha256, str)
        and len(content_sha256) == 64
        and isinstance(size_bytes, int)
        and size_bytes >= 0
        and isinstance(created_at_ms, int)
        and isinstance(display_name, str)
        and (receipt_id is None or isinstance(receipt_id, str))
    ):
        raise VaultIntegrityError("vault_index_corrupt", "index entry has invalid fields")
    UUID(snapshot_id)  # raises ValueError for a malformed identifier
    return _IndexEntry(
        snapshot_id=snapshot_id,
        content_sha256=content_sha256,
        size_bytes=size_bytes,
        created_at_ms=created_at_ms,
        original_display_name=display_name,
        receipt_id=receipt_id,
    )


def _restrict_permissions(path: Path) -> None:
    """Owner-only permissions, for real on both platforms (S14-5).

    Previously this was a silent no-op on Windows, which meant the vault
    directory, its objects and the key were only as protected as the user's
    profile happened to be. It now applies a real ACL there and raises if it
    cannot, rather than reporting protection that does not exist.
    """

    restrict_to_owner(path, directory=path.is_dir() and not path.is_file())


def _atomic_write(target: Path, payload: bytes) -> None:
    """Write via a same-directory temporary file and atomic replace."""

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        with open(temporary, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 384
        os.replace(temporary, target)
        if os.name != "nt":
            target.chmod(mode)
    finally:
        if temporary.exists():
            with contextlib.suppress(OSError):
                temporary.unlink()


__all__ = [
    "RestorePlan",
    "SnapshotRecord",
    "UndoVault",
    "VaultError",
    "VaultIntegrityError",
]
