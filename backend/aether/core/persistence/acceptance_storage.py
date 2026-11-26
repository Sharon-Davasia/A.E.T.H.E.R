"""G03: controlled Phase 3 acceptance storage (schema v3, isolated).

Ordinary operation uses schema v2 (`ACTIVE_SCHEMA_VERSION`). This
factory is the *only* supported way to open dedicated synthetic
acceptance storage at schema v3, and only with an explicit owner
authorization object supplied by trusted composition. It:

* requires a dedicated directory whose name starts
  ``aether-phase3-acceptance-``;
* rejects symlinked/reparse-style path components;
* rejects pre-existing unrelated storage (a database or other files
  without this factory's marker);
* binds the storage to a marker recording storage id, schema version
  and the owner decision reference;
* verifies migration integrity through the normal store path (Phase 2
  migration hashes and protections are untouched);
* reconciles interrupted navigation/UI operations before returning,
  so no interrupted operation is silently resumed.

It never migrates or opens a real-user database: callers must pass a
new dedicated synthetic directory. Rollback = close the store and,
after verifying the exact directory created here, remove that
directory; there is no downgrade migration.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from aether.core.persistence.sqlite_store import SQLiteTaskStore

_MARKER = "acceptance-storage.json"
_DB_NAME = "phase3-acceptance.sqlite3"
_PREFIX = "aether-phase3-acceptance-"


class AcceptanceStorageError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class OwnerAcceptanceAuthorization:
    """Owner decision supplied by trusted composition (not renderer/env)."""

    decision_reference: str
    storage_id: str
    expires_at: datetime
    campaign_id: str = ""


def _reject_symlink_components(path: Path) -> None:
    """Reject symlinks, junctions and any reparse-point component."""
    from aether.core.resources.path_safety import PathSafetyError, reject_reparse_components

    try:
        reject_reparse_components(path)
    except PathSafetyError as exc:
        raise AcceptanceStorageError(
            "acceptance storage path contains a reparse component"
        ) from exc


def read_acceptance_marker(storage_dir: Path | str) -> dict[str, object] | None:
    """Read and shape-check the storage marker, or None if absent."""
    marker_path = Path(storage_dir) / _MARKER
    if not marker_path.exists():
        return None
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return marker if isinstance(marker, dict) else None


def _file_identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    return (metadata.st_dev, metadata.st_ino)


def _check_single_link(path: Path) -> None:
    """Reject linked/substituted files: a storage file must have
    exactly one hard link and must not be a link/reparse point."""
    _reject_symlink_components(path)
    metadata = path.lstat()
    if getattr(metadata, "st_nlink", 1) != 1:
        raise AcceptanceStorageError("acceptance storage file is hard-linked")


# Exact sidecar names the store creates beside the database; anything
# else in the directory is unrelated content.
_ALLOWED_NAMES = frozenset(
    {
        _MARKER,
        _DB_NAME,
        _DB_NAME + "-wal",
        _DB_NAME + "-shm",
        _DB_NAME + "-journal",
        _DB_NAME + ".owner.lock",
    }
)


def open_acceptance_store(
    storage_dir: Path | str,
    *,
    authorization: OwnerAcceptanceAuthorization | None,
    now: datetime | None = None,
) -> SQLiteTaskStore:
    """Open (creating if needed) isolated v3 acceptance storage."""
    if authorization is None or not authorization.decision_reference.strip():
        raise AcceptanceStorageError("owner acceptance authorization is required")
    moment = now or datetime.now(UTC)
    expires = authorization.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if moment >= expires:
        raise AcceptanceStorageError("owner acceptance authorization has expired")
    try:
        uuid.UUID(authorization.storage_id)
    except ValueError as exc:
        raise AcceptanceStorageError("acceptance storage identity is malformed") from exc

    directory = Path(storage_dir).expanduser()
    if not directory.is_absolute():
        raise AcceptanceStorageError("acceptance storage path must be absolute")
    if any(part in (".", "..") for part in directory.parts):
        raise AcceptanceStorageError("acceptance storage path is not canonical")
    if not directory.name.startswith(_PREFIX):
        raise AcceptanceStorageError("acceptance storage must use a dedicated synthetic directory")
    _reject_symlink_components(directory)
    # Canonical approved local location: fixed local volume only.
    from aether.core.resources.path_safety import VolumeKind, inspect_volume

    volume = inspect_volume(directory.parent)
    if volume.kind is not VolumeKind.FIXED:
        raise AcceptanceStorageError("acceptance storage must be on a fixed local volume")

    marker_path = directory / _MARKER
    db_path = directory / _DB_NAME
    if directory.exists():
        if directory.is_symlink() or not directory.is_dir():
            raise AcceptanceStorageError("acceptance storage path is not a directory")
        if Path(os.path.abspath(directory)) != directory or directory.resolve() != directory:
            raise AcceptanceStorageError("acceptance storage path does not canonicalize to itself")
        existing = {p.name for p in directory.iterdir()}
        unexpected = existing - _ALLOWED_NAMES
        if _DB_NAME in existing and _MARKER not in existing:
            raise AcceptanceStorageError("pre-existing unrelated storage is refused")
        if unexpected:
            raise AcceptanceStorageError("acceptance storage directory contains unrelated files")
        if marker_path.exists():
            _check_single_link(marker_path)
            if db_path.exists():
                _check_single_link(db_path)
            marker = read_acceptance_marker(directory)
            if marker is None:
                raise AcceptanceStorageError("acceptance storage marker is unreadable")
            if (
                marker.get("storage_id") != authorization.storage_id
                or marker.get("schema_version") != 3
                or marker.get("kind") != "aether-phase3-acceptance"
                or marker.get("decision_reference") != authorization.decision_reference
                or marker.get("campaign_id", "") != authorization.campaign_id
                or marker.get("directory_identity") != list(_file_identity(directory))
            ):
                raise AcceptanceStorageError(
                    "acceptance storage marker does not match authorization"
                )
    else:
        # Exclusive creation: never adopt a directory that appears
        # between validation and creation.
        try:
            directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise AcceptanceStorageError("acceptance storage directory already exists") from exc
        os.chmod(directory, 0o700)
        marker_path.write_text(
            json.dumps(
                {
                    "kind": "aether-phase3-acceptance",
                    "storage_id": authorization.storage_id,
                    "schema_version": 3,
                    "decision_reference": authorization.decision_reference,
                    "campaign_id": authorization.campaign_id,
                    "directory_identity": list(_file_identity(directory)),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    store = SQLiteTaskStore(db_path, target_schema_version=3, _acceptance_pending_authorized=True)
    # The opened database must be exactly the validated file.
    _check_single_link(db_path)
    if Path(store.database_path).resolve() != db_path.resolve():
        store.close()
        raise AcceptanceStorageError("opened database is not the validated acceptance database")
    # Reconcile interrupted operations before any new execution.
    store.reconcile_navigation_tasks(now=moment)
    store.reconcile_ui_tasks(now=moment)
    return store
