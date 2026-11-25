"""Security-reviewed bounded file access for planning and hashing (FI-06A).

One shared mechanism replaces every direct ``read_bytes()`` on a
registered resource in planning/preview paths:

* the caller passes an already registry-resolved resource; the path is
  re-checked for reparse components before opening;
* the file is opened once (``O_NOFOLLOW`` where available) and read
  from that descriptor only — no check-then-open on the path;
* the descriptor's ``fstat`` identity must match both the resolved
  path's ``lstat`` identity and the registry-issued device/file
  identity captured at resolution, the file must be a regular file
  with no hard links, and its size must fit the bound *before* any
  allocation;
* bytes are streamed in bounded chunks and the descriptor identity
  (device, inode, size, mtime) must be unchanged after the read, so
  the returned pre-image is one consistent snapshot.

The single returned byte string is therefore safe to hash *and* diff:
both derive from exactly the same identity-validated bytes.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Protocol

from aether.core.resources.path_safety import PathSafetyError, reject_reparse_components

MAX_BOUNDED_READ_BYTES = 4 * 1024 * 1024
_CHUNK_BYTES = 64 * 1024


class BoundedReadError(ValueError):
    """A bounded read failed closed; ``reason_code`` is wire-safe."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class _Resolved(Protocol):
    @property
    def canonical_path(self) -> Path: ...

    @property
    def device_id(self) -> int: ...

    @property
    def file_id(self) -> int: ...


def read_bounded_bytes(resolved: _Resolved, *, max_bytes: int = MAX_BOUNDED_READ_BYTES) -> bytes:
    """Return the complete bytes of one resolved regular file, bounded."""

    if not 1 <= max_bytes <= MAX_BOUNDED_READ_BYTES:
        raise ValueError("bounded-read limit outside the permitted range")
    path = resolved.canonical_path
    try:
        reject_reparse_components(path)
    except PathSafetyError as exc:
        raise BoundedReadError(
            "reparse_point_not_allowed", "the target path crosses a reparse point"
        ) from exc
    # Pre-open file-type classification (W-A2): on Windows, os.open on
    # a directory fails before any descriptor exists, which would hide
    # the real reason behind a generic open failure. lstat classifies
    # the target first (reparse components were already rejected above,
    # and the descriptor checks below remain authoritative).
    try:
        pre_open = path.lstat()
    except OSError as exc:
        raise BoundedReadError("target_unavailable", "the target could not be examined") from exc
    if not stat.S_ISREG(pre_open.st_mode):
        raise BoundedReadError("target_not_a_regular_file", "the target is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BoundedReadError("target_unavailable", "the target could not be opened") from exc
    try:
        try:
            info = os.fstat(descriptor)
            path_info = path.lstat()
        except OSError as exc:
            raise BoundedReadError(
                "target_unavailable", "the target identity could not be verified"
            ) from exc
        if (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino):
            raise BoundedReadError(
                "resource_identity_mismatch", "the opened file is not the resolved resource"
            )
        # The opened descriptor must be the very file the registry
        # issued for this resource (device/file identity captured at
        # resolution) — not merely whatever the path happens to name
        # now. A rename/symlink substitution after resolution fails
        # here even if every path-based check would pass.
        issued = (getattr(resolved, "device_id", None), getattr(resolved, "file_id", None))
        if issued != (None, None) and (info.st_dev, info.st_ino) != issued:
            raise BoundedReadError(
                "resource_identity_mismatch",
                "the opened file is not the registry-issued resource identity",
            )
        if not stat.S_ISREG(info.st_mode):
            raise BoundedReadError("target_not_a_regular_file", "the target is not a regular file")
        if info.st_nlink > 1:
            raise BoundedReadError("hard_link_not_allowed", "the target is hard-linked")
        if info.st_size > max_bytes:
            raise BoundedReadError("target_too_large", "the target exceeds the bounded-read limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, _CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise BoundedReadError(
                    "target_too_large", "the target grew beyond the bounded-read limit"
                )
            chunks.append(chunk)
        try:
            after = os.fstat(descriptor)
        except OSError as exc:
            raise BoundedReadError(
                "target_unavailable", "the target identity could not be re-verified"
            ) from exc
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
        ):
            raise BoundedReadError(
                "resource_changed_during_read", "the target changed while it was being read"
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


__all__ = ["MAX_BOUNDED_READ_BYTES", "BoundedReadError", "read_bounded_bytes"]
