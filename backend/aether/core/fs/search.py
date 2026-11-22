"""Bounded, deterministic, cancellable text search inside one allowed root.

Design rules, all enforced here rather than left to callers:

* **Deterministic.** Directory entries are visited in a fixed sort order and
  matches are emitted in a stable sequence, so the same tree yields the same
  result on every host and every run.
* **Bounded.** File count, depth, per-file matches, total output and wall-clock
  time are all capped. Hitting a cap produces a truthful partial result with a
  ``truncated``/``reason`` marker, never a silent short answer.
* **Cancellable.** A caller-supplied predicate is checked between entries, so a
  user cancel stops promptly rather than at the end of a large tree.
* **No escape.** Reparse points are rejected during traversal, not merely at the
  root, so a junction planted inside the tree cannot redirect the walk.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from aether.core.fs import errors
from aether.core.fs.content import ContentRejected, decode_text, is_secret_filename
from aether.core.fs.limits import MAX_SEARCH_FILE_BYTES, MAX_SEARCH_QUERY_CHARS, SearchBounds
from aether.core.resources.path_safety import (
    PathSafetyError,
    is_protected_path,
    reject_reparse_components,
)

_SKIP_DIRECTORIES: Final = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".next",
        ".cache",
    }
)


@dataclass(frozen=True, slots=True)
class SearchMatch:
    """One matching line, with bounded context for honest reporting."""

    relative_path: str
    line_number: int
    line_text: str


@dataclass(frozen=True, slots=True)
class SearchOutcome:
    """Result of one bounded search, including everything it did *not* do."""

    matches: tuple[SearchMatch, ...]
    files_scanned: int
    files_skipped: int
    directories_scanned: int
    truncated: bool
    partial_reason: str | None
    elapsed_seconds: float

    @property
    def complete(self) -> bool:
        return not self.truncated


def validate_query(query: str) -> str:
    """Return a normalized query or raise with a typed reason code."""

    if not isinstance(query, str):
        raise SearchRejected(errors.SEARCH_QUERY_INVALID, "query must be text")
    stripped = query.strip()
    if not stripped:
        raise SearchRejected(errors.SEARCH_QUERY_INVALID, "query must not be empty")
    if len(stripped) > MAX_SEARCH_QUERY_CHARS:
        raise SearchRejected(errors.SEARCH_QUERY_INVALID, "query exceeds its length bound")
    if "\x00" in stripped:
        raise SearchRejected(errors.SEARCH_QUERY_INVALID, "query contains a NUL byte")
    return stripped


def search_tree(
    root: Path,
    *,
    query: str,
    bounds: SearchBounds,
    cancelled: Callable[[], bool] | None = None,
    now: Callable[[], float] = time.monotonic,
) -> SearchOutcome:
    """Search ``root`` for ``query`` under ``bounds``; never raise for limits."""

    needle = validate_query(query).casefold()
    started = now()
    matches: list[SearchMatch] = []
    files_scanned = 0
    files_skipped = 0
    directories_scanned = 0
    output_chars = 0
    truncated = False
    partial_reason: str | None = None

    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        if cancelled is not None and cancelled():
            truncated, partial_reason = True, errors.SEARCH_CANCELLED
            break
        if now() - started > bounds.timeout_seconds:
            truncated, partial_reason = True, errors.SEARCH_TIMEOUT
            break
        current, depth = stack.pop()
        directories_scanned += 1
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name)
        except OSError:
            files_skipped += 1
            continue
        subdirectories: list[tuple[Path, int]] = []
        for entry in entries:
            if len(matches) >= bounds.max_results:
                truncated, partial_reason = True, errors.SEARCH_LIMIT_EXCEEDED
                break
            if files_scanned >= bounds.max_files_scanned:
                truncated, partial_reason = True, errors.SEARCH_LIMIT_EXCEEDED
                break
            name = entry.name
            if name.startswith(".") and name not in {".env.example", ".gitignore"}:
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if name.casefold() in _SKIP_DIRECTORIES:
                        continue
                    if depth + 1 > bounds.max_depth:
                        truncated, partial_reason = True, errors.SEARCH_DEPTH_EXCEEDED
                        continue
                    subdirectories.append((Path(entry.path), depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                files_skipped += 1
                continue
            if is_secret_filename(name) or is_protected_path(Path(entry.path)):
                files_skipped += 1
                continue
            if entry.stat(follow_symlinks=False).st_size > MAX_SEARCH_FILE_BYTES:
                files_skipped += 1
                continue
            files_scanned += 1
            for match in _scan_file(Path(entry.path), root, needle, bounds):
                line_length = len(match.line_text)
                if output_chars + line_length > bounds.max_output_chars:
                    truncated, partial_reason = True, errors.SEARCH_OUTPUT_EXCEEDED
                    break
                output_chars += line_length
                matches.append(match)
                if len(matches) >= bounds.max_results:
                    truncated, partial_reason = True, errors.SEARCH_LIMIT_EXCEEDED
                    break
            if truncated:
                break
        if truncated:
            break
        # Depth-first, but push in reverse so the lowest name is visited first.
        stack.extend(reversed(subdirectories))
    return SearchOutcome(
        matches=tuple(matches),
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        directories_scanned=directories_scanned,
        truncated=truncated,
        partial_reason=partial_reason,
        elapsed_seconds=now() - started,
    )


def _scan_file(
    path: Path,
    root: Path,
    needle: str,
    bounds: SearchBounds,
) -> Iterator[SearchMatch]:
    try:
        reject_reparse_components(path)
        with open(path, "rb") as stream:
            data = stream.read(MAX_SEARCH_FILE_BYTES + 1)
    except (OSError, PathSafetyError):
        return
    if len(data) > MAX_SEARCH_FILE_BYTES:
        return
    try:
        decoded = decode_text(data, total_bytes=len(data))
    except ContentRejected:
        # Binary or secret-bearing files are skipped, never partially matched.
        return
    relative = _relative(path, root)
    emitted = 0
    for number, line in enumerate(decoded.text.splitlines(), start=1):
        if needle in line.casefold():
            yield SearchMatch(
                relative_path=relative,
                line_number=number,
                line_text=line[:512],
            )
            emitted += 1
            if emitted >= bounds.max_matches_per_file:
                return


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


class SearchRejected(Exception):
    """The search request itself is invalid; nothing was scanned."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


__all__ = [
    "SearchMatch",
    "SearchOutcome",
    "SearchRejected",
    "search_tree",
    "validate_query",
]
