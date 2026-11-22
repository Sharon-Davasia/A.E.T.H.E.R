"""Disposable acceptance fixtures with provable containment (S14-6).

The Phase 2 Windows verifier must create and destroy a scratch project on a real
disk. Getting that wrong deletes a user's data, so the rules here are written as
a security boundary rather than as script convenience:

1. **Exact containment.** A candidate is inside the base only if its *canonical*
   path has the canonical base as a proper ancestor. A string prefix check is not
   containment: ``D:\\Projects\\Fixture-Other`` shares the prefix
   ``D:\\Projects\\Fixture`` but is a sibling, and deleting it would be a bug.
2. **No redirection.** Every component from the base down to the candidate must
   be free of reparse points, so a junction cannot point the deletion at another
   directory.
3. **Ownership is proven, not assumed.** A fixture may only be deleted when it
   carries a marker file written by this module for that exact lease token. A
   directory that merely happens to have the right name is never deleted.
4. **Creation never reuses an existing path.** If the (randomly unique) target
   already exists, creation fails. It never adopts or overwrites a directory.
5. **Deletion never follows a link.** The tree walk removes reparse points as
   links and refuses to descend through them.

None of this depends on the operating system for its guarantees; the Windows
specific attribute handling is additive.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

FIXTURE_PREFIX = "AETHER-Phase2-Fixture-"
MARKER_NAME = ".aether-fixture-owner"
LEASE_VERSION = "1"
_TOKEN_BYTES = 6  # 12 hex characters
_MAX_ENTRIES = 50_000

_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class FixtureSafetyError(Exception):
    """The fixture operation was refused; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


def _is_reparse_point(path: Path) -> bool:
    """True if ``path`` is a symlink or a Windows reparse point.

    ``lstat`` is used deliberately: ``stat`` would follow the link first, which is
    exactly the behaviour this module must not have.
    """

    try:
        info = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def canonical(path: str | Path) -> Path:
    """Return the fully resolved path, or raise if it cannot be represented."""

    try:
        return Path(os.path.realpath(str(path)))
    except (OSError, ValueError) as exc:  # pragma: no cover - platform dependent
        raise FixtureSafetyError(
            "fixture_path_unresolvable", "the path could not be resolved"
        ) from exc


def assert_contained(base: str | Path, candidate: str | Path) -> Path:
    """Return the canonical candidate, proving it is strictly inside ``base``.

    Strict containment means the candidate is never the base itself, so a caller
    cannot turn "the fixture is inside D:\\Projects" into "delete D:\\Projects".
    """

    base_canonical = canonical(base)
    candidate_canonical = canonical(candidate)
    if base_canonical == candidate_canonical:
        raise FixtureSafetyError(
            "fixture_is_base",
            "refusing to treat the base directory itself as a disposable fixture",
        )
    try:
        common = Path(os.path.commonpath([str(base_canonical), str(candidate_canonical)]))
    except ValueError as exc:  # different drives, or mixed absolute/relative
        raise FixtureSafetyError(
            "fixture_outside_base", "the candidate is not on the base's volume"
        ) from exc
    if common != base_canonical:
        raise FixtureSafetyError(
            "fixture_outside_base",
            "the candidate is outside the base directory",
        )
    return candidate_canonical


def assert_no_redirection(base: str | Path, candidate: str | Path) -> None:
    """Reject any reparse point between ``base`` and ``candidate`` inclusive.

    The candidate is inspected **unresolved**: canonicalising it first would
    follow the very link this function exists to detect. Only the base is
    resolved, so a legitimate base reached through a mounted path still works.
    """

    base_canonical = canonical(base)
    candidate_path = Path(candidate)
    if not candidate_path.is_absolute():
        candidate_path = Path(os.path.abspath(str(candidate_path)))
    # Walk the literal path downwards, checking base, then each added component.
    parts: list[Path] = []
    probe = candidate_path
    while probe.parent != probe:
        parts.append(probe)
        probe = probe.parent
    parts.append(probe)
    parts.reverse()  # root ... candidate
    start = 0
    for index, component in enumerate(parts):
        if index and Path(os.path.realpath(str(component))) == base_canonical:
            start = index
            break
    if Path(os.path.realpath(str(candidate_path))) == base_canonical:
        start = len(parts) - 1
    for component in parts[start:]:
        if _is_reparse_point(component):
            raise FixtureSafetyError(
                "fixture_reparse_detected",
                "the fixture path or one of its components is a reparse point",
            )


def _read_marker(directory: Path) -> dict[str, object] | None:
    marker = directory / MARKER_NAME
    if not marker.is_file() or _is_reparse_point(marker):
        return None
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


@dataclass(frozen=True, slots=True)
class FixtureLease:
    """Proof that one specific directory was created by this module."""

    directory: Path
    base: Path
    token: str

    @property
    def marker_path(self) -> Path:
        return self.directory / MARKER_NAME

    def verify_ownership(self) -> None:
        """Prove this lease still owns its directory. Raises otherwise."""

        assert_contained(self.base, self.directory)
        assert_no_redirection(self.base, self.directory)
        if not self.directory.is_dir():
            raise FixtureSafetyError("fixture_missing", "the fixture directory no longer exists")
        if not self.directory.name.startswith(FIXTURE_PREFIX):
            raise FixtureSafetyError(
                "fixture_name_unexpected", "the fixture directory name is not ours"
            )
        marker = _read_marker(self.directory)
        if marker is None:
            raise FixtureSafetyError(
                "fixture_marker_missing",
                "the directory carries no ownership marker, so it is treated as "
                "someone else's data and is never deleted",
            )
        if marker.get("token") != self.token or marker.get("version") != LEASE_VERSION:
            raise FixtureSafetyError(
                "fixture_marker_mismatch",
                "the ownership marker does not belong to this lease",
            )

    def cleanup(self) -> None:
        """Delete the fixture, but only after proving ownership."""

        self.verify_ownership()
        _remove_tree_without_following_links(self.directory, counter=[0])
        if self.directory.exists():
            raise FixtureSafetyError(
                "fixture_cleanup_incomplete", "the fixture directory survived cleanup"
            )


def create_lease(base: str | Path) -> FixtureLease:
    """Create a fresh, uniquely named fixture under ``base``.

    ``base`` must already exist and be a real directory. An existing path is never
    adopted: creation fails rather than deleting or reusing unknown data.
    """

    base_path = Path(base)
    if not base_path.is_absolute():
        raise FixtureSafetyError("fixture_base_not_absolute", "the base directory must be absolute")
    if _is_reparse_point(base_path):
        raise FixtureSafetyError("fixture_base_reparse", "the base directory is a reparse point")
    if not base_path.is_dir():
        raise FixtureSafetyError("fixture_base_missing", "the base directory does not exist")
    base_canonical = canonical(base_path)

    token = secrets.token_hex(_TOKEN_BYTES)
    directory = base_canonical / f"{FIXTURE_PREFIX}{token}"
    # strict containment and no redirection must both hold before creation
    assert_contained(base_canonical, directory)
    assert_no_redirection(base_canonical, base_canonical)
    if directory.exists() or _is_reparse_point(directory):
        # Astronomically unlikely with a random token, but adopting a directory
        # we did not create is exactly the mistake this module exists to prevent.
        raise FixtureSafetyError(
            "fixture_target_exists",
            "a directory with the generated fixture name already exists",
        )
    try:
        directory.mkdir(mode=0o700)
    except OSError as exc:
        raise FixtureSafetyError(
            "fixture_create_failed", "the fixture directory could not be created"
        ) from exc

    marker = {
        "version": LEASE_VERSION,
        "token": token,
        "created_at": datetime.now(UTC).isoformat(),
        "purpose": "AETHER Phase 2 acceptance fixture; safe to delete",
    }
    try:
        (directory / MARKER_NAME).write_text(json.dumps(marker, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        # Do not leave a half-created directory that could later be mistaken for
        # someone else's data.
        _remove_tree_without_following_links(directory, counter=[0])
        raise FixtureSafetyError(
            "fixture_marker_write_failed", "the ownership marker could not be written"
        ) from exc

    lease = FixtureLease(directory=directory, base=base_canonical, token=token)
    lease.verify_ownership()
    return lease


def cleanup_lease(base: str | Path, directory: str | Path, token: str) -> None:
    """Delete a fixture identified by base, directory and token."""

    create = FixtureLease(directory=Path(directory), base=Path(base), token=token)
    create.cleanup()


def _remove_tree_without_following_links(directory: Path, *, counter: list[int]) -> None:
    """Remove a tree, never descending through a reparse point."""

    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        raise FixtureSafetyError(
            "fixture_unreadable", "the fixture directory could not be listed"
        ) from exc
    for entry in entries:
        counter[0] += 1
        if counter[0] > _MAX_ENTRIES:
            raise FixtureSafetyError("fixture_too_large", "the fixture exceeds the deletion bound")
        path = Path(entry.path)
        if entry.is_symlink() or _is_reparse_point(path):
            # Remove the link itself. Never recurse: the target is not ours.
            try:
                path.unlink()
            except OSError as exc:
                raise FixtureSafetyError(
                    "fixture_link_removal_failed", "a link inside the fixture could not be removed"
                ) from exc
            continue
        if entry.is_dir(follow_symlinks=False):
            _remove_tree_without_following_links(path, counter=counter)
            continue
        try:
            path.unlink()
        except OSError as exc:
            raise FixtureSafetyError(
                "fixture_entry_removal_failed", "a file inside the fixture could not be removed"
            ) from exc
    try:
        # rmdir, not rmtree: this refuses to act on a non-empty or reparse target.
        directory.rmdir()
    except OSError as exc:
        raise FixtureSafetyError(
            "fixture_directory_removal_failed", "the fixture root could not be removed"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    """CLI used by ``scripts/verify_phase2.ps1``.

    Sub-commands print one JSON object on stdout and use exit codes:
    ``0`` success, ``3`` refused (a safety rule fired), ``4`` usage error.
    """

    import sys

    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        print(
            "usage: fixture_safety <create|cleanup|verify> --base <dir> [--dir <d>] [--token <t>]"
        )
        return 4
    command = arguments[0]
    options: dict[str, str] = {}
    index = 1
    while index < len(arguments):
        flag = arguments[index]
        if not flag.startswith("--") or index + 1 >= len(arguments):
            print(json.dumps({"error": "usage"}))
            return 4
        options[flag[2:]] = arguments[index + 1]
        index += 2
    base = options.get("base")
    if not base:
        print(json.dumps({"error": "base_required"}))
        return 4

    try:
        if command == "create":
            lease = create_lease(base)
            print(
                json.dumps(
                    {
                        "directory": str(lease.directory),
                        "token": lease.token,
                        "created": True,
                    }
                )
            )
            return 0
        if command == "cleanup":
            directory, token = options.get("dir"), options.get("token")
            if not directory or not token:
                print(json.dumps({"error": "dir_and_token_required"}))
                return 4
            cleanup_lease(base, directory, token)
            print(json.dumps({"removed": directory}))
            return 0
        if command == "verify":
            directory, token = options.get("dir"), options.get("token")
            if not directory or not token:
                print(json.dumps({"error": "dir_and_token_required"}))
                return 4
            FixtureLease(Path(directory), Path(base), token).verify_ownership()
            print(json.dumps({"owned": True}))
            return 0
    except FixtureSafetyError as exc:
        print(json.dumps({"refused": exc.reason_code, "detail": str(exc)}))
        return 3
    print(json.dumps({"error": "unknown_command"}))
    return 4


__all__ = [
    "FIXTURE_PREFIX",
    "LEASE_VERSION",
    "MARKER_NAME",
    "FixtureLease",
    "FixtureSafetyError",
    "assert_contained",
    "assert_no_redirection",
    "canonical",
    "cleanup_lease",
    "create_lease",
]


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
