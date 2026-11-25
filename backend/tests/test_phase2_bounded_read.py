"""FI-06A: the shared bounded read behind planning and hashing.

The planner's pre-image (hash + exact diff) and the bridge's target
hash both come from `read_bounded_bytes`: one identity-validated,
size-capped, consistent snapshot. These tests pin the failure modes:
oversized targets refuse before unbounded allocation, hard links /
symlinks / non-regular files refuse, a file changed mid-read refuses
(so a partial or torn pre-image can never produce a plan whose
approved bytes truncate the real file), and a path swapped after
resolution refuses (resource substitution / reparse escape).
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aether.core.resources.bounded_read import BoundedReadError, read_bounded_bytes


def _resolved(path):
    info = path.lstat()
    return SimpleNamespace(canonical_path=path, device_id=info.st_dev, file_id=info.st_ino)


def test_reads_exact_bytes(tmp_path) -> None:
    target = tmp_path / "sample.txt"
    target.write_bytes(b"hello world\n")
    assert read_bounded_bytes(_resolved(target)) == b"hello world\n"


def test_oversized_target_refused_before_allocation(tmp_path) -> None:
    target = tmp_path / "big.bin"
    with target.open("wb") as handle:
        handle.truncate(4 * 1024 * 1024 + 1)  # sparse: no real allocation here either
    with pytest.raises(BoundedReadError) as caught:
        read_bounded_bytes(_resolved(target))
    assert caught.value.reason_code == "target_too_large"


def test_hard_linked_target_refused(tmp_path) -> None:
    target = tmp_path / "sample.txt"
    target.write_bytes(b"data\n")
    os.link(target, tmp_path / "linked.txt")
    with pytest.raises(BoundedReadError) as caught:
        read_bounded_bytes(_resolved(target))
    assert caught.value.reason_code == "hard_link_not_allowed"


def _symlink(link: Path, target: Path, *, directory: bool = False) -> None:
    from fs_support import skip_if_symlink_unavailable

    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        skip_if_symlink_unavailable(exc)


def test_symlink_target_refused(tmp_path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside\n")
    target = tmp_path / "sample.txt"
    _symlink(target, outside)
    with pytest.raises(BoundedReadError) as caught:
        read_bounded_bytes(_resolved(target))
    assert caught.value.reason_code in {"reparse_point_not_allowed", "target_unavailable"}
    assert outside.read_bytes() == b"outside\n"


def test_directory_target_refused(tmp_path) -> None:
    with pytest.raises(BoundedReadError) as caught:
        read_bounded_bytes(_resolved(tmp_path))
    assert caught.value.reason_code == "target_not_a_regular_file"


def test_change_during_read_refused_no_partial_pre_image(tmp_path, monkeypatch) -> None:
    target = tmp_path / "sample.txt"
    target.write_bytes(b"a" * 200_000)
    real_read = os.read
    calls = {"count": 0}

    def mutating_read(fd: int, size: int) -> bytes:
        chunk = real_read(fd, size)
        calls["count"] += 1
        if calls["count"] == 1:
            # Another writer changes the file mid-read: the snapshot is
            # torn, so the read must fail rather than return a prefix
            # that a planner could turn into a truncating approved edit.
            with target.open("ab") as handle:
                handle.write(b"tail")
        return chunk

    monkeypatch.setattr(os, "read", mutating_read)
    with pytest.raises(BoundedReadError) as caught:
        read_bounded_bytes(_resolved(target))
    assert caught.value.reason_code == "resource_changed_during_read"
    assert target.read_bytes().endswith(b"tail")  # planner never touched it


def test_substituted_path_after_resolution_refused(tmp_path) -> None:
    target = tmp_path / "sample.txt"
    target.write_bytes(b"original\n")
    resolved = _resolved(target)
    # Substitute a different file at the resolved path (different inode,
    # via rename): the descriptor-vs-path identity and reparse checks
    # operate on the opened file, and a symlink substitution refuses.
    target.unlink()
    _symlink(target, tmp_path / "elsewhere.txt")
    (tmp_path / "elsewhere.txt").write_bytes(b"substituted\n")
    with pytest.raises(BoundedReadError):
        read_bounded_bytes(resolved)


def test_planner_binds_pre_image_through_bounded_read(tmp_path) -> None:
    """The planner refuses oversized sources with the bounded reason."""
    from datetime import UTC, datetime
    from uuid import uuid4

    from fs_support import build_registry, build_tree, resolve

    from aether.core.planning.planner import PlanGoal, PlanIntent, Planner, PlannerError
    from aether.core.policy.capabilities import CapabilityRegistry

    tree = build_tree(tmp_path)
    big = tree.readme
    with big.open("wb") as handle:
        handle.truncate(4 * 1024 * 1024 + 1)
    registry = build_registry(
        tree, capabilities=frozenset({"fs.inspect_file", "fs.read_file", "fs.apply_approved_edit"})
    )
    planner = Planner(
        capabilities=CapabilityRegistry.phase2_filesystem(),
        resources=registry,
        clock=lambda: datetime.now(UTC),
    )
    resource_id = resolve(registry, "README.md")
    intent = PlanIntent(
        goal=PlanGoal.APPLY_EDIT,
        resource_id=resource_id,
        arguments={
            "resource_id": resource_id,
            "approval_id": str(uuid4()),
            "step_id": str(uuid4()),
            "expected_sha256": "0" * 64,
        },
        summary="oversized edit",
        proposed_content=b"small\n",
    )
    with pytest.raises(PlannerError) as caught:
        planner.plan(uuid4(), intent, revision=1)
    assert caught.value.reason_code == "target_too_large"
    assert big.stat().st_size == 4 * 1024 * 1024 + 1  # never truncated


def test_rename_substitution_after_resolution_refused(tmp_path) -> None:
    """A different file renamed onto the resolved path is not the
    registry-issued identity, even though the path is unchanged."""
    target = tmp_path / "sample.txt"
    target.write_bytes(b"original\n")
    resolved = _resolved(target)
    substitute = tmp_path / "substitute.txt"
    substitute.write_bytes(b"substituted\n")
    substitute.replace(target)  # same path, different inode
    with pytest.raises(BoundedReadError) as caught:
        read_bounded_bytes(resolved)
    assert caught.value.reason_code == "resource_identity_mismatch"


def test_junction_escape_refused_without_elevation(tmp_path) -> None:
    """Non-elevated native Windows reparse coverage (W-A1).

    A directory junction needs no privilege, so this runs where the
    symlink tests must skip. The bounded reader must refuse a file
    reached through the junction, and the outside bytes stay intact.
    Skips only where junctions genuinely cannot be created (or off
    Windows); a skip is not evidence the scenario passed.
    """
    from fs_support import make_junction

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret = outside_dir / "secret.txt"
    secret.write_bytes(b"outside the project\n")
    project = tmp_path / "project"
    project.mkdir()
    make_junction(project / "escape", outside_dir)
    info = secret.lstat()
    resolved = SimpleNamespace(
        canonical_path=project / "escape" / "secret.txt",
        device_id=info.st_dev,
        file_id=info.st_ino,
    )
    with pytest.raises(BoundedReadError) as caught:
        read_bounded_bytes(resolved)
    assert caught.value.reason_code == "reparse_point_not_allowed"
    assert secret.read_bytes() == b"outside the project\n"


# ----------------------------------------------------------------------
# W-A3: deterministic constructor cleanup on initialization failure
# ----------------------------------------------------------------------


def test_sqlite_store_constructors_close_connections_on_failure(tmp_path) -> None:
    """Corrupt sibling databases: construction fails, nothing leaks.

    After each failed construction the file must be immediately
    removable/replaceable (on Windows a leaked connection keeps it
    locked, WinError 32) and the original sqlite failure must
    propagate unchanged. No garbage-collection reliance.
    """
    import sqlite3

    from aether.core.edits.journal import MutationJournal
    from aether.core.edits.receipts import ReceiptStore
    from aether.core.grants.consumption import ConsumptionLedger

    for factory, name in (
        (ReceiptStore, "receipts.sqlite3"),
        (MutationJournal, "journal.sqlite3"),
        (ConsumptionLedger, "consumption.sqlite3"),
    ):
        database = tmp_path / name
        database.write_bytes(b"this is not a sqlite database" * 4)
        with pytest.raises(sqlite3.DatabaseError):
            factory(database)  # type: ignore[operator]
        database.unlink()  # would raise PermissionError if a handle leaked
        assert not database.exists()
