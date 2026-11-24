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
from types import SimpleNamespace

import pytest

from aether.core.resources.bounded_read import BoundedReadError, read_bounded_bytes


def _resolved(path):
    return SimpleNamespace(canonical_path=path)


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


def test_symlink_target_refused(tmp_path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside\n")
    target = tmp_path / "sample.txt"
    target.symlink_to(outside)
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
    target.symlink_to(tmp_path / "elsewhere.txt")
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
