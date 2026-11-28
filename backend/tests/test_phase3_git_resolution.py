"""Trusted Git executable resolution for controlled startup (fake only)."""

from __future__ import annotations

from pathlib import Path

from aether.channel.service import _trusted_git_executable


def test_explicit_validated_git_path_is_used(tmp_path: Path) -> None:
    git = tmp_path / "git.exe"
    git.write_bytes(b"fake")
    assert _trusted_git_executable({"AETHER_GIT_EXECUTABLE": str(git)}) == str(git)


def test_explicit_invalid_git_path_denies_without_fallback(tmp_path: Path) -> None:
    missing = tmp_path / "git.exe"
    assert (
        _trusted_git_executable(
            {"AETHER_GIT_EXECUTABLE": str(missing)}, candidates=[str(tmp_path / "git")]
        )
        is None
    )
    not_git = tmp_path / "python.exe"
    not_git.write_bytes(b"fake")
    assert _trusted_git_executable({"AETHER_GIT_EXECUTABLE": str(not_git)}) is None
    relative = "git"
    assert _trusted_git_executable({"AETHER_GIT_EXECUTABLE": relative}) is None


def test_well_known_candidates_are_validated(tmp_path: Path) -> None:
    git = tmp_path / "git"
    git.write_bytes(b"fake")
    assert _trusted_git_executable({}, candidates=[str(git)]) == str(git)
    assert _trusted_git_executable({}, candidates=[str(tmp_path / "missing-git")]) is None
