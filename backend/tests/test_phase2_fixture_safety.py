"""S14-6 — the verifier's fixture handling must be provably non-destructive.

The review found that a string-prefix test plus unconditional recursive deletion
would delete ``D:\\Projects\\AETHER-Phase2-Fixture-Other`` (a sibling sharing a
prefix) and could delete a pre-existing directory of the same name. These tests
are the negative proofs that those paths are now refused.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from aether.core.acceptance.fixture_safety import (
    FIXTURE_PREFIX,
    MARKER_NAME,
    FixtureLease,
    FixtureSafetyError,
    assert_contained,
    assert_no_redirection,
    cleanup_lease,
    create_lease,
)

BACKEND = Path(__file__).parents[1]


@pytest.fixture
def base(tmp_path: Path) -> Path:
    directory = tmp_path / "Projects"
    directory.mkdir()
    return directory


# ---------------------------------------------------------------------------
# A. Exact containment (the reported defect)
# ---------------------------------------------------------------------------


def test_sibling_prefix_is_not_contained(base: Path) -> None:
    """The exact bug: a sibling sharing a string prefix is NOT inside the base."""

    sibling = base.parent / f"{base.name}-Other" / "payload"
    sibling.mkdir(parents=True)
    (sibling / "valuable.txt").write_text("do not delete", encoding="utf-8")

    with pytest.raises(FixtureSafetyError) as refused:
        assert_contained(base, sibling)
    assert refused.value.reason_code == "fixture_outside_base"
    # And the data is untouched.
    assert (sibling / "valuable.txt").read_text(encoding="utf-8") == "do not delete"


def test_prefix_of_a_broader_name_is_not_contained(base: Path) -> None:
    wider = base.parent / f"{base.name}Extra"
    wider.mkdir()
    with pytest.raises(FixtureSafetyError):
        assert_contained(base, wider)


def test_the_base_itself_is_never_a_fixture(base: Path) -> None:
    with pytest.raises(FixtureSafetyError) as refused:
        assert_contained(base, base)
    assert refused.value.reason_code == "fixture_is_base"


def test_parent_paths_are_refused(base: Path) -> None:
    for candidate in (base.parent, base.parent.parent, Path("/")):
        with pytest.raises(FixtureSafetyError):
            assert_contained(base, candidate)


def test_traversal_spelling_is_refused(base: Path) -> None:
    with pytest.raises(FixtureSafetyError):
        assert_contained(base, f"{base}/../escape")


def test_a_real_child_is_contained(base: Path) -> None:
    child = base / f"{FIXTURE_PREFIX}deadbeef"
    child.mkdir()
    assert assert_contained(base, child) == child


# ---------------------------------------------------------------------------
# B. Creation never adopts or destroys pre-existing data
# ---------------------------------------------------------------------------


def test_creation_refuses_when_the_generated_name_exists(base: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "aether.core.acceptance.fixture_safety.secrets.token_hex", lambda _n: "fixed123456"
    )
    existing = base / f"{FIXTURE_PREFIX}fixed123456"
    existing.mkdir()
    (existing / "valuable.txt").write_text("mine", encoding="utf-8")

    with pytest.raises(FixtureSafetyError) as refused:
        create_lease(base)
    assert refused.value.reason_code == "fixture_target_exists"
    assert (existing / "valuable.txt").read_text(encoding="utf-8") == "mine"


def test_creation_requires_an_existing_absolute_base(tmp_path: Path) -> None:
    with pytest.raises(FixtureSafetyError):
        create_lease(tmp_path / "does-not-exist")
    with pytest.raises(FixtureSafetyError):
        create_lease(Path("relative/path"))


def test_creation_makes_a_fresh_unique_directory(base: Path) -> None:
    first, second = create_lease(base), create_lease(base)
    try:
        assert first.directory != second.directory
        assert first.token != second.token
        assert first.directory.name.startswith(FIXTURE_PREFIX)
        assert (first.directory / MARKER_NAME).is_file()
    finally:
        first.cleanup()
        second.cleanup()


# ---------------------------------------------------------------------------
# C. Deletion requires proven ownership
# ---------------------------------------------------------------------------


def test_unmarked_directory_with_the_right_name_is_never_deleted(base: Path) -> None:
    """A directory that merely looks like a fixture is someone else's data."""

    impostor = base / f"{FIXTURE_PREFIX}0123456789ab"
    impostor.mkdir()
    (impostor / "thesis.txt").write_text("irreplaceable", encoding="utf-8")

    with pytest.raises(FixtureSafetyError) as refused:
        FixtureLease(impostor, base, "0123456789ab").cleanup()
    assert refused.value.reason_code == "fixture_marker_missing"
    assert (impostor / "thesis.txt").read_text(encoding="utf-8") == "irreplaceable"


def test_wrong_token_never_deletes(base: Path) -> None:
    lease = create_lease(base)
    try:
        with pytest.raises(FixtureSafetyError) as refused:
            cleanup_lease(base, lease.directory, "000000000000")
        assert refused.value.reason_code == "fixture_marker_mismatch"
        assert lease.directory.is_dir()
    finally:
        lease.cleanup()


def test_corrupted_marker_never_deletes(base: Path) -> None:
    lease = create_lease(base)
    try:
        (lease.directory / MARKER_NAME).write_text("{not json", encoding="utf-8")
        with pytest.raises(FixtureSafetyError) as refused:
            lease.cleanup()
        assert refused.value.reason_code == "fixture_marker_missing"
        assert lease.directory.is_dir()
    finally:
        (lease.directory / MARKER_NAME).write_text(
            json.dumps({"version": "1", "token": lease.token}), encoding="utf-8"
        )
        lease.cleanup()


def test_cleanup_outside_the_base_is_refused(base: Path, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(FixtureSafetyError):
        FixtureLease(outside, base, "whatever").cleanup()
    assert (outside / "keep.txt").is_file()


# ---------------------------------------------------------------------------
# D. Redirection
# ---------------------------------------------------------------------------


def test_symlinked_component_is_refused(base: Path, tmp_path: Path) -> None:
    real = tmp_path / "real-data"
    real.mkdir()
    (real / "keep.txt").write_text("keep", encoding="utf-8")
    trap = base / f"{FIXTURE_PREFIX}aaaaaaaaaaaa"
    try:
        trap.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("host cannot create directory symlinks")

    with pytest.raises(FixtureSafetyError) as refused:
        assert_no_redirection(base, trap)
    assert refused.value.reason_code == "fixture_reparse_detected"
    with pytest.raises(FixtureSafetyError):
        FixtureLease(trap, base, "aaaaaaaaaaaa").cleanup()
    assert (real / "keep.txt").is_file()


def test_cleanup_removes_links_without_following_them(base: Path, tmp_path: Path) -> None:
    precious = tmp_path / "precious"
    precious.mkdir()
    (precious / "keep.txt").write_text("keep", encoding="utf-8")

    lease = create_lease(base)
    try:
        link = lease.directory / "link-to-precious"
        try:
            link.symlink_to(precious, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("host cannot create directory symlinks")
        lease.cleanup()
    finally:
        if lease.directory.exists():
            lease.cleanup()

    assert not lease.directory.exists()
    # The link target and its contents survived.
    assert (precious / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_lease_verify_rejects_a_replaced_directory(base: Path) -> None:
    lease = create_lease(base)
    directory = lease.directory
    try:
        lease.cleanup()
        directory.mkdir()
        (directory / "someone-elses.txt").write_text("keep", encoding="utf-8")
        with pytest.raises(FixtureSafetyError):
            lease.verify_ownership()
        assert (directory / "someone-elses.txt").is_file()
    finally:
        (directory / "someone-elses.txt").unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            directory.rmdir()


# ---------------------------------------------------------------------------
# E. The CLI the PowerShell verifier actually calls
# ---------------------------------------------------------------------------


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aether.core.acceptance.fixture_safety", *arguments],
        capture_output=True,
        text=True,
        cwd=BACKEND,
        timeout=120,
    )


def test_cli_round_trip_creates_and_cleans_up(base: Path) -> None:
    import json

    created = _run("create", "--base", str(base))
    assert created.returncode == 0, created.stdout + created.stderr
    payload = json.loads(created.stdout)
    directory, token = payload["directory"], payload["token"]
    assert Path(directory).is_dir()

    verified = _run("verify", "--base", str(base), "--dir", directory, "--token", token)
    assert verified.returncode == 0, verified.stdout

    removed = _run("cleanup", "--base", str(base), "--dir", directory, "--token", token)
    assert removed.returncode == 0, removed.stdout
    assert not Path(directory).exists()


def test_cli_refuses_to_delete_unowned_data(base: Path) -> None:
    import json

    victim = base / "user-project"
    victim.mkdir()
    (victim / "app.py").write_text("print('hi')", encoding="utf-8")

    result = _run("cleanup", "--base", str(base), "--dir", str(victim), "--token", "abc")
    assert result.returncode == 3, result.stdout
    # Refused on the name first: an ordinary project directory is not ours to
    # delete, and the reason code says so without touching it.
    assert json.loads(result.stdout)["refused"] in {
        "fixture_name_unexpected",
        "fixture_marker_missing",
    }
    assert (victim / "app.py").is_file()


def test_cli_refuses_a_sibling_prefix(base: Path) -> None:
    import json

    sibling = base.parent / f"{base.name}-Other"
    sibling.mkdir()
    (sibling / "keep.txt").write_text("keep", encoding="utf-8")

    result = _run("cleanup", "--base", str(base), "--dir", str(sibling), "--token", "abc")
    assert result.returncode == 3, result.stdout
    assert json.loads(result.stdout)["refused"] == "fixture_outside_base"
    assert (sibling / "keep.txt").is_file()


def test_cli_usage_errors_are_distinct(base: Path) -> None:
    assert _run().returncode == 4
    assert _run("create").returncode == 4
    assert _run("bogus", "--base", str(base)).returncode == 4


# ---------------------------------------------------------------------------
# F. The PowerShell verifier must not contain its own deletion logic
# ---------------------------------------------------------------------------


def test_verifier_delegates_containment_to_the_tested_module() -> None:
    script = (BACKEND.parent / "scripts" / "verify_phase2.ps1").read_text(encoding="utf-8")
    # No unconditional recursive deletion anywhere in the script.
    assert "Remove-Item -Recurse" not in script
    assert "Remove-Item -Recurse -Force" not in script
    assert "rmdir /s" not in script.lower()
    # Deletion goes through the reviewed module.
    assert "aether.core.acceptance.fixture_safety" in script
