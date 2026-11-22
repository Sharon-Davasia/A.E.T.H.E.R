"""Phase 2C — typed T0/T1 filesystem capabilities (Linux synthetic evidence).

Covers inspect, read, search and open against a disposable tree, plus the
adversarial half: escape attempts, secret files, binary payloads, identity
drift, bounds, cancellation and volume refusal.

Windows behaviour is *not* inferred here. Reparse/junction/ACL specifics are in
``docs/engineering/PHASE2_WINDOWS_ACCEPTANCE.md`` and must be run on the target
machine.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aether.core.fs import errors
from aether.core.fs.content import contains_secret_material, is_secret_filename
from aether.core.fs.executor import FilesystemExecutor, FsCapabilityDenied
from aether.core.fs.limits import MAX_READ_BYTES, ReadBounds, SearchBounds
from aether.core.resources.path_safety import VolumeKind
from aether.core.resources.registry import ResourceRegistryError
from tests.fs_support import (
    build_registry,
    build_tree,
    resolve,
)


@pytest.fixture
def tree(tmp_path: Path):
    return build_tree(tmp_path)


@pytest.fixture
def registry(tree):
    return build_registry(tree)


@pytest.fixture
def executor(registry):
    return FilesystemExecutor(registry)


# ---------------------------------------------------------------------------
# A. Inspect — metadata only
# ---------------------------------------------------------------------------


def test_inspect_returns_metadata_without_content(executor, registry) -> None:
    metadata, audit = executor.inspect(resource_id=resolve(registry, "README.md"))
    assert metadata.kind == "file"
    assert metadata.display_name == "README.md"
    assert metadata.size_bytes > 0
    assert metadata.extension == ".md"
    assert audit.capability_id == "fs.inspect_file"
    assert audit.outcome == "SUCCEEDED"
    # Metadata dataclass has no content field at all: inspect cannot leak bytes.
    assert not hasattr(metadata, "text")


def test_inspect_directory_reports_directory_kind(executor, registry) -> None:
    metadata, _ = executor.inspect(resource_id=resolve(registry, "src"))
    assert metadata.kind == "directory"


def test_inspect_refuses_an_unissued_resource_id(executor) -> None:
    with pytest.raises(FsCapabilityDenied) as denied:
        executor.inspect(resource_id="file:00000000-0000-4000-8000-000000000000")
    assert denied.value.reason_code == errors.RESOURCE_NOT_REGISTERED


def test_inspect_rejects_unknown_kind_prefix(executor) -> None:
    with pytest.raises(FsCapabilityDenied) as denied:
        executor.inspect(resource_id="process:00000000-0000-4000-8000-000000000000")
    assert denied.value.reason_code == errors.RESOURCE_NOT_REGISTERED


# ---------------------------------------------------------------------------
# B. Read — strict decoding, bounds, sensitivity
# ---------------------------------------------------------------------------


def test_read_returns_exact_text_and_digest(executor, registry, tree) -> None:
    import hashlib

    result, audit = executor.read_file(resource_id=resolve(registry, "src/module.py"))
    expected = tree.module.read_bytes()
    assert result.text == expected.decode("utf-8")
    assert result.sha256 == hashlib.sha256(expected).hexdigest()
    assert result.encoding == "utf-8"
    assert result.truncated is False
    assert result.total_bytes == len(expected)
    assert audit.outcome == "SUCCEEDED"
    # The audit trail never carries content.
    assert "def needle" not in repr(audit.detail)


def test_read_reports_truncation_honestly(executor, registry, tree) -> None:
    result, audit = executor.read_file(resource_id=resolve(registry, "README.md"), max_bytes=10)
    assert len(result.text.encode()) <= 10
    assert result.truncated is True
    assert result.total_bytes == len(tree.readme.read_bytes())
    assert result.returned_bytes == 10
    assert audit.outcome == "PARTIAL"
    assert audit.reason_code == errors.READ_TRUNCATED


def test_read_default_bound_is_well_under_the_hard_ceiling(executor, registry) -> None:
    bounds = ReadBounds.clamp(None)
    assert bounds.max_bytes < MAX_READ_BYTES
    with pytest.raises(ValueError):
        ReadBounds(max_bytes=MAX_READ_BYTES + 1)


def test_read_refuses_binary_payloads(executor, registry) -> None:
    with pytest.raises(FsCapabilityDenied) as denied:
        executor.read_file(resource_id=resolve(registry, "blob.bin"))
    assert denied.value.reason_code == errors.BINARY_CONTENT_DENIED


def test_read_refuses_invalid_utf8(executor, tree, registry) -> None:
    (tree.root / "latin1.txt").write_bytes(b"caf\xe9 not utf8\n")
    with pytest.raises(FsCapabilityDenied) as denied:
        executor.read_file(resource_id=resolve(registry, "latin1.txt"))
    assert denied.value.reason_code == errors.INVALID_ENCODING


def test_read_refuses_a_secret_named_file(executor, registry) -> None:
    # The registry already refuses to resolve .env; assert that boundary holds.
    with pytest.raises(ResourceRegistryError):
        resolve(registry, ".env")


def test_read_refuses_directory_targets(executor, registry) -> None:
    with pytest.raises(FsCapabilityDenied) as denied:
        executor.read_file(resource_id=resolve(registry, "src"))
    assert denied.value.reason_code == errors.UNSUPPORTED_RESOURCE_TYPE


def test_read_refuses_content_that_embeds_credentials(executor, tree, registry) -> None:
    leaked = tree.root / "config.txt"
    leaked.write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    with pytest.raises(FsCapabilityDenied) as denied:
        executor.read_file(resource_id=resolve(registry, "config.txt"))
    assert denied.value.reason_code == errors.SENSITIVE_CONTENT_DENIED


def test_read_refuses_a_capability_outside_root_scope(tree) -> None:
    registry = build_registry(tree, capabilities=frozenset({"fs.inspect_file"}))
    executor = FilesystemExecutor(registry)
    resource_id = resolve(registry, "README.md")
    with pytest.raises(FsCapabilityDenied) as denied:
        executor.read_file(resource_id=resource_id)
    assert denied.value.reason_code == errors.CAPABILITY_OUTSIDE_ROOT_SCOPE


def test_read_detects_a_file_replaced_after_resolution(executor, registry, tree) -> None:
    resource_id = resolve(registry, "README.md")
    # Swap the file for a different inode behind the registry's back.
    original = tree.readme
    replacement = tree.root / "replacement.tmp"
    replacement.write_text("different content entirely\n", encoding="utf-8")
    os.replace(replacement, original)
    with pytest.raises(FsCapabilityDenied) as denied:
        executor.read_file(resource_id=resource_id)
    assert denied.value.reason_code in {
        errors.RESOURCE_VERSION_CHANGED,
        errors.RESOURCE_IDENTITY_CHANGED,
    }


def test_read_refuses_hard_linked_files(tree) -> None:
    link = tree.root / "hardlink.txt"
    os.link(tree.readme, link)
    registry = build_registry(tree)
    # The registry refuses to resolve a multiply-linked file at all.
    with pytest.raises(ResourceRegistryError) as refused:
        resolve(registry, "hardlink.txt")
    assert refused.value.reason_code == "hard_link_not_allowed"


# ---------------------------------------------------------------------------
# C. Search — bounded, deterministic, cancellable
# ---------------------------------------------------------------------------


def test_search_finds_matches_deterministically(executor, registry) -> None:
    first, audit = executor.search(resource_id=resolve(registry, ""), query="needle")
    paths = [(match["relative_path"], match["line_number"]) for match in first.matches]
    assert ("README.md", 3) in paths
    assert ("src/module.py", 1) in paths
    assert ("docs/deep/notes.txt", 1) in paths
    assert first.status == "SUCCEEDED"
    assert audit.capability_id == "fs.search"
    # Repeating the search yields the identical sequence.
    second, _ = executor.search(resource_id=resolve(registry, ""), query="needle")
    assert second.matches == first.matches


def test_search_skips_binary_and_secret_files(executor, registry) -> None:
    result, _ = executor.search(resource_id=resolve(registry, ""), query="needle")
    paths = {match["relative_path"] for match in result.matches}
    assert "blob.bin" not in paths
    assert ".env" not in paths
    assert result.files_skipped >= 0


def test_search_reports_partial_results_when_the_limit_is_hit(executor, registry) -> None:
    result, audit = executor.search(
        resource_id=resolve(registry, ""),
        query="needle",
        bounds=SearchBounds(max_results=1),
    )
    assert len(result.matches) == 1
    assert result.status == "PARTIAL"
    assert result.partial_reason == errors.SEARCH_LIMIT_EXCEEDED
    assert audit.outcome == "PARTIAL"


def test_search_cancellation_stops_promptly(executor, registry) -> None:
    calls = {"n": 0}

    def cancelled() -> bool:
        calls["n"] += 1
        return calls["n"] > 0

    result, audit = executor.search(
        resource_id=resolve(registry, ""), query="needle", cancelled=cancelled
    )
    assert result.status == "PARTIAL"
    assert result.partial_reason == errors.SEARCH_CANCELLED
    assert result.matches == ()
    assert audit.outcome == "PARTIAL"


def test_search_timeout_is_reported_not_hidden(registry) -> None:
    """A wall-clock overrun yields a truthful PARTIAL, never a silent short list."""

    from aether.core.fs.search import search_tree

    ticks = iter([0.0, 0.0, 1_000.0, 1_000.0, 1_000.0])
    outcome = search_tree(
        registry.root_by_alias("synthetic-project").canonical_root,
        query="needle",
        bounds=SearchBounds(timeout_seconds=1.0),
        now=lambda: next(ticks, 1_000.0),
    )
    assert outcome.truncated is True
    assert outcome.partial_reason == errors.SEARCH_TIMEOUT


def test_search_rejects_empty_and_oversized_queries(executor, registry) -> None:
    root_id = resolve(registry, "")
    for query in ("", "   ", "x" * 5_000):
        with pytest.raises(FsCapabilityDenied) as denied:
            executor.search(resource_id=root_id, query=query)
        assert denied.value.reason_code == errors.SEARCH_QUERY_INVALID


def test_search_refuses_file_targets(executor, registry) -> None:
    with pytest.raises(FsCapabilityDenied) as denied:
        executor.search(resource_id=resolve(registry, "README.md"), query="needle")
    assert denied.value.reason_code == errors.UNSUPPORTED_RESOURCE_TYPE


def test_search_does_not_descend_into_node_modules(tree) -> None:
    vendored = tree.root / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("needle in vendored code\n", encoding="utf-8")
    registry = build_registry(tree)
    executor = FilesystemExecutor(registry)
    result, _ = executor.search(resource_id=resolve(registry, ""), query="needle")
    assert "node_modules/pkg/index.js" not in {m["relative_path"] for m in result.matches}


def test_search_depth_bound_is_enforced(tree) -> None:
    deep = tree.root
    for index in range(12):
        deep = deep / f"level{index}"
    deep.mkdir(parents=True)
    (deep / "leaf.txt").write_text("needle at depth\n", encoding="utf-8")
    registry = build_registry(tree)
    executor = FilesystemExecutor(registry)
    result, _ = executor.search(
        resource_id=resolve(registry, ""),
        query="needle",
        bounds=SearchBounds(max_depth=2),
    )
    assert result.status == "PARTIAL"
    assert result.partial_reason == errors.SEARCH_DEPTH_EXCEEDED
    assert all("level" not in m["relative_path"] for m in result.matches)


# ---------------------------------------------------------------------------
# D. Open — delegated, honestly reported
# ---------------------------------------------------------------------------


def test_open_reports_shell_acceptance_without_claiming_a_process(
    executor, registry, monkeypatch
) -> None:
    calls: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        assert kwargs.get("shell") is False
        assert isinstance(argv, list)
        return Completed()

    monkeypatch.setattr("aether.core.fs.executor.subprocess.run", fake_run)
    result, audit = executor.open_target(resource_id=resolve(registry, "src"))
    assert result.status == "SUCCEEDED"
    assert result.verification == "SHELL_ACCEPTED_REQUEST"
    assert "unverified" in result.detail
    assert len(calls) == 1 and len(calls[0]) == 2
    assert audit.capability_id == "fs.open_folder"


def test_open_reports_failure_when_the_shell_rejects(executor, registry, monkeypatch) -> None:
    class Failed:
        returncode = 1
        stdout = b""
        stderr = b""

    monkeypatch.setattr("aether.core.fs.executor.subprocess.run", lambda argv, **kwargs: Failed())
    result, audit = executor.open_target(resource_id=resolve(registry, "src"))
    assert result.status == "FAILED"
    assert audit.reason_code == errors.OPEN_FAILED


def test_open_never_uses_a_shell_string(executor, registry, monkeypatch) -> None:
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["shell"] = kwargs.get("shell")
        return Completed()

    monkeypatch.setattr("aether.core.fs.executor.subprocess.run", fake_run)
    executor.open_target(resource_id=resolve(registry, "src"))
    assert captured["shell"] is False
    assert isinstance(captured["argv"], list)
    assert not any(" " in str(part) and "&&" in str(part) for part in captured["argv"])


def test_open_refuses_network_and_removable_volumes(tree) -> None:
    for kind, expected in (
        (VolumeKind.NETWORK, errors.NETWORK_VOLUME_DENIED),
        (VolumeKind.REMOVABLE, errors.REMOVABLE_VOLUME_DENIED),
    ):
        registry = build_registry(tree, kind=kind)
        executor = FilesystemExecutor(registry)
        with pytest.raises(FsCapabilityDenied) as denied:
            executor.open_target(resource_id=resolve(registry, "src"))
        assert denied.value.reason_code == expected


# ---------------------------------------------------------------------------
# E. Path escape and reparse adversarial cases
# ---------------------------------------------------------------------------


def test_relative_traversal_is_refused(registry) -> None:
    for attempt in ("../outside.txt", "src/../../outside.txt", "src/./module.py"):
        with pytest.raises(ResourceRegistryError):
            resolve(registry, attempt)


def test_absolute_path_injection_is_refused(registry) -> None:
    for attempt in ("/etc/passwd", "C:\\Windows\\System32\\config\\SAM", "\\\\server\\share\\x"):
        with pytest.raises(ResourceRegistryError):
            resolve(registry, attempt)


def test_symlink_escape_is_refused(tree, tmp_path) -> None:
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("needle outside the allowed root\n", encoding="utf-8")
    link = tree.root / "escape.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("host cannot create symlinks")
    registry = build_registry(tree)
    with pytest.raises(ResourceRegistryError) as refused:
        resolve(registry, "escape.txt")
    assert "reparse" in refused.value.reason_code


def test_search_does_not_follow_a_symlinked_directory(tree, tmp_path) -> None:
    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    (outside_dir / "leak.txt").write_text("needle must not be found here\n", encoding="utf-8")
    link = tree.root / "linked"
    try:
        link.symlink_to(outside_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("host cannot create directory symlinks")
    registry = build_registry(tree)
    executor = FilesystemExecutor(registry)
    result, _ = executor.search(resource_id=resolve(registry, ""), query="needle")
    assert not any("leak.txt" in m["relative_path"] for m in result.matches)


def test_registry_narrowed_capability_scope_blocks_every_other_capability(tree) -> None:
    registry = build_registry(tree, capabilities=frozenset({"fs.inspect_file"}))
    executor = FilesystemExecutor(registry)
    resource_id = resolve(registry, "README.md")
    with pytest.raises(FsCapabilityDenied):
        executor.read_file(resource_id=resource_id)


# ---------------------------------------------------------------------------
# F. Content screening unit coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [".env", ".env.local", "id_rsa", "server.pem", "credentials.json", "secrets.yaml", "app.key"],
)
def test_secret_filenames_are_recognised(name: str) -> None:
    assert is_secret_filename(name) is True


@pytest.mark.parametrize("name", ["README.md", "module.py", "notes.txt", "data.json"])
def test_ordinary_filenames_are_not_secrets(name: str) -> None:
    assert is_secret_filename(name) is False


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "a" * 36,
        'password = "correct-horse-battery"',
    ],
)
def test_inline_credentials_are_detected(text: str) -> None:
    assert contains_secret_material(text) is True


def test_ordinary_prose_is_not_flagged_as_credentials() -> None:
    assert contains_secret_material("The password field is required in the form.") is False


# ---------------------------------------------------------------------------
# G. No mutation surface exists in this package
# ---------------------------------------------------------------------------


def test_filesystem_package_never_writes_or_deletes() -> None:
    """Phase 2C is read-only by construction, not by convention."""

    package = Path(__file__).parents[1] / "aether" / "core" / "fs"
    forbidden = (
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "shutil.rmtree",
        "shutil.move",
        'open(path, "w"',
        "open(path, 'w'",
        ".write_text(",
        ".write_bytes(",
        "os.replace",
        "os.rename",
    )
    for module in package.glob("*.py"):
        text = module.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{module.name} must not contain {token}"


def test_executor_does_not_import_a_task_store_or_database() -> None:
    """The executor is a capability surface, not a state owner."""

    source = (Path(__file__).parents[1] / "aether" / "core" / "fs" / "executor.py").read_text(
        encoding="utf-8"
    )
    for token in ("sqlite3", "SQLiteTaskStore", "aether.core.persistence"):
        assert token not in source
