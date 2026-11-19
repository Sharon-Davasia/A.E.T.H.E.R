"""Adversarial tests for Phase 2 canonical resource registration/resolution."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from aether.core.contracts.resource import DataClass
from aether.core.resources.path_safety import (
    PathSafetyError,
    VolumeInfo,
    VolumeKind,
    relative_parts,
)
from aether.core.resources.registry import ResourceRegistry, ResourceRegistryError


class FixedVolume:
    def inspect(self, path: Path) -> VolumeInfo:
        del path
        return VolumeInfo("synthetic-volume-1", VolumeKind.FIXED)


class UnknownVolume:
    def inspect(self, path: Path) -> VolumeInfo:
        del path
        return VolumeInfo("unidentified", VolumeKind.UNKNOWN)


def _registry(path: Path, *, capabilities: frozenset[str] = frozenset({"fs.read_file"})):
    registry = ResourceRegistry(volume_inspector=FixedVolume())
    root = registry.register_root("demo", path, allowed_capabilities=capabilities)
    return registry, root


@pytest.mark.parametrize(
    "raw",
    [
        "../outside.txt",
        "a/../../outside.txt",
        r"..\outside.txt",
        r"C:\Windows\win.ini",
        r"D:\\Projects\\private.txt",
        r"\\server\share\private.txt",
        r"\\?\C:\Windows\win.ini",
        "folder/../secret.txt",
        "folder//file.txt",
        "folder:stream.txt",
        "CON.txt",
        "COM¹.txt",
        "folder/COM¹.txt",
        "nested/LpT².LOG",
        "Com³.backup.txt",
        "CONIN$",
        "cOnIn$.txt",
        "folder/CONOUT$",
        "nested/cOnOuT$.log",
        "trailing.",
        "/absolute/path.txt",
    ],
)
def test_windows_lexical_path_substitution_and_traversal_are_rejected(raw: str) -> None:
    with pytest.raises(PathSafetyError):
        relative_parts(raw)


def test_registry_resolves_only_under_explicit_registered_root(tmp_path: Path) -> None:
    workspace = tmp_path / "Projects"
    sibling = tmp_path / "Projects-evil"
    workspace.mkdir()
    sibling.mkdir()
    (workspace / "readme.txt").write_text("synthetic safe file", encoding="utf-8")
    (sibling / "secret.txt").write_text("synthetic outside file", encoding="utf-8")
    registry, root = _registry(workspace)

    resolved = registry.resolve(root.root_id, "readme.txt")
    assert resolved.ref.kind == "file"
    assert resolved.canonical_path == (workspace / "readme.txt").resolve()
    assert resolved.ref.resource_id.startswith("file:")
    assert UUID(resolved.ref.resource_id.removeprefix("file:"))
    assert resolved.relative_path == "readme.txt"
    assert "synthetic safe" not in resolved.ref.resource_id
    with pytest.raises(ResourceRegistryError, match="path_traversal_not_allowed"):
        registry.resolve(root.root_id, "../Projects-evil/secret.txt")
    with pytest.raises(ResourceRegistryError, match="root_not_registered"):
        registry.root_by_alias("unregistered")


def test_resource_ids_are_registry_issued_and_version_drift_is_detected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "note.txt"
    target.write_text("before", encoding="utf-8")
    registry, root = _registry(workspace)
    resolved = registry.resolve(root.root_id, "note.txt")
    assert registry.authorize_ref(resolved.ref, "fs.read_file", expected_kind="file")

    target.write_text("changed content", encoding="utf-8")
    with pytest.raises(ResourceRegistryError, match="resource_version_changed"):
        registry.authorize_ref(resolved.ref, "fs.read_file", expected_kind="file")
    with pytest.raises(ResourceRegistryError, match="resource_id_not_registered"):
        registry.authorize_ref(
            type(resolved.ref)(
                kind="file", resource_id="file:00000000-0000-0000-0000-000000000000"
            ),
            "fs.read_file",
        )


def test_windows_case_sensitive_distinct_files_never_share_resource_id(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "case-sensitive-workspace"
    workspace.mkdir()
    uppercase = workspace / "A.txt"
    lowercase = workspace / "a.txt"
    uppercase.write_text("synthetic uppercase entry", encoding="utf-8")
    lowercase.write_text("synthetic lowercase entry", encoding="utf-8")
    if uppercase.stat().st_ino == lowercase.stat().st_ino:
        pytest.skip("fixture volume does not support case-sensitive sibling files")

    registry = ResourceRegistry(volume_inspector=FixedVolume(), windows_semantics=True)
    root = registry.register_root(
        "case-test", workspace, allowed_capabilities=frozenset({"fs.read_file"})
    )
    first = registry.resolve(root.root_id, "A.txt")
    with pytest.raises(ResourceRegistryError, match="resource_identity_collision"):
        registry.resolve(root.root_id, "a.txt")

    # The rejected resolution must not overwrite the first resource's mapping.
    still_first = registry.authorize_ref(first.ref, "fs.read_file", expected_kind="file")
    assert still_first.canonical_path == uppercase.resolve()
    assert still_first.file_id == uppercase.stat().st_ino


def test_whitespace_only_root_alias_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    registry = ResourceRegistry(volume_inspector=FixedVolume())
    with pytest.raises(ResourceRegistryError, match="root_alias_invalid_or_duplicate"):
        registry.register_root(" \t ", workspace, allowed_capabilities=frozenset({"fs.read_file"}))


def test_sibling_prefix_and_absolute_child_paths_never_match_root(tmp_path: Path) -> None:
    workspace = tmp_path / "root"
    prefix_sibling = tmp_path / "root-escape"
    workspace.mkdir()
    prefix_sibling.mkdir()
    (prefix_sibling / "secret.txt").write_text("synthetic secret", encoding="utf-8")
    registry, root = _registry(workspace)
    with pytest.raises(ResourceRegistryError):
        registry.resolve(root.root_id, str(prefix_sibling / "secret.txt"))


def test_symlink_escape_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("synthetic secret", encoding="utf-8")
    try:
        (workspace / "escape").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable in this environment: {exc}")
    registry, root = _registry(workspace)
    with pytest.raises(ResourceRegistryError, match="reparse_point_not_allowed"):
        registry.resolve(root.root_id, "escape/secret.txt")


def test_secret_files_and_secret_roots_are_denied(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".env").write_text("SYNTHETIC=not-a-secret", encoding="utf-8")
    (workspace / ".git").mkdir()
    (workspace / ".git" / "config").write_text("synthetic config", encoding="utf-8")
    registry, root = _registry(workspace)
    with pytest.raises(ResourceRegistryError, match="protected_resource_denied"):
        registry.resolve(root.root_id, ".env")
    with pytest.raises(ResourceRegistryError, match="protected_resource_denied"):
        registry.resolve(root.root_id, ".git/config")

    with pytest.raises(ResourceRegistryError, match="protected_root_forbidden"):
        registry.register_root(
            "classified",
            workspace,
            data_class=DataClass.SECRET,
            allowed_capabilities=frozenset({"fs.read_file"}),
        )


def test_registration_requires_explicit_narrow_scope_and_known_fixed_volume(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    registry = ResourceRegistry(volume_inspector=FixedVolume())
    with pytest.raises(ResourceRegistryError, match="explicit_capability_scope_required"):
        registry.register_root("empty", workspace)

    unknown = ResourceRegistry(volume_inspector=UnknownVolume())
    with pytest.raises(ResourceRegistryError, match="volume_kind_not_allowed"):
        unknown.register_root(
            "unknown", workspace, allowed_capabilities=frozenset({"fs.read_file"})
        )


def test_volume_root_cannot_be_registered(tmp_path: Path) -> None:
    registry = ResourceRegistry(volume_inspector=FixedVolume())
    with pytest.raises(ResourceRegistryError):
        registry.register_root("root", Path("/"), allowed_capabilities=frozenset({"fs.read_file"}))
