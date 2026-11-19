"""Explicit root registration and canonical, versioned resource resolution."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from uuid import UUID, uuid4, uuid5

from aether.core.contracts.resource import DataClass, Provenance, ResourceKind, ResourceRef
from aether.core.resources.path_safety import (
    PathSafetyError,
    VolumeInfo,
    VolumeInspector,
    VolumeKind,
    is_protected_path,
    reject_reparse_components,
    relative_parts,
)


class ResourceRegistryError(ValueError):
    """A root, resource or requested scope is unknown or unsafe."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class RegisteredRoot:
    root_id: UUID
    alias: str
    canonical_root: Path
    volume: VolumeInfo
    device_id: int
    file_id: int
    data_class: DataClass
    allowed_capabilities: frozenset[str]


@dataclass(frozen=True, slots=True)
class ResolvedResource:
    ref: ResourceRef
    root_id: UUID
    relative_path: str
    canonical_path: Path
    volume_id: str
    device_id: int
    file_id: int
    version_token: str
    data_class: DataClass


class ResourceRegistry:
    """Resolves aliases + relative names to registry-issued resource IDs.

    This is a broker-side path boundary, not an OS sandbox. It rejects unsafe
    path forms and reparse points; future mutation adapters must still re-open
    and verify Windows file handles immediately before access.
    """

    def __init__(
        self,
        *,
        volume_inspector: VolumeInspector | None = None,
        allowed_volume_kinds: frozenset[VolumeKind] = frozenset({VolumeKind.FIXED}),
        windows_semantics: bool | None = None,
    ) -> None:
        self._volume_inspector = volume_inspector or _SystemVolumeInspector()
        self._allowed_volume_kinds = allowed_volume_kinds
        self._windows_semantics = (
            os.name == "nt" if windows_semantics is None else windows_semantics
        )
        self._roots: dict[UUID, RegisteredRoot] = {}
        self._aliases: dict[str, UUID] = {}
        self._resources: dict[str, ResolvedResource] = {}

    def register_root(
        self,
        alias: str,
        path: Path | str,
        *,
        data_class: DataClass = DataClass.PRIVATE,
        allowed_capabilities: frozenset[str] = frozenset(),
    ) -> RegisteredRoot:
        """Register one explicit non-volume-root directory in trusted code."""
        normalized_alias = alias.strip().casefold()
        if not normalized_alias or len(alias) > 64 or normalized_alias in self._aliases:
            raise ResourceRegistryError("root_alias_invalid_or_duplicate")
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ResourceRegistryError("root_must_be_absolute")
        try:
            reject_reparse_components(candidate)
            canonical = candidate.resolve(strict=True)
            metadata = canonical.stat()
        except (OSError, PathSafetyError) as exc:
            raise ResourceRegistryError(_path_error_code(exc)) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise ResourceRegistryError("root_not_directory")
        if _is_volume_root(canonical):
            raise ResourceRegistryError("volume_root_registration_forbidden")
        if is_protected_path(canonical) or data_class == DataClass.SECRET:
            raise ResourceRegistryError("protected_root_forbidden")
        try:
            volume = self._volume_inspector.inspect(canonical)
        except (OSError, PathSafetyError) as exc:
            raise ResourceRegistryError("volume_identity_unavailable") from exc
        if volume.kind not in self._allowed_volume_kinds:
            raise ResourceRegistryError("volume_kind_not_allowed")
        if not allowed_capabilities or any(
            not _is_capability_id(capability) for capability in allowed_capabilities
        ):
            raise ResourceRegistryError("explicit_capability_scope_required")

        root = RegisteredRoot(
            root_id=uuid4(),
            alias=alias.strip(),
            canonical_root=canonical,
            volume=volume,
            device_id=metadata.st_dev,
            file_id=metadata.st_ino,
            data_class=data_class,
            allowed_capabilities=frozenset(allowed_capabilities),
        )
        self._roots[root.root_id] = root
        self._aliases[normalized_alias] = root.root_id
        return root

    def root_by_alias(self, alias: str) -> RegisteredRoot:
        root_id = self._aliases.get(alias.strip().casefold())
        if root_id is None:
            raise ResourceRegistryError("root_not_registered")
        return self.root_by_id(root_id)

    def root_by_id(self, root_id: UUID) -> RegisteredRoot:
        root = self._roots.get(root_id)
        if root is None:
            raise ResourceRegistryError("root_not_registered")
        self._verify_root(root)
        return root

    def resolve(
        self,
        root_id: UUID,
        relative_path: str = "",
        *,
        allow_missing_leaf: bool = False,
    ) -> ResolvedResource:
        """Resolve an existing child, or optionally one safe missing final file."""
        root = self.root_by_id(root_id)
        try:
            parts = () if relative_path == "" else relative_parts(relative_path)
            lexical = root.canonical_root.joinpath(*parts)
            reject_reparse_components(lexical)
            if lexical.exists():
                canonical = lexical.resolve(strict=True)
            elif allow_missing_leaf and parts:
                parent = lexical.parent.resolve(strict=True)
                _ensure_within(parent, root.canonical_root)
                if not parent.is_dir():
                    raise ResourceRegistryError("parent_not_directory")
                canonical = parent / lexical.name
            else:
                raise ResourceRegistryError("resource_not_found")
        except ResourceRegistryError:
            raise
        except (OSError, PathSafetyError) as exc:
            raise ResourceRegistryError(_path_error_code(exc)) from exc

        _ensure_within(canonical, root.canonical_root)
        if is_protected_path(lexical) or is_protected_path(canonical):
            raise ResourceRegistryError("protected_resource_denied")
        exists = canonical.exists()
        if not exists and not allow_missing_leaf:
            raise ResourceRegistryError("resource_not_found")
        try:
            volume = self._volume_inspector.inspect(canonical if exists else canonical.parent)
            metadata = canonical.stat() if exists else canonical.parent.stat()
        except (OSError, PathSafetyError) as exc:
            raise ResourceRegistryError("resource_identity_unavailable") from exc
        if (
            volume.volume_id != root.volume.volume_id
            or volume.kind not in self._allowed_volume_kinds
            or metadata.st_dev != root.device_id
        ):
            raise ResourceRegistryError("volume_boundary_crossing")
        if exists:
            is_file = stat.S_ISREG(metadata.st_mode)
            is_directory = stat.S_ISDIR(metadata.st_mode)
            if not (is_file or is_directory):
                raise ResourceRegistryError("unsupported_resource_type")
            if is_file and getattr(metadata, "st_nlink", 1) > 1:
                raise ResourceRegistryError("hard_link_not_allowed")
        else:
            is_file = True
        kind: ResourceKind = "file" if is_file else "directory"
        relative = _relative_display(canonical, root.canonical_root)
        identity_text = relative.casefold() if self._windows_semantics else relative
        resource_uuid = uuid5(root.root_id, identity_text)
        version = _version_token(volume.volume_id, metadata)
        resource_id = f"{kind}:{resource_uuid}"
        ref = ResourceRef(
            kind=kind,
            resource_id=resource_id,
            observed_version=version,
            data_class=root.data_class,
            provenance=Provenance.SYSTEM_OBSERVED,
        )
        result = ResolvedResource(
            ref=ref,
            root_id=root.root_id,
            relative_path=relative,
            canonical_path=canonical,
            volume_id=volume.volume_id,
            device_id=metadata.st_dev,
            file_id=metadata.st_ino,
            version_token=version,
            data_class=root.data_class,
        )
        existing_identity = self._resources.get(resource_id)
        if (
            existing_identity is not None
            and (
                existing_identity.volume_id != result.volume_id
                or existing_identity.device_id != result.device_id
                or existing_identity.file_id != result.file_id
            )
            and existing_identity.relative_path != result.relative_path
        ):
            raise ResourceRegistryError("resource_identity_collision")
        self._resources[resource_id] = result
        return result

    def authorize_ref(
        self,
        ref: ResourceRef,
        capability_id: str,
        *,
        expected_kind: str | None = None,
        max_data_class: DataClass = DataClass.PRIVATE,
    ) -> ResolvedResource:
        """Re-resolve a broker-issued ref and enforce root scope/version."""
        previous = self._resources.get(ref.resource_id)
        if previous is None:
            raise ResourceRegistryError("resource_id_not_registered")
        if ref.kind != previous.ref.kind or (
            expected_kind is not None and ref.kind != expected_kind
        ):
            raise ResourceRegistryError("resource_kind_mismatch")
        if ref.observed_version != previous.version_token:
            raise ResourceRegistryError("resource_reference_version_mismatch")
        root = self.root_by_id(previous.root_id)
        if capability_id not in root.allowed_capabilities:
            raise ResourceRegistryError("capability_outside_root_scope")
        if root.data_class == DataClass.SECRET or _classification_rank(
            root.data_class
        ) > _classification_rank(max_data_class):
            raise ResourceRegistryError("sensitive_resource_denied")
        refreshed = self.resolve(root.root_id, previous.relative_path)
        if refreshed.version_token != ref.observed_version:
            raise ResourceRegistryError("resource_version_changed")
        return refreshed

    def _verify_root(self, root: RegisteredRoot) -> None:
        try:
            reject_reparse_components(root.canonical_root)
            canonical = root.canonical_root.resolve(strict=True)
            metadata = canonical.stat()
            volume = self._volume_inspector.inspect(canonical)
        except (OSError, PathSafetyError) as exc:
            raise ResourceRegistryError("registered_root_unavailable") from exc
        if (
            canonical != root.canonical_root
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != root.device_id
            or metadata.st_ino != root.file_id
            or volume.volume_id != root.volume.volume_id
            or volume.kind not in self._allowed_volume_kinds
        ):
            raise ResourceRegistryError("registered_root_identity_changed")


def _is_volume_root(path: Path) -> bool:
    if path.parent == path:
        return True
    if isinstance(path, PureWindowsPath) or os.name == "nt":
        windows_path = PureWindowsPath(str(path))
        return bool(windows_path.drive) and len(windows_path.parts) <= 1
    return False


def _ensure_within(candidate: Path, root: Path) -> None:
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ResourceRegistryError("path_escape_denied") from exc


def _relative_display(candidate: Path, root: Path) -> str:
    if candidate == root:
        return ""
    try:
        return candidate.relative_to(root).as_posix()
    except ValueError as exc:
        raise ResourceRegistryError("path_escape_denied") from exc


def _version_token(volume_id: str, metadata: os.stat_result) -> str:
    value = {
        "volume": volume_id,
        "device": metadata.st_dev,
        "file": metadata.st_ino,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "mode": metadata.st_mode,
    }
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _classification_rank(value: DataClass) -> int:
    return {
        DataClass.PUBLIC: 0,
        DataClass.INTERNAL: 1,
        DataClass.PRIVATE: 2,
        DataClass.SECRET: 3,
    }[value]


def _is_capability_id(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 128
        and all(
            char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
            for char in value
        )
    )


def _path_error_code(exc: BaseException) -> str:
    if isinstance(exc, PathSafetyError):
        return str(exc)
    return "path_unavailable"


class _SystemVolumeInspector:
    def inspect(self, path: Path) -> VolumeInfo:
        from aether.core.resources.path_safety import inspect_volume

        return inspect_volume(path)
