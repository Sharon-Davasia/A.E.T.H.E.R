"""The single filesystem capability executor (Phase 2C read/inspect/search/open).

This is the only place in the backend that performs real, non-mutating
filesystem operations on behalf of a task. It is deliberately *not* an adapter
framework: it exposes exactly four typed operations, each of which

1. accepts a broker-resolved :class:`ResourceRef`, never a raw path;
2. asks the :class:`ResourceRegistry` to re-resolve and re-verify identity,
   version, root scope and data class *immediately* before touching the disk;
3. enforces root/capability/sensitivity policy itself, in addition to whatever
   the broker already decided;
4. reports an honest outcome — including the cases where it declined to act or
   could only act partially.

**TOCTOU honesty.** Step 2 narrows the race between "policy approved this
resource" and "we opened this resource"; it does not eliminate it. The identity
and version token are re-derived from a live ``stat`` and, for reads, the file
handle is opened and its identity re-checked against that ``stat`` before any
byte is returned. For opens there is no byte-level verification because the
effect is delegated to the OS shell — which is exactly why ``open`` is limited
to NAVIGATE-tier targets and reports only that a launch was requested, with the
spawned-process attribution left to a future adapter that can verify it.

Nothing here writes, renames, deletes or executes anything beyond asking the
Windows shell to open an allow-listed path with its registered handler.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from aether.core.contracts.resource import ResourceRef
from aether.core.fs import errors
from aether.core.fs.content import ContentRejected, decode_text, is_secret_filename
from aether.core.fs.limits import ReadBounds, SearchBounds
from aether.core.fs.search import SearchRejected, search_tree
from aether.core.resources.path_safety import (
    PathSafetyError,
    VolumeKind,
    is_protected_path,
    reject_reparse_components,
)
from aether.core.resources.registry import (
    ResolvedResource,
    ResourceRegistry,
    ResourceRegistryError,
)

OutcomeStatus = Literal["SUCCEEDED", "FAILED", "PARTIAL"]


class FsCapabilityDenied(Exception):
    """The requested operation is refused; nothing was read, opened or changed."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True, slots=True)
class FileMetadata:
    """Metadata-only inspection result. Never contains file bytes."""

    resource_id: str
    display_name: str
    kind: Literal["file", "directory"]
    size_bytes: int
    modified_at: datetime
    version_token: str
    extension: str


@dataclass(frozen=True, slots=True)
class ReadResult:
    """One bounded read, with the evidence needed to verify it later."""

    resource_id: str
    display_name: str
    text: str
    encoding: str
    total_bytes: int
    returned_bytes: int
    truncated: bool
    sha256: str
    version_token: str
    data_class: str


@dataclass(frozen=True, slots=True)
class SearchResult:
    resource_id: str
    query: str
    matches: tuple[dict[str, object], ...]
    files_scanned: int
    files_skipped: int
    status: OutcomeStatus
    partial_reason: str | None


@dataclass(frozen=True, slots=True)
class OpenResult:
    """Result of asking the OS to open one allow-listed path.

    ``status`` is ``SUCCEEDED`` only when the shell accepted the request. It is
    deliberately not "the application opened": this phase cannot attribute a
    process to the path, and claiming otherwise would be a fabricated success.
    """

    resource_id: str
    display_name: str
    target_kind: Literal["file", "directory"]
    status: OutcomeStatus
    verification: str
    detail: str


@dataclass(frozen=True, slots=True)
class OperationAudit:
    """Audit record for one filesystem operation (never contains content)."""

    capability_id: str
    task_id: str
    resource_id: str
    outcome: OutcomeStatus
    reason_code: str
    started_at: datetime
    finished_at: datetime
    detail: dict[str, object] = field(default_factory=dict)


class FilesystemExecutor:
    """Executes the four non-mutating Phase 2C capabilities, fail-closed."""

    #: Volumes this executor may touch. Network, removable, optical and unknown
    #: media are refused outright: device labels are not proof of identity and
    #: the Master Specification requires unknown media to start read-only and
    #: no-execute, which is stronger than this executor can guarantee.
    ALLOWED_VOLUME_KINDS: Final = frozenset({VolumeKind.FIXED})

    def __init__(
        self,
        registry: ResourceRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def registry(self) -> ResourceRegistry:
        """The registry this executor re-verifies against (read-only by use)."""

        return self._registry

    def resource(self, resource_id: str) -> ResolvedResource:
        """Return a previously issued resource, or fail closed."""

        try:
            return self._registry.resource_by_id(resource_id)
        except ResourceRegistryError as exc:
            raise FsCapabilityDenied(
                errors.RESOURCE_NOT_REGISTERED,
                "resource id was never issued by the registry",
            ) from exc

    # -- capabilities ----------------------------------------------------

    def inspect(
        self, *, resource_id: str, expected_kind: str | None = None
    ) -> tuple[FileMetadata, OperationAudit]:
        """Return metadata only. Never reads file content."""

        started = self._clock()
        resolved = self._resolve(resource_id, capability="fs.inspect_file")
        if expected_kind is not None and resolved.ref.kind != expected_kind:
            raise FsCapabilityDenied(
                errors.UNSUPPORTED_RESOURCE_TYPE, "resource kind does not match the request"
            )
        path = resolved.canonical_path
        try:
            metadata = path.lstat()
            reject_reparse_components(path)
        except (OSError, PathSafetyError) as exc:
            raise FsCapabilityDenied(errors.RESOURCE_NOT_FOUND, "resource is unavailable") from exc
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            raise FsCapabilityDenied(
                errors.UNSUPPORTED_RESOURCE_TYPE, "not a regular file or directory"
            )
        result = FileMetadata(
            resource_id=resolved.ref.resource_id,
            display_name=path.name,
            kind="file" if stat.S_ISREG(metadata.st_mode) else "directory",
            size_bytes=int(metadata.st_size),
            modified_at=datetime.fromtimestamp(metadata.st_mtime, tz=UTC),
            version_token=resolved.version_token,
            extension=path.suffix.casefold(),
        )
        return result, self._audit(
            "fs.inspect_file", resolved, "SUCCEEDED", "fs_ok", started, size_bytes=result.size_bytes
        )

    def read_file(
        self,
        *,
        resource_id: str,
        max_bytes: int | None = None,
    ) -> tuple[ReadResult, OperationAudit]:
        """Read validated text content under the read bound."""

        import hashlib

        started = self._clock()
        resolved = self._resolve(resource_id, capability="fs.read_file")
        if resolved.ref.kind != "file":
            raise FsCapabilityDenied(errors.UNSUPPORTED_RESOURCE_TYPE, "not a file")
        bounds = ReadBounds.clamp(max_bytes)
        path = resolved.canonical_path
        self._deny_sensitive_leaf(path, resolved)
        try:
            with open(path, "rb") as stream:
                opened = os.fstat(stream.fileno())
                self._verify_handle_identity(opened, resolved)
                total_bytes = int(opened.st_size)
                data = stream.read(bounds.max_bytes)
                after = os.fstat(stream.fileno())
        except FsCapabilityDenied:
            raise
        except (OSError, PathSafetyError) as exc:
            raise FsCapabilityDenied(errors.RESOURCE_NOT_FOUND, "resource is unreadable") from exc
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise FsCapabilityDenied(
                errors.RESOURCE_IDENTITY_CHANGED, "file changed while it was being read"
            )
        truncated = total_bytes > len(data)
        try:
            content = decode_text(data, total_bytes=total_bytes)
        except ContentRejected as exc:
            raise FsCapabilityDenied(exc.reason_code, str(exc)) from exc
        result = ReadResult(
            resource_id=resolved.ref.resource_id,
            display_name=path.name,
            text=content.text,
            encoding=content.encoding,
            total_bytes=content.total_bytes,
            returned_bytes=content.returned_bytes,
            truncated=truncated,
            sha256=hashlib.sha256(data).hexdigest(),
            version_token=resolved.version_token,
            data_class=resolved.data_class.value,
        )
        return result, self._audit(
            "fs.read_file",
            resolved,
            "PARTIAL" if truncated else "SUCCEEDED",
            errors.READ_TRUNCATED if truncated else "fs_ok",
            started,
            returned_bytes=result.returned_bytes,
            total_bytes=result.total_bytes,
        )

    def search(
        self,
        *,
        resource_id: str,
        query: str,
        bounds: SearchBounds | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> tuple[SearchResult, OperationAudit]:
        """Run a bounded deterministic search inside one registered root."""

        started = self._clock()
        resolved = self._resolve(resource_id, capability="fs.search")
        if resolved.ref.kind != "directory":
            raise FsCapabilityDenied(errors.UNSUPPORTED_RESOURCE_TYPE, "not a directory")
        effective = bounds or SearchBounds()
        try:
            outcome = search_tree(
                resolved.canonical_path,
                query=query,
                bounds=effective,
                cancelled=cancelled,
            )
        except SearchRejected as exc:
            raise FsCapabilityDenied(exc.reason_code, str(exc)) from exc
        status: OutcomeStatus = "PARTIAL" if outcome.truncated else "SUCCEEDED"
        reason = outcome.partial_reason or "fs_ok"
        result = SearchResult(
            resource_id=resolved.ref.resource_id,
            query=query,
            matches=tuple(
                {
                    "relative_path": match.relative_path,
                    "line_number": match.line_number,
                    "line_text": match.line_text,
                }
                for match in outcome.matches
            ),
            files_scanned=outcome.files_scanned,
            files_skipped=outcome.files_skipped,
            status=status,
            partial_reason=outcome.partial_reason,
        )
        return result, self._audit(
            "fs.search",
            resolved,
            status,
            reason,
            started,
            files_scanned=outcome.files_scanned,
            matches=len(outcome.matches),
        )

    def open_target(self, *, resource_id: str) -> tuple[OpenResult, OperationAudit]:
        """Ask the OS shell to open one allow-listed file or folder.

        This is the only operation that crosses a process boundary, and it does
        so through a fixed, argument-validated invocation — never a shell
        string, never a model-supplied command. The success claim is limited to
        "the shell accepted the launch request".
        """

        started = self._clock()
        resolved = self._resolve(resource_id, capability="fs.open_folder")
        target_kind: Literal["file", "directory"] = (
            "directory" if resolved.ref.kind == "directory" else "file"
        )
        path = resolved.canonical_path
        self._deny_sensitive_leaf(path, resolved)
        self._require_fixed_volume(resolved)
        try:
            launch = _launch_command(path)
            completed = subprocess.run(
                launch,
                shell=False,
                check=False,
                capture_output=True,
                timeout=15,
                env=_launch_env(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise FsCapabilityDenied(errors.OPEN_FAILED, "the shell refused the open") from exc
        accepted = completed.returncode == 0
        result = OpenResult(
            resource_id=resolved.ref.resource_id,
            display_name=path.name,
            target_kind=target_kind,
            status="SUCCEEDED" if accepted else "FAILED",
            verification="SHELL_ACCEPTED_REQUEST",
            detail=(
                "the operating system accepted the open request; this phase cannot "
                "attribute a running process to the path, so application state is "
                "reported as unverified"
                if accepted
                else "the operating system rejected the open request"
            ),
        )
        return result, self._audit(
            "fs.open_folder",
            resolved,
            "SUCCEEDED" if accepted else "FAILED",
            "fs_ok" if accepted else errors.OPEN_FAILED,
            started,
            target_kind=target_kind,
        )

    # -- internals -------------------------------------------------------

    def _resolve(self, resource_id: str, *, capability: str) -> ResolvedResource:
        """Re-resolve a broker-issued ref and enforce this executor's policy."""

        try:
            return self._registry.authorize_ref(_ref_for(resource_id, self._registry), capability)
        except ResourceRegistryError as exc:
            raise FsCapabilityDenied(_map_registry_error(exc.reason_code), str(exc)) from exc

    def _require_fixed_volume(self, resolved: ResolvedResource) -> None:
        try:
            root = self._registry.root_by_id(resolved.root_id)
        except ResourceRegistryError as exc:
            raise FsCapabilityDenied(errors.RESOURCE_NOT_REGISTERED, str(exc)) from exc
        kind = root.volume.kind
        if kind == VolumeKind.NETWORK:
            raise FsCapabilityDenied(
                errors.NETWORK_VOLUME_DENIED, "network volumes are not available to this phase"
            )
        if kind == VolumeKind.REMOVABLE:
            raise FsCapabilityDenied(
                errors.REMOVABLE_VOLUME_DENIED,
                "removable media requires a dedicated review before use",
            )
        if kind not in self.ALLOWED_VOLUME_KINDS:
            raise FsCapabilityDenied(errors.UNSUPPORTED_FILESYSTEM, "volume kind is not supported")

    def _deny_sensitive_leaf(self, path: Path, resolved: ResolvedResource) -> None:
        if is_secret_filename(path.name) or is_protected_path(path):
            raise FsCapabilityDenied(
                errors.PROTECTED_PATH_DENIED,
                "secret or protected paths are excluded from ordinary capabilities",
            )
        if resolved.data_class.value == "SECRET":
            raise FsCapabilityDenied(
                errors.SECRET_CLASS_DENIED, "SECRET-class resources are never readable"
            )

    def _verify_handle_identity(self, opened: os.stat_result, resolved: ResolvedResource) -> None:
        if not stat.S_ISREG(opened.st_mode):
            raise FsCapabilityDenied(
                errors.UNSUPPORTED_RESOURCE_TYPE, "handle is not a regular file"
            )
        if getattr(opened, "st_nlink", 1) > 1:
            raise FsCapabilityDenied(errors.HARD_LINK_DENIED, "hard-linked files are not readable")
        if (opened.st_dev, opened.st_ino) != (resolved.device_id, resolved.file_id):
            raise FsCapabilityDenied(
                errors.RESOURCE_IDENTITY_CHANGED,
                "the opened file is not the resource that was authorized",
            )

    def _audit(
        self,
        capability_id: str,
        resolved: ResolvedResource,
        outcome: OutcomeStatus,
        reason_code: str,
        started: datetime,
        **detail: object,
    ) -> OperationAudit:
        return OperationAudit(
            capability_id=capability_id,
            task_id="",
            resource_id=resolved.ref.resource_id,
            outcome=outcome,
            reason_code=reason_code,
            started_at=started,
            finished_at=self._clock(),
            detail=dict(detail),
        )


def _ref_for(resource_id: str, registry: ResourceRegistry) -> ResourceRef:
    """Rebuild a :class:`ResourceRef` from a registry-issued id.

    The registry is the authority on identity, so the reference is looked up
    rather than trusted from the caller: an id the registry has never issued
    fails closed.
    """

    kind = resource_id.split(":", 1)[0]
    if kind not in {"file", "directory"}:
        raise FsCapabilityDenied(errors.RESOURCE_NOT_REGISTERED, "unknown resource kind")
    try:
        previous = registry.resource_by_id(resource_id)
    except ResourceRegistryError as exc:
        raise FsCapabilityDenied(
            errors.RESOURCE_NOT_REGISTERED, "resource id was never issued by the registry"
        ) from exc
    return ResourceRef(
        kind=previous.ref.kind,
        resource_id=previous.ref.resource_id,
        observed_version=previous.version_token,
        data_class=previous.data_class,
    )


def _map_registry_error(reason_code: str) -> str:
    mapping = {
        "resource_id_not_registered": errors.RESOURCE_NOT_REGISTERED,
        "resource_kind_mismatch": errors.UNSUPPORTED_RESOURCE_TYPE,
        "resource_reference_version_mismatch": errors.RESOURCE_VERSION_CHANGED,
        "resource_version_changed": errors.RESOURCE_VERSION_CHANGED,
        "capability_outside_root_scope": errors.CAPABILITY_OUTSIDE_ROOT_SCOPE,
        "sensitive_resource_denied": errors.SENSITIVE_CONTENT_DENIED,
        "protected_resource_denied": errors.PROTECTED_PATH_DENIED,
        "path_escape_denied": errors.OUTSIDE_ALLOWED_ROOT,
        "reparse_point_not_allowed": errors.REPARSE_ESCAPE_DENIED,
        "hard_link_not_allowed": errors.HARD_LINK_DENIED,
        "volume_boundary_crossing": errors.OUTSIDE_ALLOWED_ROOT,
        "unsupported_resource_type": errors.UNSUPPORTED_RESOURCE_TYPE,
        "resource_not_found": errors.RESOURCE_NOT_FOUND,
    }
    return mapping.get(reason_code, errors.PATH_UNSAFE)


def _launch_command(path: Path) -> list[str]:
    """Return the fixed launch argv for the current platform.

    Windows uses ``os.startfile`` semantics through ``explorer.exe``; POSIX uses
    ``xdg-open``/``open``. The path is a single argv element — there is no shell
    string, so no path can inject an extra command.
    """

    if sys.platform == "win32":
        return ["explorer.exe", str(path)]
    if sys.platform == "darwin":
        return ["open", str(path)]
    return ["xdg-open", str(path)]


def _launch_env() -> dict[str, str]:
    """Minimal environment for the launcher; never inherits tokens or proxies."""

    if sys.platform == "win32":
        # Windows environment variable names are case-insensitive, so accept
        # either conventional spelling rather than assuming one.
        root = (
            os.environ.get("SYSTEMROOT")
            or os.environ.get("SystemRoot")  # noqa: SIM112 - legitimate spelling
            or r"C:\Windows"
        )
        return {
            "SYSTEMROOT": root,
            "WINDIR": root,
            "PATH": f"{root}\\System32",
        }
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


__all__ = [
    "FileMetadata",
    "FilesystemExecutor",
    "FsCapabilityDenied",
    "OpenResult",
    "OperationAudit",
    "ReadResult",
    "SearchResult",
]
