"""Streaming SHA-256 and strict model-directory validation."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

from aether.core.contracts.model import ModelManifest


class IntegrityError(ValueError):
    """A required file is missing, unexpected, incorrectly sized or mismatched."""


def verify_runtime_executable(executable: Path, expected_sha256: str) -> str:
    """Verify the exact configured runtime executable before any launch."""
    if not executable.is_file():
        raise IntegrityError("runtime executable is missing or not a regular file")
    digest = hashlib.sha256()
    try:
        with executable.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise IntegrityError("runtime executable is unavailable") from exc
    actual = digest.hexdigest()
    if actual.casefold() != expected_sha256.casefold():
        raise IntegrityError("runtime executable SHA-256 mismatch")
    return actual


def verify_model_assets(model_root: Path, manifest: ModelManifest) -> dict[str, str]:
    relative = manifest.local_install_path
    relative_path = PurePosixPath(relative)
    if (
        not relative
        or relative_path.is_absolute()
        or str(relative_path) == "."
        or "\\" in relative
        or ":" in relative
        or ".." in relative_path.parts
    ):
        raise IntegrityError("model installation path is not a safe relative path")
    try:
        base = model_root.resolve(strict=True)
        install = (base / Path(*relative_path.parts)).resolve(strict=True)
    except OSError as exc:
        raise IntegrityError("model installation directory is missing or inaccessible") from exc
    if not base.is_dir():
        raise IntegrityError("configured model root is not a directory")
    if not install.is_relative_to(base) or not install.is_dir():
        raise IntegrityError("model installation directory escapes configured root")
    expected = {item.filename for item in manifest.files}
    found = {path.name for path in install.iterdir()}
    if found != expected:
        missing = sorted(expected - found)
        unexpected = sorted(found - expected)
        raise IntegrityError(
            f"model asset set mismatch (missing={missing}, unexpected={unexpected})"
        )
    results: dict[str, str] = {}
    for asset in manifest.files:
        path = install / asset.filename
        if path.is_symlink() or path.resolve(strict=True).parent != install:
            raise IntegrityError("model asset escapes the configured installation directory")
        if not path.is_file():
            raise IntegrityError(f"model asset is not a regular file: {asset.filename}")
        if path.stat().st_size != asset.size_bytes:
            raise IntegrityError(f"model asset size mismatch: {asset.filename}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        actual = digest.hexdigest()
        if actual.casefold() != asset.sha256.casefold():
            raise IntegrityError(f"model asset SHA-256 mismatch: {asset.filename}")
        results[asset.filename] = actual
    return results
