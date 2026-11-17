"""Strict manifest loading and file-set validation."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from aether.core.contracts.model import ModelManifest


class ManifestError(ValueError):
    """Invalid or unavailable model manifest."""


def load_manifest(path: Path) -> ModelManifest:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        manifest = ModelManifest.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ManifestError("model manifest is missing or invalid") from exc
    names = [entry.filename for entry in manifest.files]
    if len(names) != len(set(names)):
        raise ManifestError("manifest contains duplicate asset filenames")
    install_path = manifest.local_install_path
    pure_path = PurePosixPath(install_path)
    if (
        not install_path
        or pure_path.is_absolute()
        or str(pure_path) == "."
        or "\\" in install_path
        or ":" in install_path
        or any(part in {"", ".", ".."} for part in pure_path.parts)
    ):
        raise ManifestError("manifest installation path must be a safe relative POSIX path")
    return manifest
