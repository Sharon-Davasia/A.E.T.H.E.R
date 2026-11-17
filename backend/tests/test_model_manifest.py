"""Manifest schema and checksum enforcement without model downloads."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from aether.core.contracts.model import ModelManifest
from aether.model_runtime.integrity import (
    IntegrityError,
    verify_model_assets,
    verify_runtime_executable,
)
from aether.model_runtime.manifest import ManifestError, load_manifest


def _manifest(path, data: bytes) -> ModelManifest:
    return ModelManifest(
        model_id="synthetic-q4",
        publisher="synthetic publisher",
        source_repository="https://example.invalid/source",
        source_revision="a" * 40,
        conversion_repository="https://example.invalid/conversion",
        conversion_revision="b" * 40,
        architecture="test-arch",
        quantisation="Q4_K_M",
        files=[
            {
                "filename": "fixture.gguf",
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        ],
        license="TEST-ONLY",
        local_install_path="candidate",
        context_length=4096,
        chat_template="synthetic-template",
        runtime={
            "version": "test-version",
            "build_id": "test-build",
            "executable_sha256": "c" * 64,
            "cuda_required": False,
        },
        text_generation=True,
    )


def test_valid_synthetic_manifest_asset_passes_hash_and_size(tmp_path) -> None:
    content = b"synthetic model bytes, not a model"
    asset_dir = tmp_path / "candidate"
    asset_dir.mkdir()
    (asset_dir / "fixture.gguf").write_bytes(content)
    manifest = _manifest(tmp_path, content)
    result = verify_model_assets(tmp_path, manifest)
    assert result["fixture.gguf"] == hashlib.sha256(content).hexdigest()


def test_missing_mismatched_and_unexpected_assets_fail_closed(tmp_path) -> None:
    content = b"abc"
    asset_dir = tmp_path / "candidate"
    asset_dir.mkdir()
    manifest = _manifest(tmp_path, content)
    with pytest.raises(IntegrityError, match="asset set mismatch"):
        verify_model_assets(tmp_path, manifest)
    (asset_dir / "fixture.gguf").write_bytes(b"wrong")
    with pytest.raises(IntegrityError, match="size mismatch"):
        verify_model_assets(tmp_path, manifest)
    (asset_dir / "fixture.gguf").write_bytes(content)
    (asset_dir / "extra.bin").write_bytes(b"extra")
    with pytest.raises(IntegrityError, match="asset set mismatch"):
        verify_model_assets(tmp_path, manifest)


def test_missing_model_directory_fails_closed(tmp_path) -> None:
    manifest = _manifest(tmp_path, b"placeholder")
    with pytest.raises(IntegrityError, match="missing or inaccessible"):
        verify_model_assets(tmp_path, manifest)


def test_checksum_mismatch_fails(tmp_path) -> None:
    asset_dir = tmp_path / "candidate"
    asset_dir.mkdir()
    (asset_dir / "fixture.gguf").write_bytes(b"abc")
    manifest = _manifest(tmp_path, b"xyz")
    with pytest.raises(IntegrityError, match="SHA-256 mismatch"):
        verify_model_assets(tmp_path, manifest)


def test_manifest_rejects_bad_hash_and_absolute_install_path(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        ModelManifest(
            model_id="x",
            publisher="x",
            source_repository="x",
            source_revision="x",
            conversion_repository="x",
            conversion_revision="x",
            architecture="x",
            quantisation="Q4_K_M",
            files=[{"filename": "m.gguf", "size_bytes": 1, "sha256": "bad"}],
            license="pending",
            local_install_path="models",
            context_length=4096,
            chat_template="unknown",
            runtime={"version": "unknown", "build_id": "unknown", "executable_sha256": "d" * 64},
            text_generation=True,
        )
    data = _manifest(tmp_path, b"a").model_dump(mode="json")
    data["local_install_path"] = "D:\\private-models"
    absolute_manifest = tmp_path / "absolute.json"
    absolute_manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ManifestError, match=r"invalid|relative"):
        load_manifest(absolute_manifest)

    data["local_install_path"] = "../outside"
    traversal_manifest = tmp_path / "traversal.json"
    traversal_manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ManifestError, match=r"invalid|relative"):
        load_manifest(traversal_manifest)


def test_checked_in_manifest_schema_exactly_matches_pydantic_model() -> None:
    schema_path = Path(__file__).parents[2] / "models" / "manifests" / "schema.json"
    checked_in = json.loads(schema_path.resolve().read_text(encoding="utf-8"))
    assert checked_in == ModelManifest.model_json_schema()


def test_runtime_executable_checksum_is_verified(tmp_path: Path) -> None:
    executable = tmp_path / "llama-server.exe"
    executable.write_bytes(b"synthetic runtime binary, not executable")
    expected = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert verify_runtime_executable(executable, expected) == expected
    with pytest.raises(IntegrityError, match="runtime executable SHA-256 mismatch"):
        verify_runtime_executable(executable, "0" * 64)
