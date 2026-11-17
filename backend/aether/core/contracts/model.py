"""Model manifest and readiness contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ModelReadiness(StrEnum):
    PENDING = "pending"
    NOT_INSTALLED = "not_installed"
    INTEGRITY_FAILED = "integrity_failed"
    STOPPED = "stopped"
    STARTING = "starting"
    READY = "ready"
    FAILED = "failed"


class ModelFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._-]+$")
    role: Literal["weights", "projector"] = "weights"
    size_bytes: int = Field(gt=0)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class RuntimeCompatibility(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project: str = "llama.cpp"
    version: str = Field(min_length=1, max_length=128)
    build_id: str = Field(min_length=1, max_length=256)
    executable_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    cuda_required: bool = False


class ModelManifest(BaseModel):
    """Manifest for verified local assets; paths are relative to configured root."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    model_id: str = Field(min_length=1, max_length=128)
    publisher: str = Field(min_length=1, max_length=256)
    source_repository: str = Field(min_length=1, max_length=512)
    source_revision: str = Field(pattern=r"^[0-9a-fA-F]{40}$")
    conversion_repository: str = Field(min_length=1, max_length=512)
    conversion_revision: str = Field(pattern=r"^[0-9a-fA-F]{40}$")
    architecture: str = Field(min_length=1, max_length=128)
    quantisation: str = Field(min_length=1, max_length=64)
    files: list[ModelFile] = Field(min_length=1, max_length=8)
    license: str = Field(min_length=1, max_length=256)
    local_install_path: str = Field(
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$",
    )
    context_length: int = Field(ge=512, le=262_144)
    chat_template: str = Field(min_length=1, max_length=256)
    runtime: RuntimeCompatibility
    text_generation: bool
    multimodal: bool = False
    projector_required: bool = False
    unsupported_features: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def validate_asset_roles(self) -> ModelManifest:
        names = [asset.filename for asset in self.files]
        if len(names) != len(set(names)):
            raise ValueError("model manifest file names must be unique")
        roles = {asset.role for asset in self.files}
        if "weights" not in roles:
            raise ValueError("model manifest must include a weights file")
        if self.projector_required and "projector" not in roles:
            raise ValueError("projector_required must include a projector asset")
        return self
