"""Runtime settings; all filesystem locations and ports are configurable."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    backend_port: int = 9931
    model_port: int = 9932
    context_tokens: int = 4096
    max_output_tokens: int = 512
    gpu_layers: int = 0
    model_root: Path | None = None
    manifest_path: Path | None = None
    llama_server_path: Path | None = None
    startup_timeout_seconds: float = 90.0
    request_timeout_seconds: float = 60.0

    @classmethod
    def from_env(cls) -> RuntimeSettings:
        model_root = os.getenv("AETHER_MODEL_ROOT")
        manifest = os.getenv("AETHER_MODEL_MANIFEST")
        server = os.getenv("AETHER_LLAMA_SERVER")
        settings = cls(
            backend_port=_int_env("AETHER_BACKEND_PORT", 9931, 1, 65535),
            model_port=_int_env("AETHER_MODEL_PORT", 9932, 1024, 65535),
            context_tokens=_int_env("AETHER_CONTEXT_TOKENS", 4096, 512, 4096),
            max_output_tokens=_int_env("AETHER_MAX_OUTPUT_TOKENS", 512, 1, 512),
            gpu_layers=_int_env("AETHER_GPU_LAYERS", 0, 0, 256),
            model_root=Path(model_root).expanduser() if model_root else None,
            manifest_path=Path(manifest).expanduser() if manifest else None,
            llama_server_path=Path(server).expanduser() if server else None,
            startup_timeout_seconds=_float_env("AETHER_MODEL_STARTUP_TIMEOUT", 90.0, 1, 300),
            request_timeout_seconds=_float_env("AETHER_MODEL_REQUEST_TIMEOUT", 60.0, 1, 300),
        )
        if settings.backend_port == settings.model_port:
            raise ValueError("backend and model server ports must be different")
        return settings


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    value = int(os.getenv(name, default))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _float_env(name: str, default: float, minimum: float, maximum: float) -> float:
    value = float(os.getenv(name, default))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value
