"""Optional real llama.cpp smoke test; absence is an explicit skip, not a pass."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from aether.model_gateway.llama_cpp import LlamaCppGateway
from aether.model_runtime.config import RuntimeSettings
from aether.model_runtime.manifest import load_manifest
from aether.model_runtime.supervisor import LlamaCppSupervisor

pytestmark = pytest.mark.integration


def test_local_model_runtime_smoke() -> None:
    if os.getenv("AETHER_RUN_MODEL_INTEGRATION") != "1":
        pytest.skip("actual runtime integration requires AETHER_RUN_MODEL_INTEGRATION=1")
    settings = RuntimeSettings.from_env()
    if not (settings.manifest_path and settings.model_root and settings.llama_server_path):
        pytest.skip(
            "actual runtime integration skipped: manifest/model root/runtime not configured"
        )
    if not settings.manifest_path.is_file() or not settings.llama_server_path.is_file():
        pytest.skip("actual runtime integration skipped: local manifest/runtime assets missing")

    async def run() -> None:
        manifest = load_manifest(Path(settings.manifest_path))
        supervisor = LlamaCppSupervisor(
            executable=settings.llama_server_path,
            manifest=manifest,
            model_root=settings.model_root,
            port=settings.model_port,
            context_tokens=settings.context_tokens,
            gpu_layers=settings.gpu_layers,
            startup_timeout_seconds=settings.startup_timeout_seconds,
        )
        gateway: LlamaCppGateway | None = None
        try:
            await supervisor.start()
            assert supervisor.api_key is not None
            gateway = LlamaCppGateway(
                base_url=supervisor.base_url,
                api_key=supervisor.api_key,
                model_id=manifest.model_id,
                timeout_seconds=settings.request_timeout_seconds,
            )
            health = await gateway.health()
            assert health.ready is True
            text = await gateway.generate_text(
                [{"role": "user", "content": "Reply with one short greeting."}],
                max_tokens=16,
            )
            assert text.strip()
        finally:
            if gateway is not None:
                await gateway.close()
            await supervisor.stop()

    asyncio.run(run())
