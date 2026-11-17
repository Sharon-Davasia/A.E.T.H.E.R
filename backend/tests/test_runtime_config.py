"""Runtime settings are bounded and keep backend/model ports distinct."""

from __future__ import annotations

import pytest

from aether.model_runtime.config import RuntimeSettings


def test_defaults_keep_distinct_ports_and_phase1_context() -> None:
    settings = RuntimeSettings()
    assert settings.backend_port == 9931
    assert settings.model_port == 9932
    assert settings.context_tokens == 4096
    assert settings.gpu_layers == 0


def test_equal_ports_and_unsupported_context_are_rejected(monkeypatch) -> None:
    monkeypatch.setenv("AETHER_BACKEND_PORT", "9932")
    monkeypatch.setenv("AETHER_MODEL_PORT", "9932")
    with pytest.raises(ValueError, match="different"):
        RuntimeSettings.from_env()

    monkeypatch.setenv("AETHER_BACKEND_PORT", "9931")
    monkeypatch.setenv("AETHER_CONTEXT_TOKENS", "8192")
    with pytest.raises(ValueError, match="AETHER_CONTEXT_TOKENS"):
        RuntimeSettings.from_env()


def test_gpu_layer_count_is_configurable_and_bounded(monkeypatch) -> None:
    monkeypatch.setenv("AETHER_GPU_LAYERS", "24")
    assert RuntimeSettings.from_env().gpu_layers == 24
    monkeypatch.setenv("AETHER_GPU_LAYERS", "999")
    with pytest.raises(ValueError, match="AETHER_GPU_LAYERS"):
        RuntimeSettings.from_env()
