"""Offline contract checks: gateway URLs are fixed to loopback, no remote type."""

from __future__ import annotations

from aether.core.policy.broker import PolicyBroker
from aether.model_gateway.base import UnavailableGateway
from aether.model_gateway.llama_cpp import LlamaCppGateway


def test_unavailable_gateway_exposes_no_remote_or_image_capability() -> None:
    capabilities = UnavailableGateway().capabilities()
    assert capabilities["generate_with_images"] is False
    assert "remote_inference" not in capabilities
    assert "auto_cloud" not in capabilities


def test_gateway_accepts_only_numeric_loopback_transport() -> None:
    gateway = LlamaCppGateway(base_url="http://127.0.0.1:9932", api_key="test", model_id="fixture")
    assert gateway.capabilities()["generate_text"] is True


def test_os_policy_remains_deny_by_default(tool_request) -> None:
    assert PolicyBroker().evaluate(tool_request).allowed is False


def test_windows_ci_remains_manual_only() -> None:
    import re
    from pathlib import Path

    workflow = Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml"
    source = workflow.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in source
    assert re.search(r"(?m)^\s*(push|pull_request):", source) is None


def test_storage_setup_never_persists_uv_environment_at_user_scope() -> None:
    from pathlib import Path

    script = Path(__file__).parents[2] / "scripts" / "configure_dev_storage.ps1"
    source = script.read_text(encoding="utf-8")
    assert "SetEnvironmentVariable" not in source
    assert "UV_PROJECT_ENVIRONMENT =" not in source
    assert "$env:UV_CACHE_DIR" in source
