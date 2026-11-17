"""Authenticated Phase 1 health and endpoint-boundary regression tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aether.api.app import create_app
from aether.model_gateway.base import GatewayHealth


def _client(app):
    client = TestClient(app, client=("127.0.0.1", 43000))
    client.headers["Authorization"] = f"Bearer {app.state.session_token}"
    return client


def test_health_reports_backend_and_model_readiness() -> None:
    app = create_app()
    with _client(app) as client:
        resp = client.get("/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "aether-os"
    assert body["phase"] == "phase1"
    assert body["os_actions"] == "denied-by-default"
    assert body["inference"] == "not_ready"
    assert body["model_ready"] is False
    assert body["model_runtime_status"] == "not_installed"


def test_health_requires_ephemeral_session_authentication() -> None:
    app = create_app()
    with TestClient(app, client=("127.0.0.1", 43000)) as client:
        response = client.get("/v1/health")
    assert response.status_code == 401


def test_origin_restriction_is_exact() -> None:
    app = create_app(allowed_origins=frozenset({"http://127.0.0.1:3000"}))
    with _client(app) as client:
        denied = client.get("/v1/health", headers={"Origin": "https://attacker.invalid"})
        allowed = client.get("/v1/health", headers={"Origin": "http://127.0.0.1:3000"})
    assert denied.status_code == 403
    assert allowed.status_code == 200
    # The allowlist rejects Origin values but does not enable browser CORS.
    assert "access-control-allow-origin" not in allowed.headers


def test_wildcard_or_remote_origins_cannot_be_configured() -> None:
    with pytest.raises(ValueError, match="loopback"):
        create_app(allowed_origins=frozenset({"*"}))
    with pytest.raises(ValueError, match="loopback"):
        create_app(allowed_origins=frozenset({"https://remote.invalid"}))


def test_non_loopback_peer_is_rejected_even_with_valid_token() -> None:
    app = create_app()
    client = TestClient(app, client=("192.0.2.8", 43000))
    response = client.get(
        "/v1/health", headers={"Authorization": f"Bearer {app.state.session_token}"}
    )
    assert response.status_code == 403


def test_phase1_does_not_expose_privileged_or_later_phase_endpoints() -> None:
    app = create_app()
    with _client(app) as client:
        for path in (
            "/v1/tasks/abc/approve",
            "/v1/rsi/send",
            "/v1/world-state",
            "/v1/memory/search",
        ):
            response = client.get(path)
            assert response.status_code == 404, f"{path} must not exist in Phase 1"


def test_health_gateway_timeout_returns_controlled_unready_response() -> None:
    from aether.model_gateway.base import ModelTimeout

    class TimedOutGateway:
        async def health(self):
            raise ModelTimeout("synthetic private timeout detail")

        def capabilities(self):
            return {
                "generate_text": False,
                "generate_structured": False,
                "count_tokens": False,
                "generate_with_images": False,
            }

        async def generate_text(self, *args, **kwargs):
            raise AssertionError("health route must not generate")

        async def generate_structured(self, *args, **kwargs):
            raise AssertionError("health route must not generate")

        async def count_tokens(self, *args, **kwargs):
            return None

        async def load(self):
            return None

        async def unload(self):
            return None

    app = create_app(TimedOutGateway())
    with _client(app) as client:
        response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json()["model_ready"] is False
    assert response.json()["model_failure_code"] == "runtime_health_check_failed"
    assert "synthetic private" not in response.text


def test_health_does_not_report_ready_after_supervised_child_exits() -> None:
    from types import SimpleNamespace

    class ReadyGateway:
        async def health(self) -> GatewayHealth:
            return GatewayHealth(True, "synthetic-model", "ready")

        def capabilities(self):
            return {
                "generate_text": True,
                "generate_structured": True,
                "count_tokens": True,
                "generate_with_images": False,
            }

    app = create_app(ReadyGateway())
    dead_supervisor = SimpleNamespace(
        manifest=SimpleNamespace(model_id="synthetic-model"),
        startup_seconds=1.0,
        failure_code="runtime_exited_after_startup",
        process_id=None,
        health=lambda: {
            "ready": False,
            "state": "failed",
            "failure_code": "runtime_exited_after_startup",
        },
    )
    with _client(app) as client:
        app.state.model_supervisor = dead_supervisor
        response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json()["model_ready"] is False
    assert response.json()["model_runtime_status"] == "failed"
    assert response.json()["model_failure_code"] == "runtime_exited_after_startup"
    assert response.json()["model_process_id"] is None
