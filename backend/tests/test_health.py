"""Health endpoint tests (Phase 0)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from aether.api.app import create_app


def test_health_ok() -> None:
    client = TestClient(create_app())
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "aether-os"
    assert body["phase"] == "phase0"
    assert body["os_actions"] == "denied-by-default"
    assert body["inference"] == "not-implemented"


def test_no_os_control_endpoints_in_phase0() -> None:
    client = TestClient(create_app())
    # Only /v1/health exists; other spec endpoints must 404 in Phase 0.
    for path in ("/v1/chat/turns", "/v1/tasks/abc", "/v1/rsi/send", "/v1/world-state"):
        resp = client.get(path)
        assert resp.status_code in (404, 405), f"{path} should not exist in Phase 0"
