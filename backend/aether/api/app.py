"""FastAPI application (Phase 0).

Only ``GET /v1/health`` is implemented. No chat, task, approval, memory,
RSI, or OS-control endpoints exist in Phase 0.

Localhost binding is controlled by the server launch configuration
(``uvicorn --host 127.0.0.1``), not by this application object. The
FastAPI app itself does not enforce loopback binding; operators must
launch it with an explicit loopback host. See DEVELOPER_SETUP.md.
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Health payload (no sensitive data)."""

    status: str = "ok"
    service: str = "aether-os"
    version: str = "0.0.1"
    phase: str = "phase0"
    os_actions: str = "denied-by-default"
    inference: str = "not-implemented"


def create_app() -> FastAPI:
    """Create the Phase 0 FastAPI app."""
    app = FastAPI(
        title="AETHER OS",
        version="0.0.1",
        description="Phase 0 foundation: health only. No OS control.",
    )

    @app.get("/v1/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        """Return service health (no auth in Phase 0; bind via launch config)."""
        return HealthResponse()

    return app


app = create_app()
