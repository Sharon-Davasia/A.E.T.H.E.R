"""Developer-only loopback API launcher with an ephemeral session token."""

from __future__ import annotations

import secrets

import uvicorn

from aether.api.app import create_app
from aether.model_runtime.config import RuntimeSettings


def main() -> None:
    settings = RuntimeSettings.from_env()
    token = secrets.token_urlsafe(32)
    app = create_app(session_token=token, runtime_settings=settings)
    print("AETHER local API session token (shown once; do not paste into logs):")
    print(token)
    print(
        f"API bound to http://127.0.0.1:{settings.backend_port}; use Authorization: Bearer <token>"
    )
    uvicorn.run(app, host="127.0.0.1", port=settings.backend_port, log_level="info")


if __name__ == "__main__":
    main()
