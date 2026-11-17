"""Phase 1 local chat API; no real OS actions, cloud inference or unauth access."""

from __future__ import annotations

import asyncio
import ipaddress
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.responses import Response

from aether.api.auth import new_session_token, require_local_session
from aether.api.errors import ChatErrorResponse
from aether.core.chat_service import ChatFailure, ChatTurnService
from aether.core.contracts.chat import ChatTurnRequest, ChatTurnResponse
from aether.core.contracts.decision import DecisionKind
from aether.core.contracts.model import ModelManifest
from aether.model_gateway.base import (
    GatewayHealth,
    ModelGateway,
    SwitchableGateway,
    UnavailableGateway,
)
from aether.model_gateway.llama_cpp import LlamaCppGateway
from aether.model_runtime.config import RuntimeSettings
from aether.model_runtime.manifest import load_manifest
from aether.model_runtime.supervisor import LlamaCppSupervisor
from aether.observability.logging import configure_logging, get_logger


class HealthResponse(BaseModel):
    """Backend liveness and independent local-model readiness."""

    model_config = ConfigDict(extra="forbid")

    status: str = "ok"
    service: str = "aether-os"
    version: str = "0.1.0"
    phase: str = "phase1"
    os_actions: str = "denied-by-default"
    inference: str
    model_ready: bool
    model_id: str | None = None
    model_runtime_status: str
    model_failure_code: str | None = None
    model_startup_seconds: float | None = None
    model_process_id: int | None = None
    capabilities: dict[str, bool]


def _prepare_runtime(
    settings: RuntimeSettings,
) -> tuple[ModelManifest | None, LlamaCppSupervisor | None, str | None]:
    """Prepare configured assets without blocking API startup or downloading."""
    if settings.manifest_path is None and settings.llama_server_path is None:
        return None, None, "model_manifest_pending"
    if not (settings.model_root and settings.manifest_path and settings.llama_server_path):
        return None, None, "runtime_configuration_incomplete"
    try:
        assert settings.manifest_path is not None
        assert settings.model_root is not None
        assert settings.llama_server_path is not None
        manifest = load_manifest(settings.manifest_path)
        if not manifest.text_generation:
            return None, None, "model_text_generation_unsupported"
        supervisor = LlamaCppSupervisor(
            executable=settings.llama_server_path,
            manifest=manifest,
            model_root=settings.model_root,
            port=settings.model_port,
            context_tokens=settings.context_tokens,
            gpu_layers=settings.gpu_layers,
            startup_timeout_seconds=settings.startup_timeout_seconds,
        )
        return manifest, supervisor, None
    except Exception:
        # No local path, exception text or credential reaches health/log output.
        return None, None, "model_manifest_invalid"


def create_app(
    gateway: ModelGateway | None = None,
    *,
    session_token: str | None = None,
    allowed_origins: frozenset[str] | None = None,
    runtime_settings: RuntimeSettings | None = None,
) -> FastAPI:
    """Create an authenticated app; injected gateways are intended for tests."""
    configure_logging()
    logger = get_logger("aether.api")
    selected_settings = runtime_settings or RuntimeSettings()
    switching_gateway = gateway is None
    selected_gateway: ModelGateway = gateway or SwitchableGateway(
        UnavailableGateway("not_installed", "model_manifest_pending")
    )
    selected_supervisor: LlamaCppSupervisor | None = None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        nonlocal selected_supervisor
        runtime_task: asyncio.Task[None] | None = None
        if switching_gateway:
            manifest, selected_supervisor, preparation_error = _prepare_runtime(selected_settings)
            if selected_supervisor is None:
                assert isinstance(selected_gateway, SwitchableGateway)
                state = (
                    UnavailableGateway("not_installed", preparation_error)
                    if preparation_error == "model_manifest_pending"
                    else UnavailableGateway("failed", preparation_error or "model_runtime_failed")
                )
                selected_gateway.set_state(state)
                app.state.model_start_failure = (
                    None if preparation_error == "model_manifest_pending" else preparation_error
                )
            else:
                assert manifest is not None
                assert isinstance(selected_gateway, SwitchableGateway)
                selected_gateway.set_state(UnavailableGateway("starting", "model_loading"))
                app.state.model_start_failure = None
                app.state.model_supervisor = selected_supervisor

                async def start_runtime() -> None:
                    assert selected_supervisor is not None
                    try:
                        await selected_supervisor.start()
                        api_key = selected_supervisor.api_key
                        if not api_key:
                            raise RuntimeError("runtime_credential_missing")
                        delegate = LlamaCppGateway(
                            base_url=selected_supervisor.base_url,
                            api_key=api_key,
                            model_id=manifest.model_id,
                            timeout_seconds=selected_settings.request_timeout_seconds,
                        )
                        selected_gateway.set_delegate(delegate)
                    except asyncio.CancelledError:
                        await selected_supervisor.stop()
                        raise
                    except Exception:
                        failure = selected_supervisor.failure_code or "model_runtime_start_failed"
                        selected_gateway.set_state(UnavailableGateway("failed", failure))
                        app.state.model_start_failure = failure

                runtime_task = asyncio.create_task(start_runtime())
        app.state.model_supervisor = selected_supervisor
        try:
            yield
        finally:
            if runtime_task is not None and not runtime_task.done():
                runtime_task.cancel()
                await asyncio.gather(runtime_task, return_exceptions=True)
            close = getattr(selected_gateway, "close", None)
            if close is not None:
                await close()
            if selected_supervisor is not None:
                await selected_supervisor.stop()

    app = FastAPI(
        title="AETHER OS",
        version="0.1.0",
        description="Phase 1 local intelligence foundation; all OS actions remain denied.",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.session_token = session_token or new_session_token()
    configured_origins = allowed_origins if allowed_origins is not None else _origins_from_env()
    app.state.allowed_origins = _validate_origins(configured_origins)
    app.state.chat_service = ChatTurnService(selected_gateway)
    app.state.model_supervisor = selected_supervisor
    app.state.model_start_failure = None

    @app.middleware("http")
    async def require_loopback_peer(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        peer = request.client.host if request.client is not None else ""
        try:
            is_loopback = ipaddress.ip_address(peer).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            return JSONResponse(status_code=403, content={"detail": {"code": "LOOPBACK_ONLY"}})
        return await call_next(request)

    @app.get("/v1/health", response_model=HealthResponse, tags=["health"])
    async def health(_: None = Depends(require_local_session)) -> HealthResponse:
        supervisor = app.state.model_supervisor
        try:
            model: GatewayHealth = await app.state.chat_service.gateway.health()
        except Exception:
            # Health is diagnostic, not an inference request. Never surface transport,
            # credential, path, or exception details as an unhandled 500 response.
            model = GatewayHealth(False, None, "failed", "runtime_health_check_failed")
        if supervisor is not None:
            runtime_health = supervisor.health()
            if not runtime_health["ready"]:
                code = runtime_health["failure_code"] or "runtime_not_ready"
                model = GatewayHealth(
                    False,
                    supervisor.manifest.model_id,
                    "failed" if runtime_health["state"] == "failed" else "starting",
                    str(code),
                )
        failure = (
            app.state.model_start_failure
            or (supervisor.failure_code if supervisor is not None else None)
            or model.detail_code
        )
        return HealthResponse(
            inference="ready" if model.ready else "not_ready",
            model_ready=model.ready,
            model_id=model.model_id,
            model_runtime_status=model.runtime_status,
            model_failure_code=failure,
            model_startup_seconds=supervisor.startup_seconds if supervisor is not None else None,
            model_process_id=supervisor.process_id if supervisor is not None else None,
            capabilities=app.state.chat_service.gateway.capabilities(),
        )

    @app.post(
        "/v1/chat/turns",
        response_model=ChatTurnResponse,
        tags=["chat"],
        dependencies=[Depends(require_local_session)],
    )
    async def chat_turn(
        payload: ChatTurnRequest, request: Request
    ) -> ChatTurnResponse | JSONResponse:
        try:
            outcome = await request.app.state.chat_service.turn(payload)
        except ChatFailure as exc:
            logger.warning(
                "chat_turn_failed",
                code=exc.code,
                status_code=exc.status_code,
                task_id=str(exc.task_id),
                correlation_id=str(exc.correlation_id),
            )
            body = ChatErrorResponse(
                code=exc.code,
                message=exc.message,
                task_id=exc.task_id,
                correlation_id=exc.correlation_id,
                repair_attempted=exc.repair_attempted,
            )
            return JSONResponse(status_code=exc.status_code, content=body.model_dump(mode="json"))
        return ChatTurnResponse(
            task_id=outcome.task_id,
            correlation_id=outcome.correlation_id,
            conversation_id=outcome.conversation_id,
            created_at=datetime.now(UTC),
            task_state=outcome.task_state.value,
            decision=outcome.decision,
            model_id=outcome.model_id,
            model_ready=True,
            context_truncated=outcome.context_truncated,
            generation_seconds=outcome.generation_metrics.get("generation_seconds"),
            prompt_tokens=outcome.generation_metrics.get("prompt_tokens"),
            completion_tokens=outcome.generation_metrics.get("completion_tokens"),
            tokens_per_second=outcome.generation_metrics.get("tokens_per_second"),
            time_to_first_token_seconds=None,
            repair_attempted=outcome.repair_attempted,
            policy_status=outcome.policy_status,
            warning=(
                "Tool proposal only; no tool or operating-system action is executed, and Phase 1 has no approval workflow."
                if outcome.decision.kind == DecisionKind.REQUEST_TOOL
                else "Discussion proposal only; no approval workflow or external action exists in Phase 1."
                if outcome.decision.kind in {DecisionKind.PROPOSE_PLAN, DecisionKind.OFFER_RSI}
                else "Model-generated text only; no operating-system action was performed."
            ),
        )

    return app


def _origins_from_env() -> frozenset[str]:
    raw = os.getenv("AETHER_ALLOWED_ORIGINS", "")
    return frozenset(origin.strip() for origin in raw.split(",") if origin.strip())


def _validate_origins(origins: frozenset[str]) -> frozenset[str]:
    """Reject wildcards and non-loopback web origins at configuration time."""
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            origin == "*"
            or parsed.scheme not in {"http", "https"}
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "allowed origins must be exact loopback HTTP(S) origins; wildcards are forbidden"
            )
    return origins


app = create_app()
