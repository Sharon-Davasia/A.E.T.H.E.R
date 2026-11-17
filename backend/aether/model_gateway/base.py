"""Model gateway protocol and typed failures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ModelGatewayError(RuntimeError):
    code = "model_error"


class ModelUnavailable(ModelGatewayError):
    code = "model_unavailable"


class ModelTimeout(ModelGatewayError):
    code = "model_timeout"


class ModelMalformedResponse(ModelGatewayError):
    code = "model_malformed_response"


class ModelCapabilityUnsupported(ModelGatewayError):
    code = "model_capability_unsupported"


@dataclass(frozen=True, slots=True)
class GatewayHealth:
    ready: bool
    model_id: str | None
    runtime_status: str
    detail_code: str | None = None


class ModelGateway(Protocol):
    async def generate_text(self, messages: list[dict[str, str]], *, max_tokens: int) -> str: ...

    async def generate_structured(
        self,
        messages: list[dict[str, str]],
        *,
        schema: dict[str, object],
        max_tokens: int,
    ) -> str: ...

    async def count_tokens(self, text: str) -> int | None: ...

    async def health(self) -> GatewayHealth: ...

    async def load(self) -> None: ...

    async def unload(self) -> None: ...

    def capabilities(self) -> dict[str, bool]: ...


class UnavailableGateway:
    """Gateway state when assets or runtime are not ready."""

    def __init__(
        self,
        runtime_status: str = "not_installed",
        detail_code: str = "model_manifest_pending",
    ) -> None:
        self.runtime_status = runtime_status
        self.detail_code = detail_code

    async def generate_text(self, messages: list[dict[str, str]], *, max_tokens: int) -> str:
        del messages, max_tokens
        raise ModelUnavailable("verified local model is not ready")

    async def generate_structured(
        self,
        messages: list[dict[str, str]],
        *,
        schema: dict[str, object],
        max_tokens: int,
    ) -> str:
        del messages, schema, max_tokens
        raise ModelUnavailable("verified local model is not ready")

    async def count_tokens(self, text: str) -> int | None:
        del text
        return None

    async def health(self) -> GatewayHealth:
        return GatewayHealth(False, None, self.runtime_status, self.detail_code)

    async def load(self) -> None:
        raise ModelUnavailable("verified local model is not ready")

    async def unload(self) -> None:
        return None

    def capabilities(self) -> dict[str, bool]:
        return {
            "generate_text": False,
            "generate_structured": False,
            "count_tokens": False,
            "generate_with_images": False,
        }


class SwitchableGateway:
    """Stable gateway reference while the supervised runtime starts or fails."""

    def __init__(self, state: UnavailableGateway | None = None) -> None:
        self._delegate: ModelGateway | None = None
        self._state = state or UnavailableGateway("starting", "model_loading")

    def set_state(self, state: UnavailableGateway) -> None:
        self._delegate = None
        self._state = state

    def set_delegate(self, gateway: ModelGateway) -> None:
        self._delegate = gateway

    async def generate_text(self, messages: list[dict[str, str]], *, max_tokens: int) -> str:
        return await self._ready_delegate().generate_text(messages, max_tokens=max_tokens)

    async def generate_structured(
        self,
        messages: list[dict[str, str]],
        *,
        schema: dict[str, object],
        max_tokens: int,
    ) -> str:
        return await self._ready_delegate().generate_structured(
            messages, schema=schema, max_tokens=max_tokens
        )

    async def count_tokens(self, text: str) -> int | None:
        if self._delegate is None:
            return None
        return await self._delegate.count_tokens(text)

    async def health(self) -> GatewayHealth:
        if self._delegate is None:
            return await self._state.health()
        return await self._delegate.health()

    async def load(self) -> None:
        await self._ready_delegate().load()

    async def unload(self) -> None:
        if self._delegate is not None:
            await self._delegate.unload()

    def capabilities(self) -> dict[str, bool]:
        if self._delegate is None:
            return self._state.capabilities()
        return self._delegate.capabilities()

    @property
    def last_generation_metrics(self) -> dict[str, int | float | None]:
        if self._delegate is None:
            return {}
        return getattr(self._delegate, "last_generation_metrics", {})

    async def close(self) -> None:
        if self._delegate is not None:
            close = getattr(self._delegate, "close", None)
            if close is not None:
                await close()

    def _ready_delegate(self) -> ModelGateway:
        if self._delegate is None:
            raise ModelUnavailable("verified local model is not ready")
        return self._delegate
