"""Authenticated loopback-only llama.cpp HTTP gateway."""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import time
from urllib.parse import urlsplit

import httpx

from aether.model_gateway.base import (
    GatewayHealth,
    ModelCapabilityUnsupported,
    ModelMalformedResponse,
    ModelTimeout,
    ModelUnavailable,
)


def _remove_max_length(value: object) -> None:
    """Drop llama.cpp-incompatible length metadata from a copied JSON schema."""
    if isinstance(value, dict):
        value.pop("maxLength", None)
        for nested in value.values():
            _remove_max_length(nested)
    elif isinstance(value, list):
        for nested in value:
            _remove_max_length(nested)


class LlamaCppGateway:
    """Calls only a numeric loopback address, with bounded one-at-a-time work."""

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:9932",
        api_key: str,
        model_id: str,
        timeout_seconds: float = 60.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname is None
            or not ipaddress.ip_address(parsed.hostname).is_loopback
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
        ):
            raise ValueError("model gateway URL must be plain HTTP on a numeric loopback address")
        if parsed.port is None or not 1 <= parsed.port <= 65535:
            raise ValueError("model gateway port is invalid")
        if not api_key:
            raise ValueError("model server API key is required")
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._api_key = api_key
        self._model_id = model_id
        self._timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 3.0))
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=self._timeout, trust_env=False)
        self._semaphore = asyncio.Semaphore(1)
        self.last_generation_metrics: dict[str, int | float | None] = {}

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def health(self) -> GatewayHealth:
        try:
            response = await self._client.get(f"{self._base_url}/health")
        except httpx.TimeoutException:
            return GatewayHealth(False, self._model_id, "unavailable", "runtime_health_timeout")
        except httpx.HTTPError:
            return GatewayHealth(False, self._model_id, "unavailable", "runtime_unreachable")
        if response.status_code == 503:
            return GatewayHealth(False, self._model_id, "starting", "model_loading")
        if response.status_code != 200:
            return GatewayHealth(False, self._model_id, "failed", "unexpected_health_status")
        # Upstream /health is deliberately public and minimal. Verify the
        # protected API key against an authenticated, non-generative endpoint.
        try:
            auth_check = await self._client.post(
                f"{self._base_url}/tokenize",
                json={"content": "a", "add_special": False},
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        except httpx.TimeoutException:
            return GatewayHealth(False, self._model_id, "unavailable", "runtime_health_timeout")
        except httpx.HTTPError:
            return GatewayHealth(False, self._model_id, "unavailable", "runtime_unreachable")
        if auth_check.status_code in (401, 403):
            return GatewayHealth(False, self._model_id, "failed", "runtime_authentication_failed")
        if not 200 <= auth_check.status_code < 300:
            return GatewayHealth(False, self._model_id, "failed", "runtime_tokenizer_unavailable")
        try:
            tokenizer_result = auth_check.json()
        except ValueError:
            return GatewayHealth(
                False, self._model_id, "failed", "runtime_authentication_check_failed"
            )
        if not isinstance(tokenizer_result, dict) or not isinstance(
            tokenizer_result.get("tokens"), list
        ):
            return GatewayHealth(
                False, self._model_id, "failed", "runtime_authentication_check_failed"
            )
        return GatewayHealth(True, self._model_id, "ready")

    async def generate_text(self, messages: list[dict[str, str]], *, max_tokens: int) -> str:
        if not 1 <= max_tokens <= 512:
            raise ValueError("max_tokens must be between 1 and 512")
        payload = {
            "model": self._model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "reasoning_effort": "none",
            "chat_template_kwargs": {"enable_thinking": False},
        }
        return await self._complete(payload)

    async def generate_structured(
        self,
        messages: list[dict[str, str]],
        *,
        schema: dict[str, object],
        max_tokens: int,
    ) -> str:
        if not 1 <= max_tokens <= 512:
            raise ValueError("max_tokens must be between 1 and 512")
        runtime_schema = copy.deepcopy(schema)
        _remove_max_length(runtime_schema)
        payload = {
            "model": self._model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "reasoning_effort": "none",
            "chat_template_kwargs": {"enable_thinking": False},
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "aether_decision", "schema": runtime_schema},
            },
        }
        return await self._complete(payload)

    async def _complete(self, payload: dict[str, object]) -> str:
        started = time.perf_counter()
        async with self._semaphore:
            try:
                response = await self._client.post(
                    f"{self._base_url}/v1/chat/completions",
                    json=payload,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
            except httpx.TimeoutException as exc:
                raise ModelTimeout("local model request timed out") from exc
            except httpx.HTTPError as exc:
                raise ModelUnavailable("local model endpoint is unavailable") from exc
        if response.status_code in (401, 403):
            raise ModelUnavailable("local model authentication failed")
        if response.status_code in (404, 422):
            raise ModelCapabilityUnsupported("selected runtime rejected the requested API feature")
        if not 200 <= response.status_code < 300:
            raise ModelUnavailable("local model runtime returned a non-success status")
        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ModelMalformedResponse(
                "local model response did not match the expected API shape"
            ) from exc
        if not isinstance(content, str) or not content.strip():
            raise ModelMalformedResponse("local model returned empty content")
        elapsed = time.perf_counter() - started
        usage = data.get("usage", {}) if isinstance(data, dict) else {}
        timings = data.get("timings", {}) if isinstance(data, dict) else {}
        prompt_tokens = usage.get("prompt_tokens") if isinstance(usage, dict) else None
        completion_tokens = usage.get("completion_tokens") if isinstance(usage, dict) else None
        server_tps = timings.get("predicted_per_second") if isinstance(timings, dict) else None
        self.last_generation_metrics = {
            "generation_seconds": elapsed,
            "prompt_tokens": prompt_tokens if isinstance(prompt_tokens, int) else None,
            "completion_tokens": completion_tokens if isinstance(completion_tokens, int) else None,
            "tokens_per_second": server_tps if isinstance(server_tps, (int, float)) else None,
        }
        return content

    async def count_tokens(self, text: str) -> int | None:
        try:
            response = await self._client.post(
                f"{self._base_url}/tokenize",
                json={"content": text, "add_special": False},
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
            response.raise_for_status()
            data = response.json()
            tokens = data.get("tokens") if isinstance(data, dict) else None
            return len(tokens) if isinstance(tokens, list) else None
        except (httpx.HTTPError, ValueError, TypeError):
            return None

    async def load(self) -> None:
        health = await self.health()
        if not health.ready:
            raise ModelUnavailable("model runtime is not ready")

    async def unload(self) -> None:
        # The supervisor owns process shutdown. The gateway does not ask the
        # remote server to unload a model through an unauthenticated endpoint.
        return None

    def capabilities(self) -> dict[str, bool]:
        return {
            "generate_text": True,
            "generate_structured": True,
            "count_tokens": True,
            "generate_with_images": False,
        }
