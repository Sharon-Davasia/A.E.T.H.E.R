"""Local gateway authentication, loopback allowlist and failure mapping."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from aether.core.contracts.decision import Decision
from aether.model_gateway.base import ModelMalformedResponse, ModelUnavailable
from aether.model_gateway.llama_cpp import LlamaCppGateway


@pytest.mark.asyncio
async def test_chat_request_uses_bearer_key_and_schema_constrained_json() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"kind":"answer","text":"ok"}'}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = LlamaCppGateway(
        base_url="http://127.0.0.1:9932",
        api_key="ephemeral-test-secret",
        model_id="fixture",
        client=client,
    )
    result = await gateway.generate_structured([], schema={"type": "object"}, max_tokens=16)
    assert result == '{"kind":"answer","text":"ok"}'
    assert requests[0].headers["authorization"] == "Bearer ephemeral-test-secret"
    assert requests[0].url.host == "127.0.0.1"
    assert requests[0].url.port == 9932
    body = json.loads(requests[0].content)
    assert body["model"] == "fixture"
    assert body["reasoning_effort"] == "none"
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == {"type": "object"}
    await client.aclose()


@pytest.mark.asyncio
async def test_readiness_requires_public_health_and_authenticated_tokenizer() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        assert request.headers.get("authorization") == "Bearer secret"
        return httpx.Response(200, json={"tokens": [1]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="secret", model_id="fixture", client=client
    )
    health = await gateway.health()
    assert health.ready is True
    assert await gateway.count_tokens("hello") == 1
    await client.aclose()


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:9932",
        "https://127.0.0.1:9932",
        "http://localhost:9932",
        "http://127.0.0.1",
    ],
)
def test_non_loopback_or_ambiguous_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        LlamaCppGateway(base_url=url, api_key="x", model_id="fixture")


@pytest.mark.asyncio
async def test_unauthorized_or_unexpected_model_response_is_not_success() -> None:
    async def unauthorized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    client = httpx.AsyncClient(transport=httpx.MockTransport(unauthorized))
    gateway = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="x", model_id="fixture", client=client
    )
    with pytest.raises(ModelUnavailable):
        await gateway.generate_text([], max_tokens=8)
    await client.aclose()

    async def malformed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": True})

    client2 = httpx.AsyncClient(transport=httpx.MockTransport(malformed))
    gateway2 = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="x", model_id="fixture", client=client2
    )
    with pytest.raises(ModelMalformedResponse):
        await gateway2.generate_text([], max_tokens=8)
    await client2.aclose()

    async def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    client3 = httpx.AsyncClient(transport=httpx.MockTransport(timeout))
    gateway3 = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="x", model_id="fixture", client=client3
    )
    from aether.model_gateway.base import ModelTimeout

    with pytest.raises(ModelTimeout):
        await gateway3.generate_text([], max_tokens=8)
    await client3.aclose()


@pytest.mark.asyncio
async def test_health_timeout_returns_sanitized_unready_status():
    from aether.model_gateway.llama_cpp import LlamaCppGateway

    async def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic private endpoint detail", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(timeout))
    gateway = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="secret", model_id="fixture", client=client
    )
    health = await gateway.health()
    assert health.ready is False
    assert health.runtime_status == "unavailable"
    assert health.detail_code == "runtime_health_timeout"
    await client.aclose()


@pytest.mark.asyncio
async def test_readiness_rejects_unauthenticated_or_malformed_tokenizer():
    async def unauthorized(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(401)

    client = httpx.AsyncClient(transport=httpx.MockTransport(unauthorized))
    gateway = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="secret", model_id="fixture", client=client
    )
    health = await gateway.health()
    assert health.ready is False
    assert health.detail_code == "runtime_authentication_failed"
    await client.aclose()

    async def malformed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not_tokens": []})

    client2 = httpx.AsyncClient(transport=httpx.MockTransport(malformed))
    gateway2 = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="secret", model_id="fixture", client=client2
    )
    health2 = await gateway2.health()
    assert health2.ready is False
    assert health2.detail_code == "runtime_authentication_check_failed"
    await client2.aclose()


def _contains_max_length(value: object) -> bool:
    if isinstance(value, dict):
        return "maxLength" in value or any(_contains_max_length(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_max_length(child) for child in value)
    return False


@pytest.mark.asyncio
async def test_structured_request_simplifies_wire_schema_and_validates_original_decision() -> None:
    requests: list[httpx.Request] = []
    response_text = '{"kind":"answer","text":"A valid answer."}'

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": response_text}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="secret", model_id="fixture", client=client
    )
    original_schema = Decision.model_json_schema()
    assert _contains_max_length(original_schema)

    result = await gateway.generate_structured(
        [{"role": "user", "content": "Say something."}],
        schema=original_schema,
        max_tokens=32,
    )
    decision = Decision.model_validate_json(result)

    body = json.loads(requests[0].content)
    assert body["reasoning_effort"] == "none"
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    response_format = body["response_format"]
    assert response_format["type"] == "json_schema"
    json_schema = response_format["json_schema"]
    assert json_schema["name"] == "aether_decision"
    submitted_schema = json_schema["schema"]
    assert isinstance(submitted_schema, dict)
    assert submitted_schema["$defs"].keys() == original_schema["$defs"].keys()
    assert not _contains_max_length(submitted_schema)
    assert _contains_max_length(original_schema)
    assert decision.kind.value == "answer"
    assert decision.text == "A valid answer."
    await client.aclose()


@pytest.mark.asyncio
async def test_text_generation_disables_reasoning_and_thinking() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ordinary text"}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="secret", model_id="fixture", client=client
    )
    assert await gateway.generate_text([], max_tokens=16) == "ordinary text"
    body = json.loads(requests[0].content)
    assert body["reasoning_effort"] == "none"
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    await client.aclose()


@pytest.mark.asyncio
async def test_invalid_structured_model_output_fails_original_decision_validation() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"kind":"answer","text":""}'}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = LlamaCppGateway(
        base_url="http://127.0.0.1:9932", api_key="secret", model_id="fixture", client=client
    )
    result = await gateway.generate_structured(
        [], schema=Decision.model_json_schema(), max_tokens=32
    )
    with pytest.raises(ValidationError):
        Decision.model_validate_json(result)
    await client.aclose()
