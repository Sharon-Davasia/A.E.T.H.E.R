"""Typed, synthetic-only mock capabilities. Chat proposals are never run here."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class Operation(StrEnum):
    ADD = "add"
    SUBTRACT = "subtract"
    MULTIPLY = "multiply"


class CalculatorArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Operation
    left: float = Field(ge=-1_000_000, le=1_000_000)
    right: float = Field(ge=-1_000_000, le=1_000_000)


class AppLookupArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_id: str = Field(min_length=1, max_length=64)


class SyntheticFileInfoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_id: str = Field(min_length=1, max_length=64)


class FailureArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="synthetic failure", max_length=128)


class UnknownCapability(ValueError):
    pass


class InvalidCapabilityArguments(ValueError):
    pass


class MockToolRegistry:
    """Registry of inert deterministic handlers backed only by fixed data."""

    def __init__(self) -> None:
        self._schemas: dict[str, type[BaseModel]] = {
            "mock.calculator": CalculatorArgs,
            "mock.app_lookup": AppLookupArgs,
            "mock.filesystem_info": SyntheticFileInfoArgs,
            "mock.fail": FailureArgs,
        }

    def capability_schemas(self) -> dict[str, dict[str, object]]:
        return {name: schema.model_json_schema() for name, schema in self._schemas.items()}

    def validate(self, capability_id: str, arguments: dict[str, Any]) -> BaseModel:
        schema = self._schemas.get(capability_id)
        if schema is None:
            raise UnknownCapability("unknown mock capability")
        try:
            return schema.model_validate(arguments)
        except ValidationError as exc:
            raise InvalidCapabilityArguments("mock capability arguments are invalid") from exc

    def execute_for_test(self, capability_id: str, arguments: dict[str, Any]) -> dict[str, object]:
        """Explicit synthetic harness only; the API/service never calls this."""
        parsed = self.validate(capability_id, arguments)
        if capability_id == "mock.calculator":
            assert isinstance(parsed, CalculatorArgs)
            result = {
                Operation.ADD: parsed.left + parsed.right,
                Operation.SUBTRACT: parsed.left - parsed.right,
                Operation.MULTIPLY: parsed.left * parsed.right,
            }[parsed.operation]
            return {"status": "ok", "result": result}
        if capability_id == "mock.app_lookup":
            assert isinstance(parsed, AppLookupArgs)
            fixture = {"editor.fake": "Synthetic Editor", "browser.fake": "Synthetic Browser"}
            return {"status": "ok", "app": fixture.get(parsed.app_id)}
        if capability_id == "mock.filesystem_info":
            assert isinstance(parsed, SyntheticFileInfoArgs)
            synthetic_files: dict[str, dict[str, int]] = {
                "fixture-project": {"file_count": 3, "bytes": 128}
            }
            return {"status": "ok", "info": synthetic_files.get(parsed.fixture_id)}
        assert capability_id == "mock.fail"
        return {"status": "failed", "error_code": "SYNTHETIC_FAILURE"}
