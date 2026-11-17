"""Mock capabilities are typed, deterministic and synthetic only."""

from __future__ import annotations

import pytest

from aether.core.tools.mock_registry import (
    InvalidCapabilityArguments,
    MockToolRegistry,
    UnknownCapability,
)


def test_registered_calculator_is_deterministic_synthetic_data() -> None:
    registry = MockToolRegistry()
    assert registry.execute_for_test(
        "mock.calculator", {"operation": "add", "left": 4, "right": 5}
    ) == {"status": "ok", "result": 9}


def test_fake_application_and_file_information_use_fixed_fixtures() -> None:
    registry = MockToolRegistry()
    assert (
        registry.execute_for_test("mock.app_lookup", {"app_id": "editor.fake"})["app"]
        == "Synthetic Editor"
    )
    info = registry.execute_for_test("mock.filesystem_info", {"fixture_id": "fixture-project"})[
        "info"
    ]
    assert info == {"file_count": 3, "bytes": 128}


def test_unknown_id_and_invalid_arguments_are_rejected() -> None:
    registry = MockToolRegistry()
    with pytest.raises(UnknownCapability):
        registry.validate("shell.exec", {"command": "whoami"})
    with pytest.raises(InvalidCapabilityArguments):
        registry.validate("mock.calculator", {"operation": "divide", "left": 1, "right": 0})


def test_failure_capability_reports_simulated_failure() -> None:
    registry = MockToolRegistry()
    result = registry.execute_for_test("mock.fail", {"reason": "synthetic"})
    assert result == {"status": "failed", "error_code": "SYNTHETIC_FAILURE"}
