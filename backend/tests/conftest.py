"""Shared test fixtures (Phase 0, synthetic data only)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aether.core.contracts.resource import ResourceRef
from aether.core.contracts.tool import ToolRequest


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def tool_request() -> ToolRequest:
    return ToolRequest(
        request_id="req-001",
        task_id="task-001",
        capability_id="fake.noop",
        arguments={"target": "synthetic"},
        resources=[
            ResourceRef(kind="file", resource_id="file:synthetic-001"),
        ],
        reason="synthetic test",
        expected_effect="none (fake)",
    )
