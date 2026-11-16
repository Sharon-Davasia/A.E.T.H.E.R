"""Deny-by-default policy tests (Phase 0 invariant).

All real OS actions must be denied. No grants are issued in Phase 0.
"""

from __future__ import annotations

from aether.core.contracts.tool import ToolRequest
from aether.core.policy.broker import PHASE0_REASON_CODE, PolicyBroker


def test_broker_denies_all(tool_request: ToolRequest) -> None:
    broker = PolicyBroker()
    decision = broker.evaluate(tool_request)
    assert decision.allowed is False
    assert decision.reason_code == PHASE0_REASON_CODE
    assert decision.requires_approval is True


def test_broker_denies_arbitrary_capability() -> None:
    broker = PolicyBroker()
    req = ToolRequest(
        request_id="r2",
        task_id="t2",
        capability_id="filesystem.delete_everything",
        arguments={"path": "C:\\Windows"},
    )
    decision = broker.evaluate(req)
    assert decision.allowed is False


def test_broker_denies_empty_capability() -> None:
    # Even malformed requests are denied (validation happens upstream,
    # but the broker never allows).
    broker = PolicyBroker()
    req = ToolRequest(request_id="r3", task_id="t3", capability_id="x")
    assert broker.evaluate(req).allowed is False


def test_rsi_send_always_denied() -> None:
    broker = PolicyBroker()
    decision = broker.evaluate_rsi_send()
    assert decision.allowed is False
    assert decision.reason_code == "PHASE0_RSI_DISABLED"
