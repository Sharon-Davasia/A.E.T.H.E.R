"""Deny-by-default policy broker (Phase 0).

Fundamental invariant: **all real operating-system actions are denied**
until permission and execution systems are implemented in later phases.

The broker is independent of model-generated text. It never grants
permissions, never executes OS operations, and never approves RSI sends.
Later phases will add T0-T3 evaluation, approval binding, and resource
resolution — Phase 0 deliberately does none of that.
"""

from __future__ import annotations

from aether.core.contracts.policy import PolicyDecision, RiskTier
from aether.core.contracts.tool import ToolRequest

PHASE0_REASON_CODE = "PHASE0_DENY_ALL_OS_ACTIONS"
PHASE0_REASON = (
    "Phase 0: all real OS actions are denied by default. "
    "Permission and execution systems are not yet implemented."
)


class PolicyBroker:
    """Deterministic deny-by-default broker (Phase 0)."""

    def evaluate(self, request: ToolRequest) -> PolicyDecision:
        """Evaluate a tool request. Always denies in Phase 0."""
        return PolicyDecision(
            allowed=False,
            risk_tier=RiskTier.CRITICAL,
            reason_code=PHASE0_REASON_CODE,
            reason=PHASE0_REASON,
            requires_approval=True,
            approval_id=None,
        )

    def evaluate_rsi_send(self) -> PolicyDecision:
        """RSI sends are always denied in Phase 0 (no provider code)."""
        return PolicyDecision(
            allowed=False,
            risk_tier=RiskTier.CRITICAL,
            reason_code="PHASE0_RSI_DISABLED",
            reason="Phase 0: RSI is disabled. No remote sends are permitted.",
            requires_approval=True,
            approval_id=None,
        )
