"""Adapter capabilities.

Spec refs: Application adapter contract, Control ladder.
Adapters declare what they can do; the broker decides authority.
Phase 0: fake adapters only. Phase 3 CP0 adds declared preparation
semantics (``supports_prepare``) without changing existing adapters:
preparation builds a bounded, non-effectful operation description and
never executes anything.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from aether.core.contracts.policy import RiskTier


class AdapterCapabilities(BaseModel):
    """Declared capability surface of an adapter."""

    schema_version: str = "0.1.0"
    adapter_id: str = Field(min_length=1, max_length=256)
    adapter_version: str = Field(min_length=1, max_length=64)
    capabilities: list[str] = Field(default_factory=list)
    max_risk_tier: RiskTier = RiskTier.OBSERVE
    supports_pause: bool = False
    supports_resume: bool = False
    supports_rollback: bool = False
    # Phase 3: adapter can prepare (describe/precompute) an operation
    # without performing it. Default False preserves Phase 0 behaviour.
    supports_prepare: bool = False
    health: str = Field(default="unknown", max_length=64)
