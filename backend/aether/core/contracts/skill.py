"""Skill manifests (Phase 0 foundation).

Spec refs: Skill system definition, Skill installation pipeline.
Skills are versioned manifests under broker policy; no auto-install,
no auto-import, no privilege acquisition in any phase.
Phase 0 defines the manifest shape only.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from aether.core.contracts.policy import RiskTier


class SkillManifest(BaseModel):
    """Declared skill identity, effects, and trust status."""

    schema_version: str = "0.1.0"
    skill_id: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=4000)
    declared_effects: list[str] = Field(default_factory=list)
    max_risk_tier: RiskTier = RiskTier.OBSERVE
    package_sha256: str | None = Field(default=None, max_length=128)
    trust_status: str = Field(default="quarantined", max_length=64)
    enabled: bool = False
