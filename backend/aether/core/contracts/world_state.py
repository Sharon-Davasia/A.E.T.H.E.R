"""World-state observations (Phase 0 foundation).

Spec refs: WorldState service, State observation privacy policy.
Observations carry source, timestamp, freshness, and sensitivity.
Phase 0 defines the shape; no OS observers run in this phase.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from aether.core.contracts.resource import DataClass


class WorldStateObservation(BaseModel):
    """A single permission-filtered observation."""

    schema_version: str = "0.1.0"
    observation_id: str = Field(min_length=1, max_length=128)
    kind: str = Field(min_length=1, max_length=128)
    summary: str = Field(default="", max_length=4000)
    source: str = Field(default="synthetic", max_length=256)
    observed_at: datetime
    data_class: DataClass = DataClass.INTERNAL
    # Evidence strength (0.0-1.0), never permission authority.
    evidence_strength: float = Field(default=0.0, ge=0.0, le=1.0)
