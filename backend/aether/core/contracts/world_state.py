"""World-state observations.

Spec refs: WorldState service, State observation privacy policy.

Observations carry source, timestamp, freshness, and sensitivity.
Phase 0 defined the shape with no OS observers. Phase 3 CP1 extends the
contract compatibly (all Phase 3 fields are optional/additive) for the
in-memory, privacy-filtered WorldState foundation. Observations are
evidence, never authorization; ``evidence_strength`` is never a
permission signal. No observation is persisted by default.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from aether.core.contracts.resource import DataClass, Provenance

ObservationAvailability = Literal["available", "unavailable", "stale", "invalidated"]


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
    # --- Phase 3 CP1 additive fields (defaults preserve Phase 0 use) ---
    # Broker-issued resource identity this observation concerns, if any
    # (e.g. ``window:<uuid>`` / ``app:<uuid>``). Never a raw HWND/path.
    resource_id: str | None = Field(default=None, max_length=256)
    # Provenance of the observation; model-inferred state is labelled.
    provenance: Provenance = Provenance.SYSTEM_OBSERVED
    # Freshness bound: after this instant the observation must not be
    # presented as current. ``None`` preserves legacy behaviour for
    # synthetic Phase 0 fixtures only.
    expires_at: datetime | None = None
    # Monotonic invalidation/version token for the observed resource.
    version_token: str | None = Field(default=None, max_length=512)
    availability: ObservationAvailability = "available"
