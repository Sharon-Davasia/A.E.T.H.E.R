"""Versioned, bounded UI Automation snapshot contract (CP4, CP4-R2/R3).

Snapshots contain signed-off, privacy-filtered metadata only. Element
references are transient and snapshot-bound; a caller can never
construct an element reference from a name, index or raw handle.
Nothing in this module carries raw COM objects, HWNDs toward the
model/renderer, or executable selectors.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aether.core.contracts.resource import DataClass, Provenance

SCHEMA_VERSION = "0.1.0"

# Provisional aggregate limits (CP4-R3): same style as window-fact
# limits. Truncated always means *unknown* beyond the cutoff.
MAX_DEPTH = 8
MAX_ELEMENTS = 300
MAX_TOTAL_TEXT_CHARS = 32 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_INSPECTION_SECONDS = 5.0
MAX_RETAINED_SNAPSHOTS = 16
SNAPSHOT_TTL_SECONDS = 60.0

SUPPORTED_PATTERNS = frozenset({"invoke", "value", "selectionitem", "toggle", "expandcollapse"})

SENSITIVE_CONTROL_TYPES = frozenset({"Edit"})  # sensitive only with password classification
PASSWORD_INDICATORS = frozenset({"password", "credential", "secret"})


class SnapshotPrivacy(StrEnum):
    """What the snapshot was permitted to carry (never content-free-form)."""

    METADATA = "metadata"
    CONTENT = "content"


class UiaLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_depth: int = Field(default=MAX_DEPTH, gt=0, le=MAX_DEPTH)
    max_elements: int = Field(default=MAX_ELEMENTS, gt=0, le=MAX_ELEMENTS)
    max_total_text_chars: int = Field(default=MAX_TOTAL_TEXT_CHARS, gt=0, le=MAX_TOTAL_TEXT_CHARS)
    budget_seconds: float = Field(default=MAX_INSPECTION_SECONDS, gt=0, le=MAX_INSPECTION_SECONDS)


class UiaElement(BaseModel):
    """One bounded, transient element reference in a snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    element_ref: str = Field(min_length=1)
    runtime_id: str = Field(min_length=1)
    control_type: str = Field(min_length=1)
    automation_id: str | None = None
    name: str | None = None
    patterns: frozenset[str] = Field(default_factory=frozenset)
    is_enabled: bool = False
    is_offscreen: bool = True
    is_password: bool = False
    depth: int = Field(ge=0)
    parent_ref: str | None = None
    ancestor_refs: tuple[str, ...] = ()
    child_count: int = Field(default=0, ge=0)
    bounding_rect: tuple[int, int, int, int] | None = None
    value_present: bool = False  # value *content* is never captured for password controls


class UiaSnapshot(BaseModel):
    """A bounded accessibility snapshot bound to one window instance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION
    snapshot_id: str = Field(min_length=1)
    session_id: str
    app_resource_id: str
    window_resource_id: str
    window_version_token: str
    process_token: str
    observed_at: datetime
    expires_at: datetime
    generation: int = Field(ge=0)
    privacy_generation: int = Field(default=0, ge=0)
    provenance: Provenance = Provenance.SYSTEM_OBSERVED
    data_class: DataClass = DataClass.PRIVATE
    privacy_classification: SnapshotPrivacy = SnapshotPrivacy.METADATA
    completeness: str = "complete"  # complete|truncated|partial|unavailable
    truncated: bool = False
    truncated_reason: str | None = None
    elements: tuple[UiaElement, ...] = ()
    retained_text_chars: int = Field(default=0, ge=0)
    root_element_ref: str | None = None

    def model_post_init(self, __context: object) -> None:
        if len(self.elements) > MAX_ELEMENTS:
            raise ValueError("snapshot exceeds the element bound")
        if self.retained_text_chars > MAX_TOTAL_TEXT_CHARS:
            raise ValueError("snapshot exceeds the retained-text bound")
        if any(e.depth > MAX_DEPTH for e in self.elements):
            raise ValueError("snapshot exceeds the depth bound")
        for element in self.elements:
            if not set(element.patterns) <= SUPPORTED_PATTERNS:
                raise ValueError("unsupported UIA pattern in snapshot")

    def find(self, element_ref: str) -> UiaElement | None:
        return next((e for e in self.elements if e.element_ref == element_ref), None)

    def find_by_runtime(self, runtime_id: str) -> UiaElement | None:
        return next((e for e in self.elements if e.runtime_id == runtime_id), None)
