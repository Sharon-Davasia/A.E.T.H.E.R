"""Resource identification and data classification (Phase 0 foundation).

Spec refs: Security architecture (classifications), Windows path security,
Typed data boundaries. ``ResourceRef`` carries a broker-resolved ID, never
a trusted raw path.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class DataClass(StrEnum):
    """Sensitivity classification. SECRET never leaves the machine."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    PRIVATE = "PRIVATE"
    SECRET = "SECRET"


class Provenance(StrEnum):
    """Where content came from. UNTRUSTED is a flag, not a class."""

    USER_DECLARED = "USER_DECLARED"
    SYSTEM_OBSERVED = "SYSTEM_OBSERVED"
    TOOL_VERIFIED = "TOOL_VERIFIED"
    DOCUMENT_QUOTED = "DOCUMENT_QUOTED"
    MODEL_INFERRED = "MODEL_INFERRED"
    REMOTE_SUGGESTED = "REMOTE_SUGGESTED"
    UNTRUSTED = "UNTRUSTED"


ResourceKind = Literal["file", "directory", "app", "window", "browser_tab", "service"]


class ResourceRef(BaseModel):
    """Broker-resolved resource reference.

    ``resource_id`` is canonical (e.g. ``file:<uuid>`` or ``project:<uuid>``),
    not a raw OS path. Raw paths must be resolved by the broker before use.
    """

    schema_version: str = "0.1.0"
    kind: ResourceKind
    resource_id: str = Field(min_length=1, max_length=256)
    observed_version: str | None = Field(default=None, max_length=512)
    data_class: DataClass = DataClass.INTERNAL
    provenance: Provenance = Provenance.SYSTEM_OBSERVED
