"""RSI disclosure requests (Phase 0 foundation).

Spec refs: RSI decision rules, RSI disclosure security.
RSI is optional, disabled by default, explicit per-task only.
No auto-escalation, no provider fallback. Phase 0 defines the
disclosure-request shape only — no provider code, no sending.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from aether.core.contracts.resource import DataClass


class RSIDisclosureRequest(BaseModel):
    """Exact outbound payload awaiting user disclosure approval."""

    schema_version: str = "0.1.0"
    request_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    payload_hash: str = Field(min_length=1, max_length=256)
    payload_summary: str = Field(default="", max_length=4000)
    max_data_class: DataClass = DataClass.INTERNAL
    requested_at: datetime
    # Phase 0 never sends; approval is a separate trusted step.
    approved: bool = False
