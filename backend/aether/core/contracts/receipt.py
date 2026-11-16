"""Execution receipts (Phase 0 foundation).

Spec refs: Execution receipts and recovery classes, Audit trail.
Phase 0 defines the receipt shape; no executor produces receipts yet.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class RecoveryClass(StrEnum):
    REVERSIBLE = "REVERSIBLE"
    SNAPSHOT_RESTORABLE = "SNAPSHOT_RESTORABLE"
    COMPENSATABLE = "COMPENSATABLE"
    IRREVERSIBLE = "IRREVERSIBLE"


ReceiptStatus = Literal["SUCCEEDED", "FAILED", "UNVERIFIED", "PARTIAL"]


class ActionReceipt(BaseModel):
    """Authoritative record of attempted + observed effects."""

    schema_version: str = "0.1.0"
    receipt_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    step_id: str = Field(min_length=1, max_length=128)
    approval_id: str | None = Field(default=None, max_length=128)
    status: ReceiptStatus
    recovery_class: RecoveryClass
    observed_effects: list[dict[str, object]] = Field(default_factory=list)
    verification_refs: list[str] = Field(default_factory=list)
    before_ref: str | None = Field(default=None, max_length=512)
    after_ref: str | None = Field(default=None, max_length=512)
    verified_at: datetime | None = None
    created_at: datetime
