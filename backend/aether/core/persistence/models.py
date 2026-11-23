"""Typed immutable records for the Phase 2B persistence boundary.

The persistent state vocabulary follows MASTER_SPEC.md. It is intentionally
separate from the Phase 1 ``TaskState`` contract and is not an executor API.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from aether.core.contracts.policy import RiskTier
from aether.core.security.redaction import redact_text


class PersistentTaskState(StrEnum):
    """Master-spec task states persisted by Phase 2B."""

    RECEIVED = "RECEIVED"
    RESOLVING_CONTEXT = "RESOLVING_CONTEXT"
    PLANNING = "PLANNING"
    VALIDATING = "VALIDATING"
    PREVIEW_READY = "PREVIEW_READY"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    PRECHECK = "PRECHECK"
    EXECUTING = "EXECUTING"
    POSTCHECK = "POSTCHECK"
    COMPLETED = "COMPLETED"
    CLARIFICATION_REQUIRED = "CLARIFICATION_REQUIRED"
    PAUSED = "PAUSED"
    DENIED = "DENIED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"
    RECOVERING = "RECOVERING"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    UNVERIFIED = "UNVERIFIED"


# Phase 2B persists contracts for later phases but must never advance an action
# into an execution/recovery state. The vocabulary is not authorization.
DISABLED_EXECUTION_STATES = frozenset(
    {
        PersistentTaskState.PRECHECK,
        PersistentTaskState.EXECUTING,
        PersistentTaskState.POSTCHECK,
        PersistentTaskState.RECOVERING,
        PersistentTaskState.PARTIALLY_COMPLETED,
        PersistentTaskState.UNVERIFIED,
    }
)


class PlanStepApprovalStatus(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    REQUIRED = "REQUIRED"
    CONTRACT_ONLY = "CONTRACT_ONLY"


class TaskPlanResource(BaseModel):
    """A resource identity/version in a plan; never a raw-path authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9._:-]{0,255}$")
    expected_version: str = Field(min_length=1, max_length=512)
    display_name: str = Field(min_length=1, max_length=256)

    @field_validator("display_name")
    @classmethod
    def require_basename(cls, value: str) -> str:
        if "/" in value or "\\" in value or value in {".", ".."}:
            raise ValueError("resource display name must not contain a path")
        if redact_text(value) != value:
            raise ValueError("resource display name contains secret-like text")
        return value

    @field_validator("expected_version")
    @classmethod
    def require_non_sensitive_version(cls, value: str) -> str:
        if redact_text(value) != value or re.match(r"^(?:[A-Za-z]:[\\/]|\\\\|/)", value):
            raise ValueError("resource version must not contain secrets or raw paths")
        return value


class PlanStep(BaseModel):
    """One typed step candidate in an immutable plan revision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: UUID
    dependencies: tuple[UUID, ...] = ()
    capability_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    resources: tuple[TaskPlanResource, ...] = ()
    resource_locks: tuple[str, ...] = ()
    expected_state: dict[str, Any] = Field(default_factory=dict)
    expected_effect: dict[str, Any] = Field(default_factory=dict)
    risk_tier: RiskTier
    approval_status: PlanStepApprovalStatus = PlanStepApprovalStatus.REQUIRED
    timeout_seconds: int = Field(default=60, ge=1, le=86_400)
    max_attempts: int = Field(default=1, ge=1, le=5)
    idempotency_key: UUID
    postconditions: tuple[dict[str, Any], ...] = ()
    recovery_class: Literal[
        "REVERSIBLE", "SNAPSHOT_RESTORABLE", "COMPENSATABLE", "IRREVERSIBLE"
    ] = "REVERSIBLE"

    @field_validator("arguments", "expected_state", "expected_effect")
    @classmethod
    def validate_json_object(cls, value: dict[str, Any]) -> Any:
        _validate_json_value(value)
        return _freeze_json(value)

    @field_serializer("arguments", "expected_state", "expected_effect")
    def serialize_json_object(self, value: Mapping[str, Any]) -> Any:
        return _thaw_json(value)

    @field_validator("postconditions")
    @classmethod
    def validate_postconditions(
        cls, value: tuple[dict[str, Any], ...]
    ) -> tuple[dict[str, Any], ...]:
        _validate_json_value(value)
        return tuple(_freeze_json(item) for item in value)

    @field_serializer("postconditions")
    def serialize_postconditions(
        self, value: tuple[Mapping[str, Any], ...]
    ) -> list[dict[str, Any]]:
        return [_thaw_json(item) for item in value]

    @model_validator(mode="after")
    def validate_step_collections(self) -> PlanStep:
        if len(self.dependencies) != len(set(self.dependencies)):
            raise ValueError("step dependencies must be unique")
        if self.step_id in self.dependencies:
            raise ValueError("a step cannot depend on itself")
        if len(self.resources) > 64 or len(self.resource_locks) > 64:
            raise ValueError("step resource collections exceed their limit")
        if len(self.resource_locks) != len(set(self.resource_locks)):
            raise ValueError("resource locks must be unique")
        return self


class TaskPlan(BaseModel):
    """A full immutable plan revision with a deterministic canonical digest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: UUID
    revision: int = Field(ge=1)
    summary: str = Field(min_length=1, max_length=512)
    steps: tuple[PlanStep, ...] = Field(min_length=1, max_length=256)
    created_at: datetime

    @field_validator("summary")
    @classmethod
    def reject_sensitive_summary(cls, value: str) -> str:
        if redact_text(value) != value:
            raise ValueError("plan summary contains secret-like text")
        if re.match(r"^(?:[A-Za-z]:[\\/]|\\\\|/)", value):
            raise ValueError("plan summary must not contain an absolute path")
        return value

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("plan timestamps must include an explicit timezone")
        return value

    @model_validator(mode="after")
    def validate_dag(self) -> TaskPlan:
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("plan step IDs must be unique")
        known = set(step_ids)
        for step in self.steps:
            if any(dependency not in known for dependency in step.dependencies):
                raise ValueError("step dependency must reference this plan")
        visited: set[UUID] = set()
        visiting: set[UUID] = set()
        by_id = {step.step_id: step for step in self.steps}

        def visit(step_id: UUID) -> None:
            if step_id in visiting:
                raise ValueError("plan dependencies must be acyclic")
            if step_id in visited:
                return
            visiting.add(step_id)
            for dependency in by_id[step_id].dependencies:
                visit(dependency)
            visiting.remove(step_id)
            visited.add(step_id)

        for step_id in step_ids:
            visit(step_id)
        return self

    def canonical_json(self) -> str:
        """Return stable UTF-8-compatible JSON for exact immutable storage."""
        return json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

    @property
    def plan_hash(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class ApprovalDecisionValue(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class ApprovalDecisionRecord(BaseModel):
    """Immutable audit of a decision on a preview; never a grant or authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: UUID
    task_id: UUID
    plan_revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    preview_id: UUID
    preview_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: ApprovalDecisionValue
    decided_at: datetime
    authority: Literal["NON_AUTHORIZING_AUDIT_RECORD"] = "NON_AUTHORIZING_AUDIT_RECORD"

    @field_validator("decided_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval timestamps must include an explicit timezone")
        return value


_UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class EventMetadata(BaseModel):
    """Small redacted metadata only; no document/preview bodies or credentials."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    values: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @field_validator("values")
    @classmethod
    def reject_sensitive_keys(
        cls, value: dict[str, str | int | float | bool | None]
    ) -> dict[str, str | int | float | bool | None]:
        forbidden = re.compile(
            r"(?:secret|token|password|credential|content|prompt|payload|document|raw|path)", re.I
        )
        if any(forbidden.search(key) for key in value):
            raise ValueError("event metadata contains a prohibited sensitive field")
        allowed = {
            "state",
            "from_state",
            "to_state",
            "plan_revision",
            "plan_hash",
            "approval_id",
            "decision",
            "authority",
            "requires_fresh_plan_and_consent",
            "preview_digest",
            "preview_id",
            "requested_outcome",
            "error_code",
            # Capability audit (Phase 2C/2D). Deliberately excludes any path,
            # content, query text or free-form detail: an audit event records
            # that a capability ran, against which resource identity, and with
            # what outcome code -- never the data itself.
            "capability",
            "outcome",
            "reason_code",
            "resource_id",
            "receipt_id",
            "snapshot_id",
            "pre_sha256",
            "post_sha256",
        }
        if any(key not in allowed for key in value):
            raise ValueError("event metadata key is not allow-listed")
        for key, item in value.items():
            if key in {"state", "from_state", "to_state"} and item not in {
                state.value for state in PersistentTaskState
            }:
                raise ValueError("event state metadata is invalid")
            if key == "plan_revision" and (
                isinstance(item, bool) or not isinstance(item, int) or item < 0
            ):
                raise ValueError("event plan revision must be a non-negative integer")
            if key == "plan_hash" and (
                not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item)
            ):
                raise ValueError("event plan hash must be a lowercase SHA-256 digest")
            if key == "approval_id" and (
                not isinstance(item, str)
                or not re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    item,
                    re.I,
                )
            ):
                raise ValueError("event approval ID must be a UUID")
            if key == "requested_outcome" and item not in {
                "APPROVE",
                "REVISE",
                "REJECT",
                "CANCELLED",
            }:
                raise ValueError("event requested outcome is invalid")
            if key == "decision" and item not in {"APPROVE", "REJECT"}:
                raise ValueError("event decision is invalid")
            if key == "authority" and item != "NON_AUTHORIZING_AUDIT_RECORD":
                raise ValueError("event authority metadata is invalid")
            if key == "requires_fresh_plan_and_consent" and not isinstance(item, bool):
                raise ValueError("fresh-consent metadata must be boolean")
            if key == "preview_digest" and (
                not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item)
            ):
                raise ValueError("event preview digest must be a lowercase SHA-256 digest")
            if key == "preview_id" and (
                not isinstance(item, str)
                or not re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    item,
                    re.I,
                )
            ):
                raise ValueError("event preview ID must be a UUID")
            if key == "error_code" and (
                not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", item)
            ):
                raise ValueError("event error code is invalid")
            if key == "capability" and (
                not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", item)
            ):
                raise ValueError("event capability id is invalid")
            if key == "outcome" and item not in {
                "SUCCEEDED",
                "FAILED",
                "PARTIAL",
                "UNVERIFIED",
            }:
                raise ValueError("event outcome is invalid")
            if key == "reason_code" and (
                not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item)
            ):
                raise ValueError("event reason code is invalid")
            if key == "resource_id" and (
                not isinstance(item, str)
                or not re.fullmatch(r"(?:file|directory):[0-9a-fA-F-]{36}", item)
            ):
                raise ValueError("event resource id must be a registry resource id")
            if key in {"receipt_id", "snapshot_id"} and (
                not isinstance(item, str) or not _UUID_PATTERN.fullmatch(item)
            ):
                raise ValueError("event identifier must be a UUID")
            if key in {"pre_sha256", "post_sha256"} and (
                not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item)
            ):
                raise ValueError("event content digest must be a lowercase SHA-256 digest")
        return value


def _validate_json_value(value: Any) -> None:
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("plan fields must contain finite JSON values only") from exc

    sensitive_key = re.compile(
        r"(?:secret|token|password|credential|authorization|api[_-]?key|document|content|body|prompt|payload|raw|path|diff|patch)",
        re.I,
    )

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if sensitive_key.search(str(key)):
                    raise ValueError(
                        "plan fields cannot persist sensitive or document-content keys"
                    )
                walk(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                walk(child)
        elif isinstance(item, str):
            if redact_text(item) != item:
                raise ValueError("plan fields contain secret-like text")
            if re.match(r"^(?:[A-Za-z]:[\\/]|\\\\|/)", item):
                raise ValueError("plan fields must use resource IDs, not raw paths")
            if len(item) > 512:
                raise ValueError("plan string values are limited to 512 characters")

    walk(value)


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value
