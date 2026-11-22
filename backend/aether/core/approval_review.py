"""Stage 2 exact previews and non-authorizing approval-review evidence.

An ``ExactPreview`` is immutable review evidence for one persisted plan
revision. It is not a grant, capability, or permission to execute anything.
Stage 2 outcomes are persisted as audit-only records/events; no executor,
grant issuer, or execution path is provided here.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import StrEnum
from typing import Literal, cast
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aether.core.contracts.policy import RiskTier
from aether.core.persistence.models import (
    PersistentTaskState,
    PlanStep,
    TaskPlan,
    TaskPlanResource,
    _thaw_json,
)
from aether.core.persistence.sqlite_store import (
    PersistenceIntegrityError,
    SQLiteTaskStore,
    Stage2ReviewWrite,
    StoredTask,
)
from aether.core.security.redaction import redact_text

PREVIEW_SCHEMA_VERSION: Literal["2.0"] = "2.0"
REVIEW_EVIDENCE_ONLY: Literal["REVIEW_EVIDENCE_ONLY"] = "REVIEW_EVIDENCE_ONLY"
NON_AUTHORIZING_AUDIT_RECORD: Literal["NON_AUTHORIZING_AUDIT_RECORD"] = (
    "NON_AUTHORIZING_AUDIT_RECORD"
)

_PREVIEW_NAMESPACE = UUID("58a48ad3-72f8-4d36-b2e7-e6d0b8d4f725")
_REVIEW_NAMESPACE = UUID("364d9991-2687-4cc4-afc3-c0f5ab78379d")
_REVOKE_NAMESPACE = UUID("24a20e7e-caa1-4af7-98be-8b09d709ac19")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
_ABSOLUTE_PATH = re.compile(r"(?:^|[\s(])(?:[A-Za-z]:[\\/]|\\\\|/)")
_RECOVERY_SEVERITY = {
    "REVERSIBLE": 0,
    "SNAPSHOT_RESTORABLE": 1,
    "COMPENSATABLE": 2,
    "IRREVERSIBLE": 3,
}


def _validate_display_text(value: str) -> str:
    if not value or value != value.strip():
        raise ValueError("display text must contain visible characters")
    if redact_text(value) != value:
        raise ValueError("display text contains secret-like material")
    if _ABSOLUTE_PATH.search(value):
        raise ValueError("display text must not contain an absolute path")
    if any(not (" " <= character <= "~" or ord(character) >= 160) for character in value):
        raise ValueError("display text must not contain control characters")
    return value


def _validate_diff_text(value: str) -> str:
    if not value.strip():
        raise ValueError("full diff must not be empty")
    if len(value) > 64_000:
        raise ValueError("full diff exceeds the supported preview bound")
    if redact_text(value) != value:
        raise ValueError("full diff contains secret-like material")
    if any(character == "\x7f" for character in value):
        raise ValueError("full diff must not contain control characters")
    if any(
        not (character == "\n" or character == "\t" or " " <= character <= "~" or ord(character) >= 160)
        for character in value
    ):
        raise ValueError("full diff must not contain control characters")
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ReviewUnavailableError(RuntimeError):
    """Raised when no exact preview may be presented for review."""


class PreviewDiff(BaseModel):
    """Ephemeral exact text shown for inspection; it is never persisted here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9._:-]{0,255}$")
    unified_diff: str

    @field_validator("unified_diff")
    @classmethod
    def validate_diff(cls, value: str) -> str:
        return _validate_diff_text(value)

    @property
    def diff_sha256(self) -> str:
        return _hash_text(self.unified_diff)


class PreviewNarrative(BaseModel):
    """Human-facing exact-change claims supplied for a persisted plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_intent: str = Field(min_length=1, max_length=512)
    explanation: str = Field(min_length=1, max_length=4000)
    preconditions: tuple[str, ...] = Field(min_length=1, max_length=32)
    external_effects: tuple[str, ...] = Field(min_length=1, max_length=32)
    risks: tuple[str, ...] = Field(min_length=1, max_length=32)
    verification_strategy: tuple[str, ...] = Field(min_length=1, max_length=32)
    proposed_effect: str = Field(min_length=1, max_length=4000)
    full_diff: tuple[PreviewDiff, ...] = Field(default=(), max_length=16)

    @field_validator(
        "action_intent",
        "explanation",
        "proposed_effect",
    )
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _validate_display_text(value)

    @field_validator(
        "preconditions",
        "external_effects",
        "risks",
        "verification_strategy",
    )
    @classmethod
    def validate_text_items(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validate_display_text(item) for item in value)

    @model_validator(mode="after")
    def validate_diffs(self) -> PreviewNarrative:
        resource_ids = [diff.resource_id for diff in self.full_diff]
        if len(resource_ids) != len(set(resource_ids)):
            raise ValueError("full diff resource IDs must be unique")
        return self


class PreviewResource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9._:-]{0,255}$")
    display_name: str = Field(min_length=1, max_length=256)
    expected_version: str = Field(min_length=1, max_length=512)
    operations: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator("display_name", "expected_version", "operations")
    @classmethod
    def validate_visible_text(cls, value: object) -> object:
        if isinstance(value, tuple):
            return tuple(_validate_display_text(item) for item in value)
        return _validate_display_text(str(value))


class PreviewStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: UUID
    dependencies: tuple[UUID, ...] = ()
    capability_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_effect_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_state_json: str = Field(min_length=2, max_length=4000)
    expected_effect_json: str = Field(min_length=2, max_length=4000)
    resource_ids: tuple[str, ...] = ()
    risk_tier: RiskTier
    recovery_class: Literal[
        "REVERSIBLE", "SNAPSHOT_RESTORABLE", "COMPENSATABLE", "IRREVERSIBLE"
    ]

    @field_validator("expected_state_json", "expected_effect_json")
    @classmethod
    def validate_exact_json(cls, value: str) -> str:
        if len(value) > 4000:
            raise ValueError("expected JSON is too large for preview display")
        _validate_display_text(value)
        parsed = json.loads(value)
        if not isinstance(parsed, (dict, list, str, int, float, bool)) and parsed is not None:
            raise ValueError("expected JSON has an unsupported display shape")
        if _canonical_json(parsed) != value:
            raise ValueError("expected display JSON must be canonical")
        return value

    @field_validator("resource_ids")
    @classmethod
    def validate_resource_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("preview step resource IDs must be unique")
        for resource_id in value:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9._:-]{0,255}", resource_id):
                raise ValueError("preview step resource ID is invalid")
        return value


class ExactPreview(BaseModel):
    """Canonical immutable preview for exactly one persisted plan revision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.0"] = PREVIEW_SCHEMA_VERSION
    authority: Literal["REVIEW_EVIDENCE_ONLY"] = REVIEW_EVIDENCE_ONLY
    task_id: UUID
    plan_revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    action_intent: str = Field(min_length=1, max_length=512)
    explanation: str = Field(min_length=1, max_length=4000)
    preconditions: tuple[str, ...] = Field(min_length=1, max_length=32)
    proposed_effect: str = Field(min_length=1, max_length=4000)
    external_effects: tuple[str, ...] = Field(min_length=1, max_length=32)
    risks: tuple[str, ...] = Field(min_length=1, max_length=32)
    verification_strategy: tuple[str, ...] = Field(min_length=1, max_length=32)
    highest_risk_tier: RiskTier
    risk_classification: Literal[
        "T0_OBSERVE",
        "T1_NAVIGATE_READ",
        "T2_MUTATE_RECOVERABLE",
        "T3_HIGH_CONSEQUENCE",
    ]
    recovery_class: Literal[
        "REVERSIBLE", "SNAPSHOT_RESTORABLE", "COMPENSATABLE", "IRREVERSIBLE"
    ]
    resources: tuple[PreviewResource, ...] = ()
    steps: tuple[PreviewStep, ...] = Field(min_length=1, max_length=256)
    full_diff: tuple[PreviewDiff, ...] = Field(default=(), max_length=16)
    full_diff_available: bool = False

    @field_validator(
        "action_intent",
        "explanation",
        "proposed_effect",
    )
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _validate_display_text(value)

    @field_validator(
        "preconditions",
        "external_effects",
        "risks",
        "verification_strategy",
    )
    @classmethod
    def validate_text_items(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validate_display_text(item) for item in value)

    @model_validator(mode="after")
    def validate_preview(self) -> ExactPreview:
        if self.authority != REVIEW_EVIDENCE_ONLY:
            raise ValueError("preview authority is fixed as review evidence only")
        if self.full_diff_available != bool(self.full_diff):
            raise ValueError("full_diff_available must match the supplied full diff")
        expected_risk = max(step.risk_tier for step in self.steps)
        if self.highest_risk_tier != expected_risk:
            raise ValueError("preview risk classification must match its steps")
        expected_label = {
            RiskTier.OBSERVE: "T0_OBSERVE",
            RiskTier.NAVIGATE: "T1_NAVIGATE_READ",
            RiskTier.MODIFY: "T2_MUTATE_RECOVERABLE",
            RiskTier.CRITICAL: "T3_HIGH_CONSEQUENCE",
        }[expected_risk]
        if self.risk_classification != expected_label:
            raise ValueError("preview risk classification must match highest step risk")
        expected_recovery = max(
            (step.recovery_class for step in self.steps),
            key=lambda recovery: _RECOVERY_SEVERITY[recovery],
        )
        if self.recovery_class != expected_recovery:
            raise ValueError("preview recovery class must use the most conservative step class")
        resource_ids = [resource.resource_id for resource in self.resources]
        if len(resource_ids) != len(set(resource_ids)):
            raise ValueError("preview resource IDs must be unique")
        if tuple(resource_ids) != tuple(sorted(resource_ids)):
            raise ValueError("preview resources must be in canonical resource ID order")
        known_resource_ids = set(resource_ids)
        if any(step.risk_tier > RiskTier.CRITICAL for step in self.steps):
            raise ValueError("preview step risk tier is invalid")
        for step in self.steps:
            if any(resource_id not in known_resource_ids for resource_id in step.resource_ids):
                raise ValueError("preview step refers to an unknown resource")
        if any(diff.resource_id not in known_resource_ids for diff in self.full_diff):
            raise ValueError("full diff refers to an unknown preview resource")
        diff_ids = [diff.resource_id for diff in self.full_diff]
        if len(diff_ids) != len(set(diff_ids)):
            raise ValueError("full diff resource IDs must be unique")
        return self

    @property
    def digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", exclude={"full_diff"})
        payload["full_diff"] = [
            {"resource_id": diff.resource_id, "diff_sha256": diff.diff_sha256}
            for diff in sorted(self.full_diff, key=lambda item: item.resource_id)
        ]
        return payload

    def canonical_json(self) -> str:
        """Return the canonical representation used by the binding digest."""

        return _canonical_json(self.digest_payload)

    @property
    def preview_digest(self) -> str:
        return _hash_text(self.canonical_json())

    @property
    def preview_id(self) -> UUID:
        return uuid5(_PREVIEW_NAMESPACE, self.preview_digest)

    @property
    def review_request_id(self) -> UUID:
        """Stable request identity for idempotent redelivery of this exact review."""

        return uuid5(_REVIEW_NAMESPACE, self.preview_digest)


class ReviewOutcome(StrEnum):
    APPROVE = "APPROVE"
    REVISE = "REVISE"
    REJECT = "REJECT"
    CANCELLED = "CANCELLED"


class ReviewResolution(StrEnum):
    APPROVE = "APPROVE"
    REVISE = "REVISE"
    REJECT = "REJECT"
    CANCELLED = "CANCELLED"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"


class ReviewOutcomeRequest(BaseModel):
    """Trusted-IPC-shaped request; the model deliberately has no authority field."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    review_request_id: UUID
    task_id: UUID
    plan_revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    preview_id: UUID
    preview_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    outcome: ReviewOutcome
    full_diff_acknowledged: bool = False


class ReviewResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resolution: ReviewResolution
    requested_outcome: ReviewOutcome
    task_id: UUID
    plan_revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    preview_id: UUID
    preview_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_request_id: UUID
    authority: Literal["NON_AUTHORIZING_AUDIT_RECORD"] = NON_AUTHORIZING_AUDIT_RECORD
    audit_persisted: Literal[True] = True
    granted: Literal[False] = False
    execution_available: Literal[False] = False
    idempotent_replay: bool
    message: str = Field(min_length=1, max_length=256)


class PreviewRevocation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: UUID
    plan_revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    preview_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    revocation_id: UUID
    authority: Literal["NON_AUTHORIZING_AUDIT_RECORD"] = NON_AUTHORIZING_AUDIT_RECORD
    granted: Literal[False] = False
    execution_available: Literal[False] = False
    already_revoked: bool


def preview_id_for_digest(digest: str) -> UUID:
    if _LOWER_SHA256.fullmatch(digest) is None:
        raise ValueError("preview digest must be a lowercase SHA-256 digest")
    return uuid5(_PREVIEW_NAMESPACE, digest)


def _step_payload(step: PlanStep) -> PreviewStep:
    arguments_json = _canonical_json(_thaw_json(step.arguments))
    expected_state_json = _canonical_json(_thaw_json(step.expected_state))
    expected_effect_json = _canonical_json(_thaw_json(step.expected_effect))
    return PreviewStep(
        step_id=step.step_id,
        dependencies=step.dependencies,
        capability_id=step.capability_id,
        arguments_sha256=_hash_text(arguments_json),
        expected_state_sha256=_hash_text(expected_state_json),
        expected_effect_sha256=_hash_text(expected_effect_json),
        expected_state_json=expected_state_json,
        expected_effect_json=expected_effect_json,
        resource_ids=tuple(resource.resource_id for resource in step.resources),
        risk_tier=step.risk_tier,
        recovery_class=step.recovery_class,
    )


def _preview_resources(plan: TaskPlan) -> tuple[PreviewResource, ...]:
    operations_by_resource: dict[str, list[str]] = {}
    resource_details: dict[str, TaskPlanResource] = {}
    for step in plan.steps:
        for resource in step.resources:
            key = resource.resource_id
            existing = resource_details.get(key)
            if existing is not None and (
                existing.display_name != resource.display_name
                or existing.expected_version != resource.expected_version
            ):
                raise ValueError(
                    f"resource {key} is referenced with conflicting display name or expected version"
                )
            resource_details[key] = resource
            operations_by_resource.setdefault(key, []).append(step.capability_id)
    return tuple(
        PreviewResource(
            resource_id=resource_id,
            display_name=resource_details[resource_id].display_name,
            expected_version=resource_details[resource_id].expected_version,
            operations=tuple(sorted(set(operations_by_resource[resource_id]))),
        )
        for resource_id in sorted(resource_details)
    )


def build_preview(plan: TaskPlan, narrative: PreviewNarrative) -> ExactPreview:
    """Build a deterministic exact preview from an immutable persisted plan."""

    full_diff = tuple(sorted(narrative.full_diff, key=lambda diff: diff.resource_id))
    highest_risk_tier = max(step.risk_tier for step in plan.steps)
    risk_classification = cast(
        Literal["T0_OBSERVE", "T1_NAVIGATE_READ", "T2_MUTATE_RECOVERABLE", "T3_HIGH_CONSEQUENCE"],
        {
            RiskTier.OBSERVE: "T0_OBSERVE",
            RiskTier.NAVIGATE: "T1_NAVIGATE_READ",
            RiskTier.MODIFY: "T2_MUTATE_RECOVERABLE",
            RiskTier.CRITICAL: "T3_HIGH_CONSEQUENCE",
        }[highest_risk_tier],
    )
    recovery_class = max(
        (step.recovery_class for step in plan.steps),
        key=lambda recovery: _RECOVERY_SEVERITY[recovery],
    )
    preview = ExactPreview(
        task_id=plan.task_id,
        plan_revision=plan.revision,
        plan_hash=plan.plan_hash,
        action_intent=narrative.action_intent,
        explanation=narrative.explanation,
        preconditions=narrative.preconditions,
        proposed_effect=narrative.proposed_effect,
        external_effects=narrative.external_effects,
        risks=narrative.risks,
        verification_strategy=narrative.verification_strategy,
        highest_risk_tier=highest_risk_tier,
        risk_classification=risk_classification,
        recovery_class=recovery_class,
        resources=_preview_resources(plan),
        steps=tuple(_step_payload(step) for step in plan.steps),
        full_diff=full_diff,
        full_diff_available=bool(full_diff),
    )
    diff_resource_ids = {diff.resource_id for diff in preview.full_diff}
    known_resource_ids = {resource.resource_id for resource in preview.resources}
    if not diff_resource_ids <= known_resource_ids:
        raise ValueError("full diff refers to an unknown preview resource")
    return preview


def _result_from_write(
    write: Stage2ReviewWrite,
    *,
    request: ReviewOutcomeRequest,
) -> ReviewResult:
    outcome = request.outcome
    message = {
        ReviewResolution.APPROVE: (
            "Preview review recorded as approved. This is audit evidence only and does not authorize execution."
        ),
        ReviewResolution.REVISE: (
            "Revision requested. The plan must be revised and reviewed again; nothing may execute."
        ),
        ReviewResolution.REJECT: (
            "Preview rejected. No grant was issued and no action may execute."
        ),
        ReviewResolution.CANCELLED: (
            "Preview review cancelled. No grant was issued and no action may execute."
        ),
        ReviewResolution.STALE: (
            "Preview is stale or changed. Review a newly computed preview before deciding."
        ),
        ReviewResolution.UNAVAILABLE: (
            "Preview review is unavailable. The task must be planned and consented anew."
        ),
    }[ReviewResolution(write.resolution)]
    return ReviewResult(
        resolution=ReviewResolution(write.resolution),
        requested_outcome=outcome,
        task_id=write.task_id,
        plan_revision=write.plan_revision,
        plan_hash=write.plan_hash,
        preview_id=write.preview_id,
        preview_digest=write.preview_digest,
        review_request_id=write.review_request_id,
        idempotent_replay=write.idempotent_replay,
        message=message,
    )


class PreviewReviewService:
    """Coordinates exact preview display and non-authorizing audit outcomes."""

    def __init__(self, store: SQLiteTaskStore) -> None:
        self._store = store

    def present(self, task_id: UUID, narrative: PreviewNarrative) -> ExactPreview:
        preview, task = self._preview_for_context(task_id, narrative)
        if task.state not in {
            PersistentTaskState.PREVIEW_READY,
            PersistentTaskState.AWAITING_APPROVAL,
        } or self._store.is_stage2_preview_blocked(task_id):
            raise ReviewUnavailableError(
                "review is unavailable; the task requires planning and fresh consent"
            )
        return preview

    def revoke(
        self,
        task_id: UUID,
        narrative: PreviewNarrative,
        *,
        reason_code: str = "review_revoked",
        now: datetime | None = None,
    ) -> PreviewRevocation:
        preview, task = self._preview_for_context(task_id, narrative)
        if task.state not in {
            PersistentTaskState.PREVIEW_READY,
            PersistentTaskState.AWAITING_APPROVAL,
        }:
            raise ReviewUnavailableError(
                "review revocation is unavailable; no current exact preview is presentable"
            )
        revocation_id = uuid5(_REVOKE_NAMESPACE, preview.preview_digest)
        revocation = self._store.record_preview_revocation(
            task_id,
            plan_revision=preview.plan_revision,
            plan_hash=preview.plan_hash,
            preview_id=preview.preview_id,
            preview_digest=preview.preview_digest,
            revocation_id=revocation_id,
            reason_code=reason_code,
            now=now,
        )
        return PreviewRevocation(
            task_id=task_id,
            plan_revision=preview.plan_revision,
            plan_hash=preview.plan_hash,
            preview_digest=preview.preview_digest,
            revocation_id=revocation_id,
            already_revoked=revocation.already_recorded,
        )

    def record_outcome(
        self,
        task_id: UUID,
        narrative: PreviewNarrative,
        request: ReviewOutcomeRequest,
        *,
        now: datetime | None = None,
    ) -> ReviewResult:
        if request.task_id != task_id:
            raise ValueError("review request task does not match the requested task")
        preview, _task = self._preview_for_context(task_id, narrative)
        preview_matches_current = (
            request.plan_revision == preview.plan_revision
            and request.plan_hash == preview.plan_hash
            and request.preview_id == preview.preview_id
            and request.preview_digest == preview.preview_digest
        )
        if preview_matches_current:
            if (
                preview.full_diff
                and request.outcome == ReviewOutcome.APPROVE
                and not request.full_diff_acknowledged
            ):
                raise ValueError("full diff must be inspected before approving this exact preview")
            if request.review_request_id != preview.review_request_id:
                raise ValueError("review request identity does not match this exact preview")
        write = self._store.record_stage2_review_outcome(
            task_id,
            review_request_id=request.review_request_id,
            plan_revision=request.plan_revision,
            plan_hash=request.plan_hash,
            preview_id=request.preview_id,
            preview_digest=request.preview_digest,
            requested_outcome=request.outcome.value,
            preview_matches_current=preview_matches_current,
            decided_at=now,
        )
        return _result_from_write(write, request=request)

    def _preview_for_context(
        self,
        task_id: UUID,
        narrative: PreviewNarrative,
    ) -> tuple[ExactPreview, StoredTask]:
        task = self._store.get_task(task_id)
        if task.plan_revision < 1:
            raise ReviewUnavailableError("task has no reviewable persisted plan")
        plan = self._store.get_plan(task_id)
        if plan.task_id != task.task_id or plan.revision != task.plan_revision:
            raise PersistenceIntegrityError("task plan pointer does not match persisted plan")
        return build_preview(plan, narrative), task


__all__ = [
    "NON_AUTHORIZING_AUDIT_RECORD",
    "REVIEW_EVIDENCE_ONLY",
    "ExactPreview",
    "PreviewDiff",
    "PreviewNarrative",
    "PreviewResource",
    "PreviewReviewService",
    "PreviewRevocation",
    "PreviewStep",
    "ReviewOutcome",
    "ReviewOutcomeRequest",
    "ReviewResolution",
    "ReviewResult",
    "ReviewUnavailableError",
    "build_preview",
    "preview_id_for_digest",
]
