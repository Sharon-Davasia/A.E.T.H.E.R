"""Deterministic production planner: intent → bounded typed plan (Phase 2B/2C).

The Master Specification requires that plans be typed, immutable, persisted and
bound to exact resources and versions — and that no model-supplied text can
grant itself authority. This planner honours all three by construction:

* It does **not** ask a model what to do. It accepts an already-chosen
  :class:`PlanIntent` (the capability and its exact resource) and produces the
  DAG, arguments, expected effects and recovery classes itself.
* Every step's arguments are validated by the same typed argument models the
  policy broker uses, so a plan cannot encode an argument the capability does
  not accept.
* Resource versions come from the registry at planning time. A plan that names
  a resource whose version has since changed is *stale*, and the preview
  authority refuses to present it rather than silently re-planning.
* Adding a write step after approval is impossible: plans are immutable and
  revisions are append-only, so any change is a new revision with a new hash.

This is the seam the Stage 3 review surface and the Stage 4 grant issuer both
read from. It contains no authorization logic: it plans, it does not permit.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4, uuid5

from aether.core.approval_review import PreviewDiff, PreviewNarrative
from aether.core.contracts.policy import RiskTier
from aether.core.persistence.models import PlanStep, TaskPlan, TaskPlanResource
from aether.core.planning.edit_binding import ApprovedEdit, EditBindingError
from aether.core.policy.capabilities import CapabilityRegistry, CapabilityRegistryError
from aether.core.resources.registry import ResourceRegistry, ResourceRegistryError

_PLAN_NAMESPACE = UUID("6f1f4a52-2c3e-4b7a-9b1e-6a1d2c3b4a50")


class PlannerError(Exception):
    """The plan cannot be built safely; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


class PlanGoal(StrEnum):
    """The narrow, enumerable set of Phase 2 user intents."""

    INSPECT_FILE = "inspect_file"
    READ_FILE = "read_file"
    SEARCH_PROJECT = "search_project"
    OPEN_FOLDER = "open_folder"
    APPLY_EDIT = "apply_edit"
    UNDO_EDIT = "undo_edit"


@dataclass(frozen=True, slots=True)
class PlanIntent:
    """One already-decided user intent, with its exact typed arguments.

    ``proposed_content`` is required for edit goals and forbidden otherwise. It is
    the exact bytes the user is being asked to approve, so the planner can render
    and bind them rather than describing the change in prose (S14-1).
    """

    goal: PlanGoal
    resource_id: str
    arguments: dict[str, Any]
    summary: str
    proposed_content: bytes | None = None


@dataclass(frozen=True, slots=True)
class PlannedRevision:
    """A built plan plus the human-facing narrative that describes it.

    The narrative is *display evidence*, not authority: it is derived from the
    plan (never the reverse), and the preview authority recomputes the digest
    over both so a narrative cannot describe a different action than the plan.
    """

    plan: TaskPlan
    plan_hash: str
    narrative: PreviewNarrative
    step_id: UUID


_EDIT_GOALS: frozenset[PlanGoal] = frozenset({PlanGoal.APPLY_EDIT, PlanGoal.UNDO_EDIT})

_GOAL_CAPABILITY: dict[PlanGoal, str] = {
    PlanGoal.INSPECT_FILE: "fs.inspect_file",
    PlanGoal.READ_FILE: "fs.read_file",
    PlanGoal.SEARCH_PROJECT: "fs.search",
    PlanGoal.OPEN_FOLDER: "fs.open_folder",
    PlanGoal.APPLY_EDIT: "fs.apply_approved_edit",
    PlanGoal.UNDO_EDIT: "fs.undo_edit",
}


class Planner:
    """Builds one immutable plan revision per intent, deterministically."""

    def __init__(
        self,
        *,
        capabilities: CapabilityRegistry,
        resources: ResourceRegistry,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._capabilities = capabilities
        self._resources = resources
        self._clock = clock or (lambda: datetime.now(UTC))

    def plan(self, task_id: UUID, intent: PlanIntent, *, revision: int = 1) -> PlannedRevision:
        """Build revision ``revision`` of the plan for ``intent``."""

        capability_id = _GOAL_CAPABILITY[intent.goal]
        editing = intent.goal in _EDIT_GOALS
        if editing and intent.proposed_content is None:
            raise PlannerError(
                "PLAN_APPROVED_BYTES_REQUIRED",
                "an edit plan must carry the exact proposed bytes so they can be bound",
            )
        if not editing and intent.proposed_content is not None:
            raise PlannerError(
                "PLAN_UNEXPECTED_PROPOSED_CONTENT",
                "only edit goals may carry proposed content",
            )
        try:
            definition = self._capabilities.get(capability_id)
            arguments = self._capabilities.validate(capability_id, intent.arguments)
        except CapabilityRegistryError as exc:
            raise PlannerError(
                "PLAN_ARGUMENTS_INVALID", "the intent's arguments are not valid for the capability"
            ) from exc
        try:
            resolved = self._resources.resource_by_id(intent.resource_id)
        except ResourceRegistryError as exc:
            raise PlannerError(
                "PLAN_RESOURCE_UNKNOWN", "the resource was never issued by the registry"
            ) from exc
        try:
            root = self._resources.root_by_id(resolved.root_id)
        except ResourceRegistryError as exc:
            raise PlannerError("PLAN_ROOT_UNAVAILABLE", str(exc)) from exc
        if capability_id not in root.allowed_capabilities:
            raise PlannerError(
                "PLAN_CAPABILITY_OUT_OF_SCOPE",
                "the registered root does not permit this capability",
            )
        if definition.risk_tier == RiskTier.CRITICAL:
            raise PlannerError("PLAN_TIER3_DISABLED", "T3 intents cannot be planned")

        now = self._clock()
        step_id = uuid5(
            _PLAN_NAMESPACE, f"{task_id}:{revision}:{capability_id}:{intent.resource_id}"
        )
        resource = TaskPlanResource(
            resource_id=resolved.ref.resource_id,
            expected_version=resolved.version_token,
            display_name=resolved.canonical_path.name or root.alias,
        )
        arguments_dump = arguments.model_dump(mode="json")
        expected_effect = _expected_effect(
            intent.goal, resolved.canonical_path.name, arguments_dump
        )
        approved_edit: ApprovedEdit | None = None
        if editing:
            approved_edit = self._bind_approved_edit(intent, resolved)
            # The plan's expected effect now names the exact bytes. Because the
            # plan hash covers expected_effect, the approved post-image cannot be
            # changed by a later revision without a new hash and a new approval.
            expected_effect = {**expected_effect, **approved_edit.to_step_arguments()}
        step = PlanStep(
            step_id=step_id,
            capability_id=capability_id,
            arguments=arguments_dump,
            resources=(resource,),
            resource_locks=(f"file:{resolved.volume_id}:{resolved.file_id}",),
            expected_state={
                "resource_id": resource.resource_id,
                "expected_version": resource.expected_version,
            },
            expected_effect=expected_effect,
            risk_tier=definition.risk_tier,
            timeout_seconds=_timeout_for(intent.goal),
            idempotency_key=uuid5(_PLAN_NAMESPACE, f"{task_id}:{revision}:{step_id}:idempotency"),
            postconditions=(_postcondition(intent.goal),),
            recovery_class=_recovery_for(intent.goal),
        )
        plan = TaskPlan(
            task_id=task_id,
            revision=revision,
            summary=intent.summary[:512],
            steps=(step,),
            created_at=now,
        )
        plan_hash = hashlib.sha256(plan.canonical_json().encode("utf-8")).hexdigest()
        narrative = _narrative_for(
            intent,
            resolved.canonical_path.name,
            expected_effect,
            approved_edit=approved_edit,
        )
        return PlannedRevision(plan=plan, plan_hash=plan_hash, narrative=narrative, step_id=step_id)

    def _bind_approved_edit(self, intent: PlanIntent, resolved: Any) -> ApprovedEdit:
        """Render and bind the exact change the user is being asked to approve."""

        assert intent.proposed_content is not None  # guarded by plan()
        try:
            pre_image = resolved.canonical_path.read_bytes()
        except OSError as exc:
            raise PlannerError(
                "PLAN_SOURCE_UNREADABLE",
                "the current content could not be read, so no exact diff can be shown",
            ) from exc
        try:
            return ApprovedEdit.build(
                resource_id=resolved.ref.resource_id,
                pre_image=pre_image,
                post_image=intent.proposed_content,
                display_name=resolved.canonical_path.name,
            )
        except EditBindingError as exc:
            raise PlannerError(exc.reason_code, str(exc)) from exc

    def revision_for_change(
        self,
        *,
        existing: TaskPlan,
        intent: PlanIntent,
        approved_steps: frozenset[UUID],
    ) -> PlannedRevision:
        """Build a superseding revision that keeps approved steps intact.

        The Master Specification forbids adding new write steps after approval.
        This method therefore refuses to *replace* any already-approved step; a
        changed intent is expressed as a new step with its own new step id, and
        the caller must obtain a fresh approval for it. Removing approved scope
        is allowed, because it can only narrow what was authorized.
        """

        revision = existing.revision + 1
        planned = self.plan(existing.task_id, intent, revision=revision)
        new_step = planned.plan.steps[0]
        if new_step.step_id in approved_steps:
            raise PlannerError(
                "PLAN_APPROVED_STEP_IMMUTABLE",
                "an approved step cannot be redefined by a later revision",
            )
        retained = tuple(step for step in existing.steps if step.step_id in approved_steps)
        combined = TaskPlan(
            task_id=existing.task_id,
            revision=revision,
            summary=existing.summary,
            steps=(*retained, new_step),
            created_at=self._clock(),
        )
        plan_hash = hashlib.sha256(combined.canonical_json().encode("utf-8")).hexdigest()
        # Re-derive the narrative with the same approved binding the new step
        # records, so a superseding revision cannot describe different bytes than
        # its own step binds (S14-1).
        narrative = _narrative_for(
            intent,
            planned.plan.steps[0].resources[0].display_name,
            dict(new_step.expected_effect),
            # The newly planned step carries its freshly rendered diff. A
            # retained approved step's diff text is deliberately not persisted
            # (no document content in the plan tables), so it is not re-rendered
            # here; its binding stays in its own immutable expected effect.
            approved_edit=_freshly_planned_binding(planned),
        )
        return PlannedRevision(
            plan=combined, plan_hash=plan_hash, narrative=narrative, step_id=new_step.step_id
        )


def _expected_effect(
    goal: PlanGoal, display_name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    match goal:
        case PlanGoal.INSPECT_FILE:
            return {"effect": "metadata_read", "resource": display_name}
        case PlanGoal.READ_FILE:
            return {"effect": "content_read", "resource": display_name}
        case PlanGoal.SEARCH_PROJECT:
            return {"effect": "search_performed", "query": arguments.get("query")}
        case PlanGoal.OPEN_FOLDER:
            return {"effect": "open_requested", "resource": display_name}
        case PlanGoal.APPLY_EDIT:
            return {
                "effect": "file_replaced",
                "resource": display_name,
                "expected_sha256": arguments.get("expected_sha256"),
            }
        case PlanGoal.UNDO_EDIT:
            return {"effect": "file_restored", "resource": display_name}


def _freshly_planned_binding(planned: PlannedRevision) -> ApprovedEdit | None:
    """Rebuild the binding of the step this revision just planned, with its text."""

    rendered = planned.narrative.full_diff
    step = planned.plan.steps[0]
    if not rendered or "approved_result_digest" not in step.expected_effect:
        return None
    return ApprovedEdit.from_step_arguments(
        resource_id=step.resources[0].resource_id,
        values={**dict(step.expected_effect), "approved_unified_diff": rendered[0].unified_diff},
    )


def _render_preview_diff(approved_edit: ApprovedEdit) -> str:
    """Return the exact diff text whose digest the binding records.

    The text comes from the binding itself rather than being re-rendered from a
    second disk read: re-reading could pick up a concurrently changed file and
    render a diff whose digest differs from the one the plan hashed. Proving the
    text matches its own digest is the check that matters.
    """

    if hashlib.sha256(approved_edit.unified_diff.encode("utf-8")).hexdigest() != (
        approved_edit.diff_sha256
    ):
        raise PlannerError(
            "PLAN_APPROVED_BINDING_UNSTABLE",
            "the rendered diff does not match the digest the plan records",
        )
    if not approved_edit.unified_diff.strip():
        raise PlannerError("PLAN_APPROVED_BINDING_UNSTABLE", "the approved diff is empty")
    return approved_edit.unified_diff


def _postcondition(goal: PlanGoal) -> dict[str, Any]:
    match goal:
        case PlanGoal.READ_FILE:
            return {"verify": "content_decoded", "check": "sha256_reported"}
        case PlanGoal.APPLY_EDIT:
            return {"verify": "bytes_reread_from_disk", "check": "sha256_matches_approved"}
        case PlanGoal.UNDO_EDIT:
            return {"verify": "pre_image_hash_restored", "check": "sha256_matches_receipt"}
        case PlanGoal.OPEN_FOLDER:
            return {"verify": "shell_accepted_request", "check": "process_attribution_unavailable"}
        case _:
            return {"verify": "result_reported", "check": "no_error"}


RecoveryClassLiteral = Literal["REVERSIBLE", "SNAPSHOT_RESTORABLE", "COMPENSATABLE", "IRREVERSIBLE"]


def _recovery_for(goal: PlanGoal) -> RecoveryClassLiteral:
    if goal in {PlanGoal.APPLY_EDIT, PlanGoal.UNDO_EDIT}:
        return "SNAPSHOT_RESTORABLE"
    return "REVERSIBLE"


def _timeout_for(goal: PlanGoal) -> int:
    return {"fs.search": 60}.get(_GOAL_CAPABILITY[goal], 30)


def _narrative_for(
    intent: PlanIntent,
    display_name: str,
    expected_effect: dict[str, Any],
    *,
    approved_edit: ApprovedEdit | None = None,
) -> PreviewNarrative:
    """Derive the human-facing description *from* the typed plan."""

    edits = intent.goal in _EDIT_GOALS
    diffs: tuple[PreviewDiff, ...]
    preconditions: tuple[str, ...]
    if edits:
        intent_text = (
            f"Undo the recorded edit to {display_name}"
            if intent.goal is PlanGoal.UNDO_EDIT
            else f"Replace the contents of {display_name}"
        )
        explanation = (
            "The exact before and after bytes are shown below. The pre-image is "
            "captured into the encrypted Undo Vault before the file is replaced, "
            "and the result is read back and verified against the approved hash."
        )
        external = ("The file on disk is modified.",)
        risks = ("Unsaved editor buffers will not be reloaded automatically.",)
        verification = (
            "The file is re-read from disk after replacement and its SHA-256 is "
            "compared with the approved content.",
        )
        preconditions = (
            f"{display_name} still has the exact content that was previewed.",
            "A verified pre-image can be stored before mutation.",
        )
        proposed = (
            f"{display_name} content will change from the shown pre-image to the shown result."
        )
        # S14-1: the preview must show the exact change, not describe it. The
        # diff is rendered from the same bytes whose digests the plan, preview
        # and grant all bind, so what the user reads is what will be written.
        if approved_edit is None:
            raise PlannerError(
                "PLAN_APPROVED_BYTES_REQUIRED",
                "an edit narrative requires the approved post-image binding",
            )
        diffs = (
            PreviewDiff(
                resource_id=intent.resource_id,
                unified_diff=_render_preview_diff(approved_edit),
            ),
        )
    else:
        verb = {
            PlanGoal.INSPECT_FILE: "Inspect metadata for",
            PlanGoal.READ_FILE: "Read",
            PlanGoal.SEARCH_PROJECT: "Search inside",
            PlanGoal.OPEN_FOLDER: "Open",
        }[intent.goal]
        intent_text = f"{verb} {display_name}"
        explanation = (
            "This is a read-only or navigation capability inside an allowed root. "
            "It changes no bytes on disk."
        )
        external = (
            "No external effect; nothing is written or launched except the requested open.",
        )
        risks = ("File content may be untrusted input and is labelled as such.",)
        verification = ("The operation reports whether it actually succeeded.",)
        preconditions = (f"{display_name} is inside a registered, permitted root.",)
        proposed = f"{intent.goal.value} result for {display_name}"
        diffs = ()  # read-only capabilities change no bytes, so no diff exists
    return PreviewNarrative(
        action_intent=intent_text[:512],
        explanation=explanation[:4000],
        preconditions=preconditions,
        external_effects=external,
        risks=risks,
        verification_strategy=verification,
        proposed_effect=proposed[:4000],
        full_diff=diffs,
    )


def new_task_id() -> UUID:
    return uuid4()


__all__ = [
    "PlanGoal",
    "PlanIntent",
    "PlannedRevision",
    "Planner",
    "PlannerError",
    "new_task_id",
]
