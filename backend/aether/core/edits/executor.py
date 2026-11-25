"""The single T2 mutation path: verified edits and authorized undo (Phase 2D).

There is exactly one function in the backend that replaces user file content,
and this is it. Everything that mutates goes through :meth:`EditExecutor.apply`
or :meth:`EditExecutor.undo`, so a single review can reason about every write.

The order of operations is the security property:

1. **Binding first.** No mutation is attempted before the exact grant has
   been scope-verified against the persisted ledger, the current plan and the
   live resource version, and before the persisted approval binding —
   including a recomputed canonical aether-diff-v2 rendering of the actual
   bytes — has been verified against the pre-image. Verification is not
   consumption: a refused legacy binding spends no grant use.
2. **Freshness second.** The target is re-inspected and compared with the
   version the user approved, and re-read immediately before the replace.
   A file that changed since preview stops here with
   ``STALE_TARGET`` and *no write* — the caller must produce a new preview and a
   new approval.
3. **Snapshot third.** The pre-image is captured, stored in the encrypted vault,
   and read back to verify it before the original is touched.
4. **Atomic replace fourth.** Same-directory temporary file, fsync, then
   ``os.replace`` — same volume by construction, so the replacement is atomic on
   NTFS and POSIX alike.
5. **Verify fifth.** The result is re-read, hashed and compared with the intended
   bytes. Sharing violations, partial writes and interruption are detected here.
6. **Receipt last.** Only a verified effect produces ``SUCCEEDED``.

If any step fails, the receipt records what actually happened. A failure after
the replace but before verification is recorded ``UNVERIFIED`` with the snapshot
reference intact, so recovery is possible and no false success is claimed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from aether.core.contracts.policy import RiskTier
from aether.core.contracts.resource import ResourceRef
from aether.core.contracts.tool import ToolRequest
from aether.core.edits.journal import JournalError, MutationJournal
from aether.core.edits.receipts import (
    ActionReceiptRecord,
    ReceiptError,
    ReceiptStore,
)
from aether.core.fs import errors as fs_errors
from aether.core.grants.authority import GrantAuthority, GrantRequest
from aether.core.grants.consumption import IssuanceDisabledConsumptionLedger
from aether.core.planning.edit_binding import ApprovedEdit, EditBindingError
from aether.core.planning.exact_diff import DiffError, render_exact_diff
from aether.core.resources.path_safety import (
    PathSafetyError,
    is_protected_path,
    reject_reparse_components,
)
from aether.core.resources.registry import ResourceRegistry, ResourceRegistryError
from aether.core.vault.undo_vault import UndoVault, VaultError

EditStatus = Literal["SUCCEEDED", "FAILED", "UNVERIFIED", "PARTIAL"]


class TaskPlanSource(Protocol):
    """The narrow read surface this executor needs from plan persistence."""

    def get_plan(self, task_id: UUID, revision: int | None = None) -> Any: ...


class GrantConsumer(Protocol):
    """Atomic, replay-safe grant accounting (S14-2).

    ``consume`` must be transactional: it either decrements a use *and* records
    the consumption for this exact action identity, or it changes nothing. The
    executor never treats an unverified grant as permission, and never spends a
    use before the action is certain to be attempted.
    """

    def consume(
        self,
        *,
        consumption_id: UUID,
        approval_id: UUID,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        step_id: UUID,
        capability_id: str,
        risk_tier: RiskTier,
        arguments_sha256: str,
        expected_effect_sha256: str,
        resource_versions: dict[str, str],
        consumed_by: str,
        now: datetime | None = None,
    ) -> Any: ...


_MAX_EDIT_BYTES = 4 * 1024 * 1024
_FORWARD_EDIT_CAPABILITY = "fs.apply_approved_edit"
_UNDO_CAPABILITY = "fs.undo_edit"


@dataclass(frozen=True, slots=True)
class _OperationContext:
    """State belonging to exactly one attempt, never shared between attempts.

    S14-9: ``_consumption_id`` used to be mutable executor state. Two overlapping
    operations therefore shared it, and the second could resolve the first's
    consumption (or the first could resolve the second's). Everything a single
    attempt needs to identify itself is created per attempt and passed down
    explicitly, so no operation can touch another's accounting.
    """

    consumption_id: UUID | None = None
    journal_id: UUID | None = None
    capability_id: str = _FORWARD_EDIT_CAPABILITY


class EditDenied(Exception):
    """The edit was refused before any mutation; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True, slots=True)
class EditRequest:
    """Everything needed to attempt exactly one approved edit."""

    task_id: UUID
    step_id: UUID
    approval_id: UUID
    plan_revision: int
    plan_hash: str
    resource_id: str
    expected_sha256: str
    proposed_content: bytes
    expected_effect_sha256: str


@dataclass(frozen=True, slots=True)
class EditOutcome:
    """Result of one attempted edit, with the receipt that proves it."""

    status: EditStatus
    reason_code: str
    receipt: ActionReceiptRecord | None
    pre_sha256: str | None
    post_sha256: str | None
    snapshot_id: str | None
    detail: str


class EditExecutor:
    """Executes verified edits and authorized undo through one code path."""

    def __init__(
        self,
        registry: ResourceRegistry,
        authority: GrantAuthority,
        vault: UndoVault,
        receipts: ReceiptStore,
        *,
        plans: TaskPlanSource | None = None,
        grants: GrantConsumer | None = None,
        journal: MutationJournal | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        # S14-1: the approved post-image is read from the persisted plan, never
        # from the request. A caller-supplied digest would let a caller approve
        # itself, which is precisely the substitution this closes.
        self._plans = plans
        # S14-2: a validated grant is not execution authority. One use must be
        # spent atomically against the exact action, or nothing happens. The
        # default refuses every consumption, so a default-constructed executor
        # cannot mutate -- the same shape as GRANT_ISSUANCE_DISABLED.
        self._grants = grants if grants is not None else IssuanceDisabledConsumptionLedger()
        # S14-4: the durable pre-mutation intent, so a crash between replace and
        # receipt is never invisible.
        self._journal = journal
        self._authority = authority
        self._vault = vault
        self._receipts = receipts
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- public operations -----------------------------------------------

    def apply(
        self, request: EditRequest, *, checkpoint: Callable[[str], None] | None = None
    ) -> EditOutcome:
        """Apply exactly one approved edit, or refuse without writing.

        ``checkpoint`` (FI-04) is invoked at the real execution checkpoints
        so callers can record actual progress: ``"consumed"`` after the
        grant use is durably spent and before any mutation, ``"verified"``
        after the durable verified receipt exists. A checkpoint that raises
        aborts the operation at that point (before mutation for
        ``"consumed"``); progress is never reconstructed after the fact.
        """

        if len(request.proposed_content) > _MAX_EDIT_BYTES:
            raise EditDenied("edit_too_large", "proposed content exceeds the edit bound")
        target = self._authorize(request, capability_id=_FORWARD_EDIT_CAPABILITY)
        return self._mutate(
            target=target,
            content=request.proposed_content,
            request=request,
            capability_id=_FORWARD_EDIT_CAPABILITY,
            recovery_class="SNAPSHOT_RESTORABLE",
            checkpoint=checkpoint,
        )

    def undo(
        self,
        request: EditRequest,
        *,
        snapshot_id: UUID,
        receipt_id: UUID,
        checkpoint: Callable[[str], None] | None = None,
    ) -> EditOutcome:
        """Restore a snapshot under its own fs.undo_edit authorization (S14-3).

        Undo is a distinct capability, not a reuse of the edit approval:

        1. The target is re-authorized against the *undo* capability scope.
        2. The receipt must exist, reference this exact snapshot, name this
           resource, and have recorded a verified post-image.
        3. The snapshot plaintext must hash to the receipt's pre-image.
        4. The current file must still be the receipt's verified post-image. If it
           is not, a newer edit happened and an ordinary undo is refused as a
           conflict: the user edits after the edit must never be silently undone.
        5. Only then is one fs.undo_edit use consumed, before any mutation.
        """

        target = self._authorize_undo(request, receipt_id=receipt_id, snapshot_id=snapshot_id)
        original_receipt = self._receipts.get(receipt_id)
        if original_receipt.snapshot_id != str(snapshot_id):
            raise EditDenied(
                "undo_receipt_snapshot_mismatch",
                "the receipt does not reference this snapshot",
            )
        try:
            restored = self._vault.get(snapshot_id)
        except VaultError as exc:
            raise EditDenied(exc.reason_code, str(exc)) from exc
        if hashlib.sha256(restored).hexdigest() != original_receipt.pre_sha256:
            raise EditDenied(
                "undo_snapshot_hash_mismatch",
                "the snapshot does not match the pre-image recorded by the receipt",
            )
        return self._mutate(
            target=target,
            content=restored,
            request=request,
            capability_id="fs.undo_edit",
            recovery_class="SNAPSHOT_RESTORABLE",
            extra_warnings=(),
            undo_of=str(receipt_id),
            checkpoint=checkpoint,
        )

    # -- internals -------------------------------------------------------

    def _authorize_undo(self, request: EditRequest, *, receipt_id: UUID, snapshot_id: UUID) -> Path:
        """Authorize an undo as its own capability, with conflict detection."""

        target = self._authorize(request, capability_id=_UNDO_CAPABILITY)
        try:
            original = self._receipts.get(receipt_id)
        except ReceiptError as exc:
            raise EditDenied(
                "undo_receipt_unavailable", "the receipt named by the undo is unreadable"
            ) from exc
        if original.snapshot_id != str(snapshot_id):
            raise EditDenied(
                "undo_receipt_snapshot_mismatch",
                "the receipt does not reference this snapshot",
            )
        if original.resource_id != request.resource_id:
            raise EditDenied(
                "undo_receipt_resource_mismatch",
                "the receipt belongs to a different resource",
            )
        if original.status != "SUCCEEDED" or original.post_sha256 is None:
            # Only an edit whose effect was *verified* can be undone. An
            # UNVERIFIED edit has unknown content and needs review, not undo.
            raise EditDenied(
                "undo_receipt_not_verified",
                "only a verified edit can be undone as an ordinary action",
            )
        try:
            current = target.read_bytes()
        except OSError as exc:
            raise EditDenied(fs_errors.RESOURCE_NOT_FOUND, "target is unreadable") from exc
        current_sha = hashlib.sha256(current).hexdigest()
        if current_sha != original.post_sha256:
            # A newer edit (or an external change) intervened. Ordinary undo must
            # not clobber it: this is an explicit conflict needing fresh review.
            raise EditDenied(
                "undo_conflict_newer_content",
                "the file changed after the edit being undone; a fresh preview and "
                "approval are required before restoring",
            )
        if request.expected_sha256 != current_sha:
            raise EditDenied(
                "STALE_TARGET",
                "the undo was authorized against different current content",
            )
        return target

    def _authorize(self, request: EditRequest, *, capability_id: str = "") -> Path:
        """Verify grant scope and freshness; return the target path. No writes."""
        """Verify grant scope and freshness; return the target path. No writes."""

        try:
            resolved = self._registry.resource_by_id(request.resource_id)
        except ResourceRegistryError as exc:
            raise EditDenied(
                fs_errors.RESOURCE_NOT_REGISTERED, "resource id was never issued"
            ) from exc
        path = resolved.canonical_path
        try:
            root = self._registry.root_by_id(resolved.root_id)
        except ResourceRegistryError as exc:
            raise EditDenied(fs_errors.RESOURCE_NOT_REGISTERED, str(exc)) from exc
        if capability_id not in root.allowed_capabilities:
            raise EditDenied(
                fs_errors.CAPABILITY_OUTSIDE_ROOT_SCOPE,
                "the registered root does not permit this capability",
            )
        if is_protected_path(path):
            raise EditDenied(fs_errors.PROTECTED_PATH_DENIED, "protected paths are never editable")
        try:
            reject_reparse_components(path)
            current = path.stat()
        except (OSError, PathSafetyError) as exc:
            raise EditDenied(fs_errors.RESOURCE_NOT_FOUND, "target is unavailable") from exc
        if not stat.S_ISREG(current.st_mode):
            raise EditDenied(fs_errors.UNSUPPORTED_RESOURCE_TYPE, "target is not a regular file")
        if getattr(current, "st_nlink", 1) > 1:
            raise EditDenied(fs_errors.HARD_LINK_DENIED, "hard-linked targets are refused")
        arguments: dict[str, Any] = {
            "resource_id": request.resource_id,
            "step_id": str(request.step_id),
            "approval_id": str(request.approval_id),
            "expected_sha256": request.expected_sha256,
        }
        if self._plans is not None:
            # Phase 2 final integration: the grant binds the persisted step's
            # exact arguments — the same hash the consumption presents — so
            # present those verbatim rather than a reconstructed subset. A
            # subset silently drops undo's receipt/snapshot identity and can
            # never match the issued operation. If the step cannot be loaded,
            # keep the historical shape and let the binding checks below
            # refuse with their usual reason; the scope check never gets a
            # chance to authorize anything on this path either way.
            with contextlib.suppress(EditDenied):
                arguments = dict(self._plan_step(request, capability_id=capability_id).arguments)
        request_shape = ToolRequest(
            request_id=str(request.step_id),
            task_id=str(request.task_id),
            capability_id=capability_id,
            arguments=arguments,
            resources=[
                ResourceRef(
                    kind="file",
                    resource_id=resolved.ref.resource_id,
                    observed_version=resolved.version_token,
                    data_class=resolved.data_class,
                )
            ],
        )
        check = self._authority.check_action(
            request_shape,
            GrantRequest(
                approval_id=request.approval_id,
                plan_revision=request.plan_revision,
                plan_hash=request.plan_hash,
                step_id=request.step_id,
                expected_effect_sha256=request.expected_effect_sha256,
            ),
            risk_tier=RiskTier.MODIFY,
            now=self._clock(),
        )
        if not check.ok:
            raise EditDenied(check.reason_code, "the exact grant does not cover this edit")
        return path

    def _plan_step(
        self, request: EditRequest, *, capability_id: str = _FORWARD_EDIT_CAPABILITY
    ) -> Any:
        """The authoritative persisted step for this request, or refuse.

        The step's capability is checked, so an edit step cannot authorize an
        undo and an undo step cannot authorize an edit. This is the check that
        keeps the two capabilities from sharing authority.
        """

        if self._plans is None:
            raise EditDenied(
                "approved_result_binding_unavailable",
                "no persisted plan source is configured, so no step was approved",
            )
        try:
            plan = self._plans.get_plan(request.task_id, request.plan_revision)
        except Exception as exc:
            raise EditDenied(
                "approved_plan_unavailable", "the approved plan revision could not be read"
            ) from exc
        step = next((item for item in plan.steps if item.step_id == request.step_id), None)
        if step is None:
            raise EditDenied(
                "approved_step_missing",
                "the persisted plan has no such step, so nothing was approved here",
            )
        if step.capability_id != capability_id:
            raise EditDenied(
                "approved_capability_mismatch",
                "the persisted step authorizes a different capability than this action",
            )
        return step

    def _plan_binding(
        self, request: EditRequest, *, capability_id: str = _FORWARD_EDIT_CAPABILITY
    ) -> ApprovedEdit:
        """The persisted approval binding for this request, or refuse."""

        step = self._plan_step(request, capability_id=capability_id)
        try:
            return ApprovedEdit.from_step_arguments(
                resource_id=request.resource_id, values=dict(step.expected_effect)
            )
        except EditBindingError as exc:
            raise EditDenied(
                "approved_binding_malformed",
                "the persisted plan does not carry a usable approval binding",
            ) from exc

    def _consume_grant(
        self,
        request: EditRequest,
        step: Any,
        binding: ApprovedEdit,
        *,
        capability_id: str = _FORWARD_EDIT_CAPABILITY,
    ) -> UUID:
        """Spend exactly one grant use against this exact action (S14-2).

        Ordering matters and is deliberate:

        1. Prove a consumer is configured. Without one there is no accounting, so
           no mutation: ``GRANT_VALIDATED_EXECUTOR_NOT_ENABLED`` is a *policy*
           answer, not permission, and this method never treats it as one.
        2. Derive the action identity from the *persisted plan*, not the request,
           so a caller cannot describe a different action to the ledger than the
           one it is about to perform.
        3. Consume atomically. The ledger decrements and records in one
           transaction, so a duplicate execution is impossible and a replay with
           different terms is refused.
        4. Refuse anything that is not a first, exact consumption.
        """

        consumption_id = uuid4()
        try:
            consumption = self._grants.consume(
                consumption_id=consumption_id,
                approval_id=request.approval_id,
                task_id=request.task_id,
                plan_revision=request.plan_revision,
                plan_hash=request.plan_hash,
                step_id=request.step_id,
                capability_id=capability_id,
                risk_tier=RiskTier.MODIFY,
                arguments_sha256=_canonical_digest(dict(step.arguments)),
                expected_effect_sha256=str(step.expected_effect.get("approved_effect_digest")),
                resource_versions={request.resource_id: str(step.resources[0].expected_version)},
                consumed_by=_CONSUMER_CODE,
                now=self._clock(),
            )
        except Exception as exc:
            reason = getattr(exc, "reason_code", None) or "grant_consumption_failed"
            raise EditDenied(str(reason), "grant consumption was refused") from exc
        if getattr(consumption, "replayed", False):
            # A replay of the same consumption id would double-execute the same
            # grant use. Refuse rather than perform the action twice.
            raise EditDenied(
                "grant_consumption_replayed",
                "this grant use has already been spent on the same action",
            )
        del binding
        return consumption_id

    def _mutate(
        self,
        *,
        target: Path,
        content: bytes,
        request: EditRequest,
        capability_id: str,
        recovery_class: str,
        extra_warnings: tuple[str, ...] = (),
        undo_of: str | None = None,
        checkpoint: Callable[[str], None] | None = None,
    ) -> EditOutcome:
        intended_sha256 = hashlib.sha256(content).hexdigest()
        # S14-9: mutation requires a durable journal. Without one there is no
        # record that the write was attempted, so a crash would be invisible and
        # the operation is refused before any state changes.
        if self._journal is None:
            raise EditDenied(
                "journal_unavailable",
                "a durable mutation journal is mandatory for every mutation-capable "
                "executor; refusing to mutate without one",
            )
        try:
            pre_image = target.read_bytes()
        except OSError as exc:
            raise EditDenied(fs_errors.RESOURCE_NOT_FOUND, "target is unreadable") from exc
        pre_sha256 = hashlib.sha256(pre_image).hexdigest()

        # Legacy EOF binding: if the actual byte pair already matches the
        # persisted binding, the persisted rendering/effect digests must
        # also be the canonical aether-diff-v2 rendering of those bytes --
        # and that is checked BEFORE the grant is spent, so a legacy (v1)
        # binding spends nothing, creates no PENDING consumption and
        # mutates nothing. If the byte pair does not match, this defers to
        # the post-consumption verification below, preserving the existing
        # grant-accounting ordering for every other refusal.
        self._refuse_unrenderable_binding_before_spend(
            request,
            content=content,
            pre_image=pre_image,
            display_name=target.name,
            capability_id=capability_id,
        )

        # S14-2: spend the use before touching the file at all, so a crash leaves
        # a PENDING consumption (findable) rather than an unaccounted side effect.
        consumption_id = self._consume_grant(
            request,
            self._plan_step(request, capability_id=capability_id),
            self._plan_binding(request, capability_id=capability_id),
            capability_id=capability_id,
        )
        context = _OperationContext(consumption_id=consumption_id, capability_id=capability_id)
        # FI-04 consumed checkpoint: the use is durably spent; nothing has
        # been mutated yet. A raising checkpoint aborts here, pre-journal.
        if checkpoint is not None:
            checkpoint("consumed")

        # Freshness: the bytes the user approved must still be the bytes on disk.
        if pre_sha256 != request.expected_sha256:
            raise EditDenied(
                "STALE_TARGET",
                "the file changed after preview; a new preview and approval are required",
            )
        if intended_sha256 == pre_sha256:
            raise EditDenied(
                "edit_no_change", "the proposed content is identical to the current content"
            )

        # S14-1: the bytes about to be written must be the bytes the persisted
        # plan bound and the user approved. Checked here, immediately before any
        # mutation, so a caller cannot pair the approved pre-image with a
        # different post-image. ``content`` is the intended write for apply
        # and the verified vault bytes for undo -- never a caller-supplied
        # description of them.
        self._verify_approved_result(
            request,
            intended_sha256,
            pre_image,
            content=content,
            display_name=target.name,
            capability_id=capability_id,
        )

        # Snapshot first, and verify the snapshot before touching the original.
        try:
            snapshot = self._vault.put(
                pre_image,
                original_display_name=target.name,
                receipt_id=str(request.step_id),
            )
            if hashlib.sha256(self._vault.get(snapshot.snapshot_id)).hexdigest() != pre_sha256:
                raise EditDenied(
                    "snapshot_verification_failed",
                    "the captured pre-image did not verify; refusing to mutate",
                )
        except VaultError as exc:
            # Without a verified snapshot the edit is not snapshot-restorable, so
            # it is refused rather than performed irreversibly.
            raise EditDenied(
                "snapshot_unavailable",
                f"a verified pre-image is required before mutation ({exc.reason_code})",
            ) from exc

        # S14-4: the durable intent is written AFTER the snapshot (so the
        # recovery path has an image to restore) and BEFORE the replace (so a
        # crash can never leave a changed file with no record of why). If the
        # intent cannot be written, nothing is mutated.
        journal_id = self._begin_journal(
            context,
            request,
            capability_id=capability_id,
            resource_id=request.resource_id,
            target_path=target,
            pre_sha256=pre_sha256,
            intended_sha256=intended_sha256,
            snapshot_id=snapshot.snapshot_id,
        )

        context = _OperationContext(
            consumption_id=context.consumption_id,
            journal_id=journal_id,
            capability_id=capability_id,
        )

        warnings: list[str] = list(extra_warnings)
        try:
            self._atomic_replace(target, content, pre_image)
        except EditDenied as denied:
            failure_receipt = self._record_failure(
                request,
                capability_id,
                target,
                pre_sha256,
                snapshot.snapshot_id,
                recovery_class,
                denied.reason_code,
                extra=undo_of,
            )
            # The replacement definitively did not happen, so the spent use is
            # resolved FAILED. Leaving it PENDING would report a refused
            # mutation to reconciliation as an unexplained one (S14-8).
            self._resolve_consumption(context.consumption_id, "FAILED", denied.reason_code)
            self._resolve_journal(context.journal_id, "FAILED", denied.reason_code)
            return EditOutcome(
                status="FAILED",
                reason_code=denied.reason_code,
                receipt=failure_receipt,
                pre_sha256=pre_sha256,
                post_sha256=None,
                snapshot_id=str(snapshot.snapshot_id),
                detail="the replacement failed; the original content is unchanged",
            )

        # The replace is done but not yet proven. Recording this narrows the
        # crash window to "bytes written, verification not finished", which
        # reconciliation can interpret.
        self._journal_replaced_unverified(journal_id)

        # Verification: re-read from disk, never trust the write call.
        try:
            observed = target.read_bytes()
            post_sha256 = hashlib.sha256(observed).hexdigest()
        except OSError:
            return self._unverified(
                request,
                capability_id,
                target,
                pre_sha256,
                snapshot.snapshot_id,
                recovery_class,
                "readback_failed",
                warnings,
                undo_of,
                context,
            )
        if post_sha256 != intended_sha256 or observed != content:
            return self._unverified(
                request,
                capability_id,
                target,
                pre_sha256,
                snapshot.snapshot_id,
                recovery_class,
                "verification_mismatch",
                warnings,
                undo_of,
                context,
            )

        # The verified effect happened, so the receipt is recorded *now*. A
        # receipt that only existed in memory would make a completed edit
        # invisible to reconciliation after a crash.
        receipt = self._record(
            request,
            capability_id,
            target,
            pre_sha256,
            post_sha256,
            snapshot.snapshot_id,
            recovery_class,
            "SUCCEEDED",
            warnings,
            undo_of,
            verified_at=self._clock(),
        )
        # FI-04 verified checkpoint: the durable verified receipt now
        # exists; only bookkeeping resolution remains.
        if checkpoint is not None:
            checkpoint("verified")
        self._resolve_consumption(context.consumption_id, "SUCCEEDED", "verified effect")
        self._resolve_journal(context.journal_id, "VERIFIED", "verified effect")
        return EditOutcome(
            status="SUCCEEDED",
            reason_code="edit_verified",
            receipt=receipt,
            pre_sha256=pre_sha256,
            post_sha256=post_sha256,
            snapshot_id=str(snapshot.snapshot_id),
            detail="bytes were re-read from disk and match the approved content exactly",
        )

    def _begin_journal(
        self,
        context: _OperationContext,
        request: EditRequest,
        *,
        capability_id: str,
        resource_id: str,
        target_path: Path,
        pre_sha256: str,
        intended_sha256: str,
        snapshot_id: UUID,
    ) -> UUID:
        """Write the durable intent, or refuse the mutation.

        A journal that cannot record the intent must not let the write proceed:
        an unrecorded mutation is the failure mode this closes. The journal is
        mandatory (S14-9), so this method is only reached with one configured,
        and the check is repeated here so the guarantee does not depend on the
        caller having remembered it.
        """

        if self._journal is None:
            raise EditDenied(
                "journal_unavailable",
                "a durable mutation journal is mandatory before mutation",
            )
        try:
            intent = self._journal.begin(
                task_id=request.task_id,
                step_id=request.step_id,
                approval_id=request.approval_id,
                capability_id=capability_id,
                resource_id=resource_id,
                target_path=target_path,
                resource_version=request.expected_sha256,
                pre_sha256=pre_sha256,
                intended_post_sha256=intended_sha256,
                expected_effect_sha256=request.expected_effect_sha256,
                snapshot_id=snapshot_id,
                consumption_id=context.consumption_id,
            )
        except JournalError as exc:
            raise EditDenied(
                exc.reason_code,
                "a durable intent is required before mutation, and it could not be recorded",
            ) from exc
        return intent.intent_id

    def _journal_replaced_unverified(self, journal_id: UUID | None) -> None:
        if self._journal is None or journal_id is None:
            return
        try:
            self._journal.record_replaced_unverified(
                journal_id, "replaced; verification not yet recorded"
            )
        except JournalError:
            # The intent still exists, which is what reconciliation needs.
            return

    def _resolve_journal(self, journal_id: UUID | None, state: str, detail: str) -> None:
        if self._journal is None or journal_id is None:
            return
        try:
            self._journal.resolve(journal_id, state=state, detail=detail)  # type: ignore[arg-type]

        except JournalError:
            # An unresolved intent is the reconciliation work list; never mask it.
            return

    def _resolve_consumption(self, consumption_id: UUID | None, state: str, detail: str) -> None:
        """Record what actually happened to the spent use.

        A failure here leaves the consumption PENDING, which is exactly what
        reconciliation looks for. A spent use is never recorded as successful
        merely because the process reached this call. The identity is passed in
        rather than read from instance state, so one attempt can only ever resolve
        its own consumption (S14-9).
        """

        if consumption_id is None:
            return
        resolver = getattr(self._grants, "resolve", None)
        if resolver is None:
            return
        try:
            resolver(consumption_id, state=state, detail=detail)
        except Exception:
            # The receipt still records the truth; the pending consumption is
            # the recovery work item.
            return

    def _verify_rendering_binding(
        self, binding: ApprovedEdit, *, pre_image: bytes, content: bytes, display_name: str
    ) -> None:
        """Refuse unless the binding is the canonical v2 rendering of the bytes.

        Recomputed from the actual pre/post bytes every time; the display
        name comes from the executor-resolved target -- the same source
        the planner used -- never from the request or the persisted step,
        so it cannot be spoofed.
        """

        try:
            rendered = render_exact_diff(
                pre_image=pre_image, post_image=content, display_name=display_name
            )
        except DiffError as exc:
            raise EditDenied(
                "approved_rendering_unverifiable",
                "the approved bytes cannot be rendered as a canonical "
                f"aether-diff-v2 diff ({exc.reason_code}); a fresh preview "
                "and approval are required",
            ) from exc
        if (
            rendered.diff_sha256 != binding.diff_sha256
            or rendered.effect_sha256 != binding.effect_sha256
        ):
            raise EditDenied(
                "approved_rendering_mismatch",
                "the persisted approval does not correspond to the canonical "
                "aether-diff-v2 rendering of the approved bytes; a fresh "
                "preview and approval are required",
            )

    def _refuse_unrenderable_binding_before_spend(
        self,
        request: EditRequest,
        *,
        content: bytes,
        pre_image: bytes,
        display_name: str,
        capability_id: str,
    ) -> None:
        """Reject a legacy/unrenderable binding before any grant consumption.

        Only fires when the actual byte pair already matches the persisted
        binding -- precisely the legacy case, where byte digests pass but
        the rendering was never EOF-exact. Any other mismatch defers to
        the post-consumption verification, preserving the existing
        grant-accounting ordering for those refusals.
        """

        if self._plans is None:
            return
        try:
            binding = self._plan_binding(request, capability_id=capability_id)
        except EditDenied:
            return
        try:
            binding.verify_proposed(proposed_content=content, current_pre_image=pre_image)
        except EditBindingError:
            return
        self._verify_rendering_binding(
            binding, pre_image=pre_image, content=content, display_name=display_name
        )

    def _verify_approved_result(
        self,
        request: EditRequest,
        intended_sha256: str,
        pre_image: bytes,
        *,
        content: bytes,
        display_name: str,
        capability_id: str = _FORWARD_EDIT_CAPABILITY,
    ) -> None:
        """Refuse unless the content matches the binding in the persisted plan.

        The digest is *not* taken from the request. Reading it from the immutable
        persisted plan means the only way to change which bytes are authorized is
        to produce a new plan revision with a new hash — which invalidates the
        existing approval instead of silently reusing it.

        ``content`` is the actual byte string about to be written: the
        approved proposed content for a forward edit, and the vault-restored
        bytes for an undo. ``request.proposed_content`` is deliberately not
        consulted here, so an undo can never be verified against
        caller-supplied bytes that differ from the snapshot being restored.

        Finally, the canonical aether-diff-v2 rendering is recomputed from
        the actual pre/post bytes and its digests must equal the persisted
        binding. A legacy (pre-trailer, v1) binding therefore fails closed
        here — before any grant consumption or mutation — because its
        rendering/effect digests cannot match the v2 rendering, even though
        its byte digests still do.
        """

        if self._plans is None:
            raise EditDenied(
                "approved_result_binding_unavailable",
                "no persisted plan source is configured, so approval cannot be "
                "bound to the bytes about to be written",
            )
        step = self._plan_step(request, capability_id=capability_id)
        binding = self._plan_binding(request, capability_id=capability_id)
        try:
            binding.verify_proposed(proposed_content=content, current_pre_image=pre_image)
        except EditBindingError as exc:
            raise EditDenied(exc.reason_code, str(exc)) from exc
        if intended_sha256 != binding.post_sha256:
            raise EditDenied(
                "approved_post_image_mismatch",
                "the content to be written is not the content that was approved",
            )
        # The grant's effect digest must be the one the plan bound, otherwise the
        # grant covers a different change than the one being applied.
        bound_effect = str(step.expected_effect.get("approved_effect_digest", ""))
        if not bound_effect or request.expected_effect_sha256 != bound_effect:
            raise EditDenied(
                "approved_effect_digest_mismatch",
                "the grant does not cover the effect the approved plan records",
            )
        # Legacy EOF binding: recompute the canonical v2 rendering from the
        # actual bytes and compare (see _verify_rendering_binding).
        self._verify_rendering_binding(
            binding, pre_image=pre_image, content=content, display_name=display_name
        )

    def _atomic_replace(self, target: Path, content: bytes, pre_image: bytes) -> None:
        """Same-volume atomic replacement, preserving the original file mode.

        The target is re-read immediately before the replace and must still
        be the verified pre-image: a concurrent change since verification
        is refused as ``STALE_TARGET`` rather than silently overwritten.
        (A change in the remaining instant between this read and
        ``os.replace`` cannot be closed portably without a conditional
        rename primitive; that residual window is reported separately
        rather than papered over here.)
        """

        try:
            with open(target, "rb") as stream:
                current = stream.read()
        except OSError as exc:
            raise EditDenied(fs_errors.RESOURCE_NOT_FOUND, "target is unreadable") from exc
        if hashlib.sha256(current).hexdigest() != hashlib.sha256(pre_image).hexdigest():
            raise EditDenied(
                "STALE_TARGET",
                "the file changed after verification; a new preview and approval are required",
            )
        try:
            mode = stat.S_IMODE(target.stat().st_mode)
        except OSError as exc:
            raise EditDenied(fs_errors.RESOURCE_NOT_FOUND, "target mode is unavailable") from exc
        temporary_path: str | None = None
        try:
            descriptor, temporary_path = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".aether-tmp", dir=str(target.parent)
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_path, mode)
            # Verify the staged bytes before the swap so a truncated write never
            # becomes the user's file.
            with open(temporary_path, "rb") as staged:
                if hashlib.sha256(staged.read()).hexdigest() != hashlib.sha256(content).hexdigest():
                    raise EditDenied(
                        "staged_write_mismatch", "the staged temporary file did not verify"
                    )
            os.replace(temporary_path, target)
            temporary_path = None
            _fsync_directory(target.parent)
        except OSError as exc:
            raise EditDenied(
                _map_os_error(exc), "the target could not be replaced atomically"
            ) from exc
        finally:
            if temporary_path is not None:
                with contextlib.suppress(OSError):
                    os.unlink(temporary_path)

    def _unverified(
        self,
        request: EditRequest,
        capability_id: str,
        target: Path,
        pre_sha256: str,
        snapshot_id: UUID,
        recovery_class: str,
        reason: str,
        warnings: list[str],
        undo_of: str | None,
        context: _OperationContext,
    ) -> EditOutcome:
        """Record an edit we cannot prove; never claim success."""

        warnings = [*warnings, reason]
        self._resolve_consumption(context.consumption_id, "UNVERIFIED", reason)
        self._resolve_journal(context.journal_id, "REPLACED_UNVERIFIED", reason)
        receipt = self._record(
            request,
            capability_id,
            target,
            pre_sha256,
            None,
            snapshot_id,
            recovery_class,
            "UNVERIFIED",
            warnings,
            undo_of,
        )
        return EditOutcome(
            status="UNVERIFIED",
            reason_code="edit_unverified",
            receipt=receipt,
            pre_sha256=pre_sha256,
            post_sha256=None,
            snapshot_id=str(snapshot_id),
            detail=(
                "the file was replaced but the result could not be verified; the "
                "recorded pre-image allows recovery, and this is not reported as success"
            ),
        )

    def _record_failure(
        self,
        request: EditRequest,
        capability_id: str,
        target: Path,
        pre_sha256: str,
        snapshot_id: UUID,
        recovery_class: str,
        reason_code: str,
        *,
        extra: str | None = None,
    ) -> ActionReceiptRecord:
        return self._record(
            request,
            capability_id,
            target,
            pre_sha256,
            None,
            snapshot_id,
            recovery_class,
            "FAILED",
            [reason_code],
            extra,
        )

    def _record(
        self,
        request: EditRequest,
        capability_id: str,
        target: Path,
        pre_sha256: str,
        post_sha256: str | None,
        snapshot_id: UUID,
        recovery_class: str,
        status: str,
        warnings: list[str],
        undo_of: str | None,
        verified_at: datetime | None = None,
    ) -> ActionReceiptRecord:
        receipt = ActionReceiptRecord(
            receipt_id=_receipt_id(),
            task_id=str(request.task_id),
            step_id=str(request.step_id),
            approval_id=str(request.approval_id),
            capability_id=capability_id,
            status=status,  # type: ignore[arg-type]
            recovery_class=recovery_class,
            resource_id=request.resource_id,
            attempted_path=target.name,
            pre_sha256=pre_sha256,
            post_sha256=post_sha256,
            snapshot_id=str(snapshot_id),
            warnings=tuple(warnings),
            detail={"undo_of": undo_of} if undo_of else {},
            created_at=self._clock(),
            verified_at=verified_at,
        )
        try:
            return self._receipts.record(receipt)
        except ReceiptError as exc:
            raise EditDenied(
                "receipt_unavailable",
                f"the edit outcome could not be recorded durably ({exc.reason_code})",
            ) from exc


_CONSUMER_CODE = "aether.core.edits.executor"


def _canonical_digest(value: dict[str, Any]) -> str:
    """Stable digest of a plan step's typed arguments."""

    material = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _receipt_id() -> UUID:
    """A fresh receipt id per operation.

    Receipt ids are not derived from the step id, because a step can legitimately
    produce more than one receipt: a failed attempt, a retry and a later undo are
    distinct events that must each be recordable and independently reviewable.
    Duplicate protection comes from append-only storage, not from id reuse.
    """

    import uuid

    return uuid.uuid4()


def _fsync_directory(directory: Path) -> None:
    """Best-effort directory durability (no-op where unsupported, e.g. Windows)."""

    if os.name == "nt":
        return
    try:
        descriptor = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _map_os_error(exc: OSError) -> str:
    """Map platform errors to stable reason codes.

    Windows sharing violations surface as ``WinError 32``; POSIX reports EBUSY.
    Both mean "the file is locked by another process", which is a reportable
    condition rather than a crash.
    """

    if getattr(exc, "winerror", None) in {32, 33}:
        return "target_locked_by_another_process"
    if exc.errno in {16, 26}:  # EBUSY, ETXTBSY
        return "target_locked_by_another_process"
    if exc.errno == 28:  # ENOSPC
        return "insufficient_disk_space"
    if exc.errno == 13:  # EACCES
        return "target_permission_denied"
    return "replace_failed"


__all__ = [
    "EditDenied",
    "EditExecutor",
    "EditOutcome",
    "EditRequest",
]
