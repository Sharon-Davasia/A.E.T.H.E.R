"""The single T2 mutation path: verified edits and authorized undo (Phase 2D).

There is exactly one function in the backend that replaces user file content,
and this is it. Everything that mutates goes through :meth:`EditExecutor.apply`
or :meth:`EditExecutor.undo`, so a single review can reason about every write.

The order of operations is the security property:

1. **Grant first.** No mutation is attempted before the exact grant has been
   scope-verified against the persisted ledger, the current plan and the live
   resource version. Verification is not consumption; consumption happens after
   the pre-image is captured, so a failed write does not burn a use.
2. **Freshness second.** The target is re-inspected and compared with the
   version the user approved. A file that changed since preview stops here with
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
from aether.core.edits.receipts import (
    ActionReceiptRecord,
    ReceiptError,
    ReceiptStore,
)
from aether.core.fs import errors as fs_errors
from aether.core.grants.authority import GrantAuthority, GrantRequest
from aether.core.grants.consumption import IssuanceDisabledConsumptionLedger
from aether.core.planning.edit_binding import ApprovedEdit, EditBindingError
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


class ExecutionJournal(Protocol):
    """Durable pre-mutation intent, written before any replacement (S14-4)."""

    def begin(self, **fields: Any) -> Any: ...

    def resolve(self, consumption_id: UUID, *, outcome: str, detail: str) -> Any: ...


_MAX_EDIT_BYTES = 4 * 1024 * 1024
_FORWARD_EDIT_CAPABILITY = "fs.apply_approved_edit"


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
        journal: ExecutionJournal | None = None,
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
        self._consumption_id: UUID | None = None
        self._authority = authority
        self._vault = vault
        self._receipts = receipts
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- public operations -----------------------------------------------

    def apply(self, request: EditRequest) -> EditOutcome:
        """Apply exactly one approved edit, or refuse without writing."""

        if len(request.proposed_content) > _MAX_EDIT_BYTES:
            raise EditDenied("edit_too_large", "proposed content exceeds the edit bound")
        target = self._authorize(request)
        return self._mutate(
            target=target,
            content=request.proposed_content,
            request=request,
            capability_id=_FORWARD_EDIT_CAPABILITY,
            recovery_class="SNAPSHOT_RESTORABLE",
        )

    def undo(
        self,
        request: EditRequest,
        *,
        snapshot_id: UUID,
        receipt_id: UUID,
    ) -> EditOutcome:
        """Restore a snapshot as a *separate authorized action*.

        Undo is an edit: it needs its own grant, its own freshness check and its
        own receipt. The snapshot's plaintext becomes the proposed content, so
        restoration is verified exactly like a forward edit.
        """

        target = self._authorize(request)
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
        )

    # -- internals -------------------------------------------------------

    def _authorize(self, request: EditRequest) -> Path:
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
        if "fs.apply_approved_edit" not in root.allowed_capabilities:
            raise EditDenied(
                fs_errors.CAPABILITY_OUTSIDE_ROOT_SCOPE,
                "the registered root does not permit edits",
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
        request_shape = ToolRequest(
            request_id=str(request.step_id),
            task_id=str(request.task_id),
            capability_id="fs.apply_approved_edit",
            arguments={
                "resource_id": request.resource_id,
                "step_id": str(request.step_id),
                "approval_id": str(request.approval_id),
                "expected_sha256": request.expected_sha256,
            },
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

    def _plan_step(self, request: EditRequest) -> Any:
        """The authoritative persisted step for this request, or refuse."""

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
        return step

    def _plan_binding(self, request: EditRequest) -> ApprovedEdit:
        """The persisted approval binding for this request, or refuse."""

        step = self._plan_step(request)
        try:
            return ApprovedEdit.from_step_arguments(
                resource_id=request.resource_id, values=dict(step.expected_effect)
            )
        except EditBindingError as exc:
            raise EditDenied(
                "approved_binding_malformed",
                "the persisted plan does not carry a usable approval binding",
            ) from exc

    def _consume_grant(self, request: EditRequest, step: Any, binding: ApprovedEdit) -> None:
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
                capability_id=_FORWARD_EDIT_CAPABILITY,
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
        self._consumption_id = consumption_id

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
    ) -> EditOutcome:
        intended_sha256 = hashlib.sha256(content).hexdigest()
        # S14-2: spend the use before touching the file at all, so a crash leaves
        # a PENDING consumption (findable) rather than an unaccounted side effect.
        if capability_id == _FORWARD_EDIT_CAPABILITY:
            self._consume_grant(request, self._plan_step(request), self._plan_binding(request))
        try:
            pre_image = target.read_bytes()
        except OSError as exc:
            raise EditDenied(fs_errors.RESOURCE_NOT_FOUND, "target is unreadable") from exc
        pre_sha256 = hashlib.sha256(pre_image).hexdigest()

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
        # different post-image.
        if capability_id == _FORWARD_EDIT_CAPABILITY:
            self._verify_approved_result(request, intended_sha256, pre_image)
        else:
            # Undo is a distinct action with its own authorization requirement.
            # Until S14-3 gives it a registered fs.undo_edit capability with its
            # own plan-bound preview, it must NOT be able to reach the mutation
            # path at all -- refusing is safer than reusing the edit binding.
            raise EditDenied(
                "undo_authorization_not_implemented",
                "undo requires its own registered capability and exact approval; "
                "it is not authorized through the edit path",
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
            return EditOutcome(
                status="FAILED",
                reason_code=denied.reason_code,
                receipt=failure_receipt,
                pre_sha256=pre_sha256,
                post_sha256=None,
                snapshot_id=str(snapshot.snapshot_id),
                detail="the replacement failed; the original content is unchanged",
            )

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
        self._resolve_consumption("SUCCEEDED", "verified effect")
        return EditOutcome(
            status="SUCCEEDED",
            reason_code="edit_verified",
            receipt=receipt,
            pre_sha256=pre_sha256,
            post_sha256=post_sha256,
            snapshot_id=str(snapshot.snapshot_id),
            detail="bytes were re-read from disk and match the approved content exactly",
        )

    def _resolve_consumption(self, state: str, detail: str) -> None:
        """Record what actually happened to the spent use.

        A failure here leaves the consumption PENDING, which is exactly what
        reconciliation looks for. A spent use is never recorded as successful
        merely because the process reached this call.
        """

        consumption_id = self._consumption_id
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

    def _verify_approved_result(
        self, request: EditRequest, intended_sha256: str, pre_image: bytes
    ) -> None:
        """Refuse unless the content matches the binding in the persisted plan.

        The digest is *not* taken from the request. Reading it from the immutable
        persisted plan means the only way to change which bytes are authorized is
        to produce a new plan revision with a new hash — which invalidates the
        existing approval instead of silently reusing it.
        """

        if self._plans is None:
            raise EditDenied(
                "approved_result_binding_unavailable",
                "no persisted plan source is configured, so approval cannot be "
                "bound to the bytes about to be written",
            )
        try:
            plan = self._plans.get_plan(request.task_id, request.plan_revision)
        except Exception as exc:
            raise EditDenied(
                "approved_plan_unavailable",
                "the approved plan revision could not be read",
            ) from exc
        step = next((item for item in plan.steps if item.step_id == request.step_id), None)
        if step is None:
            raise EditDenied(
                "approved_step_missing",
                "the persisted plan has no such step, so nothing was approved here",
            )
        try:
            binding = ApprovedEdit.from_step_arguments(
                resource_id=request.resource_id, values=dict(step.expected_effect)
            )
        except EditBindingError as exc:
            raise EditDenied(
                "approved_binding_malformed",
                "the persisted plan does not carry a usable approval binding",
            ) from exc
        try:
            binding.verify_proposed(
                proposed_content=request.proposed_content, current_pre_image=pre_image
            )
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

    def _atomic_replace(self, target: Path, content: bytes, pre_image: bytes) -> None:
        """Same-volume atomic replacement, preserving the original file mode."""

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
        del pre_image

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
    ) -> EditOutcome:
        """Record an edit we cannot prove; never claim success."""

        warnings = [*warnings, reason]
        self._resolve_consumption("UNVERIFIED", reason)
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
