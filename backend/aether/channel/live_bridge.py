"""Composition-backed live workflow surface for the authenticated channel.

This bridge serves the Phase 2 final-integration channel kinds on top of the
one trusted composition root (:class:`TrustedComposition`): user-authorized
project registration, bounded read/search/open, real task creation, exact
preview delivery, the authorizing-gesture flow, approved-edit execution,
receipt retrieval and separately-authorized undo.

Trust rules enforced here, mirroring the decisions in the integration plan:

* Nothing in a renderer-originated payload can authorize anything. The
  renderer may only *ask main to initiate*; signing happens in Electron main
  after a native confirmation, and this bridge only ever *verifies*.
* Authorization is derived from persisted backend state (the current plan,
  the authoritative preview, the exact scope digest recomputed from the
  plan) — never from identity fields echoed back by the client. Client-
  supplied binding fields on ``gesture.submit`` are checked against the
  server-computed binding, not trusted.
* Every failure is a bounded machine reason; no exception crosses the wire,
  and no partial success is ever reported as success.
* When the schema-v2 tier is absent (shipped configuration), the mutation
  kinds answer ``schema_activation_pending`` and production issuance
  continues to be refused by the ledger itself
  (``GRANT_ISSUANCE_DISABLED``) — this bridge cannot widen either gate.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable
from datetime import datetime
from uuid import UUID, uuid4

from aether.core.composition import CompositionUnavailable, TrustedComposition
from aether.core.edits.executor import EditDenied, EditOutcome, EditRequest
from aether.core.edits.receipts import ReceiptError
from aether.core.fs.session import CapabilityOutcome
from aether.core.grants.errors import GrantDeniedError, GrantIssuanceDenied
from aether.core.persistence import (
    ExecutionEvidence,
    PersistentTaskState,
)
from aether.core.persistence.models import PlanStep, TaskPlan
from aether.core.persistence.sqlite_store import IllegalPersistentTransition, StoredTask
from aether.core.planning.authorizing_gesture import (
    GestureBinding,
    GestureRejected,
    SignedGesture,
)
from aether.core.planning.planner import PlanGoal, PlanIntent, PlannerError
from aether.core.resources.path_safety import PathSafetyError, reject_reparse_components
from aether.core.resources.registry import ResourceRegistryError
from aether.core.review_contract import electron_preview_payload
from aether.core.vault.undo_vault import VaultError

_UUID_TEXT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SHA256_TEXT = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_PROPOSED_BYTES = 1_000_000
_MAX_READ_WIRE_BYTES = 16 * 1024
# Aligned with the edit executor's own bound: a target larger than this can
# never be edited, so hashing/planning it is refused before allocation.
_MAX_TARGET_BYTES = 4 * 1024 * 1024
_HASH_CHUNK_BYTES = 64 * 1024
# Plan-argument keys the bridge alone may set (FI-06): caller-supplied
# values for these are discarded, never merged.
_RESERVED_ARGUMENT_KEYS = frozenset(
    {"resource_id", "step_id", "approval_id", "expected_sha256", "receipt_id", "snapshot_id"}
)
_EDIT_CAPABILITIES = frozenset({"fs.apply_approved_edit", "fs.undo_edit"})

_READ_GOALS = {
    "inspect_file": PlanGoal.INSPECT_FILE,
    "read_file": PlanGoal.READ_FILE,
    "search_project": PlanGoal.SEARCH_PROJECT,
    "open_folder": PlanGoal.OPEN_FOLDER,
}
_EDIT_GOALS = {"apply_edit": PlanGoal.APPLY_EDIT, "undo_edit": PlanGoal.UNDO_EDIT}


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _canonical_sha256(value: object) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _uuid_field(value: object, reason: str = "invalid_request") -> UUID:
    if not isinstance(value, str) or _UUID_TEXT.fullmatch(value) is None:
        raise _Refused(reason)
    return UUID(value)


class LiveBridge:
    """Serves the live workflow kinds from the trusted composition."""

    def __init__(self, composition: TrustedComposition) -> None:
        self._composition = composition
        # Exact proposed bytes, held process-locally like preview narratives:
        # losing them on restart forces a safe re-plan, never a guess.
        self._proposed: dict[tuple[str, int], bytes] = {}

    # ------------------------------------------------------------------
    # Project registration (user-authorized; path chosen in main's dialog)
    # ------------------------------------------------------------------
    def register_project(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or set(payload) != {"alias", "path"}:
                raise _Refused("invalid_request")
            alias, path = payload["alias"], payload["path"]
            if not isinstance(alias, str) or not isinstance(path, str):
                raise _Refused("invalid_request")
            root = self._composition.registry.register_root(
                alias,
                path,
                allowed_capabilities=frozenset(
                    {
                        "fs.inspect_file",
                        "fs.read_file",
                        "fs.search",
                        "fs.open_folder",
                        "fs.apply_approved_edit",
                        "fs.undo_edit",
                    }
                ),
            )
            return {"rootId": str(root.root_id), "alias": root.alias}

        return self._guarded(run)

    def resolve_resource(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or set(payload) != {"rootId", "relativePath"}:
                raise _Refused("invalid_request")
            root_id = _uuid_field(payload["rootId"])
            relative = payload["relativePath"]
            if not isinstance(relative, str):
                raise _Refused("invalid_request")
            resolved = self._composition.registry.resolve(root_id, relative)
            return {
                "resourceId": resolved.ref.resource_id,
                "version": resolved.version_token,
                "kind": resolved.ref.kind,
            }

        return self._guarded(run)

    # ------------------------------------------------------------------
    # Tasks and planning
    # ------------------------------------------------------------------
    def create_task(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or set(payload) != {"goal"}:
                raise _Refused("invalid_request")
            goal = payload["goal"]
            if not isinstance(goal, str) or not goal.strip():
                raise _Refused("invalid_request")
            task = self._composition.store.create_task(goal)
            return {"taskId": str(task.task_id)}

        return self._guarded(run)

    def plan_task(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if (
                not isinstance(payload, dict)
                or not {
                    "taskId",
                    "goal",
                    "resourceId",
                }
                <= set(payload)
                or not set(payload)
                <= {
                    "taskId",
                    "goal",
                    "resourceId",
                    "arguments",
                    "proposedContentBase64",
                    "receiptId",
                }
            ):
                raise _Refused("invalid_request")
            task_id = _uuid_field(payload["taskId"])
            goal_name = payload["goal"]
            resource_id = payload["resourceId"]
            if not isinstance(goal_name, str) or not isinstance(resource_id, str):
                raise _Refused("invalid_request")
            goal = _READ_GOALS.get(goal_name) or _EDIT_GOALS.get(goal_name)
            if goal is None:
                raise _Refused("unsupported_goal")
            arguments_in = payload.get("arguments") or {}
            if not isinstance(arguments_in, dict):
                raise _Refused("invalid_request")
            # FI-06: security-critical argument keys are bridge-generated.
            # Caller values for them are discarded, never merged, so a
            # planning request cannot override the authoritative resource
            # identity, approval identity, expected hash or (FI-07) the
            # receipt/snapshot an undo is bound to.
            arguments: dict[str, object] = {
                key: value
                for key, value in arguments_in.items()
                if key not in _RESERVED_ARGUMENT_KEYS
            }
            arguments["resource_id"] = resource_id
            proposed: bytes | None = None
            if goal is PlanGoal.APPLY_EDIT:
                raw = payload.get("proposedContentBase64")
                if not isinstance(raw, str):
                    raise _Refused("proposed_content_required")
                try:
                    proposed = base64.b64decode(raw, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise _Refused("invalid_request") from exc
                if len(proposed) > _MAX_PROPOSED_BYTES:
                    raise _Refused("proposed_content_too_large")
            elif goal is PlanGoal.UNDO_EDIT:
                # FI-07: the restoration bytes, receipt and snapshot are
                # derived from the durable receipt + protected vault —
                # caller-supplied restoration content is refused outright.
                if "proposedContentBase64" in payload:
                    raise _Refused("undo_content_must_be_derived")
                receipt_id = _uuid_field(payload.get("receiptId"))
                proposed, undo_arguments = self._derive_undo(receipt_id, resource_id)
                arguments.update(undo_arguments)
                resource_id = str(arguments["resource_id"])
            if goal in (PlanGoal.APPLY_EDIT, PlanGoal.UNDO_EDIT):
                arguments["approval_id"] = str(uuid4())
                if goal is PlanGoal.APPLY_EDIT:
                    arguments["expected_sha256"] = self._current_file_sha256(resource_id)
                # Placeholder, corrected after the first in-memory build below:
                # the persisted step arguments must name the plan step's real
                # (planner-derived) id, because the executor's grant scope
                # check hashes those arguments verbatim.
                arguments["step_id"] = str(uuid4())

            store = self._composition.store
            task = store.get_task(task_id)
            state = PersistentTaskState(task.state)
            if state is PersistentTaskState.RECEIVED or state in {
                PersistentTaskState.PREVIEW_READY,
                PersistentTaskState.AWAITING_APPROVAL,
                PersistentTaskState.VALIDATING,
            }:
                store.transition_task(task_id, PersistentTaskState.PLANNING)
            elif state is not PersistentTaskState.PLANNING:
                raise _Refused("task_not_plannable")
            revision = int(store.get_task(task_id).plan_revision) + 1
            intent = PlanIntent(
                goal=goal,
                resource_id=resource_id,
                arguments=arguments,
                summary=f"{goal_name} via trusted channel",
                proposed_content=proposed,
            )
            planned = self._composition.planner.plan(task_id, intent, revision=revision)
            if goal in (PlanGoal.APPLY_EDIT, PlanGoal.UNDO_EDIT) and str(
                planned.step_id
            ) != arguments.get("step_id"):
                # Rebuild in memory with the step identity aligned (see the
                # placeholder note above); only this second build is persisted.
                arguments["step_id"] = str(planned.step_id)
                intent = PlanIntent(
                    goal=goal,
                    resource_id=resource_id,
                    arguments=arguments,
                    summary=f"{goal_name} via trusted channel",
                    proposed_content=proposed,
                )
                planned = self._composition.planner.plan(task_id, intent, revision=revision)
            plan_hash = store.save_plan(planned.plan)
            self._composition.narratives.remember(
                task_id=task_id,
                plan_revision=revision,
                plan_hash=plan_hash,
                narrative=planned.narrative,
            )
            if proposed is not None:
                self._proposed[(str(task_id), revision)] = proposed
            store.transition_task(task_id, PersistentTaskState.PREVIEW_READY)
            preview = self._composition.previews.preview_for(
                task_id, plan_revision=revision, plan_hash=plan_hash
            )
            return {
                "taskId": str(task_id),
                "planRevision": revision,
                "planHash": plan_hash,
                "preview": electron_preview_payload(preview),
            }

        return self._guarded(run)

    # ------------------------------------------------------------------
    # Bounded read/search/open execution (no grant required; T0/T1)
    # ------------------------------------------------------------------
    def execute_read(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or set(payload) != {"taskId"}:
                raise _Refused("invalid_request")
            task_id = _uuid_field(payload["taskId"])
            store = self._composition.store
            task = store.get_task(task_id)
            plan = store.get_plan(task_id, int(task.plan_revision))
            step = plan.steps[0]
            session = self._composition.session
            resource_id = step.resources[0].resource_id if step.resources else None
            if resource_id is None:
                raise _Refused("plan_has_no_resource")
            if step.capability_id == "fs.inspect_file":
                outcome = session.inspect(task_id=task_id, resource_id=resource_id)
                result = self._outcome_payload(outcome)
            elif step.capability_id == "fs.read_file":
                outcome = session.read(
                    task_id=task_id, resource_id=resource_id, max_bytes=_MAX_READ_WIRE_BYTES
                )
                result = self._outcome_payload(outcome)
            elif step.capability_id == "fs.search":
                query = step.arguments.get("query")
                if not isinstance(query, str):
                    raise _Refused("plan_arguments_invalid")
                outcome = session.search(task_id=task_id, resource_id=resource_id, query=query)
                result = self._outcome_payload(outcome)
            elif step.capability_id == "fs.open_folder":
                outcome = session.open(task_id=task_id, resource_id=resource_id)
                result = self._outcome_payload(outcome)
            else:
                raise _Refused("not_a_read_plan")
            return {"taskId": str(task_id), **result}

        return self._guarded(run)

    # ------------------------------------------------------------------
    # Authorizing gesture: begin (server-computed binding + nonce)
    # ------------------------------------------------------------------
    def begin_gesture(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or set(payload) != {"taskId"}:
                raise _Refused("invalid_request")
            task_id = _uuid_field(payload["taskId"])
            binding = self._composition.gesture_binding(task_id)
            store = self._composition.store
            state = PersistentTaskState(store.get_task(task_id).state)
            if state is PersistentTaskState.PREVIEW_READY:
                store.transition_task(task_id, PersistentTaskState.AWAITING_APPROVAL)
            elif state is not PersistentTaskState.AWAITING_APPROVAL:
                raise _Refused("task_not_awaiting_approval")
            nonce = self._composition.nonces.issue(binding)
            return {"nonce": nonce, "binding": self._binding_payload(binding)}

        return self._guarded(run)

    def submit_gesture(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            gesture = self._parse_gesture(payload)
            # All trust decisions live in the composition: it recomputes the
            # binding from persisted state, verifies the gesture through the
            # production verifier and issues (or refuses) the exact grant.
            outcome = self._composition.issue_from_gesture(gesture)
            return {"approvalId": str(outcome.approval_id), "scopeDigest": outcome.scope_digest}

        return self._guarded(run)

    # ------------------------------------------------------------------
    # Approved-edit execution + receipt + undo
    # ------------------------------------------------------------------
    def execute_edit(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or set(payload) != {"taskId"}:
                raise _Refused("invalid_request")
            task_id = _uuid_field(payload["taskId"])
            composition = self._composition
            if composition.executor is None:
                raise _Refused("schema_activation_pending")
            if composition.reconciliation_failed or task_id in composition.unresolved_task_ids:
                raise _Refused("startup_reconciliation_required")
            store = composition.store
            task = store.get_task(task_id)
            plan = store.get_plan(task_id, int(task.plan_revision))
            step = plan.steps[0]
            if step.capability_id not in _EDIT_CAPABILITIES:
                raise _Refused("not_an_edit_plan")
            approval_id = UUID(str(step.arguments["approval_id"]))
            evidence = ExecutionEvidence(approval_id=approval_id)
            # Build the request before any state transition: a missing
            # process-local proposal (e.g. after a restart) refuses cleanly
            # without touching execution states.
            proposed = self._proposed.get((str(task_id), int(task.plan_revision)))
            receipt_id: UUID | None = None
            snapshot_id: UUID | None = None
            if step.capability_id == "fs.apply_approved_edit":
                if proposed is None:
                    raise _Refused("proposed_content_unavailable")
                request = self._edit_request(task, plan, step, proposed_content=proposed)
            else:
                receipt_id = UUID(str(step.arguments["receipt_id"]))
                snapshot_id = UUID(str(step.arguments["snapshot_id"]))
                request = self._edit_request(task, plan, step, proposed_content=b"")

            # FI-04: PRECHECK is recorded BEFORE the executor runs, from the
            # live grant the ledger already holds. A transition failure here
            # refuses execution outright — it is never suppressed to obtain
            # a successful-looking response.
            store.advance_execution_state(task_id, PersistentTaskState.PRECHECK, evidence=evidence)

            progress = {"consumed": False, "verified": False}

            def checkpoint(phase: str) -> None:
                # Invoked by the executor at the real checkpoints: the grant
                # use is durably spent (pre-mutation), then the durable
                # verified receipt exists. Failures propagate and abort.
                if phase == "consumed":
                    progress["consumed"] = True
                    store.advance_execution_state(
                        task_id, PersistentTaskState.EXECUTING, evidence=evidence
                    )
                elif phase == "verified":
                    progress["verified"] = True
                    store.advance_execution_state(
                        task_id, PersistentTaskState.POSTCHECK, evidence=evidence
                    )

            try:
                if step.capability_id == "fs.apply_approved_edit":
                    outcome = composition.executor.apply(request, checkpoint=checkpoint)
                else:
                    # fs.undo_edit: content comes from the vault snapshot,
                    # never the wire.
                    assert receipt_id is not None and snapshot_id is not None
                    outcome = composition.executor.undo(
                        request,
                        snapshot_id=snapshot_id,
                        receipt_id=receipt_id,
                        checkpoint=checkpoint,
                    )
            except EditDenied:
                self._settle_denied(task_id, evidence, progress)
                raise
            except (Exception, KeyboardInterrupt):
                self._settle_interrupted(task_id, evidence, progress)
                return {"status": "unavailable", "reason": "execution_interrupted"}
            return self._execution_result(task_id, approval_id, outcome, progress)

        return self._guarded(run)

    def _settle_denied(
        self, task_id: UUID, evidence: ExecutionEvidence, progress: dict[str, bool]
    ) -> None:
        """Record a truthful terminal state for an executor denial (FI-04).

        Pre-consumption denials mutate nothing: PRECHECK -> FAILED. A denial
        after the durable spend but before verification also proves no
        verified effect; the spent use routes through RECOVERING so the
        consumption is reconciled, never silently dropped.
        """

        store = self._composition.store
        if not progress["consumed"]:
            store.advance_execution_state(task_id, PersistentTaskState.FAILED, evidence=evidence)
        elif not progress["verified"]:
            store.advance_execution_state(
                task_id, PersistentTaskState.RECOVERING, evidence=evidence
            )
            store.advance_execution_state(task_id, PersistentTaskState.FAILED, evidence=evidence)

    def _settle_interrupted(
        self, task_id: UUID, evidence: ExecutionEvidence, progress: dict[str, bool]
    ) -> None:
        """Record an interruption truthfully; never retry it here (FI-04)."""

        store = self._composition.store
        uncertain = ExecutionEvidence(
            approval_id=evidence.approval_id, mutation_may_have_happened=True
        )
        if progress["consumed"]:
            # The spend is durable and the mutation may have happened:
            # UNVERIFIED is the only honest state.
            store.advance_execution_state(
                task_id, PersistentTaskState.UNVERIFIED, evidence=uncertain
            )
        else:
            store.advance_execution_state(task_id, PersistentTaskState.CANCELLED, evidence=evidence)

    def get_receipt(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or set(payload) != {"receiptId"}:
                raise _Refused("invalid_request")
            receipt_id = _uuid_field(payload["receiptId"])
            composition = self._composition
            if composition.receipts is None:
                raise _Refused("schema_activation_pending")
            record = composition.receipts.get(receipt_id)
            return {
                "receiptId": str(record.receipt_id),
                "taskId": record.task_id,
                "status": str(record.status),
                "capabilityId": record.capability_id,
                "resourceId": record.resource_id,
                "preSha256": record.pre_sha256,
                "postSha256": record.post_sha256,
                "snapshotId": record.snapshot_id,
                "verifiedAt": record.verified_at.isoformat() if record.verified_at else None,
            }

        return self._guarded(run)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _guarded(self, run: Callable[[], dict[str, object]]) -> dict[str, object]:
        try:
            return run()
        except _Refused as refused:
            return {"status": "unavailable", "reason": refused.reason}
        except CompositionUnavailable as unavailable:
            return {"status": "unavailable", "reason": unavailable.reason_code}
        except ResourceRegistryError as exc:
            return {"status": "unavailable", "reason": str(exc)}
        except PathSafetyError as exc:
            return {"status": "unavailable", "reason": str(exc)}
        except PlannerError as exc:
            return {"status": "unavailable", "reason": exc.reason_code.lower()}
        except (GrantIssuanceDenied, GrantDeniedError) as exc:
            reason = getattr(exc, "reason_code", None) or "grant_refused"
            return {"status": "unavailable", "reason": str(reason).lower()}
        except GestureRejected as exc:
            return {"status": "unavailable", "reason": exc.reason_code.lower()}
        except EditDenied as exc:
            return {"status": "unavailable", "reason": exc.reason_code}
        except IllegalPersistentTransition:
            return {"status": "unavailable", "reason": "illegal_task_transition"}
        except KeyError:
            return {"status": "unavailable", "reason": "not_found"}
        except Exception:
            return {"status": "unavailable", "reason": "live_unavailable"}

    def _derive_undo(
        self, receipt_id: UUID, requested_resource_id: str
    ) -> tuple[bytes, dict[str, object]]:
        """Derive an undo plan's bytes and bindings authoritatively (FI-07).

        The only caller input is the receipt identity. The durable receipt
        must record a verified success with a snapshot; the restoration
        bytes come from the protected vault and must hash to the receipt's
        pre-image; the resource must be the receipt's resource; and the
        current file (bounded, revalidating hash) must still be the
        receipt's verified post-image — a conflicting newer change refuses
        the plan outright. The separately approved undo grant then binds
        exactly this receipt, snapshot, resource and restoration.
        """

        composition = self._composition
        if composition.receipts is None or composition.vault is None:
            raise _Refused("schema_activation_pending")
        try:
            record = composition.receipts.get(receipt_id)
        except ReceiptError as exc:
            raise _Refused(exc.reason_code) from exc
        if str(record.status) != "SUCCEEDED" or record.verified_at is None:
            raise _Refused("receipt_not_undoable")
        if not record.snapshot_id or record.pre_sha256 is None or record.post_sha256 is None:
            raise _Refused("receipt_has_no_snapshot")
        if requested_resource_id != record.resource_id:
            raise _Refused("undo_resource_mismatch")
        try:
            restored = composition.vault.get(UUID(record.snapshot_id))
        except VaultError as exc:
            raise _Refused(exc.reason_code) from exc
        if hashlib.sha256(restored).hexdigest() != record.pre_sha256:
            raise _Refused("undo_snapshot_hash_mismatch")
        current_sha256 = self._current_file_sha256(record.resource_id)
        if current_sha256 != record.post_sha256:
            raise _Refused("undo_conflict_newer_change")
        return restored, {
            "resource_id": record.resource_id,
            "receipt_id": str(record.receipt_id),
            "snapshot_id": record.snapshot_id,
            "expected_sha256": current_sha256,
        }

    def _current_file_sha256(self, resource_id: str) -> str:
        """Bounded, revalidating SHA-256 of a registered file (FI-06).

        The stored resolution is never trusted at face value: the resource
        is re-resolved through the registry (containment + reparse-point
        rejection), the re-resolved identity must match the issued one,
        and the file is then hashed by streaming bounded chunks from an
        opened descriptor whose fstat identity must match the resolved
        path (regular file, single hard link, size-capped). No unbounded
        allocation, and the descriptor — not a second path lookup — is
        what gets read.
        """

        registry = self._composition.registry
        stored = registry.resource_by_id(resource_id)
        resolved = registry.resolve(stored.root_id, stored.relative_path)
        if resolved.ref.resource_id != stored.ref.resource_id:
            raise _Refused("resource_identity_mismatch")
        path = resolved.canonical_path
        reject_reparse_components(path)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise _Refused("target_unavailable") from exc
        try:
            info = os.fstat(descriptor)
            path_info = path.lstat()
            if (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino):
                raise _Refused("resource_identity_mismatch")
            if not stat.S_ISREG(info.st_mode):
                raise _Refused("target_not_a_regular_file")
            if info.st_nlink > 1:
                raise _Refused("target_hard_linked")
            if info.st_size > _MAX_TARGET_BYTES:
                raise _Refused("target_too_large")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, _HASH_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_TARGET_BYTES:
                    raise _Refused("target_too_large")
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    def _parse_gesture(self, payload: object) -> SignedGesture:
        if not isinstance(payload, dict) or set(payload) != {
            "nonce",
            "binding",
            "assertedAt",
            "userIntent",
            "signature",
        }:
            raise _Refused("invalid_gesture")
        binding_raw = payload["binding"]
        if not isinstance(binding_raw, dict) or set(binding_raw) != {
            "taskId",
            "planRevision",
            "planHash",
            "previewId",
            "previewDigest",
            "scopeDigest",
        }:
            raise _Refused("invalid_gesture")
        try:
            asserted_at = datetime.fromisoformat(str(payload["assertedAt"]))
        except ValueError as exc:
            raise _Refused("invalid_gesture") from exc
        if asserted_at.tzinfo is None:
            raise _Refused("invalid_gesture")
        return SignedGesture(
            nonce=str(payload["nonce"]),
            binding=GestureBinding(
                task_id=_uuid_field(binding_raw["taskId"], "invalid_gesture"),
                plan_revision=int(binding_raw["planRevision"]),
                plan_hash=str(binding_raw["planHash"]),
                preview_id=_uuid_field(binding_raw["previewId"], "invalid_gesture"),
                preview_digest=str(binding_raw["previewDigest"]),
                scope_digest=str(binding_raw["scopeDigest"]),
            ),
            asserted_at=asserted_at,
            user_intent=str(payload["userIntent"]),
            signature=str(payload["signature"]),
        )

    @staticmethod
    def _binding_payload(binding: GestureBinding) -> dict[str, object]:
        return {
            "taskId": str(binding.task_id),
            "planRevision": binding.plan_revision,
            "planHash": binding.plan_hash,
            "previewId": str(binding.preview_id),
            "previewDigest": binding.preview_digest,
            "scopeDigest": binding.scope_digest,
        }

    def _edit_request(
        self, task: StoredTask, plan: TaskPlan, step: PlanStep, *, proposed_content: bytes
    ) -> EditRequest:
        return EditRequest(
            task_id=task.task_id,
            step_id=step.step_id,
            approval_id=UUID(str(step.arguments["approval_id"])),
            plan_revision=plan.revision,
            plan_hash=plan.plan_hash,
            resource_id=step.resources[0].resource_id,
            expected_sha256=str(step.arguments["expected_sha256"]),
            proposed_content=proposed_content,
            expected_effect_sha256=str(step.expected_effect.get("approved_effect_digest")),
        )

    def _execution_result(
        self,
        task_id: UUID,
        approval_id: UUID,
        outcome: EditOutcome,
        progress: dict[str, bool],
    ) -> dict[str, object]:
        """Record the terminal state for a returned outcome (FI-04).

        PRECHECK/EXECUTING/POSTCHECK were already recorded at the real
        checkpoints while the executor ran; this records only the terminal
        transition the outcome proves. A SUCCEEDED outcome whose verified
        checkpoint never fired is not promoted — the task stays EXECUTING
        for reconciliation rather than being marked complete.
        """

        store = self._composition.store
        evidence = ExecutionEvidence(approval_id=approval_id)
        if outcome.status == "SUCCEEDED":
            if not progress["verified"]:
                return {"status": "unavailable", "reason": "execution_checkpoint_missing"}
            receipt_id = outcome.receipt.receipt_id if outcome.receipt else None
            store.advance_execution_state(
                task_id,
                PersistentTaskState.COMPLETED,
                evidence=ExecutionEvidence(approval_id=approval_id, receipt_id=receipt_id),
            )
        elif outcome.status in ("UNVERIFIED", "PARTIAL"):
            store.advance_execution_state(
                task_id,
                PersistentTaskState.UNVERIFIED,
                evidence=ExecutionEvidence(
                    approval_id=approval_id, mutation_may_have_happened=True
                ),
            )
        elif outcome.status == "FAILED":
            # The executor proved the replacement did not happen; route the
            # spent use through RECOVERING like a post-consumption denial.
            if progress["consumed"] and not progress["verified"]:
                store.advance_execution_state(
                    task_id, PersistentTaskState.RECOVERING, evidence=evidence
                )
            store.advance_execution_state(task_id, PersistentTaskState.FAILED, evidence=evidence)
        return {
            "taskId": str(task_id),
            "status": outcome.status,
            "reasonCode": outcome.reason_code,
            "receiptId": str(outcome.receipt.receipt_id) if outcome.receipt else None,
            "preSha256": outcome.pre_sha256,
            "postSha256": outcome.post_sha256,
            "snapshotId": outcome.snapshot_id,
        }

    @staticmethod
    def _outcome_payload(outcome: CapabilityOutcome) -> dict[str, object]:
        # Bounded, JSON-safe projection of a capability result: scalar fields
        # only, lists flattened to scalars, text truncated to the wire bound.
        result = outcome.result
        payload: dict[str, object] = {"succeeded": bool(outcome.succeeded)}
        fields = vars(result) if result is not None and hasattr(result, "__dict__") else {}
        safe: dict[str, object] = {}
        for key, value in fields.items():
            if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
                safe[key] = value
            elif isinstance(value, str):
                safe[key] = value[:_MAX_READ_WIRE_BYTES]
            elif isinstance(value, (list, tuple)):
                safe[key] = [item for item in value if isinstance(item, (str, int, float, bool))][
                    :50
                ]
        if safe:
            payload["data"] = safe
        return payload


__all__ = ["LiveBridge"]
