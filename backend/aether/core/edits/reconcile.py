"""Restart reconciliation over the four sources of truth (S14-4).

After a crash, five things may disagree: the journal intent, the Undo Vault
snapshot, the file actually on disk, the grant consumption, and the receipt. This
module compares them and reports a verdict. It deliberately does **not** repair
anything: recovery is an authorized action like any other, so this produces
evidence for a human or an explicit recovery step to act on.

Verdicts are conservative on purpose. Anything that cannot be proven is
``NEEDS_REVIEW`` or ``INCONSISTENT``, never success.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID

from aether.core.edits.journal import (
    MutationIntent,
    MutationJournal,
    Reconciliation,
)
from aether.core.edits.receipts import ActionReceiptRecord, ReceiptStore


class ConsumptionView(Protocol):
    """The narrow read surface reconciliation needs from consumption accounting."""

    def pending(self) -> Sequence[object]: ...


class SnapshotReader(Protocol):
    def get(self, snapshot_id: UUID) -> bytes: ...


class ResourceResolver(Protocol):
    """Maps a registry resource id to the current on-disk path."""

    def path_for(self, resource_id: str) -> Path: ...


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    reconciliations: tuple[Reconciliation, ...]

    @property
    def needs_review(self) -> tuple[Reconciliation, ...]:
        """Everything that is not proven.

        ``COMPLETED_UNVERIFIED`` belongs here: the bytes may well be right, but
        nothing proves it, and treating that as consistent is exactly the phantom
        success this module exists to prevent.
        """

        return tuple(
            item
            for item in self.reconciliations
            if item.verdict in {"NEEDS_REVIEW", "INCONSISTENT", "COMPLETED_UNVERIFIED"}
        )

    @property
    def consistent(self) -> bool:
        return not self.needs_review


class MutationReconciler:
    """Produces an evidence-backed verdict for every open mutation intent."""

    def __init__(
        self,
        *,
        journal: MutationJournal,
        receipts: ReceiptStore,
        consumption: ConsumptionView,
        snapshots: SnapshotReader,
        resources: ResourceResolver,
        read_target: Callable[[Path], bytes] | None = None,
    ) -> None:
        self._journal = journal
        self._receipts = receipts
        self._consumption = consumption
        self._snapshots = snapshots
        self._resources = resources
        self._read_target = read_target or (lambda path: path.read_bytes())

    def reconcile(self) -> ReconciliationReport:
        pending_consumptions = {
            str(getattr(item, "consumption_id", "")) for item in self._consumption.pending()
        }
        results = [
            self._reconcile_one(intent, pending_consumptions)
            for intent in self._journal.open_intents()
        ]
        return ReconciliationReport(reconciliations=tuple(results))

    def _reconcile_one(
        self, intent: MutationIntent, pending_consumptions: set[str]
    ) -> Reconciliation:
        consumption_unresolved = (
            intent.consumption_id is not None and str(intent.consumption_id) in pending_consumptions
        )

        # 1. The file's current identity is the primary fact. The path recorded
        # with the intent is authoritative: a registry id is a one-way digest,
        # so a restart cannot map it back to a location on its own.
        try:
            path = (
                Path(intent.target_path)
                if intent.target_path
                else self._resources.path_for(intent.resource_id)
            )
            observed = self._read_target(path)
        except OSError:
            return Reconciliation(
                intent_id=intent.intent_id,
                verdict="NEEDS_REVIEW",
                reason_code="reconcile_target_unreadable",
                detail="the target could not be read; the effect is unknown",
            )
        except Exception:
            return Reconciliation(
                intent_id=intent.intent_id,
                verdict="NEEDS_REVIEW",
                reason_code="reconcile_resource_unresolved",
                detail="the resource is no longer resolvable; the effect is unknown",
            )
        observed_sha = sha256_hex(observed)

        receipt = self._receipt_for(intent)

        # 2. Nothing was replaced: the pre-image is still on disk.
        if observed_sha == intent.pre_sha256:
            if receipt is not None and receipt.status == "SUCCEEDED":
                # A verified receipt with the old bytes on disk means something
                # changed the file after the edit. Do not explain it away.
                return Reconciliation(
                    intent_id=intent.intent_id,
                    verdict="INCONSISTENT",
                    reason_code="reconcile_receipt_contradicts_disk",
                    detail=(
                        "a verified success receipt exists but the pre-image is on disk; "
                        "the file was changed after the edit"
                    ),
                )
            if consumption_unresolved:
                return Reconciliation(
                    intent_id=intent.intent_id,
                    verdict="NEEDS_REVIEW",
                    reason_code="reconcile_consumed_but_not_applied",
                    detail=(
                        "one grant use was consumed but no replacement is visible; the "
                        "use must be reconciled before any retry"
                    ),
                )
            return Reconciliation(
                intent_id=intent.intent_id,
                verdict="NOT_APPLIED",
                reason_code="reconcile_not_applied",
                detail="the pre-image is on disk; the mutation did not take effect",
            )

        # 3. The intended post-image is on disk.
        if observed_sha == intent.intended_post_sha256:
            if receipt is not None and receipt.status == "SUCCEEDED":
                return Reconciliation(
                    intent_id=intent.intent_id,
                    verdict="COMPLETED_VERIFIED",
                    reason_code="reconcile_verified",
                    detail="the approved bytes are on disk and a verified receipt exists",
                )
            if receipt is not None and receipt.status == "UNVERIFIED":
                return Reconciliation(
                    intent_id=intent.intent_id,
                    verdict="COMPLETED_UNVERIFIED",
                    reason_code="reconcile_unverified",
                    detail="the approved bytes are on disk but the receipt is UNVERIFIED",
                )
            # The bytes match but nothing proves the write completed.
            return Reconciliation(
                intent_id=intent.intent_id,
                verdict="COMPLETED_UNVERIFIED",
                reason_code="reconcile_no_verified_receipt",
                detail=(
                    "the approved bytes are on disk but no verified receipt exists; "
                    "treat as unverified until reviewed"
                ),
            )

        # 4. Something else entirely is on disk.
        if receipt is not None and receipt.post_sha256 == observed_sha:
            return Reconciliation(
                intent_id=intent.intent_id,
                verdict="COMPLETED_UNVERIFIED",
                reason_code="reconcile_effect_differs_from_intent",
                detail=(
                    "the file matches the receipt's post-image, which differs from the "
                    "intended bytes; the intended effect may not have been applied"
                ),
            )
        return Reconciliation(
            intent_id=intent.intent_id,
            verdict="NEEDS_REVIEW",
            reason_code="reconcile_third_state",
            detail=(
                "the file is neither the pre-image nor the intended post-image; a "
                "newer edit or an unrelated change is present"
            ),
        )

    def _receipt_for(self, intent: MutationIntent) -> ActionReceiptRecord | None:
        """Find the receipt for this exact attempt, if one was written."""

        try:
            candidates = self._receipts.for_task(str(intent.task_id))
        except Exception:
            return None
        for record in candidates:
            if record.step_id != str(intent.step_id):
                continue
            if record.approval_id != str(intent.approval_id):
                continue
            if record.resource_id != intent.resource_id:
                continue
            if record.pre_sha256 != intent.pre_sha256:
                continue
            return record
        return None


__all__ = [
    "ConsumptionView",
    "MutationReconciler",
    "ReconciliationReport",
    "ResourceResolver",
    "SnapshotReader",
    "sha256_hex",
]
