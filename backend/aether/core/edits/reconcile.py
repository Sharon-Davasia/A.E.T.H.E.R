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
    """The narrow read surface reconciliation needs from consumption accounting.

    ``pending`` is the local projection. ``unprojected_attempts`` and
    ``authoritative_consumption`` exist because the projection is *not* the only
    place a spend can hide: the authoritative ledger commits in its own database,
    so a crash between that commit and the projection insert leaves a real spend
    with no local row (S14-12). A reconciler that only read ``pending`` could not
    see it, and would report a spent grant use as clean.
    """

    def pending(self) -> Sequence[object]: ...

    def unprojected_attempts(self) -> Sequence[object]: ...

    def authoritative_consumption(self, consumption_id: UUID) -> object | None: ...


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
    """Produces an evidence-backed verdict for every unaccounted mutation.

    Two work lists are reconciled, not one. Open journal intents are the obvious
    list. The other is *pending consumptions with no journal intent*: the executor
    spends the grant use before it writes the journal intent, so a crash between
    those two steps leaves a spent use that no intent mentions. Iterating only
    open intents reported that state as clean, which was a silent hole in crash
    recovery (S14-8).
    """

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
        pending = list(self._consumption.pending())
        pending_consumptions = {str(getattr(item, "consumption_id", "")) for item in pending}
        open_intents = self._journal.open_intents()

        results = [self._reconcile_one(intent, pending_consumptions) for intent in open_intents]
        results.extend(self._reconcile_orphans(pending, open_intents))
        results.extend(self._reconcile_unprojected(open_intents))
        return ReconciliationReport(reconciliations=tuple(results))

    def _reconcile_unprojected(
        self, open_intents: Sequence[MutationIntent]
    ) -> list[Reconciliation]:
        """Report authoritative spends that never got a local projection.

        S14-12. The consumption projection and the authoritative grant ledger are
        two independent SQLite databases, so they cannot commit together. A
        process killed after ``GrantLedger.consume`` committed but before the
        projection insert leaves a use that is really spent, named by no local row
        and by no journal intent. The previous reconciler walked local pending rows
        and journal intents only, so it reported that state as clean.

        The durable attempt row closes the window. For each attempt with no
        projection, the *authoritative* ledger is asked whether that consumption id
        exists:

        * it exists -> the use was spent and no local record names the outcome.
          NEEDS_REVIEW, never success. There is no refund: the grant was really
          consumed.
        * it does not exist -> the spend never landed (the crash came before the
          authoritative commit, or the ledger refused it). ``NOT_APPLIED`` is an
          honest verdict because nothing was spent.
        * the ledger cannot be asked, or fails to answer -> NEEDS_REVIEW. An
          unanswered question is not a negative one.

        An attempt whose id a journal intent does name is already covered by
        ``_reconcile_one``, which compares the file against the intent.
        """

        known_intents = {
            str(intent.consumption_id) for intent in open_intents if intent.consumption_id
        }
        results: list[Reconciliation] = []
        reader = getattr(self._consumption, "unprojected_attempts", None)
        if reader is None:
            return results
        for attempt in reader():
            consumption_id = getattr(attempt, "consumption_id", None)
            if consumption_id is None:
                continue
            if str(consumption_id) in known_intents:
                continue
            try:
                spent = self._consumption.authoritative_consumption(consumption_id)
            except Exception:
                results.append(
                    Reconciliation(
                        intent_id=None,
                        consumption_id=consumption_id,
                        verdict="NEEDS_REVIEW",
                        reason_code="reconcile_authority_unavailable",
                        detail=(
                            "a grant use was attempted but the authoritative ledger could "
                            "not be queried; whether it was spent is unknown and must be "
                            "reviewed"
                        ),
                    )
                )
                continue
            if spent is None:
                results.append(
                    Reconciliation(
                        intent_id=None,
                        consumption_id=consumption_id,
                        verdict="NOT_APPLIED",
                        reason_code="reconcile_attempt_not_spent",
                        detail=(
                            "a grant use was attempted but the authoritative ledger holds "
                            "no consumption for it; nothing was spent"
                        ),
                    )
                )
                continue
            uses_remaining_after = getattr(spent, "uses_remaining_after", None)
            results.append(
                Reconciliation(
                    intent_id=None,
                    consumption_id=consumption_id,
                    verdict="NEEDS_REVIEW",
                    reason_code="reconcile_consumed_without_projection",
                    detail=(
                        "the authoritative ledger holds a consumption that no local "
                        "projection and no journal intent names: the process died between "
                        f"committing the spend and recording its outcome "
                        f"(uses_remaining_after={uses_remaining_after}); whether a file "
                        "changed is unknown and must be reviewed"
                    ),
                )
            )
        return results

    def _reconcile_orphans(
        self, pending: Sequence[object], open_intents: Sequence[MutationIntent]
    ) -> list[Reconciliation]:
        """Report spent uses that no journal intent accounts for.

        A pending consumption whose id appears in no open intent is exactly the
        crash-between-consume-and-journal window. It is never consistent: one
        grant use may or may not have mutated a file, and nothing on disk says
        which. It also covers a consumption whose intent was already resolved,
        which means the two records disagree and both need review.

        Consumptions already resolved are not pending, so they do not appear
        here; a resolved consumption is accounted for.
        """

        known = {str(intent.consumption_id) for intent in open_intents if intent.consumption_id}
        orphans: list[Reconciliation] = []
        for item in pending:
            consumption_id = str(getattr(item, "consumption_id", ""))
            if not consumption_id or consumption_id in known:
                continue
            orphans.append(
                Reconciliation(
                    intent_id=None,
                    consumption_id=getattr(item, "consumption_id", None),
                    verdict="NEEDS_REVIEW",
                    reason_code="reconcile_consumption_without_intent",
                    detail=(
                        "a grant use was consumed but no mutation intent records it: the "
                        "process died between spending the use and journaling the intent, "
                        "so whether a file changed is unknown and must be reviewed"
                    ),
                )
            )
        return orphans

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
