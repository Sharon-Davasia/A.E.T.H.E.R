"""The one trusted composition root for the live Phase 2 workflow.

Decision C: the running application is composed in exactly one place, on the
existing authenticated Electron-main<->backend child channel. This module is
that place. It owns the single task store (and therefore the single database
ownership lock), the resource registry, the preview authority, the ephemeral
gesture authority, the production attestation verifier, and — only when the
database schema supports it — the grant ledger, issuer and edit executor.

Fail-closed, deterministic capability registration:

* Construction either produces a fully consistent object graph or raises
  :class:`CompositionUnavailable`; there is no partially wired state.
* :meth:`TrustedComposition.capabilities` reports, deterministically, which
  capability groups are available and the machine reason for each that is
  not. Nothing degrades silently.
* The grant/execution tier exists only on a schema-v2 database. On the
  shipped schema-v1 configuration the tier is *absent* (not stubbed): the
  issuer and executor are never constructed, so no code path in the running
  application can issue a grant or mutate a file. Even on v2, the ledger's
  own ``GRANT_ISSUANCE_DISABLED`` policy still refuses production issuance
  until the separately reviewed enablement.
* Startup reconciliation runs through the store's ``recover_on_startup``
  (already executed on open) plus the mutation reconciler when the journal
  exists; uncertain mutations are reported, never auto-replayed.

The gesture key is the ephemeral per-launch secret delivered over the
authenticated private process bootstrap (Decision A). It is used only to
construct :class:`TrustedGestureAuthority` here and is never stored,
logged, or exposed beyond this object.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

from aether.core.contracts.approval import (
    ApprovedOperation,
    ApprovedResourceVersion,
    ExactApprovalGrant,
    exact_approval_scope_digest,
)
from aether.core.contracts.receipt import RecoveryClass
from aether.core.edits.executor import EditExecutor
from aether.core.edits.journal import MutationJournal
from aether.core.edits.receipts import ReceiptStore
from aether.core.fs.executor import FilesystemExecutor
from aether.core.fs.session import CapabilitySession
from aether.core.grants.attestation import AuthorizationAttestation
from aether.core.grants.authority import GrantAuthority
from aether.core.grants.authorization import operation_hashes
from aether.core.grants.consumption import ConsumptionLedger, GrantAuthoritySource
from aether.core.grants.issuance import GrantIssuer
from aether.core.grants.ledger import GrantLedger
from aether.core.grants.models import GrantIssuanceOutcome
from aether.core.persistence.models import TaskPlan
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.planning.authorizing_gesture import (
    GestureBinding,
    GestureNonceRegister,
    SignedGesture,
    TrustedGestureAuthority,
)
from aether.core.planning.planner import Planner
from aether.core.planning.preview_authority import (
    PersistedPreviewAuthority,
    StoredNarrativeSource,
)
from aether.core.planning.production_verifier import ProductionAttestationVerifier
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.resources.registry import ResourceRegistry
from aether.core.vault.undo_vault import UndoVault

GESTURE_AUTHORITY_ID = "electron-main-gesture"
_EDIT_CAPABILITIES = frozenset({"fs.apply_approved_edit", "fs.undo_edit"})
_GRANT_WINDOW = timedelta(minutes=30)

# Capability groups, in deterministic registration order.
CAPABILITY_GROUPS = (
    "project_registration",
    "read_search_open",
    "task_planning",
    "exact_preview",
    "trusted_gesture",
    "grant_issuance",
    "edit_execution",
    "undo",
)


class CompositionUnavailable(RuntimeError):
    """The trusted composition could not be built; nothing is available."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True, slots=True)
class CapabilityState:
    """One capability group's availability and, when absent, the reason."""

    name: str
    available: bool
    reason: str | None = None


class TrustedComposition:
    """Owns every trusted Phase 2 component for one channel session."""

    def __init__(
        self,
        *,
        store: SQLiteTaskStore,
        registry: ResourceRegistry,
        narratives: StoredNarrativeSource,
        previews: PersistedPreviewAuthority,
        gestures: TrustedGestureAuthority,
        nonces: GestureNonceRegister,
        verifier: ProductionAttestationVerifier,
        planner: Planner,
        session: CapabilitySession,
        ledger: GrantLedger | None,
        issuer: GrantIssuer | None,
        executor: EditExecutor | None,
        consumption: ConsumptionLedger | None,
        receipts: ReceiptStore | None,
        journal: MutationJournal | None,
        vault: UndoVault | None,
        schema_version: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.clock = clock or (lambda: datetime.now(UTC))
        self.store = store
        self.registry = registry
        self.narratives = narratives
        self.previews = previews
        self.gestures = gestures
        self.nonces = nonces
        self.verifier = verifier
        self.planner = planner
        self.session = session
        self.ledger = ledger
        self.issuer = issuer
        self.executor = executor
        self.consumption = consumption
        self.receipts = receipts
        self.journal = journal
        self.vault = vault
        self.schema_version = schema_version
        self._pending_gesture: SignedGesture | None = None
        self._gesture_lock = threading.Lock()
        self._closed = False

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def build(
        cls,
        *,
        store: SQLiteTaskStore,
        gesture_key: bytes,
        clock: Callable[[], datetime] | None = None,
        ledger: GrantLedger | None = None,
    ) -> TrustedComposition:
        """Compose the trusted object graph around one open store, or fail closed.

        The caller owns the store (in the channel service, the review bridge
        opened it): exactly one store, one connection and one database
        ownership lock exist per database, shared by review, planning,
        issuance and execution. Receipts, journal, consumption and vault
        state live beside the database under deterministic sibling names.
        Startup reconciliation already ran when the store opened (in-flight
        tasks paused; fresh consent forced); nothing is auto-replayed here.
        """
        clock = clock or (lambda: datetime.now(UTC))
        database_path = store.database_path
        consumption: ConsumptionLedger | None = None
        try:
            schema_version = int(store._connection.execute("PRAGMA user_version").fetchone()[0])

            registry = ResourceRegistry()
            narratives = StoredNarrativeSource()
            previews = PersistedPreviewAuthority(
                store, narratives=narratives, resources=registry, clock=clock
            )
            nonces = GestureNonceRegister(clock=clock)
            gestures = TrustedGestureAuthority(key=gesture_key, nonces=nonces, clock=clock)

            composition_ref: dict[str, TrustedComposition] = {}

            def resolve_gesture(attestation: AuthorizationAttestation) -> SignedGesture | None:
                composition = composition_ref.get("self")
                if composition is None:
                    return None
                return composition._take_pending_gesture()

            verifier = ProductionAttestationVerifier(
                authority_id=GESTURE_AUTHORITY_ID,
                previews=previews,
                gestures=gestures,
                resolve_gesture=resolve_gesture,
                clock=clock,
            )

            capabilities = CapabilityRegistry.phase2_filesystem()
            broker = PolicyBroker(
                capabilities=capabilities,
                resources=registry,
                executors=frozenset(
                    {
                        "fs.inspect_file",
                        "fs.read_file",
                        "fs.search",
                        "fs.open_folder",
                    }
                ),
            )
            session = CapabilitySession(
                store=store,
                broker=broker,
                executor=FilesystemExecutor(registry),
                clock=clock,
            )
            planner = Planner(capabilities=capabilities, resources=registry, clock=clock)

            issuer: GrantIssuer | None = None
            executor: EditExecutor | None = None
            receipts: ReceiptStore | None = None
            journal: MutationJournal | None = None
            vault: UndoVault | None = None
            if schema_version >= 2:
                # The authoritative tier. GrantLedger.open shares the store's
                # connection and lock; production issuance still refuses via
                # the ledger's own GRANT_ISSUANCE_DISABLED policy. Tests may
                # inject an already-open ledger on this same store (the only
                # way a test-scoped ledger can exist); the channel service
                # never does.
                if ledger is None:
                    ledger = GrantLedger.open(store)
                authority = GrantAuthority(ledger, store=store)
                issuer = GrantIssuer(
                    store=store, ledger=ledger, attestations=verifier, previews=previews
                )
                sibling = database_path.parent
                stem = database_path.name
                consumption = ConsumptionLedger(
                    sibling / f"{stem}.consumption.sqlite3",
                    # GrantLedger provides exactly the protocol operations;
                    # its consume() signature is narrower than the protocol's.
                    authority=cast(GrantAuthoritySource, ledger),
                    clock=clock,
                )
                vault = UndoVault(sibling / f"{stem}.vault").open()
                receipts = ReceiptStore(sibling / f"{stem}.receipts.sqlite3")
                journal = MutationJournal(sibling / f"{stem}.journal.sqlite3", clock=clock)
                executor = EditExecutor(
                    registry,
                    authority,
                    vault,
                    receipts,
                    plans=store,
                    grants=consumption,
                    journal=journal,
                    clock=clock,
                )

            composition = cls(
                store=store,
                registry=registry,
                narratives=narratives,
                previews=previews,
                gestures=gestures,
                nonces=nonces,
                verifier=verifier,
                planner=planner,
                session=session,
                ledger=ledger,
                issuer=issuer,
                executor=executor,
                consumption=consumption,
                receipts=receipts,
                journal=journal,
                vault=vault,
                schema_version=schema_version,
                clock=clock,
            )
            composition_ref["self"] = composition
            return composition
        except CompositionUnavailable:
            raise
        except Exception as exc:
            # Fail closed: release whatever this build acquired. The caller's
            # store stays open (the review surface keeps working); only the
            # trusted-execution tier reports unavailable.
            if consumption is not None:
                with contextlib.suppress(Exception):
                    consumption.close()
            if ledger is not None:
                with contextlib.suppress(Exception):
                    ledger.close()
            raise CompositionUnavailable(
                "composition_unavailable",
                "the trusted composition could not be built; no capability is available",
            ) from exc

    @classmethod
    def build_from_path(
        cls,
        *,
        database_path: Path,
        gesture_key: bytes,
        clock: Callable[[], datetime] | None = None,
    ) -> tuple[TrustedComposition, SQLiteTaskStore]:
        """Open the store and compose around it; the caller owns both.

        Returns ``(composition, store)``; close the composition first, then
        the store. Used by tests and tools; the channel service instead
        shares the review bridge's already-open store.
        """
        store = SQLiteTaskStore(database_path)
        try:
            return cls.build(store=store, gesture_key=gesture_key, clock=clock), store
        except Exception:
            store.close()
            raise

    # ------------------------------------------------------------------
    # Capability registration (deterministic; absence always has a reason)
    # ------------------------------------------------------------------
    def capabilities(self) -> tuple[CapabilityState, ...]:
        mutation_reason = None if self.ledger is not None else "schema_activation_pending"
        return (
            CapabilityState("project_registration", True),
            CapabilityState("read_search_open", True),
            CapabilityState("task_planning", True),
            CapabilityState("exact_preview", True),
            CapabilityState("trusted_gesture", True),
            CapabilityState("grant_issuance", self.issuer is not None, mutation_reason),
            CapabilityState("edit_execution", self.executor is not None, mutation_reason),
            CapabilityState("undo", self.executor is not None, mutation_reason),
        )

    # ------------------------------------------------------------------
    # Authorizing gesture: server-computed binding + verified issuance
    # ------------------------------------------------------------------
    def gesture_binding(self, task_id: UUID) -> GestureBinding:
        """Recompute the exact gesture binding from persisted state.

        Never derived from client input: the current plan, the authoritative
        preview and the scope digest recomputed from the plan's operations.
        """
        store = self.store
        task = store.get_task(task_id)
        plan = store.get_plan(task_id, int(task.plan_revision))
        if len(plan.steps) != 1 or plan.steps[0].capability_id not in _EDIT_CAPABILITIES:
            raise CompositionUnavailable(
                "not_an_edit_plan", "the task's current plan is not an editable action"
            )
        preview = self.previews.preview_for(
            task_id, plan_revision=int(task.plan_revision), plan_hash=str(task.plan_hash)
        )
        operations, approval_id = self._operations_for(plan)
        scope_digest = exact_approval_scope_digest(self._grant_shape(plan, operations, approval_id))
        return GestureBinding(
            task_id=task_id,
            plan_revision=int(task.plan_revision),
            plan_hash=str(task.plan_hash),
            preview_id=preview.preview_id,
            preview_digest=preview.preview_digest,
            scope_digest=scope_digest,
        )

    def issue_from_gesture(self, gesture: SignedGesture) -> GrantIssuanceOutcome:
        """Issue the exact grant for one main-signed gesture, or refuse.

        The submitted binding must equal the server-computed binding; the
        production verifier then re-checks authority, preview identity,
        freshness and the single-use nonce before the issuer persists
        anything. On the production-configured ledger the issuer still
        refuses with ``GRANT_ISSUANCE_DISABLED`` (Decision F).
        """
        expected = self.gesture_binding(gesture.binding.task_id)
        if gesture.binding != expected:
            raise CompositionUnavailable(
                "gesture_binding_mismatch",
                "the submitted gesture approves a different action than the persisted one",
            )
        if self.issuer is None or self.ledger is None:
            raise CompositionUnavailable(
                "schema_activation_pending",
                "grant issuance requires the schema version 2 ledger",
            )
        plan = self.store.get_plan(gesture.binding.task_id, gesture.binding.plan_revision)
        operations, approval_id = self._operations_for(plan)
        self.note_gesture(gesture)
        now = self.clock()
        attestation = AuthorizationAttestation(
            authorization_id=uuid4(),
            authority_id=GESTURE_AUTHORITY_ID,
            approval_origin="trusted-electron",
            task_id=gesture.binding.task_id,
            plan_revision=gesture.binding.plan_revision,
            plan_hash=gesture.binding.plan_hash,
            preview_id=gesture.binding.preview_id,
            preview_digest=gesture.binding.preview_digest,
            scope_digest=gesture.binding.scope_digest,
            authorized_at=now,
            expires_at=now + _GRANT_WINDOW,
        )
        return self.issuer.issue(
            attestation=attestation,
            task_id=gesture.binding.task_id,
            plan_revision=gesture.binding.plan_revision,
            plan_hash=gesture.binding.plan_hash,
            operations=operations,
            max_tier=max(step.risk_tier for step in plan.steps),
            issued_at=now,
            expires_at=now + _GRANT_WINDOW,
            uses_remaining=1,
            approval_id=approval_id,
        )

    def _operations_for(self, plan: TaskPlan) -> tuple[tuple[ApprovedOperation, ...], UUID]:
        operations = []
        approval_id: UUID | None = None
        for step in plan.steps:
            arguments_sha256, effect_sha256 = operation_hashes(step)
            operations.append(
                ApprovedOperation(
                    step_id=step.step_id,
                    capability_id=step.capability_id,
                    risk_tier=step.risk_tier,
                    arguments_sha256=arguments_sha256,
                    expected_effect_sha256=effect_sha256,
                    resources=tuple(
                        ApprovedResourceVersion(
                            resource_id=resource.resource_id,
                            expected_version=resource.expected_version,
                        )
                        for resource in step.resources
                    ),
                    recovery_class=RecoveryClass(step.recovery_class),
                )
            )
            raw_approval = step.arguments.get("approval_id")
            if isinstance(raw_approval, str):
                approval_id = UUID(raw_approval)
        if approval_id is None:
            raise CompositionUnavailable(
                "plan_has_no_approval_identity",
                "the persisted plan names no approval identity to bind a grant to",
            )
        return tuple(operations), approval_id

    def _grant_shape(
        self, plan: TaskPlan, operations: tuple[ApprovedOperation, ...], approval_id: UUID
    ) -> ExactApprovalGrant:
        now = self.clock()
        return ExactApprovalGrant(
            approval_id=approval_id,
            task_id=plan.task_id,
            plan_revision=plan.revision,
            plan_hash=plan.plan_hash,
            operations=operations,
            max_tier=max(step.risk_tier for step in plan.steps),
            issued_at=now,
            expires_at=now + _GRANT_WINDOW,
            uses_remaining=1,
            revoked_at=None,
            approval_origin="trusted-electron",
        )

    # ------------------------------------------------------------------
    # Gesture hand-off (main -> verifier, exactly once)
    # ------------------------------------------------------------------
    def note_gesture(self, gesture: SignedGesture) -> None:
        """Record the signed gesture main delivered for the pending approval.

        At most one gesture may be pending: a second arrival while one is
        outstanding is refused rather than overwriting evidence.
        """
        with self._gesture_lock:
            if self._pending_gesture is not None:
                raise CompositionUnavailable(
                    "gesture_already_pending",
                    "a signed gesture is already awaiting verification",
                )
            self._pending_gesture = gesture

    def _take_pending_gesture(self) -> SignedGesture | None:
        with self._gesture_lock:
            gesture = self._pending_gesture
            self._pending_gesture = None
            return gesture

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        """Close the tiers this composition owns (never the caller's store)."""
        if self._closed:
            return
        self._closed = True
        # Outstanding gesture nonces die with the session (Decision A).
        with self._gesture_lock:
            self._pending_gesture = None
        for closer in (
            getattr(self.consumption, "close", None),
            getattr(self.journal, "close", None),
            getattr(self.receipts, "close", None),
            getattr(self.vault, "close", None),
            getattr(self.ledger, "close", None),
        ):
            if closer is not None:
                with contextlib.suppress(Exception):
                    closer()


__all__ = [
    "CAPABILITY_GROUPS",
    "GESTURE_AUTHORITY_ID",
    "CapabilityState",
    "CompositionUnavailable",
    "TrustedComposition",
]
