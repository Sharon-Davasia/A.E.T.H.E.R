"""Shared synthetic fixtures for the Stage 4 grant tests.

Nothing here issues a real authorization, touches the network, executes a
capability or mutates a user file. Databases live in ``tmp_path``.

Schema handling: the shipped ``SQLiteTaskStore`` is pinned to schema version 1
because the Stage 4 migration is *proposed*, not approved. To exercise the
ledger end-to-end, tests register the proposed migration in a **test-only**
schema registry (``monkeypatch`` of the module constants) and point a store at
a temporary migrations directory holding ``0001`` + the proposed ``0002``.
That simulates — and only simulates — the separately required production
migration change; no production constant, migration directory or fingerprint
is modified by Stage 4.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from aether.core.contracts.approval import ApprovedOperation, ApprovedResourceVersion
from aether.core.contracts.policy import RiskTier
from aether.core.contracts.receipt import RecoveryClass
from aether.core.persistence import PersistentTaskState, SQLiteTaskStore
from aether.core.persistence.models import (
    ApprovalDecisionRecord,
    PlanStep,
    TaskPlan,
    TaskPlanResource,
)

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(minutes=5)

BACKEND_ROOT = Path(__file__).parents[1]
PERSISTENCE_DIR = BACKEND_ROOT / "aether/core/persistence"
# PR #14: 0002 is now *registered* in the production migration registry but is
# still refusals-gated (``PENDING_MIGRATION_VERSIONS``). Tests that exercise the
# migration's mechanics activate it in-memory only, via ``activated_migrations``.
MIGRATION_0002 = PERSISTENCE_DIR / "migrations/0002_phase2b_stage4_grants.sql"
# Historical name kept for the existing Stage 4 suite.
PROPOSED_MIGRATION = MIGRATION_0002
MIGRATION_0002_SHA256 = hashlib.sha256(MIGRATION_0002.read_bytes()).hexdigest()
PROPOSED_MIGRATION_SHA256 = MIGRATION_0002_SHA256
MIGRATION_NAME_V2 = "0002_phase2b_stage4_grants"

# Fingerprint of the full version-2 schema (30 tables/indexes/triggers),
# computed exactly like ``SQLiteTaskStore._verify_schema`` does. Pinned in the
# grant ledger as ``_EXPECTED_SCHEMA_SHA256_V2``.
V2_SCHEMA_SHA256 = "dec68c2c1ecdd6d7222b5dcff54b877c9895e5cee6329930148c5db97355b788"

T2_CAPABILITY = "fs.apply_approved_edit"


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def activation_state(monkeypatch, *, activated: bool = True) -> None:
    """Set schema activation for the current test only.

    ``activated=True`` mirrors the state after explicit user approval (active
    schema version 2, nothing pending) so the migration's real mechanics are
    exercised. ``activated=False`` is the shipped state: version 2 registered
    and verified, but refused.
    """

    from aether.core.persistence import sqlite_store

    if activated:
        monkeypatch.setattr(sqlite_store, "ACTIVE_SCHEMA_VERSION", 2)
        monkeypatch.setattr(sqlite_store, "PENDING_MIGRATION_VERSIONS", frozenset())
    else:
        monkeypatch.setattr(sqlite_store, "ACTIVE_SCHEMA_VERSION", 1)
        monkeypatch.setattr(sqlite_store, "PENDING_MIGRATION_VERSIONS", frozenset({2}))


def stage4_store(tmp_path: Path, monkeypatch) -> SQLiteTaskStore:
    """A schema-v2 store, with the migration activated only for this test.

    The production registry is used unchanged (0002 is registered there); only
    the pending-migration gate is lifted, in memory, so the migration's real
    mechanics are exercised. No production constant, file or fingerprint is
    modified.
    """

    migration_dir = tmp_path / "migrations"
    copy_migrations(migration_dir, include_proposed=True)
    activation_state(monkeypatch, activated=True)
    return SQLiteTaskStore(tmp_path / "store.sqlite3", migrations_dir=migration_dir)


class SyntheticT2Plan:
    """A persisted synthetic T2 plan plus the exact operations bound to it."""

    def __init__(
        self,
        database: Path,
        store: SQLiteTaskStore,
        *,
        revision: int = 1,
        resource_id: str | None = None,
        resource_version: str | None = None,
    ) -> None:
        self.database = database
        self.task_id = uuid4()
        self.step_id = uuid4()
        self.approval_id = uuid4()
        self.resource_id = resource_id or f"file:{uuid4()}"
        self.resource_version = resource_version or "v1:0000000000000001"
        self.arguments = {
            "resource_id": self.resource_id,
            "step_id": str(self.step_id),
            "approval_id": str(self.approval_id),
            "expected_sha256": "a" * 64,
        }
        self.expected_effect = {"effect": "replace-one-token"}
        self.revision = revision
        self.plan = TaskPlan(
            task_id=self.task_id,
            revision=revision,
            summary="Synthetic approved-edit proposal for grant-foundation tests.",
            steps=(
                PlanStep(
                    step_id=self.step_id,
                    capability_id=T2_CAPABILITY,
                    arguments=self.arguments,
                    resources=(
                        TaskPlanResource(
                            resource_id=self.resource_id,
                            expected_version=self.resource_version,
                            display_name="sample.txt",
                        ),
                    ),
                    resource_locks=(self.resource_id,),
                    expected_state={"resource": "present"},
                    expected_effect=self.expected_effect,
                    risk_tier=RiskTier.MODIFY,
                    approval_status="REQUIRED",
                    idempotency_key=uuid4(),
                    postconditions=({"condition": "verified"},),
                    recovery_class="SNAPSHOT_RESTORABLE",
                ),
            ),
            created_at=NOW,
        )
        self.store = store
        store.create_task("synthetic grant foundation task", task_id=self.task_id, now=NOW)
        store.transition_task(self.task_id, PersistentTaskState.PLANNING, now=NOW)
        self.plan_hash = store.save_plan(self.plan)
        # Preview-ready + awaiting approval is the only state in which a review
        # audit record may legally be written and in which issuance is legal.
        store.transition_task(self.task_id, PersistentTaskState.PREVIEW_READY, now=NOW)
        store.transition_task(self.task_id, PersistentTaskState.AWAITING_APPROVAL, now=NOW)

    @property
    def operation(self) -> ApprovedOperation:
        return self.operation_with()

    def operation_with(self, **overrides: object) -> ApprovedOperation:
        fields: dict[str, object] = {
            "step_id": self.step_id,
            "capability_id": T2_CAPABILITY,
            "risk_tier": RiskTier.MODIFY,
            "arguments_sha256": sha256_json(self.arguments),
            "expected_effect_sha256": sha256_json(self.expected_effect),
            "resources": (
                ApprovedResourceVersion(
                    resource_id=self.resource_id,
                    expected_version=self.resource_version,
                ),
            ),
            "recovery_class": RecoveryClass.SNAPSHOT_RESTORABLE,
        }
        fields.update(overrides)
        return ApprovedOperation(**fields)  # type: ignore[arg-type]

    def resource_versions(self) -> dict[str, str]:
        return {self.resource_id: self.resource_version}

    def publish_preview(self, authority: SimulatedPreviewAuthority) -> str:
        """Register the authoritative preview for this plan and return its digest."""

        return authority.publish(self.plan)

    def decision(self, *, value: str = "APPROVE") -> ApprovalDecisionRecord:
        return ApprovalDecisionRecord(
            approval_id=self.approval_id,
            task_id=self.task_id,
            plan_revision=self.revision,
            plan_hash=self.plan_hash,
            preview_id=uuid4(),
            preview_digest="a" * 64,
            decision=value,
            decided_at=NOW,
        )

    def issue_kwargs(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "plan_revision": self.revision,
            "plan_hash": self.plan_hash,
            "operations": (self.operation,),
            "max_tier": RiskTier.MODIFY,
            "issued_at": NOW,
            "expires_at": LATER,
            "uses_remaining": 1,
            "approval_id": self.approval_id,
        }


class SimulatedPreviewAuthority:
    """Test-only preview source backed by the *real* Stage 2 preview builder.

    It resolves the canonical ``ExactPreview`` for a persisted plan (exactly as
    the review surface would), so a test can prove that a claimed preview
    identity is checked against authoritative evidence rather than trusted.
    """

    authority_id = "test.preview_source"

    def __init__(self) -> None:
        self._narratives: dict[tuple[str, int], object] = {}

    def publish(self, plan: TaskPlan, *, revision: int | None = None) -> str:
        """Build and register the authoritative preview for a plan; return the digest."""

        from aether.core.approval_review import build_preview

        preview = build_preview(plan, default_narrative(plan))
        self._narratives[(str(plan.task_id), revision or plan.revision)] = preview
        return preview.preview_digest

    def resolve(self, *, task_id, plan_revision, plan_hash):  # type: ignore[no-untyped-def]
        from aether.core.grants.attestation import (
            AuthoritativePreview,
            PreviewSourceUnavailable,
        )

        preview = self._narratives.get((str(task_id), plan_revision))
        if preview is None:
            raise PreviewSourceUnavailable(
                "PREVIEW_SOURCE_UNAVAILABLE", "no synthetic preview registered for this plan"
            )
        if preview.plan_hash != plan_hash:
            raise PreviewSourceUnavailable(
                "PREVIEW_SOURCE_MISMATCH", "registered preview belongs to another plan hash"
            )
        return AuthoritativePreview(
            task_id=preview.task_id,
            plan_revision=preview.plan_revision,
            plan_hash=preview.plan_hash,
            preview_id=preview.preview_id,
            preview_digest=preview.preview_digest,
        )


def default_narrative(plan: TaskPlan):  # type: ignore[no-untyped-def]
    from aether.core.approval_review import PreviewNarrative

    return PreviewNarrative(
        action_intent="Replace one exact token in a synthetic file",
        explanation="Synthetic preview used by Stage 4 grant-foundation tests.",
        preconditions=("the file exists",),
        external_effects=("one synthetic file changes",),
        risks=("synthetic risk",),
        verification_strategy=("re-hash after write",),
        proposed_effect="one token replaced",
        full_diff=(),
    )


class SimulatedAttestationVerifier:
    """Test-only verifier standing in for the future trusted interaction.

    It proves the *contract* (binding + freshness are checked and replayed),
    not real trust: no production code path can construct it, and it lives in
    the test suite rather than the shipped package.
    """

    authority_id = "test.attestation"

    def __init__(self) -> None:
        self.seen: list[tuple[object, object]] = []

    def verify(self, attestation, *, binding) -> None:  # type: ignore[no-untyped-def]
        from aether.core.grants.attestation import AttestationRejected

        self.seen.append((attestation, binding))
        if attestation.authority_id != self.authority_id:
            raise AttestationRejected("AUTHORIZATION_SOURCE_NOT_TRUSTED", "unknown authority")
        if binding.task_id != attestation.task_id:
            raise AttestationRejected("ATTESTATION_TASK_MISMATCH", "binding task mismatch")
        if binding.scope_digest != attestation.scope_digest:
            raise AttestationRejected("ATTESTATION_SCOPE_MISMATCH", "binding scope mismatch")
        if binding.issued_at < attestation.authorized_at:
            raise AttestationRejected("ATTESTATION_NOT_YET_VALID", "issued before authorization")


def make_attestation(
    *,
    task_id,
    plan_revision,
    plan_hash,
    scope_digest,
    authorization_id=None,
    authority_id="test.attestation",
    preview_id=None,
    preview_digest="a" * 64,
    authorized_at=NOW,
    expires_at=LATER,
    **overrides,
):  # type: ignore[no-untyped-def]
    from aether.core.grants.attestation import AuthorizationAttestation

    fields = {
        "authorization_id": authorization_id or uuid4(),
        "authority_id": authority_id,
        "approval_origin": "trusted-electron",
        "task_id": task_id,
        "plan_revision": plan_revision,
        "plan_hash": plan_hash,
        "preview_id": preview_id or uuid4(),
        "preview_digest": preview_digest,
        "scope_digest": scope_digest,
        "authorized_at": authorized_at,
        "expires_at": expires_at,
    }
    fields.update(overrides)
    return AuthorizationAttestation(**fields)


def persist_with_permit(
    ledger,  # type: ignore[no-untyped-def]
    grant,  # type: ignore[no-untyped-def]
    *,
    scope_digest: str,
    issuance_key,  # type: ignore[no-untyped-def]
    issued_by: str,
):
    """Test-only: store a grant through the central test-authorization factory.

    Production reaches storage only through ``GrantIssuer.issue`` (the trusted
    decision); low-level ledger-semantics tests use the test-only factory, and
    the ledger accepts that permit only on a test-scoped instance. The
    production-configured ledger refuses it, which is asserted separately.
    """

    from aether.core.grants.authorization import authorize_test_persistence

    permit = authorize_test_persistence(
        scope_digest=scope_digest,
        issued_by=issued_by,
        task_id=grant.task_id,
        plan_revision=grant.plan_revision,
        plan_hash=grant.plan_hash,
    )
    return ledger._persist_verified_grant(
        grant,
        permit=permit,
        scope_digest=scope_digest,
        issuance_key=issuance_key,
        issued_by=issued_by,
    )


def apply_proposed_migration_raw(database: Path) -> None:
    """Raw-apply the proposed migration, bypassing the store entirely.

    Used only to build databases that must *not* be trusted (e.g. a ledger
    entry naming a different migration checksum) and to verify ledger
    fail-closed behavior.
    """

    migration_sql = PROPOSED_MIGRATION.read_text(encoding="utf-8")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(f"BEGIN IMMEDIATE;\n{migration_sql}")
        connection.execute(
            "INSERT INTO schema_migrations(version, name, sha256, applied_at) VALUES (?,?,?,?)",
            (2, MIGRATION_NAME_V2, PROPOSED_MIGRATION_SHA256, NOW.isoformat()),
        )
        connection.execute("COMMIT")


def grant_rows(database: Path, table: str) -> list[tuple]:
    with sqlite3.connect(database) as connection:
        return [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]


def copy_migrations(destination: Path, *, include_proposed: bool = False) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        PERSISTENCE_DIR / "migrations/0001_phase2b_core.sql",
        destination / "0001_phase2b_core.sql",
    )
    if include_proposed:
        shutil.copyfile(MIGRATION_0002, destination / "0002_phase2b_stage4_grants.sql")
    return destination
