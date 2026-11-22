"""Stage 4 — trusted exact approval-grant foundation (adversarial suite).

Every test is synthetic and offline. No test issues real user authorization,
exposes an IPC/HTTP grant surface, executes a capability, or mutates a user
file. Production issuance is disabled: the shipped attestation verifier is
``NullAttestationVerifier`` and production code cannot build a trusted claim.
``SimulatedAttestationVerifier`` lives here in the test suite and simulates the
*future* trusted interaction; it is never treated as real user authorization.

Schema note: the Stage 4 migration is proposed, not approved. Tests register
it in a test-only schema registry (``stage4_store``) whose bytes and
fingerprints must match the proposed file exactly — the same change the
separately approved production migration must make.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from aether.core.contracts.approval import ExactApprovalGrant, exact_approval_scope_digest
from aether.core.contracts.policy import RiskTier
from aether.core.contracts.receipt import RecoveryClass
from aether.core.contracts.tool import ToolRequest
from aether.core.grants.attestation import (
    PRODUCTION_ATTESTATION_VERIFIER,
    PRODUCTION_PREVIEW_AUTHORITY,
    AttestationRejected,
    AuthorizationAttestation,
    NullAttestationVerifier,
    NullPreviewAuthority,
    PreviewSourceUnavailable,
)
from aether.core.grants.authority import GrantAuthority, GrantRequest
from aether.core.grants.authorization import (
    UnauthorizedTestPersistence,
    authorize_issuance,
    authorize_test_persistence,
    is_permitted_test_authorizer,
)
from aether.core.grants.errors import (
    GrantConflictError,
    GrantDeniedError,
    GrantIntegrityError,
    GrantIssuanceDenied,
    GrantLedgerError,
    GrantNotFoundError,
    GrantUnavailableError,
)
from aether.core.grants.issuance import GrantIssuer
from aether.core.grants.ledger import (
    TEST_AUTHORIZATION_MODULES,
    GrantLedger,
    IssuancePermit,
    consumption_action_digest,
    issuance_intent_digest,
)
from aether.core.persistence import PersistentTaskState, SQLiteTaskStore
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.resources.path_safety import VolumeInfo, VolumeKind
from aether.core.resources.registry import ResourceRegistry
from tests.stage4_support import (
    LATER,
    NOW,
    T2_CAPABILITY,
    SimulatedAttestationVerifier,
    SimulatedPreviewAuthority,
    SyntheticT2Plan,
    apply_proposed_migration_raw,
    make_attestation,
    persist_with_permit,
    sha256_json,
    stage4_store,
)


class FixedVolume:
    def inspect(self, path: Path) -> VolumeInfo:
        del path
        return VolumeInfo("test-volume", VolumeKind.FIXED)


@pytest.fixture()
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    opened = stage4_store(tmp_path, monkeypatch)
    yield opened
    opened.close()


def _scope_digest(world: SyntheticT2Plan, **grant_overrides: object) -> str:
    fields: dict[str, object] = {
        "approval_id": world.approval_id,
        "task_id": world.task_id,
        "plan_revision": world.revision,
        "plan_hash": world.plan_hash,
        "operations": (world.operation,),
        "max_tier": RiskTier.MODIFY,
        "issued_at": NOW,
        "expires_at": LATER,
        "approval_origin": "trusted-electron",
    }
    fields.update(grant_overrides)
    return exact_approval_scope_digest(ExactApprovalGrant(**fields))  # type: ignore[arg-type]


def _previews(world: SyntheticT2Plan) -> SimulatedPreviewAuthority:
    """Publish the authoritative preview for this plan and return the source."""

    source = SimulatedPreviewAuthority()
    world.publish_preview(source)
    return source


def _attestation(
    world: SyntheticT2Plan,
    *,
    previews: SimulatedPreviewAuthority | None = None,
    **overrides: object,
) -> AuthorizationAttestation:
    source = previews if previews is not None else _previews(world)
    authoritative = source.resolve(
        task_id=world.task_id, plan_revision=world.revision, plan_hash=world.plan_hash
    )
    fields: dict[str, object] = {
        "task_id": world.task_id,
        "plan_revision": world.revision,
        "plan_hash": world.plan_hash,
        "scope_digest": _scope_digest(world),
        "preview_id": authoritative.preview_id,
        "preview_digest": authoritative.preview_digest,
    }
    fields.update(overrides)
    return make_attestation(**fields)  # type: ignore[arg-type]


def _issuer(
    store: SQLiteTaskStore,
    ledger: GrantLedger,
    verifier: object | None = None,
    previews: object | None = None,
) -> GrantIssuer:
    return GrantIssuer(
        store=store,
        ledger=ledger,
        attestations=verifier if verifier is not None else SimulatedAttestationVerifier(),  # type: ignore[arg-type]
        previews=previews if previews is not None else SimulatedPreviewAuthority(),  # type: ignore[arg-type]
    )


_NO_ATTESTATION = object()


def _issue(
    store: SQLiteTaskStore,
    ledger: GrantLedger,
    world: SyntheticT2Plan,
    *,
    uses: int = 1,
    lifetime: timedelta | None = None,
    attestation: object = _NO_ATTESTATION,
    verifier: object | None = None,
    previews: SimulatedPreviewAuthority | None = None,
    **overrides: object,
):
    kwargs = world.issue_kwargs()
    kwargs["uses_remaining"] = uses
    if lifetime is not None:
        kwargs["issued_at"] = NOW
        kwargs["expires_at"] = NOW + lifetime
    kwargs.update(overrides)
    source = previews if previews is not None else _previews(world)
    presented = (
        _attestation(world, previews=source) if attestation is _NO_ATTESTATION else attestation
    )
    return _issuer(store, ledger, verifier, previews=source).issue(
        attestation=presented,
        **kwargs,  # type: ignore[arg-type]
    )


def _consume_kwargs(world: SyntheticT2Plan, **overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "consumption_id": uuid4(),
        "approval_id": world.approval_id,
        "task_id": world.task_id,
        "plan_revision": world.revision,
        "plan_hash": world.plan_hash,
        "step_id": world.step_id,
        "capability_id": T2_CAPABILITY,
        "risk_tier": RiskTier.MODIFY,
        "arguments_sha256": sha256_json(world.arguments),
        "expected_effect_sha256": sha256_json(world.expected_effect),
        "resource_versions": world.resource_versions(),
        "consumed_by": "test_simulation",
        "now": NOW,
    }
    fields.update(overrides)
    return fields


def _grant_request(world: SyntheticT2Plan, **overrides: object) -> GrantRequest:
    fields: dict[str, object] = {
        "approval_id": world.approval_id,
        "plan_revision": world.revision,
        "plan_hash": world.plan_hash,
        "step_id": world.step_id,
        "expected_effect_sha256": sha256_json(world.expected_effect),
    }
    fields.update(overrides)
    return GrantRequest(**fields)  # type: ignore[arg-type]


def _dummy_ref(world: SyntheticT2Plan):
    from aether.core.contracts.resource import ResourceRef

    return ResourceRef(
        kind="file",
        resource_id=world.resource_id,
        observed_version=world.resource_version,
    )


def _tool_request(world: SyntheticT2Plan, ref, **overrides) -> ToolRequest:  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "request_id": "request-stage4",
        "task_id": str(world.task_id),
        "capability_id": T2_CAPABILITY,
        "arguments": dict(world.arguments),
        "resources": [ref],
    }
    fields.update(overrides)
    return ToolRequest(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# A. Authoritative grant model and validation
# ---------------------------------------------------------------------------


def test_grant_binds_exact_scope_and_digest_is_stable(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        outcome = _issue(store, ledger, world, uses=2)
        grant = ledger.load(world.approval_id)
        assert outcome.approval_id == world.approval_id
        assert outcome.scope_digest == exact_approval_scope_digest(grant)
        assert grant.task_id == world.task_id
        assert grant.plan_revision == world.revision
        assert grant.plan_hash == world.plan_hash
        assert grant.approval_origin == "trusted-electron"
        assert grant.uses_remaining == 2
        assert grant.operations[0].recovery_class.value == "SNAPSHOT_RESTORABLE"
        assert grant.expires_at - grant.issued_at <= timedelta(minutes=60)
    store.close()


def test_recovery_class_is_bound_into_the_scope_digest(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    reversible = _scope_digest(
        world, operations=(world.operation_with(recovery_class=RecoveryClass.REVERSIBLE),)
    )
    irreversible = _scope_digest(
        world, operations=(world.operation_with(recovery_class=RecoveryClass.IRREVERSIBLE),)
    )
    assert reversible != irreversible
    store.close()


def test_no_wildcard_or_blanket_tier_grant_can_be_built(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with pytest.raises(ValidationError):
        ExactApprovalGrant(
            approval_id=uuid4(),
            task_id=world.task_id,
            plan_revision=1,
            plan_hash=world.plan_hash,
            operations=(world.operation,),
            max_tier=RiskTier.CRITICAL,
            issued_at=NOW,
            expires_at=LATER,
            approval_origin="trusted-electron",
        )
    with pytest.raises(ValidationError):
        ExactApprovalGrant(
            approval_id=uuid4(),
            task_id=world.task_id,
            plan_revision=1,
            plan_hash=world.plan_hash,
            operations=(),
            max_tier=RiskTier.MODIFY,
            issued_at=NOW,
            expires_at=LATER,
            approval_origin="trusted-electron",
        )
    store.close()


# ---------------------------------------------------------------------------
# B / S4-1. Trustworthy issuance prerequisites
# ---------------------------------------------------------------------------


def test_production_package_exports_no_test_only_or_inheritance_path() -> None:
    """S4-1: nothing test-only ships, and class identity is not a trust boundary."""

    import aether.core.grants as package

    exported = set(package.__all__)
    assert not {name for name in exported if name.lower().startswith("test")}
    assert not {name for name in exported if "Proof" in name}
    import aether.core.grants.attestation as attestation_module
    import aether.core.grants.issuance as issuance_module

    for module in (attestation_module, issuance_module):
        assert not hasattr(module, "TestOnlyAuthorizingProof")
        assert not hasattr(module, "AuthorizingProof")
    # Trust is data plus an injected verifier, never an isinstance check.
    source = Path(issuance_module.__file__).read_text(encoding="utf-8")
    assert "isinstance(attestation" not in source.replace("isinstance(attestation, ", "# ")
    assert isinstance(PRODUCTION_ATTESTATION_VERIFIER, NullAttestationVerifier)


def test_production_verifier_denies_all_issuance(tmp_path, monkeypatch) -> None:
    """S4-1: with the shipped verifier configured, issuance is disabled."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        previews = _previews(world)
        issuer = GrantIssuer(
            store=store,
            ledger=ledger,
            attestations=PRODUCTION_ATTESTATION_VERIFIER,
            previews=previews,
        )
        # Even a claim that looks internally consistent cannot issue.
        with pytest.raises(GrantIssuanceDenied) as denied:
            issuer.issue(attestation=_attestation(world, previews=previews), **world.issue_kwargs())
        assert denied.value.reason_code == "AUTHORIZATION_SOURCE_NOT_TRUSTED"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


def test_issuance_requires_attestation_never_review_evidence(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        store.record_approval_decision(world.decision(value="APPROVE"))
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(store, ledger, world, attestation=None)
        assert denied.value.reason_code == "AUTHORIZATION_EVIDENCE_REQUIRED"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


def test_attestation_is_validated_data_not_a_duck_typed_object(tmp_path, monkeypatch) -> None:
    """S4-1: a forged object with matching attributes is never fetched as trust."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)

    class ForgedClaim:
        authorizing_action_id = uuid4()
        authority_id = "test.attestation"

    with (
        GrantLedger.open(store) as ledger,
        pytest.raises((GrantIssuanceDenied, AttributeError, TypeError)),
    ):
        _issue(store, ledger, world, attestation=ForgedClaim())
    store.close()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"authority_id": "renderer.claim"}, "AUTHORIZATION_SOURCE_NOT_TRUSTED"),
        ({"task_id": uuid4()}, "ATTESTATION_TASK_MISMATCH"),
        ({"plan_revision": 2}, "ATTESTATION_PLAN_MISMATCH"),
        ({"plan_hash": "b" * 64}, "ATTESTATION_PLAN_MISMATCH"),
        ({"scope_digest": "c" * 64}, "ATTESTATION_SCOPE_MISMATCH"),
        ({"authorized_at": NOW + timedelta(minutes=1)}, "ATTESTATION_NOT_YET_VALID"),
    ],
)
def test_attestation_must_bind_this_exact_authorization(
    tmp_path, monkeypatch, overrides, reason
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    previews = _previews(world)
    claim = _attestation(world, previews=previews, **overrides)
    with GrantLedger.open(store) as ledger:
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(store, ledger, world, attestation=claim)
        assert denied.value.reason_code == reason
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


def test_forged_origin_and_expired_attestation_are_rejected_by_contract(
    tmp_path, monkeypatch
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    # A non-trusted origin literal cannot even be typed as an attestation.
    with pytest.raises(ValidationError):
        make_attestation(
            task_id=world.task_id,
            plan_revision=world.revision,
            plan_hash=world.plan_hash,
            scope_digest=_scope_digest(world),
            approval_origin="renderer",
        )
    # An attestation that has already expired cannot be constructed.
    with pytest.raises(ValidationError):
        _attestation(world, expires_at=NOW - timedelta(minutes=1))
    # Nor can one that outlives the 60-minute bound.
    with pytest.raises(ValidationError):
        _attestation(world, expires_at=NOW + timedelta(minutes=61))
    store.close()


def test_attestation_from_another_task_cannot_authorize(tmp_path, monkeypatch) -> None:
    """S4-1: an unrelated-task proof cannot establish authorization."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    other = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    previews = _previews(world)
    foreign = _attestation(
        world,
        previews=previews,
        task_id=other.task_id,
        plan_revision=other.revision,
        plan_hash=other.plan_hash,
    )
    with GrantLedger.open(store) as ledger:
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(store, ledger, world, attestation=foreign)
        assert denied.value.reason_code == "ATTESTATION_TASK_MISMATCH"
    store.close()


def test_attestation_expiry_must_cover_the_grant(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    short = _attestation(world, expires_at=NOW + timedelta(minutes=2))
    with GrantLedger.open(store) as ledger:
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(store, ledger, world, attestation=short, lifetime=timedelta(minutes=30))
        assert denied.value.reason_code == "ATTESTATION_EXPIRY_EXCEEDED"
    store.close()


def test_issuance_requires_current_persisted_plan(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        with pytest.raises(GrantIssuanceDenied) as stale:
            _issue(store, ledger, world, plan_hash="b" * 64)
        assert stale.value.reason_code == "PLAN_HASH_MISMATCH"
        with pytest.raises(GrantIssuanceDenied) as wrong_task:
            _issue(store, ledger, world, task_id=uuid4())
        assert wrong_task.value.reason_code == "TASK_NOT_AVAILABLE"
        with pytest.raises(GrantIssuanceDenied) as future_step:
            _issue(store, ledger, world, operations=(world.operation_with(step_id=uuid4()),))
        assert future_step.value.reason_code == "STEP_NOT_IN_PLAN"
    store.close()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"capability_id": "fs.read_file"}, "OPERATION_MISMATCH"),
        ({"risk_tier": RiskTier.NAVIGATE}, "OPERATION_MISMATCH"),
        ({"arguments_sha256": "c" * 64}, "OPERATION_MISMATCH"),
        ({"expected_effect_sha256": "d" * 64}, "OPERATION_MISMATCH"),
        ({"recovery_class": RecoveryClass.IRREVERSIBLE}, "RECOVERY_CLASS_MISMATCH"),
    ],
)
def test_issuance_rejects_any_operation_wider_or_different_than_the_plan(
    tmp_path, monkeypatch, overrides, reason
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(store, ledger, world, operations=(world.operation_with(**overrides),))
        assert denied.value.reason_code == reason
    store.close()


def test_issuance_rejects_substituted_resources(tmp_path, monkeypatch) -> None:
    from aether.core.contracts.approval import ApprovedResourceVersion

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    substituted = world.operation_with(
        resources=(
            ApprovedResourceVersion(resource_id=f"file:{uuid4()}", expected_version="v1:9999"),
        )
    )
    with GrantLedger.open(store) as ledger:
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(store, ledger, world, operations=(substituted,))
        assert denied.value.reason_code == "RESOURCE_MISMATCH"
    store.close()


def test_issuance_bounds_lifetime_uses_and_tier(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        with pytest.raises(GrantIssuanceDenied) as too_long:
            _issue(store, ledger, world, lifetime=timedelta(minutes=61))
        assert too_long.value.reason_code == "GRANT_LIFETIME_TOO_LONG"
        with pytest.raises(GrantIssuanceDenied) as backwards:
            _issue(store, ledger, world, lifetime=timedelta(minutes=-1))
        assert backwards.value.reason_code == "GRANT_LIFETIME_INVALID"
        with pytest.raises(GrantIssuanceDenied) as too_many:
            _issue(store, ledger, world, uses=9)
        assert too_many.value.reason_code == "GRANT_USE_BOUND_INVALID"
        with pytest.raises(GrantIssuanceDenied) as zero_uses:
            _issue(store, ledger, world, uses=0)
        assert zero_uses.value.reason_code == "GRANT_USE_BOUND_INVALID"
        with pytest.raises(GrantIssuanceDenied) as t3:
            _issue(store, ledger, world, max_tier=RiskTier.CRITICAL)
        assert t3.value.reason_code == "TIER3_DISABLED"
        with pytest.raises(GrantIssuanceDenied) as naive:
            _issue(store, ledger, world, issued_at=NOW.replace(tzinfo=None))
        assert naive.value.reason_code == "AUTHORIZATION_EVIDENCE_REQUIRED"
    store.close()


def test_duplicate_issuance_is_idempotent_only_for_identical_terms(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    claim = _attestation(world)
    with GrantLedger.open(store) as ledger:
        first = _issue(store, ledger, world, attestation=claim)
        second = _issue(store, ledger, world, attestation=claim)
        assert first.replayed is False
        assert second.replayed is True
        assert second.approval_id == first.approval_id
        assert len(ledger.list_consumptions(world.approval_id)) == 0
    store.close()


# ---------------------------------------------------------------------------
# S4-2. Complete issuance replay integrity
# ---------------------------------------------------------------------------


def test_supplied_scope_digest_is_verified_independently(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    grant = ExactApprovalGrant(
        approval_id=world.approval_id,
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation,),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        approval_origin="trusted-electron",
    )
    with GrantLedger.open(store) as ledger:
        # S4-6: the ledger's storage primitive refuses anything but a permit from
        # the trusted authorization decision, so it cannot be reached directly.
        with pytest.raises(GrantIssuanceDenied) as direct:
            ledger._persist_verified_grant(  # type: ignore[attr-defined]
                grant,
                permit=object(),  # type: ignore[arg-type]
                scope_digest="f" * 64,
                issuance_key=uuid4(),
                issued_by="test.attestation",
            )
        assert direct.value.reason_code == "AUTHORIZATION_EVIDENCE_REQUIRED"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


@pytest.mark.parametrize("field", ["issued_at", "expires_at", "uses_remaining"])
def test_replay_with_changed_authorization_terms_is_a_conflict(
    tmp_path, monkeypatch, field
) -> None:
    """S4-2: one issuance identity binds the full immutable authorization intent."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    key = uuid4()

    def build(**overrides: object) -> ExactApprovalGrant:
        fields: dict[str, object] = {
            "approval_id": world.approval_id,
            "task_id": world.task_id,
            "plan_revision": world.revision,
            "plan_hash": world.plan_hash,
            "operations": (world.operation,),
            "max_tier": RiskTier.MODIFY,
            "issued_at": NOW,
            "expires_at": LATER,
            "uses_remaining": 2,
            "approval_origin": "trusted-electron",
        }
        fields.update(overrides)
        return ExactApprovalGrant(**fields)  # type: ignore[arg-type]

    # A tier ceiling below the operation's own tier is unconstructible, so the
    # tier term is covered by the intent-digest test instead.
    changed_values: dict[str, object] = {
        "issued_at": NOW + timedelta(minutes=1),
        "expires_at": LATER + timedelta(minutes=5),
        "uses_remaining": 3,
    }
    with GrantLedger.open_tests_scoped(store) as ledger:
        original = build()
        persist_with_permit(
            ledger,
            original,
            scope_digest=exact_approval_scope_digest(original),
            issuance_key=key,
            issued_by="test.attestation",
        )
        changed = build(**{field: changed_values[field]})
        with pytest.raises((GrantConflictError, GrantIntegrityError)):
            persist_with_permit(
                ledger,
                changed,
                scope_digest=exact_approval_scope_digest(changed),
                issuance_key=key,
                issued_by="test.attestation",
            )
        persisted = ledger.load(world.approval_id)
        assert persisted.expires_at == original.expires_at
        assert persisted.uses_remaining == 2
        assert ledger.list_consumptions(world.approval_id) == ()
    store.close()


def test_replay_with_changed_issuer_identity_is_a_conflict(tmp_path, monkeypatch) -> None:
    """S4-2: the trusted issuer identity is part of the issuance intent."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    key = uuid4()
    grant = ExactApprovalGrant(
        approval_id=world.approval_id,
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation,),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        uses_remaining=2,
        approval_origin="trusted-electron",
    )
    digest = exact_approval_scope_digest(grant)
    with GrantLedger.open_tests_scoped(store) as ledger:
        persist_with_permit(
            ledger, grant, scope_digest=digest, issuance_key=key, issued_by="test.attestation"
        )
        with pytest.raises(GrantConflictError):
            persist_with_permit(
                ledger, grant, scope_digest=digest, issuance_key=key, issued_by="test.other"
            )
        # Same identity and identical terms is still a legitimate retry.
        retry = persist_with_permit(
            ledger, grant, scope_digest=digest, issuance_key=key, issued_by="test.attestation"
        )
        assert retry.replayed is True
    store.close()


def test_issuance_intent_digest_covers_every_immutable_term() -> None:
    base = {
        "scope_digest": "a" * 64,
        "task_id": UUID(int=1),
        "plan_revision": 1,
        "plan_hash": "b" * 64,
        "max_tier": 2,
        "issued_at": NOW,
        "expires_at": LATER,
        "uses_remaining": 1,
        "issued_by": "test.attestation",
    }
    reference = issuance_intent_digest(**base)  # type: ignore[arg-type]
    for field, value in {
        "scope_digest": "c" * 64,
        "plan_revision": 2,
        "plan_hash": "d" * 64,
        "max_tier": 1,
        "issued_at": NOW + timedelta(seconds=1),
        "expires_at": LATER + timedelta(seconds=1),
        "uses_remaining": 2,
        "issued_by": "test.other",
    }.items():
        assert issuance_intent_digest(**{**base, field: value}) != reference  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# S4-3. Exact consumption replay binding
# ---------------------------------------------------------------------------


def test_exact_consumption_replay_is_idempotent(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)
        first = _consume_kwargs(world)
        consumed = ledger.consume(**first)
        assert consumed.uses_remaining_after == 1
        replay = ledger.consume(**first)
        assert replay.replayed is True
        assert replay.uses_remaining_after == 1
        assert len(ledger.list_consumptions(world.approval_id)) == 1
        assert ledger.status(world.approval_id, now=NOW).uses_remaining == 1
    store.close()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"risk_tier": RiskTier.NAVIGATE}, "conflict"),
        ({"arguments_sha256": "e" * 64}, "conflict"),
        ({"expected_effect_sha256": "f" * 64}, "conflict"),
        ({"resource_versions": {"file:00000000-0000-0000-0000-000000000000": "v1:1"}}, "conflict"),
        ({"step_id": uuid4()}, "conflict"),
        ({"capability_id": "fs.read_file"}, "conflict"),
        ({"plan_revision": 7}, "conflict"),
        ({"consumed_by": "policy_check"}, "conflict"),
    ],
)
def test_consumption_replay_with_changed_action_terms_fails_closed(
    tmp_path, monkeypatch, overrides, reason
) -> None:
    del reason
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=3)
        first = _consume_kwargs(world)
        ledger.consume(**first)
        with pytest.raises(GrantConflictError):
            ledger.consume(**{**first, **overrides})
        # No second consumption was recorded and no extra use was spent.
        assert len(ledger.list_consumptions(world.approval_id)) == 1
        assert ledger.status(world.approval_id, now=NOW).uses_remaining == 2
    store.close()


def test_consumption_replay_binding_survives_reopen(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    database = tmp_path / "store.sqlite3"
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)
        first = _consume_kwargs(world)
        ledger.consume(**first)
    store.close()
    reopened = SQLiteTaskStore(database, migrations_dir=tmp_path / "migrations")
    try:
        with GrantLedger.open(reopened) as ledger:
            # Identical retry is still idempotent after a full restart…
            assert ledger.consume(**first).replayed is True
            # …and a changed term still conflicts.
            with pytest.raises(GrantConflictError):
                ledger.consume(**{**first, "risk_tier": RiskTier.NAVIGATE})
            assert ledger.status(world.approval_id, now=NOW).uses_remaining == 1
    finally:
        reopened.close()


def test_consumption_action_digest_covers_every_action_field() -> None:
    base = {
        "approval_id": UUID(int=1),
        "task_id": UUID(int=2),
        "plan_revision": 1,
        "plan_hash": "a" * 64,
        "step_id": UUID(int=3),
        "capability_id": T2_CAPABILITY,
        "risk_tier": RiskTier.MODIFY,
        "arguments_sha256": "b" * 64,
        "expected_effect_sha256": "c" * 64,
        "resource_versions_digest": "d" * 64,
        "consumed_by": "test_simulation",
    }
    reference = consumption_action_digest(**base)  # type: ignore[arg-type]
    for field, value in {
        "task_id": UUID(int=9),
        "plan_revision": 2,
        "plan_hash": "e" * 64,
        "step_id": UUID(int=8),
        "capability_id": "fs.read_file",
        "risk_tier": RiskTier.NAVIGATE,
        "arguments_sha256": "f" * 64,
        "expected_effect_sha256": "0" * 64,
        "resource_versions_digest": "1" * 64,
        "consumed_by": "policy_check",
    }.items():
        assert consumption_action_digest(**{**base, field: value}) != reference  # type: ignore[arg-type]


def test_exhaustion_and_duplicate_consumption(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)
        ledger.consume(**_consume_kwargs(world))
        ledger.consume(**_consume_kwargs(world))
        assert ledger.status(world.approval_id, now=NOW).state == "EXHAUSTED"
        with pytest.raises(GrantDeniedError) as exhausted:
            ledger.consume(**_consume_kwargs(world))
        assert exhausted.value.reason_code == "GRANT_EXHAUSTED"
    store.close()


# ---------------------------------------------------------------------------
# S4-4. Current-plan authority and transactional consistency
# ---------------------------------------------------------------------------


def _advance_plan(store: SQLiteTaskStore, world: SyntheticT2Plan) -> str:
    """Move the persisted task to a new plan revision (as a REVISE would)."""

    assert store is world.store
    store.transition_task(world.task_id, PersistentTaskState.PLANNING, now=NOW)
    revised = world.plan.model_copy(
        update={
            "revision": world.revision + 1,
            "summary": "Synthetic approved-edit proposal, revised plan.",
            "created_at": NOW + timedelta(minutes=1),
        }
    )
    new_hash = store.save_plan(revised)
    store.transition_task(world.task_id, PersistentTaskState.PREVIEW_READY, now=NOW)
    store.transition_task(world.task_id, PersistentTaskState.AWAITING_APPROVAL, now=NOW)
    return new_hash


def test_issued_grant_is_denied_after_the_plan_advances(tmp_path, monkeypatch) -> None:
    """S4-4: a grant for a superseded plan cannot be used, even unexpired."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=3)
        new_hash = _advance_plan(store, world)
        assert new_hash != world.plan_hash

        # Consumption must fail on the current-plan check, not merely on hashes.
        with pytest.raises(GrantDeniedError) as denied:
            ledger.consume(**_consume_kwargs(world))
        assert denied.value.reason_code == "GRANT_PLAN_SUPERSEDED"
        assert ledger.status(world.approval_id, now=NOW).uses_remaining == 3

        # Broker-side validation also denies with current-plan authority.
        authority = GrantAuthority(ledger, store=store)
        check = authority.check_action(
            _tool_request(world, _dummy_ref(world)),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, "GRANT_PLAN_SUPERSEDED")

        # A grant for the *new* revision is still a separate authorization.
        revised_plan = store.get_plan(world.task_id)
        source = SimulatedPreviewAuthority()
        source.publish(revised_plan)
        revised_preview = source.resolve(
            task_id=world.task_id,
            plan_revision=revised_plan.revision,
            plan_hash=revised_plan.plan_hash,
        )
        new_attestation = make_attestation(
            task_id=world.task_id,
            plan_revision=world.revision + 1,
            plan_hash=new_hash,
            scope_digest=_scope_digest(world, plan_revision=world.revision + 1, plan_hash=new_hash),
            preview_id=revised_preview.preview_id,
            preview_digest=revised_preview.preview_digest,
        )
        outcome = _issuer(store, ledger, previews=source).issue(
            attestation=new_attestation,
            **{
                **world.issue_kwargs(),
                "plan_revision": world.revision + 1,
                "plan_hash": new_hash,
                "approval_id": uuid4(),
            },
        )
        assert outcome.replayed is False
    store.close()


def test_use_is_denied_once_the_task_leaves_consent_states(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)
        store.transition_task(world.task_id, PersistentTaskState.CANCELLED, now=NOW)
        with pytest.raises(GrantDeniedError) as denied:
            ledger.consume(**_consume_kwargs(world))
        assert denied.value.reason_code == "TASK_STATE_NOT_AUTHORIZABLE"
        assert ledger.status(world.approval_id, now=NOW).uses_remaining == 2
    store.close()


def test_issuance_refuses_tasks_outside_consent_states_and_invalidated_consent(
    tmp_path, monkeypatch
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        store.record_preview_revocation(
            world.task_id,
            plan_revision=world.revision,
            plan_hash=world.plan_hash,
            preview_id=uuid4(),
            preview_digest="a" * 64,
            revocation_id=uuid4(),
            now=NOW,
        )
        with pytest.raises(GrantIssuanceDenied) as invalidated:
            _issue(store, ledger, world)
        assert invalidated.value.reason_code == "CONSENT_INVALIDATED"

        store.transition_task(world.task_id, PersistentTaskState.CANCELLED, now=NOW)
        with pytest.raises(GrantIssuanceDenied) as state_denied:
            _issue(store, ledger, world)
        assert state_denied.value.reason_code == "TASK_STATE_NOT_AUTHORIZABLE"
    store.close()


def test_current_plan_check_and_decrement_are_atomic_under_concurrency(
    tmp_path, monkeypatch
) -> None:
    """S4-4: a plan change racing a consumption can never yield a spend."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=4)
        _advance_plan(store, world)

        def attempt(_: int) -> str:
            # One owner, one connection: the store's BEGIN IMMEDIATE + lock
            # serializes these attempts exactly as it serializes task writes.
            try:
                ledger.consume(**_consume_kwargs(world))
                return "consumed"
            except GrantDeniedError as exc:
                return exc.reason_code

        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(attempt, range(4)))
        assert outcomes == ["GRANT_PLAN_SUPERSEDED"] * 4
        assert ledger.status(world.approval_id, now=NOW).uses_remaining == 4
        assert ledger.list_consumptions(world.approval_id) == ()
    store.close()


def test_issuance_rechecks_the_plan_inside_its_transaction(tmp_path, monkeypatch) -> None:
    """S4-4: the plan pointer is re-verified after the pre-check, atomically."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        original_get_plan = store.get_plan
        advanced = {"done": False}

        def racing_get_plan(*args, **kwargs):
            # Issue a stale pre-check, then move the plan before the write.
            plan = original_get_plan(*args, **kwargs)
            if not advanced["done"]:
                advanced["done"] = True
                store.transition_task(world.task_id, PersistentTaskState.PLANNING, now=NOW)
                store.save_plan(
                    world.plan.model_copy(
                        update={
                            "revision": world.revision + 1,
                            "summary": "Synthetic revised plan.",
                            "created_at": NOW + timedelta(minutes=1),
                        }
                    )
                )
                store.transition_task(world.task_id, PersistentTaskState.PREVIEW_READY, now=NOW)
                store.transition_task(world.task_id, PersistentTaskState.AWAITING_APPROVAL, now=NOW)
            return plan

        monkeypatch.setattr(store, "get_plan", racing_get_plan)
        with pytest.raises(GrantDeniedError) as denied:
            _issue(store, ledger, world)
        assert denied.value.reason_code == "GRANT_PLAN_SUPERSEDED"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


def test_recovery_class_comes_from_the_trusted_plan_step(tmp_path, monkeypatch) -> None:
    """S4-4: the grant's recovery class must equal the persisted step's."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        # The plan step is SNAPSHOT_RESTORABLE; claiming REVERSIBLE is refused
        # even though REVERSIBLE looks "stronger".
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(
                store,
                ledger,
                world,
                operations=(world.operation_with(recovery_class=RecoveryClass.REVERSIBLE),),
            )
        assert denied.value.reason_code == "RECOVERY_CLASS_MISMATCH"
    store.close()


# ---------------------------------------------------------------------------
# C. Durable persistence, ownership, revocation, crash/restart
# ---------------------------------------------------------------------------


def test_ledger_refuses_v1_database_without_the_approved_migration(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)
    store.create_task("synthetic", task_id=uuid4(), now=NOW)
    try:
        with pytest.raises(GrantUnavailableError):
            GrantLedger.open(store)
    finally:
        store.close()


def test_ledger_rejects_tampered_migration_ledger_and_schema(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    store.close()
    database = tmp_path / "store.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE schema_migrations SET sha256 = ? WHERE version = 2", ("e" * 64,))
    with pytest.raises(GrantIntegrityError):
        GrantLedger.read_only(database)

    database2 = tmp_path / "other.sqlite3"
    database2.write_bytes(database.read_bytes())
    with sqlite3.connect(database2) as connection:
        connection.execute("DROP TRIGGER exact_approval_grant_state_guarded_update")
    with pytest.raises(GrantIntegrityError):
        GrantLedger.read_only(database2)


def test_raw_applied_migration_without_ledger_row_is_untrusted(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    SQLiteTaskStore(database).close()
    apply_proposed_migration_raw(database)
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 2")
    with pytest.raises(GrantIntegrityError):
        GrantLedger.read_only(database)


def test_scope_rows_and_ledgers_are_immutable(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        ledger.consume(**_consume_kwargs(world))
        ledger.revoke(world.approval_id, reason_code="SUPERSEDED_BY_PLAN", now=NOW)
    database = tmp_path / "store.sqlite3"
    store.close()
    approval = str(world.approval_id)
    statements: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("UPDATE exact_approval_grants SET scope_json = '{}' WHERE approval_id = ?", (approval,)),
        (
            "UPDATE exact_approval_grants SET issuance_digest = ? WHERE approval_id = ?",
            ("9" * 64, approval),
        ),
        (
            "UPDATE exact_approval_grants SET issued_by = 'x' WHERE approval_id = ?",
            (approval,),
        ),
        (
            "UPDATE exact_approval_grants SET expires_at = ? WHERE approval_id = ?",
            ("2030-01-01T00:00:00+00:00", approval),
        ),
        ("DELETE FROM exact_approval_grant_events WHERE approval_id = ?", (approval,)),
        ("UPDATE exact_approval_grant_consumptions SET capability_id = 'fs.read_file'", ()),
        (
            "UPDATE exact_approval_grant_state SET uses_remaining = 5 WHERE approval_id = ?",
            (approval,),
        ),
    )
    with sqlite3.connect(database) as connection:
        for statement, parameters in statements:
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement, parameters)


def test_revocation_is_bounded_code_and_idempotent(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)
        status = ledger.revoke(world.approval_id, reason_code="CONSENT_REVOKED", now=NOW)
        assert status.state == "REVOKED"
        assert status.revocation_code == "CONSENT_REVOKED"
        again = ledger.revoke(world.approval_id, reason_code="ADMINISTRATIVE", now=NOW)
        assert again.revocation_code == "CONSENT_REVOKED"
        with pytest.raises(GrantDeniedError) as denied:
            ledger.consume(**_consume_kwargs(world))
        assert denied.value.reason_code == "GRANT_REVOKED"
        assert [event for _, event, _, _ in ledger.events(world.approval_id)] == [
            "ISSUED",
            "REVOKED",
        ]
        with pytest.raises(GrantNotFoundError):
            ledger.revoke(uuid4(), reason_code="ADMINISTRATIVE")


def test_free_text_audit_metadata_is_refused(tmp_path, monkeypatch) -> None:
    """S4-5: no secret-bearing or unbounded string may reach grant metadata."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)
        for bad in (
            "token=sk-abcdefghijklmnop",
            "my secret reason",
            "C:/Users/example/notes.txt",
        ):
            with pytest.raises(GrantDeniedError):
                ledger.revoke(world.approval_id, reason_code=bad, now=NOW)
        assert [event for _, event, _, _ in ledger.events(world.approval_id)] == ["ISSUED"]
        assert all(
            "sk-" not in str(detail) and "secret" not in str(detail)
            for _, _, _, detail in ledger.events(world.approval_id)
        )
    store.close()


def test_consumption_consumer_code_is_bounded(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        with pytest.raises(GrantDeniedError):
            ledger.consume(**_consume_kwargs(world, consumed_by="Bearer abc123"))
        assert ledger.status(world.approval_id, now=NOW).uses_remaining == 1
    store.close()


def test_crash_restart_preserves_committed_state(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    database = tmp_path / "store.sqlite3"
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=3)
        ledger.consume(**_consume_kwargs(world))
    store.close()  # simulated abrupt end of the process

    reopened = SQLiteTaskStore(database, migrations_dir=tmp_path / "migrations")
    try:
        with GrantLedger.open(reopened) as ledger:
            status = ledger.status(world.approval_id, now=NOW)
            assert status.uses_remaining == 2
            assert status.consumed_count == 1
            assert status.state == "ACTIVE"
            assert len(ledger.list_consumptions(world.approval_id)) == 1
            assert reopened.get_plan(world.task_id).plan_hash == world.plan_hash
    finally:
        reopened.close()


def test_transactional_failure_leaves_no_partial_consumption(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)

        def fail_after_decrement(connection, approval_id, event, *, reason_code, detail):
            connection.execute(
                "INSERT INTO exact_approval_grant_events "
                "(id, approval_id, grant_seq, event, reason_code, detail_json, created_at) "
                "VALUES (?, ?, 99, 'BOGUS', NULL, '{}', ?)",
                (str(uuid4()), approval_id, NOW.isoformat()),
            )

        monkeypatch.setattr(ledger, "_append_event_unlocked", fail_after_decrement)
        with pytest.raises(sqlite3.IntegrityError):
            ledger.consume(**_consume_kwargs(world))
        monkeypatch.undo()
        status = ledger.status(world.approval_id, now=NOW)
        assert status.uses_remaining == 2
        assert status.consumed_count == 0
        assert ledger.events(world.approval_id)[-1][1] == "ISSUED"
    store.close()


def test_concurrent_consumption_never_overspends(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)

        def attempt(_: int) -> str:
            try:
                ledger.consume(**_consume_kwargs(world))
                return "consumed"
            except GrantDeniedError as exc:
                return exc.reason_code

        with ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(attempt, range(6)))
        assert outcomes.count("consumed") == 2
        assert set(outcomes) - {"consumed"} == {"GRANT_EXHAUSTED"}
        status = ledger.status(world.approval_id, now=NOW)
        assert status.uses_remaining == 0
        assert status.consumed_count == 2
        assert len(ledger.list_consumptions(world.approval_id)) == 2
        # Concurrent identical retries cannot double-spend either.
        shared = _consume_kwargs(world, now=NOW)
        with pytest.raises(GrantDeniedError):
            ledger.consume(**shared)
    store.close()


def test_expiry_denies_consume_and_reports_state(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        assert ledger.status(world.approval_id, now=NOW).state == "ACTIVE"
        expired_at = LATER + timedelta(seconds=1)
        assert ledger.status(world.approval_id, now=expired_at).state == "EXPIRED"
        with pytest.raises(GrantDeniedError) as denied:
            ledger.consume(**_consume_kwargs(world, now=expired_at))
        assert denied.value.reason_code == "GRANT_EXPIRED"
        with pytest.raises(GrantDeniedError) as early:
            ledger.consume(**_consume_kwargs(world, now=NOW - timedelta(seconds=1)))
        assert early.value.reason_code == "GRANT_NOT_YET_VALID"
    store.close()


# ---------------------------------------------------------------------------
# S4-5. Ownership, lock sharing, storage identity
# ---------------------------------------------------------------------------


def test_ledger_shares_the_store_connection_and_lock(tmp_path, monkeypatch) -> None:
    """S4-5: one owner lock, one connection, no second-owner window."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        assert ledger._connection is store._connection
        assert ledger._owns_connection is False
        assert ledger._owns_lock is False
        assert store._stage4_grant_ledger is ledger
        with pytest.raises(GrantUnavailableError):
            GrantLedger.open(store)  # only one ledger per store
        _issue(store, ledger, world)
        ledger.consume(**_consume_kwargs(world))
        # The store keeps working and still owns the database.
        assert store.get_plan(world.task_id).revision == world.revision
    assert store._stage4_grant_ledger is None
    assert store.get_task(world.task_id).task_id == world.task_id
    store.close()


def test_ledger_write_is_rolled_back_with_the_task_transaction(tmp_path, monkeypatch) -> None:
    """S4-5: grant writes join the store's transaction, not a parallel one."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)

        def fail_after_decrement(connection, approval_id, event, *, reason_code, detail):
            raise GrantIntegrityError("injected failure after decrement")

        monkeypatch.setattr(ledger, "_append_event_unlocked", fail_after_decrement)
        with pytest.raises(GrantIntegrityError):
            ledger.consume(**_consume_kwargs(world))
        monkeypatch.undo()
        assert ledger.status(world.approval_id, now=NOW).uses_remaining == 2
        # The store's own connection is not left inside a transaction.
        assert store._connection.in_transaction is False
    store.close()


def test_store_still_enforces_single_owner_while_ledger_is_open(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        from aether.core.persistence.sqlite_store import PersistenceBusyError

        with pytest.raises(PersistenceBusyError):
            SQLiteTaskStore(tmp_path / "store.sqlite3", migrations_dir=tmp_path / "migrations")
    store.close()


def test_standalone_ledger_cannot_take_ownership_from_a_store(tmp_path, monkeypatch) -> None:
    """S4-5: the store keeps ownership; a path-only ledger cannot hijack it."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    try:
        with pytest.raises(GrantUnavailableError):
            GrantLedger(tmp_path / "store.sqlite3")
        # The store's own ledger still works afterwards.
        with GrantLedger.open(store) as ledger:
            _issue(store, ledger, world)
    finally:
        store.close()


def test_standalone_ledgers_are_mutually_exclusive(tmp_path, monkeypatch) -> None:
    """S4-5: two standalone owners can never hold the same database."""

    store = stage4_store(tmp_path, monkeypatch)
    SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    store.close()
    with GrantLedger(tmp_path / "store.sqlite3") as first:
        with pytest.raises(GrantUnavailableError):
            GrantLedger(tmp_path / "store.sqlite3")
        assert first.database_path.name == "store.sqlite3"
    # Releasing the owner lock makes the database available again.
    with GrantLedger(tmp_path / "store.sqlite3") as second:
        assert second._owns_lock is True


def test_read_only_handle_verifies_and_cannot_write(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
    store.close()
    with GrantLedger.read_only(tmp_path / "store.sqlite3") as handle:
        assert handle.status(world.approval_id, now=NOW).state == "ACTIVE"
        with pytest.raises(sqlite3.OperationalError):
            handle._connection.execute(
                "INSERT INTO exact_approval_grants (approval_id) VALUES ('x')"
            )


def test_grant_file_permissions_are_private(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        if os.name != "nt":
            mode = (tmp_path / "store.sqlite3").stat().st_mode & 0o777
            assert mode == 0o600
    store.close()


def test_unsafe_database_paths_fail_closed(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    store.close()
    with pytest.raises(GrantIntegrityError):
        GrantLedger(str(tmp_path / ".." / "escaped.sqlite3"))
    with pytest.raises(GrantUnavailableError):
        GrantLedger(tmp_path / "absent.sqlite3")
    with pytest.raises(GrantIntegrityError):
        GrantLedger(tmp_path / "store.sqlite3\x00")


def test_ledger_never_applies_migrations(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    SQLiteTaskStore(database).close()
    before = database.read_bytes()
    with pytest.raises((GrantUnavailableError, GrantIntegrityError, GrantLedgerError)):
        GrantLedger(database)
    assert database.read_bytes() == before


# ---------------------------------------------------------------------------
# D. Fail-closed policy integration (no execution)
# ---------------------------------------------------------------------------


def _broker(tmp_path: Path) -> PolicyBroker:
    root_path = tmp_path / "workspace"
    root_path.mkdir(exist_ok=True)
    (root_path / "sample.txt").write_text("synthetic", encoding="utf-8")
    resources = ResourceRegistry(volume_inspector=FixedVolume())
    resources.register_root("fixture", root_path, allowed_capabilities=frozenset({T2_CAPABILITY}))
    return PolicyBroker(capabilities=CapabilityRegistry.phase2_filesystem(), resources=resources)


def test_broker_without_grant_still_denies_t2(tmp_path) -> None:
    broker = _broker(tmp_path)
    decision = broker.evaluate(
        ToolRequest(
            request_id="r",
            task_id=str(uuid4()),
            capability_id=T2_CAPABILITY,
            arguments={
                "resource_id": f"file:{uuid4()}",
                "step_id": str(uuid4()),
                "approval_id": str(uuid4()),
                "expected_sha256": "a" * 64,
            },
            resources=[],
        )
    )
    assert decision.allowed is False
    assert decision.requires_approval is True


def test_validated_exact_grant_verifies_scope_but_enables_no_executor(
    tmp_path, monkeypatch
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    root_path = tmp_path / "workspace"
    root_path.mkdir(exist_ok=True)
    (root_path / "sample.txt").write_text("synthetic original", encoding="utf-8")
    resources = ResourceRegistry(volume_inspector=FixedVolume())
    root = resources.register_root(
        "fixture", root_path, allowed_capabilities=frozenset({T2_CAPABILITY})
    )
    resolved = resources.resolve(root.root_id, "sample.txt").ref
    world = SyntheticT2Plan(
        tmp_path / "store.sqlite3",
        store,
        resource_id=resolved.resource_id,
        resource_version=resolved.observed_version,
    )
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        broker = PolicyBroker(
            capabilities=CapabilityRegistry.phase2_filesystem(),
            resources=resources,
            grant_authority=GrantAuthority(ledger, store=store),
        )
        request = ToolRequest(
            request_id="r",
            task_id=str(world.task_id),
            capability_id=T2_CAPABILITY,
            arguments=dict(world.arguments),
            resources=[resolved],
        )
        decision = broker.evaluate(request, grant=_grant_request(world), now=NOW)
        assert decision.allowed is False
        assert decision.reason_code == "GRANT_VALIDATED_EXECUTOR_NOT_ENABLED"
        assert ledger.status(world.approval_id, now=NOW).uses_remaining == 1
        assert ledger.list_consumptions(world.approval_id) == ()

        mismatched = _grant_request(world, step_id=uuid4())
        denied = broker.evaluate(request, grant=mismatched, now=NOW)
        assert (denied.allowed, denied.reason_code) == (False, "GRANT_STEP_MISMATCH")
    store.close()


@pytest.mark.parametrize("reason", ["expired", "revoked", "exhausted", "missing"])
def test_expired_revoked_exhausted_or_absent_grants_deny(tmp_path, monkeypatch, reason) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    ledger = GrantLedger.open(store)
    _issue(store, ledger, world)
    request = _tool_request(world, _dummy_ref(world))
    now = NOW
    if reason == "expired":
        now = LATER + timedelta(seconds=1)
        authority: GrantAuthority = GrantAuthority(ledger, store=store)
    elif reason == "revoked":
        ledger.revoke(world.approval_id, reason_code="ADMINISTRATIVE", now=NOW)
        authority = GrantAuthority(ledger, store=store)
    elif reason == "exhausted":
        ledger.consume(**_consume_kwargs(world))
        authority = GrantAuthority(ledger, store=store)
    else:
        ledger.close()
        authority = GrantAuthority(None)
    check = authority.check_action(
        request, _grant_request(world), risk_tier=RiskTier.MODIFY, now=now
    )
    assert check.ok is False
    assert (
        check.reason_code
        == {
            "expired": "GRANT_EXPIRED",
            "revoked": "GRANT_REVOKED",
            "exhausted": "GRANT_EXHAUSTED",
            "missing": "GRANT_AUTHORITY_UNAVAILABLE",
        }[reason]
    )
    if not ledger._closed:
        ledger.close()
    store.close()


def test_grant_authority_rejects_unknown_and_forged_grant_ids(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        check = GrantAuthority(ledger, store=store).check_action(
            _tool_request(world, _dummy_ref(world)),
            _grant_request(world, approval_id=uuid4()),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, "GRANT_NOT_FOUND")
    store.close()


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("task_id", "task", "GRANT_TASK_MISMATCH"),
        ("plan_revision", 2, "GRANT_PLAN_MISMATCH"),
        ("plan_hash", "f" * 64, "GRANT_PLAN_HASH_MISMATCH"),
        ("step_id", "step", "GRANT_STEP_MISMATCH"),
        ("expected_effect_sha256", "9" * 64, "GRANT_OPERATION_MISMATCH"),
    ],
)
def test_substitution_of_task_plan_step_or_effect_denies(
    tmp_path, monkeypatch, field, value, reason
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        authority = GrantAuthority(ledger, store=store)
        overrides: dict[str, object] = {}
        request_overrides: dict[str, object] = {}
        if value == "task":
            request_overrides["task_id"] = str(uuid4())
        elif value == "step":
            overrides["step_id"] = uuid4()
        else:
            overrides[field] = value
        check = authority.check_action(
            _tool_request(world, _dummy_ref(world), **request_overrides),
            _grant_request(world, **overrides),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, reason)
    store.close()


def test_resource_substitution_scope_widening_and_stale_versions_deny(
    tmp_path, monkeypatch
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        authority = GrantAuthority(ledger, store=store)
        ref = _dummy_ref(world)

        stale = ref.model_copy(update={"observed_version": "v1:deadbeef"})
        check = authority.check_action(
            _tool_request(world, stale), _grant_request(world), risk_tier=RiskTier.MODIFY, now=NOW
        )
        assert (check.ok, check.reason_code) == (False, "GRANT_RESOURCE_MISMATCH")

        extra = ref.model_copy(update={"resource_id": f"file:{uuid4()}"})
        check = authority.check_action(
            _tool_request(world, ref, resources=[ref, extra]),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, "GRANT_RESOURCE_MISMATCH")

        unversioned = ref.model_copy(update={"observed_version": None})
        check = authority.check_action(
            _tool_request(world, unversioned),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, "GRANT_RESOURCE_MISMATCH")

        for capability, tier in (
            ("fs.read_file", RiskTier.MODIFY),
            (T2_CAPABILITY, RiskTier.CRITICAL),
        ):
            check = authority.check_action(
                _tool_request(world, ref, capability_id=capability),
                _grant_request(world),
                risk_tier=tier,
                now=NOW,
            )
            assert check.ok is False
    store.close()


def test_arguments_substitution_denies(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        widened = {**world.arguments, "expected_sha256": "b" * 64}
        check = GrantAuthority(ledger, store=store).check_action(
            _tool_request(world, _dummy_ref(world), arguments=widened),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, "GRANT_OPERATION_MISMATCH")
    store.close()


def test_t3_requests_remain_denied_even_with_a_maximum_grant(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, max_tier=RiskTier.MODIFY)
        broker = _broker(tmp_path)
        critical_broker = PolicyBroker(
            capabilities=broker._capabilities,
            resources=broker._resources,
            grant_authority=GrantAuthority(ledger, store=store),
        )
        decision = critical_broker.evaluate(
            ToolRequest(
                request_id="t3",
                task_id=str(world.task_id),
                capability_id="shell.exec",
                arguments={},
                resources=[],
            ),
            grant=_grant_request(world),
            now=NOW,
        )
        assert decision.allowed is False
        assert decision.risk_tier == RiskTier.CRITICAL
        with pytest.raises(GrantIssuanceDenied):
            _issue(store, ledger, world, max_tier=RiskTier.CRITICAL)
    store.close()


def test_grant_authority_fails_closed_without_a_ledger(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    check = GrantAuthority(None).check_action(
        _tool_request(world, _dummy_ref(world)),
        _grant_request(world),
        risk_tier=RiskTier.MODIFY,
        now=NOW,
    )
    assert (check.ok, check.reason_code) == (False, "GRANT_AUTHORITY_UNAVAILABLE")
    store.close()


# ---------------------------------------------------------------------------
# Synthetic development-source isolation
# ---------------------------------------------------------------------------


def test_synthetic_preview_review_cannot_produce_a_grant(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AETHER_REVIEW_DEV_SEED", "synthetic-review")
    monkeypatch.setenv("AETHER_REVIEW_TASK_ID", str(uuid4()))
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        store.record_approval_decision(world.decision(value="APPROVE"))
        with pytest.raises(GrantIssuanceDenied):
            _issue(store, ledger, world, attestation=None)
        previews = _previews(world)
        with pytest.raises(GrantIssuanceDenied) as denied:
            GrantIssuer(
                store=store,
                ledger=ledger,
                attestations=PRODUCTION_ATTESTATION_VERIFIER,
                previews=previews,
            ).issue(attestation=_attestation(world, previews=previews), **world.issue_kwargs())
        assert denied.value.reason_code == "AUTHORIZATION_SOURCE_NOT_TRUSTED"
    store.close()


def test_no_production_module_issues_grants_or_exposes_ipc() -> None:
    """S4-6: no production module outside the grant package can issue or store.

    Neither the issuer, the attestation model, the storage primitive nor the
    single-use permit may be referenced elsewhere, so there is no second
    production-capable path into the ledger.
    """

    backend = Path(__file__).parents[1]
    markers = (
        "GrantIssuer(",
        "AuthorizationAttestation(",
        "_persist_verified_grant",
        "IssuancePermit",
    )
    offenders: list[str] = []
    for path in (backend / "aether").rglob("*.py"):
        if "core/grants" in path.as_posix():
            continue
        text = path.read_text(encoding="utf-8")
        if any(marker in text for marker in markers):
            offenders.append(path.relative_to(backend).as_posix())
    assert offenders == []


def test_attestation_rejected_is_a_fail_closed_error() -> None:
    class Rejecting:
        authority_id = "test.attestation"

        def verify(self, attestation, *, binding):
            del attestation, binding
            raise AttestationRejected("AUTHORIZATION_SOURCE_NOT_TRUSTED", "no")

    assert not isinstance(Rejecting(), NullAttestationVerifier)


# ---------------------------------------------------------------------------
# G. S4-6 — separation of authorization from storage
# ---------------------------------------------------------------------------


def test_no_ledger_entry_point_can_persist_a_grant_without_authorization(
    tmp_path, monkeypatch
) -> None:
    """S4-6: storage refuses every direct write, so issuance cannot be bypassed."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    grant = ExactApprovalGrant(
        approval_id=world.approval_id,
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation,),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        approval_origin="trusted-electron",
    )
    digest = exact_approval_scope_digest(grant)
    with GrantLedger.open(store) as ledger:
        # The old public write entry point is gone entirely.
        assert not hasattr(ledger, "issue")

        # No ordinary caller-created object stands in for the permit: not an
        # instance of the permit type, a subclass, a namespace, or None.
        class FakePermit:
            """Looks like a permit, is not one: class identity buys nothing."""

            def _claim(self, **kwargs: object) -> None:
                del kwargs

        for forgery in (
            None,
            object(),
            SimpleNamespace(),
            type("Permit", (), {})(),
            FakePermit(),
        ):
            with pytest.raises(GrantIssuanceDenied) as denied:
                ledger._persist_verified_grant(  # type: ignore[attr-defined]
                    grant,
                    permit=forgery,  # type: ignore[arg-type]
                    scope_digest=digest,
                    issuance_key=uuid4(),
                    issued_by="test.attestation",
                )
            assert denied.value.reason_code == "AUTHORIZATION_EVIDENCE_REQUIRED"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
        assert ledger.list_consumptions(world.approval_id) == ()
    store.close()


def test_permit_subclass_cannot_inherit_authorization_and_override_is_ignored(
    tmp_path, monkeypatch
) -> None:
    """S4-9: inheritance is not an authentication boundary."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    grant = ExactApprovalGrant(
        approval_id=world.approval_id,
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation,),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        approval_origin="trusted-electron",
    )
    digest = exact_approval_scope_digest(grant)

    class ForgedPermit(IssuancePermit):
        def _claim(self, **kwargs: object) -> None:  # pragma: no cover - never called
            del kwargs

    with GrantLedger.open_tests_scoped(store) as ledger:
        forged = object.__new__(ForgedPermit)
        forged._scope_digest = digest  # type: ignore[attr-defined]
        forged._issuer = "test.attestation"  # type: ignore[attr-defined]
        forged._trust_source = "trusted_verifier"  # type: ignore[attr-defined]
        forged._test_requester = None  # type: ignore[attr-defined]
        forged._binding = {  # type: ignore[attr-defined]
            "task_id": str(world.task_id),
            "plan_revision": world.revision,
            "plan_hash": world.plan_hash,
            "issuance_key": str(uuid4()),
        }
        forged._consumed = False  # type: ignore[attr-defined]
        with pytest.raises(GrantIssuanceDenied) as denied:
            ledger._persist_verified_grant(  # type: ignore[attr-defined]
                grant,
                permit=forged,
                scope_digest=digest,
                issuance_key=uuid4(),
                issued_by="test.attestation",
            )
        assert denied.value.reason_code == "AUTHORIZATION_EVIDENCE_REQUIRED"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


def test_issuance_permit_is_single_use_and_bound_to_its_scope(tmp_path, monkeypatch) -> None:
    """S4-9: even a real permit authorizes exactly one exact write."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    grant = ExactApprovalGrant(
        approval_id=world.approval_id,
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation,),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        approval_origin="trusted-electron",
    )
    digest = exact_approval_scope_digest(grant)
    with GrantLedger.open_tests_scoped(store) as ledger:
        permit = authorize_test_persistence(
            scope_digest=digest,
            issued_by="test.attestation",
            task_id=world.task_id,
            plan_revision=world.revision,
            plan_hash=world.plan_hash,
        )
        ledger._persist_verified_grant(  # type: ignore[attr-defined]
            grant,
            permit=permit,
            scope_digest=digest,
            issuance_key=uuid4(),
            issued_by="test.attestation",
        )
        with pytest.raises(GrantIssuanceDenied) as reused:
            ledger._persist_verified_grant(  # type: ignore[attr-defined]
                grant,
                permit=permit,
                scope_digest=digest,
                issuance_key=uuid4(),
                issued_by="test.attestation",
            )
        assert reused.value.reason_code == "ISSUANCE_PERMIT_ALREADY_USED"
        # A permit for a different scope cannot be re-pointed at this grant.
        other = authorize_test_persistence(
            scope_digest="c" * 64,
            issued_by="test.attestation",
            task_id=world.task_id,
            plan_revision=world.revision,
            plan_hash=world.plan_hash,
        )
        with pytest.raises(GrantIssuanceDenied) as mismatched:
            ledger._persist_verified_grant(  # type: ignore[attr-defined]
                grant,
                permit=other,
                scope_digest=digest,
                issuance_key=uuid4(),
                issued_by="test.attestation",
            )
        assert mismatched.value.reason_code == "ISSUANCE_PERMIT_MISMATCH"
        # A permit is also not transferable to a different authorization identity.
        third = authorize_test_persistence(
            scope_digest=digest,
            issued_by="test.other",
            task_id=world.task_id,
            plan_revision=world.revision,
            plan_hash=world.plan_hash,
        )
        with pytest.raises(GrantIssuanceDenied) as untrusted:
            ledger._persist_verified_grant(  # type: ignore[attr-defined]
                grant,
                permit=third,
                scope_digest=digest,
                issuance_key=uuid4(),
                issued_by="test.attestation",
            )
        assert untrusted.value.reason_code == "ISSUANCE_PERMIT_MISMATCH"
    store.close()


def test_production_default_has_no_preview_source_and_stays_disabled(tmp_path, monkeypatch) -> None:
    """S4-6: without authoritative preview evidence, issuance is explicitly disabled."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    assert isinstance(PRODUCTION_PREVIEW_AUTHORITY, NullPreviewAuthority)
    with pytest.raises(PreviewSourceUnavailable) as unavailable:
        PRODUCTION_PREVIEW_AUTHORITY.resolve(
            task_id=world.task_id, plan_revision=world.revision, plan_hash=world.plan_hash
        )
    assert unavailable.value.reason_code == "PREVIEW_SOURCE_UNAVAILABLE"
    with GrantLedger.open(store) as ledger:
        # Preview-verified attestation is not available in production, because
        # a claim carried in the attestation object is never evidence.
        issuer = GrantIssuer(
            store=store, ledger=ledger, attestations=SimulatedAttestationVerifier()
        )
        with pytest.raises(GrantIssuanceDenied) as denied:
            issuer.issue(attestation=_attestation(world), **world.issue_kwargs())
        assert denied.value.reason_code == "PREVIEW_SOURCE_UNAVAILABLE"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


def test_forged_preview_identity_is_rejected_against_authoritative_evidence(
    tmp_path, monkeypatch
) -> None:
    """S4-6: the attestation's preview id/digest is only a claim until verified."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    previews = _previews(world)
    authoritative = previews.resolve(
        task_id=world.task_id, plan_revision=world.revision, plan_hash=world.plan_hash
    )

    for overrides, reason in [
        ({"preview_digest": "b" * 64}, "PREVIEW_IDENTITY_MISMATCH"),
        ({"preview_id": uuid4()}, "PREVIEW_IDENTITY_MISMATCH"),
    ]:
        with GrantLedger.open(store) as ledger:
            with pytest.raises(GrantIssuanceDenied) as denied:
                _issue(
                    store,
                    ledger,
                    world,
                    attestation=_attestation(world, previews=previews, **overrides),
                    previews=previews,
                )
            assert denied.value.reason_code == reason
            with pytest.raises(GrantNotFoundError):
                ledger.load(world.approval_id)

    # A preview that is real, but authoritative for a *different* task, is
    # refused as well: the source, not the claim, decides the identity.
    assert authoritative.preview_id is not None

    class ForeignPreview:
        def resolve(self, **kwargs: object):
            del kwargs
            return authoritative.model_copy(update={"task_id": uuid4()})

    with GrantLedger.open(store) as ledger:
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(
                store,
                ledger,
                world,
                attestation=_attestation(world, previews=previews),
                previews=ForeignPreview(),
            )
        assert denied.value.reason_code == "PREVIEW_SOURCE_MISMATCH"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


def test_verified_preview_identity_is_required_for_successful_issuance(
    tmp_path, monkeypatch
) -> None:
    """S4-6: the positive path proves the check is a real gate, not a skip."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    previews = _previews(world)
    with GrantLedger.open(store) as ledger:
        outcome = _issue(store, ledger, world, previews=previews)
        assert outcome.replayed is False
        stored = ledger.load(world.approval_id)
        authoritative = previews.resolve(
            task_id=world.task_id, plan_revision=world.revision, plan_hash=world.plan_hash
        )
        assert stored.plan_hash == authoritative.plan_hash
    store.close()


def test_preview_source_failures_fail_closed(tmp_path, monkeypatch) -> None:
    """S4-6: an unavailable or exploding preview source never authorizes."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)

    class Exploding:
        def resolve(self, **kwargs):
            del kwargs
            raise RuntimeError("preview backend unreachable")

    previews = _previews(world)
    with GrantLedger.open(store) as ledger:
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(
                store,
                ledger,
                world,
                attestation=_attestation(world, previews=previews),
                previews=Exploding(),
            )
        assert denied.value.reason_code == "PREVIEW_SOURCE_UNAVAILABLE"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


# ---------------------------------------------------------------------------
# H. S4-7 — fresh consent inside the writing transaction
# ---------------------------------------------------------------------------


def _revoke_preview(store: SQLiteTaskStore, world: SyntheticT2Plan) -> None:
    """Record a non-authorizing preview revocation (Stage 2 semantics)."""

    store.record_preview_revocation(
        world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        preview_id=uuid4(),
        preview_digest="a" * 64,
        revocation_id=uuid4(),
        now=NOW,
    )


def test_revocation_between_issuance_precheck_and_transaction_denies(tmp_path, monkeypatch) -> None:
    """S4-7: a revocation landing after the pre-check still blocks the write.

    The task still has a live plan and consent-bearing state, so only the
    in-transaction check can deny; nothing may be written.
    """

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    previews = _previews(world)
    transaction_checks: list[str] = []
    connection_in_transaction: list[object] = [None]
    with GrantLedger.open(store) as ledger:
        original_consent_check = GrantLedger._check_fresh_consent

        def recording_consent_check(self, connection, task_id):  # type: ignore[no-untyped-def]
            transaction_checks.append(
                "in_transaction" if connection is connection_in_transaction[0] else "other"
            )
            return original_consent_check(self, connection, task_id)

        original_transaction = ledger._transaction

        @contextmanager
        def recording_transaction():  # type: ignore[no-untyped-def]
            with original_transaction() as connection:
                connection_in_transaction[0] = connection
                yield connection

        monkeypatch.setattr(ledger, "_transaction", recording_transaction)
        monkeypatch.setattr(GrantLedger, "_check_fresh_consent", recording_consent_check)
        from aether.core.grants import authorization as authorization_module

        original_preview_check = authorization_module._check_authoritative_preview

        def revoke_after_precheck(previews, attestation, *, grant):  # type: ignore[no-untyped-def]
            original_preview_check(previews, attestation, grant=grant)
            # Everything else already passed: revoke immediately before the
            # ledger opens its write transaction.
            _revoke_preview(store, world)
            # The pre-check would now fail too, so clear the way: this test is
            # about the check *inside* the transaction.
            assert store.is_stage2_preview_blocked(world.task_id) is True

        monkeypatch.setattr(
            authorization_module, "_check_authoritative_preview", revoke_after_precheck
        )
        with pytest.raises(GrantDeniedError) as denied:
            _issue(store, ledger, world, previews=previews)
        assert denied.value.reason_code == "CONSENT_INVALIDATED"
        # The denial came from the check inside the write transaction.
        assert transaction_checks == ["in_transaction"]
        # No grant row was written by the denied path.
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
        assert ledger.list_consumptions(world.approval_id) == ()
    store.close()


def test_revocation_after_issuance_denies_consumption_without_decrement(
    tmp_path, monkeypatch
) -> None:
    """S4-7: revocation after issuance denies use even with unchanged state/plan."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=3)
        before = ledger.status(world.approval_id, now=NOW)
        assert before.uses_remaining == 3

        _revoke_preview(store, world)
        assert store.is_stage2_preview_blocked(world.task_id) is True

        with pytest.raises(GrantDeniedError) as denied:
            ledger.consume(**_consume_kwargs(world))
        assert denied.value.reason_code == "CONSENT_INVALIDATED"

        after = ledger.status(world.approval_id, now=NOW)
        assert after.uses_remaining == 3
        assert ledger.list_consumptions(world.approval_id) == ()

        # Broker-side validation denies with the same reason, and grants no use.
        check = GrantAuthority(ledger, store=store).check_action(
            _tool_request(world, _dummy_ref(world)),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, "CONSENT_INVALIDATED")
    store.close()


def test_consent_check_is_shared_with_the_store_not_reimplemented(tmp_path, monkeypatch) -> None:
    """S4-7: the in-transaction check reuses the store's own event semantics."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    calls: list[object] = []
    original = store.is_stage2_preview_blocked

    def spy(task_id):  # type: ignore[no-untyped-def]
        calls.append(task_id)
        return original(task_id)

    monkeypatch.setattr(store, "is_stage2_preview_blocked", spy)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        after_issuance = len(calls)
        # Pre-check plus the in-transaction recheck inside the grant write.
        assert after_issuance == 2, f"issuance consulted the reader {after_issuance} times"
        ledger.consume(**_consume_kwargs(world))
        assert len(calls) == 3, "consumption must consult it again inside its transaction"
    store.close()


def test_standalone_ledger_cannot_verify_consent_and_fails_closed(tmp_path, monkeypatch) -> None:
    """S4-7: without the owning store, consent cannot be verified; deny."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    database = tmp_path / "store.sqlite3"
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
    store.close()

    standalone = GrantLedger(database)
    try:
        with pytest.raises(GrantDeniedError) as denied:
            standalone.consume(**_consume_kwargs(world))
        assert denied.value.reason_code == "CONSENT_AUTHORITY_UNAVAILABLE"
        assert standalone.status(world.approval_id, now=NOW).uses_remaining == 1
        assert standalone.list_consumptions(world.approval_id) == ()
    finally:
        standalone.close()


# ---------------------------------------------------------------------------
# I. S4-8 — current-plan authority is mandatory; reads are serialized
# ---------------------------------------------------------------------------


def test_grant_authority_without_store_fails_closed(tmp_path, monkeypatch) -> None:
    """S4-8: missing current-plan authority can never report success."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world)
        check = GrantAuthority(ledger).check_action(
            _tool_request(world, _dummy_ref(world)),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (
            False,
            "GRANT_CURRENT_PLAN_AUTHORITY_REQUIRED",
        )
        # Supplying the store makes the very same check succeed, so the missing
        # store is a real gate rather than an incidental failure.
        ok_check = GrantAuthority(ledger, store=store).check_action(
            _tool_request(world, _dummy_ref(world)),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert ok_check.ok is True
    store.close()


def test_historical_grant_denies_after_supersession_without_store(tmp_path, monkeypatch) -> None:
    """S4-8: a store-less authority denies instead of trusting a stale plan."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        _issue(store, ledger, world, uses=2)
        _advance_plan(store, world)
        check = GrantAuthority(ledger).check_action(
            _tool_request(world, _dummy_ref(world)),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert check.ok is False
        assert check.reason_code == "GRANT_CURRENT_PLAN_AUTHORITY_REQUIRED"
    store.close()


def test_shared_connection_reads_take_the_store_lock(tmp_path, monkeypatch) -> None:
    """S4-8: ledger reads use the store's own lock, so they serialize with writes."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger.open(store) as ledger:
        assert ledger._lock is store._lock, "shared mode must use the store's mechanism"
        _issue(store, ledger, world)

        completed = threading.Event()
        lock_held = threading.Event()
        release_lock = threading.Event()

        def hold_store_lock() -> None:
            with store._lock:
                lock_held.set()
                assert release_lock.wait(timeout=10)

        def read() -> None:
            try:
                ledger.load(world.approval_id)
            finally:
                completed.set()

        holder = threading.Thread(target=hold_store_lock)
        reader = threading.Thread(target=read)
        holder.start()
        try:
            assert lock_held.wait(timeout=10)
            reader.start()
            assert completed.wait(timeout=0.5) is False, "read did not take the store lock"
            release_lock.set()
            reader.join(timeout=10)
        finally:
            release_lock.set()
            holder.join(timeout=10)
        assert completed.is_set()
    store.close()


def test_reader_cannot_observe_an_uncommitted_grant_write(tmp_path, monkeypatch) -> None:
    """S4-8: a concurrent reader is serialized behind the writing transaction.

    While the writer holds a grant insert inside the store's ``BEGIN IMMEDIATE``
    transaction, a reader on the shared connection must block rather than
    observe uncommitted task/grant state.
    """

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    ledger = GrantLedger.open(store)
    previews = _previews(world)

    observed: dict[str, object] = {}
    writer_inside = threading.Event()
    release_writer = threading.Event()

    original_consent_check = GrantLedger._check_fresh_consent

    def paused_consent_check(self, connection, task_id):  # type: ignore[no-untyped-def]
        # Runs inside the write transaction, after the grant row is inserted and
        # before COMMIT.
        original_consent_check(self, connection, task_id)
        writer_inside.set()
        assert release_writer.wait(timeout=10)

    monkeypatch.setattr(GrantLedger, "_check_fresh_consent", paused_consent_check)

    def reader() -> None:
        try:
            ledger.load(world.approval_id)
            observed["read"] = "found"
        except GrantNotFoundError:
            observed["read"] = "missing"
        except GrantUnavailableError:
            observed["read"] = "unavailable"

    writer = threading.Thread(target=lambda: _issue(store, ledger, world, previews=previews))
    reader_thread = threading.Thread(target=reader)
    writer.start()
    try:
        assert writer_inside.wait(timeout=10), "issuance never reached its write transaction"
        reader_thread.start()
        reader_thread.join(timeout=0.5)
        assert reader_thread.is_alive(), "reader was not serialized behind the write transaction"
        assert observed == {}
        release_writer.set()
        writer.join(timeout=15)
        reader_thread.join(timeout=15)
    finally:
        release_writer.set()

    assert observed == {"read": "found"}
    assert ledger.load(world.approval_id).approval_id == world.approval_id
    ledger.close()
    store.close()


# ---------------------------------------------------------------------------
# J. S4-9 — provenance of the trust decision, not the permit object
# ---------------------------------------------------------------------------


def _row_counts(database: Path) -> tuple[int, int, int]:
    """Grant rows, grant events and consumptions currently persisted."""

    with sqlite3.connect(database) as connection:
        return (
            int(connection.execute("SELECT COUNT(*) FROM exact_approval_grants").fetchone()[0]),
            int(
                connection.execute("SELECT COUNT(*) FROM exact_approval_grant_events").fetchone()[0]
            ),
            int(
                connection.execute(
                    "SELECT COUNT(*) FROM exact_approval_grant_consumptions"
                ).fetchone()[0]
            ),
        )


def test_direct_permit_construction_cannot_write_through_the_default_ledger(
    tmp_path, monkeypatch
) -> None:
    """S4-9: the production-configured ledger writes nothing for a test permit."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    database = tmp_path / "store.sqlite3"
    grant = ExactApprovalGrant(
        approval_id=world.approval_id,
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation,),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        approval_origin="trusted-electron",
    )
    digest = exact_approval_scope_digest(grant)
    before = _row_counts(database)
    with GrantLedger.open(store) as ledger:  # default, production-configured
        assert ledger._trust_source_policy == "production"
        permit = authorize_test_persistence(
            scope_digest=digest,
            issued_by="test.attestation",
            task_id=world.task_id,
            plan_revision=world.revision,
            plan_hash=world.plan_hash,
        )
        with pytest.raises(GrantIssuanceDenied) as denied:
            ledger._persist_verified_grant(  # type: ignore[attr-defined]
                grant,
                permit=permit,
                scope_digest=digest,
                issuance_key=uuid4(),
                issued_by="test.attestation",
            )
        assert denied.value.reason_code == "AUTHORIZATION_EVIDENCE_REQUIRED"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    # Zero grant rows, zero grant events, zero consumptions: nothing was written.
    assert _row_counts(database) == before == (0, 0, 0)
    with sqlite3.connect(database) as connection:
        state_rows = connection.execute(
            "SELECT COUNT(*) FROM exact_approval_grant_state"
        ).fetchone()[0]
    assert state_rows == 0, "a denied path wrote grant state"
    store.close()


def test_permit_minting_is_not_authorization(tmp_path, monkeypatch) -> None:
    """S4-9: obtaining a permit is not evidence; only the decision is."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    # The public constructor cannot produce a permit at all.
    with pytest.raises(TypeError):
        IssuancePermit(scope_digest="a" * 64, issued_by="test.attestation")
    with GrantLedger.open(store) as ledger:
        # A permit whose recorded trust source is not a recognized decision is
        # refused even if it names the trusted source — a label is not a decision.
        labelled = object.__new__(IssuancePermit)
        labelled._scope_digest = "a" * 64  # type: ignore[attr-defined]
        labelled._issuer = "test.attestation"  # type: ignore[attr-defined]
        labelled._trust_source = "trusted_verifier"  # type: ignore[attr-defined]
        labelled._test_requester = None  # type: ignore[attr-defined]
        labelled._binding = {}  # type: ignore[attr-defined]
        labelled._consumed = False  # type: ignore[attr-defined]
        grant = ExactApprovalGrant(
            approval_id=world.approval_id,
            task_id=world.task_id,
            plan_revision=world.revision,
            plan_hash=world.plan_hash,
            operations=(world.operation,),
            max_tier=RiskTier.MODIFY,
            issued_at=NOW,
            expires_at=LATER,
            approval_origin="trusted-electron",
        )
        with pytest.raises(GrantIssuanceDenied) as denied:
            ledger._persist_verified_grant(  # type: ignore[attr-defined]
                grant,
                permit=labelled,
                scope_digest=exact_approval_scope_digest(grant),
                issuance_key=uuid4(),
                issued_by="test.attestation",
            )
        assert denied.value.reason_code == "ISSUANCE_PERMIT_MISMATCH"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


def test_trusted_decision_permit_is_bound_to_the_exact_authorization(tmp_path, monkeypatch) -> None:
    """S4-9: the decision binds task, plan, scope and issuance identity."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    grant = ExactApprovalGrant(
        approval_id=world.approval_id,
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation,),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        approval_origin="trusted-electron",
    )
    digest = exact_approval_scope_digest(grant)
    previews = _previews(world)
    key = uuid4()
    attestation = _attestation(
        world,
        previews=previews,
        authorization_id=key,
        scope_digest=digest,
    )
    permit = authorize_issuance(
        attestation,
        grant=grant,
        scope_digest=digest,
        attestations=SimulatedAttestationVerifier(),
        previews=previews,
    )
    assert permit.trust_source == "trusted_verifier"
    assert permit.test_requester is None
    with GrantLedger.open(store) as ledger:
        # Re-pointing a genuine permit at a different issuance identity fails.
        with pytest.raises(GrantIssuanceDenied) as denied:
            ledger._persist_verified_grant(  # type: ignore[attr-defined]
                grant,
                permit=permit,
                scope_digest=digest,
                issuance_key=uuid4(),
                issued_by="test.attestation",
            )
        assert denied.value.reason_code == "ISSUANCE_PERMIT_MISMATCH"
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
        # And the permit is consumed, so it cannot be retried either.
        with pytest.raises(GrantIssuanceDenied):
            ledger._persist_verified_grant(  # type: ignore[attr-defined]
                grant,
                permit=permit,
                scope_digest=digest,
                issuance_key=key,
                issued_by="test.attestation",
            )
    store.close()


def _capturing_store_lock(monkeypatch, store) -> list[bool]:
    """Record whether the ledger's initial integrity reads hold the store lock."""

    observed: list[bool] = []
    original_check = GrantLedger._check_integrity

    def recording_check(self) -> None:  # type: ignore[no-untyped-def]
        # The store's lock is an RLock: if construction holds it, this thread
        # already owns it, which is exactly what we assert.
        observed.append(store._lock._is_owned())  # type: ignore[attr-defined]
        return original_check(self)

    monkeypatch.setattr(GrantLedger, "_check_integrity", recording_check)
    return observed


def test_open_runs_initial_integrity_reads_under_the_store_lock(tmp_path, monkeypatch) -> None:
    """S4-9: construction and its schema reads happen under the store's lock."""

    store = stage4_store(tmp_path, monkeypatch)
    SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    observed = _capturing_store_lock(monkeypatch, store)
    with GrantLedger.open(store) as ledger:
        assert ledger._lock is store._lock
    assert observed, "the ledger never ran its integrity reads"
    assert all(observed), "initial integrity reads ran without the store lock"
    store.close()


def test_open_serializes_with_a_concurrent_store_transaction(tmp_path, monkeypatch) -> None:
    """S4-9: opening blocks while another thread is inside a store transaction."""

    store = stage4_store(tmp_path, monkeypatch)
    SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    holding = threading.Event()
    release = threading.Event()
    opened = threading.Event()

    def hold_store_transaction() -> None:
        with store._transaction():
            holding.set()
            assert release.wait(timeout=10)

    holder = threading.Thread(target=hold_store_transaction)
    holder.start()
    try:
        assert holding.wait(timeout=10)
        opener = threading.Thread(target=lambda: GrantLedger.open(store).close())
        opener.start()
        opener.join(timeout=0.5)
        assert opener.is_alive(), "ledger construction did not wait for the store lock"
        release.set()
        opener.join(timeout=10)
        opened.set()
    finally:
        release.set()
        holder.join(timeout=10)
    assert opened.is_set()
    store.close()


def test_test_only_configuration_is_isolated_from_the_shipped_package(
    tmp_path, monkeypatch
) -> None:
    """S4-9: test-only persistence needs an allow-listed caller and a test ledger."""

    store = stage4_store(tmp_path, monkeypatch)
    SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    # The allow-list is frozen and contains no shipped module.
    assert isinstance(TEST_AUTHORIZATION_MODULES, frozenset)
    assert not any(name.startswith("aether.") for name in TEST_AUTHORIZATION_MODULES)
    assert is_permitted_test_authorizer("tests.stage4_support") is True
    assert is_permitted_test_authorizer("aether.core.grants.issuance") is False
    # An unlisted module cannot obtain a test permit or a test-scoped ledger.
    with pytest.raises(UnauthorizedTestPersistence):
        exec(  # deliberate unlisted-caller probe
            "from aether.core.grants.authorization import authorize_test_persistence\n"
            "authorize_test_persistence(scope_digest='a' * 64, issued_by='test.attestation',"
            " task_id=None, plan_revision=1, plan_hash='a' * 64)",
            {"__name__": "unlisted_probe"},
        )
    assert not hasattr(GrantLedger, "issue")
    store.close()


def test_central_decision_is_the_only_source_of_a_trusted_permit(tmp_path, monkeypatch) -> None:
    """S4-9: a valid attestation alone yields no permit; the verifier decides."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    previews = _previews(world)
    grant = ExactApprovalGrant(
        approval_id=world.approval_id,
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation,),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        approval_origin="trusted-electron",
    )
    digest = exact_approval_scope_digest(grant)
    attestation = _attestation(world, previews=previews, scope_digest=digest)

    class Rejecting:
        authority_id = "test.attestation"

        def verify(self, attestation, *, binding):  # type: ignore[no-untyped-def]
            del attestation, binding
            raise AttestationRejected("AUTHORIZATION_SOURCE_NOT_TRUSTED", "no")

    with pytest.raises(GrantIssuanceDenied) as denied:
        authorize_issuance(
            attestation,
            grant=grant,
            scope_digest=digest,
            attestations=Rejecting(),
            previews=previews,
        )
    assert denied.value.reason_code == "AUTHORIZATION_SOURCE_NOT_TRUSTED"
    # A mismatched preview identity is refused by the same single decision.
    forged = _attestation(world, previews=previews, scope_digest=digest, preview_digest="b" * 64)
    with pytest.raises(GrantIssuanceDenied) as preview_denied:
        authorize_issuance(
            forged,
            grant=grant,
            scope_digest=digest,
            attestations=SimulatedAttestationVerifier(),
            previews=previews,
        )
    assert preview_denied.value.reason_code == "PREVIEW_IDENTITY_MISMATCH"
    # And an attestation-free call is refused before any verifier runs.
    with pytest.raises(GrantIssuanceDenied) as missing:
        authorize_issuance(
            None,
            grant=grant,
            scope_digest=digest,
            attestations=SimulatedAttestationVerifier(),
            previews=previews,
        )
    assert missing.value.reason_code == "AUTHORIZATION_EVIDENCE_REQUIRED"
    store.close()


def test_production_package_exports_no_test_only_authorization_surface() -> None:
    """S4-9: test-only factories are not reachable from the package surface."""

    import aether.core.grants as grants_package

    assert "authorize_test_persistence" not in grants_package.__all__
    assert not hasattr(grants_package, "authorize_test_persistence")
    # The trusted gate and the permit type are exported; the test seam is not.
    assert "IssuancePermit" in grants_package.__all__
    # No exported name is a test seam (substring match on "test" would also
    # catch ``Attestation…``, so match the seam vocabulary instead).
    test_only = {
        name
        for name in grants_package.__all__
        if name.lower() in {"authorize_test_persistence", "open_tests_scoped"}
    }
    assert test_only == set(), test_only
