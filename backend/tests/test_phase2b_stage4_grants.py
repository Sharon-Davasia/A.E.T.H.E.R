"""Stage 4 — trusted exact approval-grant foundation (adversarial suite).

Every test is synthetic and offline. No test issues real user authorization,
exposes an IPC/HTTP grant surface, or executes a capability. Production
issuance is disabled; ``TestOnlyAuthorizingProof`` simulates the *future*
trusted interaction and is never treated as real user authorization.

Schema note: the Stage 4 migration is proposed, not approved. Tests register
it in a test-only schema registry (``stage4_store``) whose bytes and
fingerprints must match the proposed file exactly — the same change the
separately approved production migration must make.
"""

from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from aether.core.contracts.approval import ExactApprovalGrant, exact_approval_scope_digest
from aether.core.contracts.policy import RiskTier
from aether.core.contracts.tool import ToolRequest
from aether.core.grants.authority import GrantAuthority, GrantRequest
from aether.core.grants.errors import (
    GrantConflictError,
    GrantDeniedError,
    GrantIntegrityError,
    GrantIssuanceDenied,
    GrantNotFoundError,
    GrantUnavailableError,
)
from aether.core.grants.issuance import (
    AuthorizingProof,
    GrantIssuer,
)
from aether.core.grants.issuance import (
    TestOnlyAuthorizingProof as _TestOnlyAuthorizingProof,
)
from aether.core.grants.ledger import GrantLedger
from aether.core.grants.models import GrantStatus
from aether.core.persistence import SQLiteTaskStore
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.resources.path_safety import VolumeInfo, VolumeKind
from aether.core.resources.registry import ResourceRegistry
from tests.stage4_support import (
    LATER,
    NOW,
    T2_CAPABILITY,
    SyntheticT2Plan,
    apply_proposed_migration_raw,
    sha256_json,
    stage4_store,
)


class FixedVolume:
    def inspect(self, path: Path) -> VolumeInfo:
        del path
        return VolumeInfo("test-volume", VolumeKind.FIXED)


@pytest.fixture()
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SQLiteTaskStore:
    opened = stage4_store(tmp_path, monkeypatch)
    yield opened
    opened.close()


def _proof(**overrides: object) -> _TestOnlyAuthorizingProof:
    fields: dict[str, object] = {
        "authorizing_action_id": uuid4(),
        "issued_by": "test-only-simulation",
    }
    fields.update(overrides)
    return _TestOnlyAuthorizingProof(**fields)  # type: ignore[arg-type]


def _issuer(store: SQLiteTaskStore, ledger: GrantLedger) -> GrantIssuer:
    return GrantIssuer(store=store, ledger=ledger)


_NO_PROOF = object()


def _issue(
    store: SQLiteTaskStore,
    ledger: GrantLedger,
    world: SyntheticT2Plan,
    *,
    uses: int = 1,
    lifetime: timedelta | None = None,
    proof: object = _NO_PROOF,
    **overrides: object,
):
    kwargs = world.issue_kwargs()
    kwargs["uses_remaining"] = uses
    if lifetime is not None:
        kwargs["issued_at"] = NOW
        kwargs["expires_at"] = NOW + lifetime
    kwargs.update(overrides)
    issuer = _issuer(store, ledger)
    presented = _proof() if proof is _NO_PROOF else proof
    return issuer.issue(proof=presented, **kwargs)  # type: ignore[arg-type]


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


def _broker(tmp_path: Path) -> PolicyBroker:
    root_path = tmp_path / "workspace"
    root_path.mkdir(exist_ok=True)
    (root_path / "sample.txt").write_text("synthetic", encoding="utf-8")
    resources = ResourceRegistry(volume_inspector=FixedVolume())
    root = resources.register_root(
        "fixture", root_path, allowed_capabilities=frozenset({T2_CAPABILITY})
    )
    del root
    return PolicyBroker(capabilities=CapabilityRegistry.phase2_filesystem(), resources=resources)


# ---------------------------------------------------------------------------
# A. Authoritative grant model and validation
# ---------------------------------------------------------------------------


def test_grant_binds_exact_scope_and_digest_is_stable(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
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
    from aether.core.contracts.receipt import RecoveryClass

    reversible = ExactApprovalGrant(
        approval_id=uuid4(),
        task_id=world.task_id,
        plan_revision=world.revision,
        plan_hash=world.plan_hash,
        operations=(world.operation_with(recovery_class=RecoveryClass.REVERSIBLE),),
        max_tier=RiskTier.MODIFY,
        issued_at=NOW,
        expires_at=LATER,
        approval_origin="trusted-electron",
    )
    irreversible = reversible.model_copy(
        update={"operations": (world.operation_with(recovery_class=RecoveryClass.IRREVERSIBLE),)}
    )
    assert exact_approval_scope_digest(reversible) != exact_approval_scope_digest(irreversible)
    store.close()


def test_no_wildcard_or_blanket_tier_grant_can_be_built(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with pytest.raises(ValidationError):
        # A grant ceiling above MODIFY is T3 — never issuable.
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
        # Zero operations is not a wildcard grant; it is rejected outright.
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
# B. Trustworthy issuance prerequisites
# ---------------------------------------------------------------------------


def test_issuance_requires_authorizing_proof_never_review_evidence(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        # A Stage 3 non-authorizing audit APPROVE record exists.
        store.record_approval_decision(world.decision(value="APPROVE"))

        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(store, ledger, world, proof=None)
        assert denied.value.reason_code == "AUTHORIZATION_EVIDENCE_REQUIRED"

        # An audit record alone therefore persisted no grant.
        with pytest.raises(GrantNotFoundError):
            ledger.load(world.approval_id)
    store.close()


def test_authorizing_proof_cannot_be_constructed_by_production_code() -> None:
    with pytest.raises(TypeError):
        AuthorizingProof(authorizing_action_id=uuid4(), issued_by="trusted-electron")
    with pytest.raises(TypeError):
        AuthorizingProof(authorizing_action_id=uuid4(), issued_by="test")  # type: ignore[call-arg]

    # Nothing but typed evidence may be used, e.g. a duck-typed forgery.
    class Forged:
        authorizing_action_id = uuid4()
        issued_by = "trusted-electron"

    assert not isinstance(Forged(), AuthorizingProof)


def test_only_test_simulation_subclass_ships() -> None:
    import aether.core.grants.issuance as issuance

    subclasses = {
        name
        for name, value in vars(issuance).items()
        if isinstance(value, type)
        and issubclass(value, AuthorizingProof)
        and value is not AuthorizingProof
    }
    assert subclasses == {"TestOnlyAuthorizingProof"}
    assert issuance.__all__[0] == "AuthorizingProof"


def test_issuance_requires_current_persisted_plan(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        with pytest.raises(GrantIssuanceDenied) as stale:
            _issue(store, ledger, world, plan_hash="b" * 64)
        assert stale.value.reason_code == "PLAN_HASH_MISMATCH"
        with pytest.raises(GrantIssuanceDenied) as wrong_task:
            _issue(store, ledger, world, task_id=uuid4())
        assert wrong_task.value.reason_code == "PLAN_NOT_FOUND"
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
        ({"recovery_class": "IRREVERSIBLE"}, "RECOVERY_CLASS_MISMATCH"),
        (
            {
                "resources": (
                    {
                        "resource_id": "file:00000000-0000-0000-0000-000000000000",
                        "expected_version": "v1:9999",
                    },
                )
            },
            "RESOURCE_MISMATCH",
        ),
    ],
)
def test_issuance_rejects_any_operation_wider_or_different_than_the_plan(
    tmp_path, monkeypatch, overrides, reason
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    operation_overrides = dict(overrides)
    if "resources" in operation_overrides:
        from aether.core.contracts.approval import ApprovedResourceVersion

        operation_overrides["resources"] = tuple(
            ApprovedResourceVersion(**item) for item in operation_overrides["resources"]
        )
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        with pytest.raises(GrantIssuanceDenied) as denied:
            _issue(store, ledger, world, operations=(world.operation_with(**operation_overrides),))
        assert denied.value.reason_code == reason
    store.close()


def test_issuance_bounds_lifetime_uses_and_tier(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
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


def test_duplicate_issuance_is_idempotent_and_conflicts_on_scope_change(
    tmp_path, monkeypatch
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    proof = _proof()
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        first = _issue(store, ledger, world, proof=proof)
        second = _issue(store, ledger, world, proof=proof)
        assert first.replayed is False
        assert second.replayed is True
        assert second.approval_id == first.approval_id
        # Replaying the same authorizing action with a different approved
        # scope is a conflict, never a second or widened grant.
        original = ledger.load(world.approval_id)
        widened = original.model_copy(
            update={
                "approval_id": uuid4(),
                "operations": (world.operation_with(arguments_sha256="c" * 64),),
            }
        )
        with pytest.raises(GrantConflictError):
            ledger.issue(
                widened,
                scope_digest=exact_approval_scope_digest(widened),
                issuance_key=proof.authorizing_action_id,
                issued_by="test-only-simulation",
            )
        # Exactly one grant exists and it is still the original scope.
        assert ledger.load(world.approval_id).operations == original.operations
    store.close()


# ---------------------------------------------------------------------------
# C. Durable persistence, revocation, replay, crash/restart
# ---------------------------------------------------------------------------


def test_ledger_refuses_v1_database_without_the_approved_migration(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    store = SQLiteTaskStore(database)  # ships version 1 only
    store.create_task("synthetic", task_id=uuid4(), now=NOW)
    store.close()
    with pytest.raises(GrantUnavailableError):
        GrantLedger(database)


def test_ledger_rejects_tampered_migration_ledger_and_schema(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    store.close()
    database = tmp_path / "store.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE schema_migrations SET sha256 = ? WHERE version = 2", ("e" * 64,))
    with pytest.raises(GrantIntegrityError):
        GrantLedger(database)

    database2 = tmp_path / "other.sqlite3"
    database2.write_bytes(database.read_bytes())
    with sqlite3.connect(database2) as connection:
        connection.execute("DROP TRIGGER exact_approval_grant_state_guarded_update")
    with pytest.raises(GrantIntegrityError):
        GrantLedger(database2)


def test_raw_applied_migration_without_ledger_row_is_untrusted(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    SQLiteTaskStore(database).close()
    apply_proposed_migration_raw(database)
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 2")
    with pytest.raises(GrantIntegrityError):
        GrantLedger(database)


def test_scope_row_and_ledgers_are_immutable(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        _issue(store, ledger, world)
        ledger.consume(**_consume_kwargs(world))
        ledger.revoke(world.approval_id, reason="superseded", now=NOW)
        database = tmp_path / "store.sqlite3"
        with sqlite3.connect(database) as connection:
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE exact_approval_grants SET scope_json = '{}' WHERE approval_id = ?",
                    (str(world.approval_id),),
                )
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "DELETE FROM exact_approval_grant_events WHERE approval_id = ?",
                    (str(world.approval_id),),
                )
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE exact_approval_grant_consumptions SET capability_id = 'fs.read_file'"
                )
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE exact_approval_grant_state SET uses_remaining = 5 "
                    "WHERE approval_id = ?",
                    (str(world.approval_id),),
                )
    store.close()


def test_expiry_denies_consume_and_reports_state(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        _issue(store, ledger, world)
        assert ledger.status(world.approval_id, now=NOW).state == "ACTIVE"
        expired_at = LATER + timedelta(seconds=1)
        assert ledger.status(world.approval_id, now=expired_at).state == "EXPIRED"
        with pytest.raises(GrantDeniedError) as denied:
            ledger.consume(**_consume_kwargs(world, now=expired_at))
        assert denied.value.reason_code == "GRANT_EXPIRED"
        not_yet = NOW - timedelta(seconds=1)
        with pytest.raises(GrantDeniedError) as early:
            ledger.consume(**_consume_kwargs(world, now=not_yet))
        assert early.value.reason_code == "GRANT_NOT_YET_VALID"
    store.close()


def test_exhaustion_replay_and_duplicate_consumption(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        _issue(store, ledger, world, uses=2)
        first = _consume_kwargs(world)
        consumed = ledger.consume(**first)
        assert consumed.uses_remaining_after == 1
        # Replay of the same idempotency identity does not double-spend.
        replay = ledger.consume(**first)
        assert replay.replayed is True
        assert replay.uses_remaining_after == 1
        # A different identity spends the second use…
        ledger.consume(**_consume_kwargs(world))
        assert ledger.status(world.approval_id, now=NOW).state == "EXHAUSTED"
        # …and a third attempt is denied.
        with pytest.raises(GrantDeniedError) as exhausted:
            ledger.consume(**_consume_kwargs(world))
        assert exhausted.value.reason_code == "GRANT_EXHAUSTED"
        # Replaying a consumption identity with different action data conflicts.
        with pytest.raises(GrantConflictError):
            ledger.consume(**{**first, "step_id": uuid4()})
        assert len(ledger.list_consumptions(world.approval_id)) == 2
    store.close()


def test_revocation_blocks_use_and_is_idempotent(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        _issue(store, ledger, world, uses=2)
        status = ledger.revoke(world.approval_id, reason="plan superseded", now=NOW)
        assert status.state == "REVOKED"
        assert status.revocation_reason == "plan superseded"
        again = ledger.revoke(world.approval_id, reason="different reason", now=NOW)
        assert again.state == "REVOKED"
        assert again.revocation_reason == "plan superseded"
        with pytest.raises(GrantDeniedError) as denied:
            ledger.consume(**_consume_kwargs(world))
        assert denied.value.reason_code == "GRANT_REVOKED"
        assert [event for _, event, _ in ledger.events(world.approval_id)] == [
            "ISSUED",
            "REVOKED",
        ]
        with pytest.raises(GrantNotFoundError):
            ledger.revoke(uuid4(), reason="unknown")
    store.close()


def test_crash_restart_preserves_committed_state(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    database = tmp_path / "store.sqlite3"
    ledger = GrantLedger(database)
    _issue(store, ledger, world, uses=3)
    ledger.consume(**_consume_kwargs(world))
    ledger.close()  # simulated abrupt end of the process
    del ledger

    reopened = GrantLedger(database)
    try:
        status: GrantStatus = reopened.status(world.approval_id, now=NOW)
        assert status.uses_remaining == 2
        assert status.consumed_count == 1
        assert status.state == "ACTIVE"
        assert len(reopened.list_consumptions(world.approval_id)) == 1
        # The store and the ledger can both reopen the same database.
        reopened.close()
        store.close()
        store2 = SQLiteTaskStore(database, migrations_dir=tmp_path / "migrations")
        assert store2.get_plan(world.task_id).plan_hash == world.plan_hash
        store2.close()
    finally:
        if not reopened._closed:
            reopened.close()
    store = SQLiteTaskStore(database, migrations_dir=tmp_path / "migrations")


def test_transactional_failure_leaves_no_partial_consumption(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        _issue(store, ledger, world, uses=2)

        def fail_after_decrement(approval_id: str, event: str, detail: dict) -> None:
            # The decrement and consumption row are already written; this
            # schema-violating audit write aborts the whole transaction.
            ledger._connection.execute(
                "INSERT INTO exact_approval_grant_events "
                "(id, approval_id, grant_seq, event, detail_json, created_at) "
                "VALUES (?, ?, 99, 'BOGUS', '{}', ?)",
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
    database = tmp_path / "store.sqlite3"
    with GrantLedger(database) as ledger:
        _issue(store, ledger, world, uses=2)

    def attempt(_: int) -> str:
        with GrantLedger(database) as ledger:
            try:
                ledger.consume(**_consume_kwargs(world))
                return "consumed"
            except GrantDeniedError as exc:
                return exc.reason_code

    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(attempt, range(6)))
    assert outcomes.count("consumed") == 2
    assert set(outcomes) - {"consumed"} == {"GRANT_EXHAUSTED"}
    with GrantLedger(database) as ledger:
        status = ledger.status(world.approval_id, now=NOW)
        assert status.uses_remaining == 0
        assert status.consumed_count == 2
        assert len(ledger.list_consumptions(world.approval_id)) == 2
    store.close()


def test_grant_file_permissions_are_private(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
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


# ---------------------------------------------------------------------------
# D. Fail-closed policy integration (no execution)
# ---------------------------------------------------------------------------


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


def _resolved_ref(broker: PolicyBroker, world: SyntheticT2Plan):
    root_id = broker._resources._roots[next(iter(broker._resources._roots))].root_id  # type: ignore[attr-defined]
    return broker._resources.resolve(root_id, "sample.txt").ref  # type: ignore[attr-defined]


def test_broker_without_grant_still_denies_t2(tmp_path) -> None:
    """A canonical, registry-issued resource with no grant stays denied."""

    broker, world, ref = _canonical_world(tmp_path)
    decision = broker.evaluate(
        ToolRequest(
            request_id="r",
            task_id=str(world.task_id),
            capability_id=T2_CAPABILITY,
            arguments={**world.arguments, "resource_id": ref.resource_id},
            resources=[ref],
        )
    )
    assert decision.allowed is False
    assert decision.reason_code == "TRUSTED_APPROVAL_NOT_AVAILABLE"
    assert decision.requires_approval is True


def test_validated_exact_grant_verifies_scope_but_still_enables_no_executor(
    tmp_path, monkeypatch
) -> None:
    """The strongest possible grant outcome is still ``allowed=False``.

    A grant whose canonical resource id and observed version come from the
    ResourceRegistry satisfies every check; the broker reports
    ``GRANT_VALIDATED_EXECUTOR_NOT_ENABLED`` — scope verified, nothing
    authorized, nothing executed.
    """

    store = stage4_store(tmp_path, monkeypatch)
    root_path = tmp_path / "workspace"
    root_path.mkdir(exist_ok=True)
    (root_path / "sample.txt").write_text("synthetic original", encoding="utf-8")
    resources = ResourceRegistry(volume_inspector=FixedVolume())
    root = resources.register_root(
        "fixture", root_path, allowed_capabilities=frozenset({T2_CAPABILITY})
    )
    resolved = resources.resolve(root.root_id, "sample.txt").ref
    assert resolved.observed_version
    world = SyntheticT2Plan(
        tmp_path / "store.sqlite3",
        store,
        resource_id=resolved.resource_id,
        resource_version=resolved.observed_version,
    )
    database = tmp_path / "store.sqlite3"
    with GrantLedger(database) as ledger:
        _issue(store, ledger, world)
        broker = PolicyBroker(
            capabilities=CapabilityRegistry.phase2_filesystem(),
            resources=resources,
            grant_authority=GrantAuthority(ledger),
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
        assert decision.risk_tier == RiskTier.MODIFY
        assert decision.reason_code == "GRANT_VALIDATED_EXECUTOR_NOT_ENABLED"
        assert decision.approval_id == str(world.approval_id)
        # Validation is read-only: the grant's use was not spent.
        assert ledger.status(world.approval_id, now=NOW).uses_remaining == 1
        assert ledger.list_consumptions(world.approval_id) == ()

        # A request whose plan/step binding differs is denied before that step.
        mismatched = _grant_request(world, step_id=uuid4())
        denied = broker.evaluate(request, grant=mismatched, now=NOW)
        assert denied.allowed is False
        assert denied.reason_code == "GRANT_STEP_MISMATCH"
    store.close()


@pytest.mark.parametrize("reason", ["expired", "revoked", "exhausted", "missing"])
def test_expired_revoked_exhausted_or_absent_grants_deny(tmp_path, monkeypatch, reason) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    database = tmp_path / "store.sqlite3"
    ledger = GrantLedger(database)
    _issue(store, ledger, world)
    request = _tool_request(world, _dummy_ref(world))
    now = NOW
    if reason == "expired":
        now = LATER + timedelta(seconds=1)
        authority: GrantAuthority = GrantAuthority(ledger)
    elif reason == "revoked":
        ledger.revoke(world.approval_id, reason="superseded", now=NOW)
        authority = GrantAuthority(ledger)
    elif reason == "exhausted":
        ledger.consume(**_consume_kwargs(world))
        authority = GrantAuthority(ledger)
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
    ledger.close() if not ledger._closed else None
    store.close()


def _dummy_ref(world: SyntheticT2Plan):
    from aether.core.contracts.resource import ResourceRef

    return ResourceRef(
        kind="file",
        resource_id=world.resource_id,
        observed_version=world.resource_version,
    )


def _canonical_world(tmp_path: Path):
    """A plan + registry whose canonical resource id is the issued one."""

    root_path = tmp_path / "workspace"
    root_path.mkdir(exist_ok=True)
    (root_path / "sample.txt").write_text("synthetic", encoding="utf-8")
    resources = ResourceRegistry(volume_inspector=FixedVolume())
    root = resources.register_root(
        "fixture", root_path, allowed_capabilities=frozenset({T2_CAPABILITY})
    )
    ref = resources.resolve(root.root_id, "sample.txt").ref
    broker = PolicyBroker(capabilities=CapabilityRegistry.phase2_filesystem(), resources=resources)
    return broker, _FakeWorld(ref), ref


class _FakeWorld:
    """Minimal stand-in: the broker must deny before reading any grant."""

    task_id = UUID("00000000-0000-0000-0000-000000000001")

    def __init__(self, ref) -> None:  # type: ignore[no-untyped-def]
        self.arguments: dict[str, object] = {
            "resource_id": ref.resource_id,
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": "a" * 64,
        }


def test_grant_authority_fails_closed_without_a_ledger(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    authority = GrantAuthority(None)
    check = authority.check_action(
        _tool_request(world, _dummy_ref(world)),
        _grant_request(world),
        risk_tier=RiskTier.MODIFY,
        now=NOW,
    )
    assert check.ok is False
    assert check.reason_code == "GRANT_AUTHORITY_UNAVAILABLE"
    store.close()


def test_grant_authority_rejects_unknown_and_forged_grant_ids(tmp_path, monkeypatch) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        authority = GrantAuthority(ledger)
        check = authority.check_action(
            _tool_request(world, _dummy_ref(world)),
            _grant_request(world, approval_id=uuid4()),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert check.ok is False
        assert check.reason_code == "GRANT_NOT_FOUND"
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
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        _issue(store, ledger, world)
        authority = GrantAuthority(ledger)
        overrides: dict[str, object] = {}
        request_overrides: dict[str, object] = {}
        if value == "task":
            # The task id is taken from the request, never from the caller's
            # grant claim: substituting it must deny against the grant's task.
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
        assert check.ok is False
        assert check.reason_code == reason
    store.close()


def test_resource_substitution_scope_widening_and_stale_versions_deny(
    tmp_path, monkeypatch
) -> None:
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        _issue(store, ledger, world)
        authority = GrantAuthority(ledger)
        ref = _dummy_ref(world)

        # Stale observed version.
        stale = ref.model_copy(update={"observed_version": "v1:deadbeef"})
        check = authority.check_action(
            _tool_request(world, stale),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, "GRANT_RESOURCE_MISMATCH")

        # Scope widening: an extra resource outside the approved set.
        extra = ref.model_copy(update={"resource_id": f"file:{uuid4()}"})
        check = authority.check_action(
            _tool_request(world, ref, resources=[ref, extra]),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, "GRANT_RESOURCE_MISMATCH")

        # A resource with no observed version can never match a grant.
        unversioned = ref.model_copy(update={"observed_version": None})
        check = authority.check_action(
            _tool_request(world, unversioned),
            _grant_request(world),
            risk_tier=RiskTier.MODIFY,
            now=NOW,
        )
        assert (check.ok, check.reason_code) == (False, "GRANT_RESOURCE_MISMATCH")

        # Capability substitution and T3 escalation attempts.
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
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        _issue(store, ledger, world)
        authority = GrantAuthority(ledger)
        widened = {**world.arguments, "expected_sha256": "b" * 64}
        check = authority.check_action(
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
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        _issue(store, ledger, world, max_tier=RiskTier.MODIFY)
        broker = _broker(tmp_path)
        critical_broker = PolicyBroker(
            capabilities=broker._capabilities,
            resources=broker._resources,
            grant_authority=GrantAuthority(ledger),
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
        assert decision.reason_code == "CAPABILITY_NOT_REGISTERED"
        with pytest.raises(GrantIssuanceDenied):
            _issue(store, ledger, world, max_tier=RiskTier.CRITICAL)
    store.close()


# ---------------------------------------------------------------------------
# Synthetic development-source isolation
# ---------------------------------------------------------------------------


def test_synthetic_preview_review_cannot_produce_a_grant(tmp_path, monkeypatch) -> None:
    """Stage 3 dev seams stay development-only evidence, never authority."""

    monkeypatch.setenv("AETHER_REVIEW_DEV_SEED", "synthetic-review")
    monkeypatch.setenv("AETHER_REVIEW_TASK_ID", str(uuid4()))
    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    with GrantLedger(tmp_path / "store.sqlite3") as ledger:
        store.record_approval_decision(world.decision(value="APPROVE"))
        with pytest.raises(GrantIssuanceDenied):
            _issue(store, ledger, world, proof=None)
        # Only an explicit authorizing artifact can issue, and it is test-only.
        assert isinstance(_proof(), _TestOnlyAuthorizingProof)
    store.close()


def test_no_production_module_issues_grants_or_exposes_ipc() -> None:
    """Stage 4 ships no grant route: nothing outside grants/tests references it."""

    backend = Path(__file__).parents[1]
    offenders: list[str] = []
    for path in (backend / "aether").rglob("*.py"):
        if "core/grants" in path.as_posix():
            continue
        text = path.read_text(encoding="utf-8")
        if "AuthorizingProof(" in text or "GrantIssuer(" in text:
            offenders.append(path.relative_to(backend).as_posix())
    assert offenders == []


def test_grant_ledger_never_applies_migrations(tmp_path) -> None:
    database = tmp_path / "store.sqlite3"
    SQLiteTaskStore(database).close()
    before = database.read_bytes()
    with pytest.raises(GrantUnavailableError):
        GrantLedger(database)
    assert database.read_bytes() == before
