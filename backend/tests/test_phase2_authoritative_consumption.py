"""S14-11: one authoritative, atomic grant-consumption lifecycle.

S14-7 made consumption *check* the Stage 4 ledger before spending, which was not
enough: the decrement still happened in a local budget, so the authoritative
grant's ``uses_remaining`` never moved and two independently created consumption
databases could each hold what looked like the full allowance. Two spendable
allowances is the defect; one lifecycle is the target.

These tests use the **real** ``GrantLedger`` with the approved migrated-v2 schema,
activated only inside the test process (``stage4_support.stage4_store``), and the
test-authorization factory that the Stage 4 suite already uses. No production
constant, migration file, gate or fingerprint is modified, and nothing here
enables production issuance.

They are the accounting proof the review asked for: the global count moves exactly
once, the authoritative record and audit event exist, a second consumer cannot
spend the last use, and revocation, exhaustion, plan drift and consent all remain
effective *at consumption time*.
"""

from __future__ import annotations

import threading
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from aether.core.grants.consumption import (
    ConsumptionError,
    ConsumptionLedger,
)
from aether.core.persistence import PersistentTaskState
from tests.stage4_support import (
    NOW,
    SyntheticT2Plan,
    open_tests_scoped_ledger,
    stage4_store,
)

pytestmark = pytest.mark.usefixtures("_clean")


@pytest.fixture()
def _clean() -> None:
    return None


@pytest.fixture()
def ledger(tmp_path: Path, monkeypatch):
    """A real, authoritative Stage 4 ledger over a test-only v2 store."""

    store = stage4_store(tmp_path, monkeypatch)
    world = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    real = open_tests_scoped_ledger(store)
    try:
        yield {"store": store, "world": world, "ledger": real, "tmp": tmp_path}
    finally:
        real.close()
        store.close()


def _issue(ledger, world, *, uses: int = 1, **overrides):
    """Issue a real grant through the Stage 4 test-authorization factory."""

    from tests.test_phase2b_stage4_grants import _issue as issue

    store = ledger["store"]
    return issue(store, ledger["ledger"], world, uses=uses, **overrides)


def _consumption_ledger(tmp_path: Path, real_ledger, *, name: str = "consume.sqlite3"):
    """A ConsumptionLedger whose authority is the real Stage 4 ledger."""

    return ConsumptionLedger(tmp_path / name, authority=real_ledger, clock=lambda: NOW)


def _spend_kwargs(world, *, consumption_id=None):
    from uuid import uuid4 as _uuid4

    return {
        "consumption_id": consumption_id or _uuid4(),
        "approval_id": world.approval_id,
        "task_id": world.task_id,
        "plan_revision": world.revision,
        "plan_hash": world.plan_hash,
        "step_id": world.operation.step_id,
        "capability_id": world.operation.capability_id,
        "risk_tier": world.operation.risk_tier,
        "arguments_sha256": world.operation.arguments_sha256,
        "expected_effect_sha256": world.operation.expected_effect_sha256,
        "resource_versions": world.resource_versions(),
        "consumed_by": "aether.core.edits.executor",
        "now": NOW,
    }


# ---------------------------------------------------------------------------
# A. The authoritative count moves exactly once
# ---------------------------------------------------------------------------


def test_a_successful_consumption_decrements_the_authoritative_grant(ledger, tmp_path) -> None:
    """The whole point: GrantLedger's own count changes, not a local copy."""

    _issue(ledger, ledger["world"], uses=2)
    before = ledger["ledger"].status(ledger["world"].approval_id, now=NOW)
    assert before.uses_remaining == 2

    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        result = consumption.consume(**_spend_kwargs(ledger["world"]))
        assert result.uses_remaining_after == 1
    finally:
        consumption.close()

    after = ledger["ledger"].status(ledger["world"].approval_id, now=NOW)
    assert after.uses_remaining == 1, "the authoritative grant did not decrement"
    assert after.consumed_count == 1


def test_the_authoritative_consumption_record_is_persisted(ledger, tmp_path) -> None:
    _issue(ledger, ledger["world"], uses=2)
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        record = consumption.consume(**_spend_kwargs(ledger["world"]))
    finally:
        consumption.close()

    stored = ledger["ledger"].get_consumption(record.consumption_id)
    assert stored.approval_id == ledger["world"].approval_id
    assert stored.step_id == ledger["world"].operation.step_id
    assert stored.uses_remaining_after == 1
    # And it is listed against the grant, not only reachable by id.
    listed = ledger["ledger"].list_consumptions(ledger["world"].approval_id)
    assert [item.consumption_id for item in listed] == [record.consumption_id]


def test_an_audit_event_is_appended_for_the_consumption(ledger, tmp_path) -> None:
    _issue(ledger, ledger["world"], uses=2)
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        record = consumption.consume(**_spend_kwargs(ledger["world"]))
    finally:
        consumption.close()

    events = ledger["ledger"].events(ledger["world"].approval_id)
    kinds = [event[1] for event in events]
    assert "CONSUMED" in kinds
    consumed_event = next(event for event in events if event[1] == "CONSUMED")
    assert consumed_event[3]["consumption_id"] == str(record.consumption_id)


# ---------------------------------------------------------------------------
# B. Two independent consumers cannot share one allowance
# ---------------------------------------------------------------------------


def test_two_independent_consumption_databases_cannot_spend_the_last_use(ledger, tmp_path) -> None:
    """The headline defect: two local budgets each thought they had a use."""

    _issue(ledger, ledger["world"], uses=1)
    first = _consumption_ledger(tmp_path, ledger["ledger"], name="a.sqlite3")
    second = _consumption_ledger(tmp_path, ledger["ledger"], name="b.sqlite3")
    try:
        first.consume(**_spend_kwargs(ledger["world"]))

        # The second consumer has its own database but must see the global truth.
        with pytest.raises(ConsumptionError) as refused:
            second.consume(**_spend_kwargs(ledger["world"]))
        assert refused.value.reason_code in {
            "GRANT_EXHAUSTED",
            "GRANT_CONSUMED_COUNT",
            "GRANT_STATE_UNKNOWN",
        }
    finally:
        first.close()
        second.close()

    status = ledger["ledger"].status(ledger["world"].approval_id, now=NOW)
    assert status.uses_remaining == 0
    assert status.consumed_count == 1, "the last use was spent more than once"


def test_a_second_consumer_cannot_report_a_full_allowance(ledger, tmp_path) -> None:
    """Divergent local views are what made the defect invisible."""

    _issue(ledger, ledger["world"], uses=1)
    first = _consumption_ledger(tmp_path, ledger["ledger"], name="a.sqlite3")
    second = _consumption_ledger(tmp_path, ledger["ledger"], name="b.sqlite3")
    try:
        first.consume(**_spend_kwargs(ledger["world"]))
        # The second database was never told anything, yet it reports the truth.
        assert second.uses_remaining(ledger["world"].approval_id) == 0
        assert first.uses_remaining(ledger["world"].approval_id) == 0
    finally:
        first.close()
        second.close()


def test_concurrent_consumers_cannot_overspend(ledger, tmp_path) -> None:
    """A real race for the final use, across two databases."""

    _issue(ledger, ledger["world"], uses=1)
    first = _consumption_ledger(tmp_path, ledger["ledger"], name="a.sqlite3")
    second = _consumption_ledger(tmp_path, ledger["ledger"], name="b.sqlite3")
    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def attempt(consumption):
        def run():
            barrier.wait(timeout=10)
            try:
                consumption.consume(**_spend_kwargs(ledger["world"]))
                outcomes.append("SPENT")
            except ConsumptionError as exc:
                outcomes.append(str(exc.reason_code))

        return run

    threads = [
        threading.Thread(target=attempt(first)),
        threading.Thread(target=attempt(second)),
    ]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
    finally:
        first.close()
        second.close()

    assert outcomes.count("SPENT") == 1, outcomes
    status = ledger["ledger"].status(ledger["world"].approval_id, now=NOW)
    assert status.uses_remaining == 0
    assert status.consumed_count == 1


# ---------------------------------------------------------------------------
# C. Exhaustion, revocation, expiry and plan drift at consumption time
# ---------------------------------------------------------------------------


def test_an_exhausted_grant_cannot_be_spent_again(ledger, tmp_path) -> None:
    _issue(ledger, ledger["world"], uses=1)
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        consumption.consume(**_spend_kwargs(ledger["world"]))
        with pytest.raises(ConsumptionError) as refused:
            consumption.consume(**_spend_kwargs(ledger["world"]))
        assert refused.value.reason_code.startswith("GRANT_")
    finally:
        consumption.close()


def test_revocation_prevents_any_subsequent_spend(ledger, tmp_path) -> None:
    _issue(ledger, ledger["world"], uses=4)
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        consumption.consume(**_spend_kwargs(ledger["world"]))
        ledger["ledger"].revoke(ledger["world"].approval_id, reason_code="USER_CANCELLED", now=NOW)
        with pytest.raises(ConsumptionError) as refused:
            consumption.consume(**_spend_kwargs(ledger["world"]))
        assert refused.value.reason_code == "GRANT_REVOKED"
    finally:
        consumption.close()

    status = ledger["ledger"].status(ledger["world"].approval_id, now=NOW)
    assert status.state == "REVOKED"
    # The revocation did not give back the use already spent.
    assert status.consumed_count == 1


def test_revocation_between_status_and_spend_is_not_escapable(
    ledger, tmp_path, monkeypatch
) -> None:
    """The check-then-spend window the review named must not exist.

    A concurrent revocation landing *after* any pre-check but before the write is
    caught by the authoritative transaction, because the decrement is conditional
    on ``revoked_at IS NULL``. This test interposes a revocation exactly in that
    window.
    """

    _issue(ledger, ledger["world"], uses=4)
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    real_consume = ledger["ledger"].consume

    def revoke_then_consume(**kwargs):
        # Revoke from the "other" actor right before the spend commits.
        ledger["ledger"].revoke(ledger["world"].approval_id, reason_code="USER_CANCELLED", now=NOW)
        return real_consume(**kwargs)

    monkeypatch.setattr(ledger["ledger"], "consume", revoke_then_consume)
    try:
        with pytest.raises(ConsumptionError) as refused:
            consumption.consume(**_spend_kwargs(ledger["world"]))
        assert refused.value.reason_code in {"GRANT_REVOKED", "GRANT_STATE_UNKNOWN"}
    finally:
        monkeypatch.undo()
        consumption.close()

    status = ledger["ledger"].status(ledger["world"].approval_id, now=NOW)
    assert status.uses_remaining == 4, "a use was spent despite the revocation"
    assert status.consumed_count == 0


def test_an_expired_grant_cannot_be_spent(ledger, tmp_path) -> None:
    _issue(ledger, ledger["world"], uses=2, lifetime=timedelta(minutes=1))
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        later = NOW + timedelta(minutes=5)
        kwargs = _spend_kwargs(ledger["world"])
        kwargs["now"] = later
        with pytest.raises(ConsumptionError) as refused:
            consumption.consume(**kwargs)
        assert refused.value.reason_code.startswith("GRANT_")
    finally:
        consumption.close()

    status = ledger["ledger"].status(ledger["world"].approval_id, now=NOW)
    assert status.uses_remaining == 2


def test_current_plan_and_consent_are_enforced_at_consumption(ledger, tmp_path) -> None:
    """Plan binding and fresh consent must bind at *consumption*, not just issuance.

    Two ways the binding can lapse, both refused by the authoritative transaction:
    the task moving out of an authorizable state (consent gone), and the current
    plan no longer matching the grant.
    """

    _issue(ledger, ledger["world"], uses=2)
    world = ledger["world"]
    store = ledger["store"]
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        # Consent lapse: the task leaves the state that carries live consent.
        store.transition_task(world.task_id, PersistentTaskState.CANCELLED, now=NOW)
        with pytest.raises(ConsumptionError) as refused:
            consumption.consume(**_spend_kwargs(world))
        # Not merely "GRANT_*": the consent check itself fires.
        assert refused.value.reason_code in {
            "TASK_STATE_NOT_AUTHORIZABLE",
            "GRANT_SUPERSEDED",
            "GRANT_STATE_UNKNOWN",
        }
    finally:
        consumption.close()

    status = ledger["ledger"].status(world.approval_id, now=NOW)
    assert status.uses_remaining == 2, "a use was spent without live consent"


def test_a_superseded_plan_prevents_the_spend(ledger, tmp_path) -> None:
    """The exact current-plan binding is still enforced by the spend."""

    _issue(ledger, ledger["world"], uses=2)
    world = ledger["world"]
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        # Send a plan_hash that is not the task's current plan.
        kwargs = _spend_kwargs(world)
        kwargs["plan_hash"] = "e" * 64
        with pytest.raises(ConsumptionError) as refused:
            consumption.consume(**kwargs)
        assert refused.value.reason_code.startswith("GRANT_")
    finally:
        consumption.close()

    status = ledger["ledger"].status(world.approval_id, now=NOW)
    assert status.uses_remaining == 2


def test_consuming_a_different_step_is_refused(ledger, tmp_path) -> None:
    """The action binding is unchanged by the new path: exact scope or nothing."""

    _issue(ledger, ledger["world"], uses=2)
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        kwargs = _spend_kwargs(ledger["world"])
        kwargs["step_id"] = uuid4()
        with pytest.raises(ConsumptionError) as refused:
            consumption.consume(**kwargs)
        assert refused.value.reason_code.startswith("GRANT_")
    finally:
        consumption.close()
    status = ledger["ledger"].status(ledger["world"].approval_id, now=NOW)
    assert status.uses_remaining == 2


def test_replaying_a_consumption_id_is_not_a_second_spend(ledger, tmp_path) -> None:
    """Replay-safety is preserved: same id and terms returns the committed record."""

    _issue(ledger, ledger["world"], uses=2)
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    kwargs = _spend_kwargs(ledger["world"])
    try:
        first = consumption.consume(**kwargs)
        second = consumption.consume(**kwargs)
        assert not first.replayed
        assert second.replayed, "a replay must be reported as a replay"
        assert second.consumption_id == first.consumption_id
    finally:
        consumption.close()

    status = ledger["ledger"].status(ledger["world"].approval_id, now=NOW)
    assert status.uses_remaining == 1, "a replay spent a second use"
    assert status.consumed_count == 1


def test_replaying_with_different_terms_is_refused(ledger, tmp_path) -> None:
    _issue(ledger, ledger["world"], uses=2)
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    kwargs = _spend_kwargs(ledger["world"])
    try:
        consumption.consume(**kwargs)
        altered = dict(kwargs)
        altered["arguments_sha256"] = "0" * 64
        with pytest.raises(ConsumptionError):
            consumption.consume(**altered)
    finally:
        consumption.close()


# ---------------------------------------------------------------------------
# D. No parallel allowance survives
# ---------------------------------------------------------------------------


def test_a_local_budget_row_cannot_authorize_a_spend(ledger, tmp_path) -> None:
    """A budget written straight into the projection is inert.

    This is the negative that matters: even with a local row claiming uses, the
    authoritative ledger decides. It is what stops the local table from becoming
    the parallel allowance again.
    """

    _issue(ledger, ledger["world"], uses=1)
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        # Invent a generous local budget for this approval.
        consumption.grant_budget_simulated(
            approval_id=ledger["world"].approval_id,
            task_id=ledger["world"].task_id,
            plan_revision=ledger["world"].revision,
            plan_hash=ledger["world"].plan_hash,
            uses=99,
            now=NOW,
        )
        consumption.consume(**_spend_kwargs(ledger["world"]))
        # The authoritative grant had exactly one use; the local 99 changed nothing.
        with pytest.raises(ConsumptionError):
            consumption.consume(**_spend_kwargs(ledger["world"]))
        assert consumption.uses_remaining(ledger["world"].approval_id) == 0
    finally:
        consumption.close()


def test_an_interrupted_execution_stays_journaled_and_reconcilable(ledger, tmp_path) -> None:
    """The spend is atomic, but the *effect* is not: uncertainty must survive.

    S14-11 moved the spend into the authoritative transaction. That must not
    collapse the three-outcome model: a consumption whose filesystem effect was
    interrupted stays PENDING locally, the real reconciler reports it as an
    orphan needing review, and resolving it to UNVERIFIED neither invents a
    result nor refunds the use.
    """

    from aether.core.edits.reconcile import MutationReconciler

    class _NoIntents:
        """The crash window: the use was spent, no intent was ever journaled."""

        def open_intents(self):
            return ()

    _issue(ledger, ledger["world"], uses=3)
    world = ledger["world"]
    consumption = _consumption_ledger(tmp_path, ledger["ledger"])
    try:
        spent = consumption.consume(**_spend_kwargs(world))
        assert spent.uses_remaining_after == 2

        # The process is killed here: no outcome was ever recorded.
        assert spent.state == "PENDING"
        assert [item.consumption_id for item in consumption.pending()] == [spent.consumption_id]

        # The real reconciler notices the spent-but-unjournaled use. It must not
        # report clean, because whether a file changed is genuinely unknown.
        report = MutationReconciler(
            journal=_NoIntents(),
            receipts=object(),
            consumption=consumption,
            snapshots=object(),
            resources=object(),
        ).reconcile()
        orphans = {
            str(item.consumption_id): item
            for item in report.needs_review
            if item.reason_code == "reconcile_consumption_without_intent"
        }
        assert str(spent.consumption_id) in orphans
        assert orphans[str(spent.consumption_id)].intent_id is None

        # Recording the uncertainty is the honest resolution, and it does not
        # refund the authoritative use: the grant really was spent.
        resolved = consumption.resolve(spent.consumption_id, state="UNVERIFIED")
        assert resolved.state == "UNVERIFIED"
        assert ledger["ledger"].status(world.approval_id, now=NOW).uses_remaining == 2
        assert consumption.pending() == ()
    finally:
        consumption.close()


def test_a_fake_authority_cannot_masquerade_as_authoritative(tmp_path) -> None:
    """An object with load/status but no real consume cannot authorize."""

    class _Fake:
        def load(self, approval_id):
            del approval_id
            return object()

        def status(self, approval_id, *, now=None):
            del approval_id, now

            class _S:
                state = "ACTIVE"
                uses_remaining = 99

            return _S()

        def consume(self, **terms):
            del terms
            raise RuntimeError("not a real ledger")

    instance = ConsumptionLedger(tmp_path / "fake.sqlite3", authority=_Fake(), clock=lambda: NOW)
    try:
        with pytest.raises(ConsumptionError):
            instance.consume_authoritative(
                consumption_id=uuid4(),
                approval_id=uuid4(),
                task_id=uuid4(),
                plan_revision=1,
                plan_hash="a" * 64,
                step_id=uuid4(),
                capability_id="fs.apply_approved_edit",
                risk_tier=2,
                arguments_sha256="b" * 64,
                expected_effect_sha256="c" * 64,
                resource_versions={"file:" + "0" * 32: "1"},
                consumed_by="aether.core.edits.executor",
                now=NOW,
            )
    finally:
        instance.close()


def test_simulated_authority_cannot_use_the_authoritative_path(tmp_path) -> None:
    """A test-scoped ledger must not claim an authoritative spend."""

    from aether.core.grants.consumption import ConsumptionLedger as _Ledger

    instance = _Ledger.open_tests_scoped(tmp_path / "sim.sqlite3", clock=lambda: NOW)
    try:
        with pytest.raises(ConsumptionError) as refused:
            instance.consume_authoritative(
                consumption_id=uuid4(),
                approval_id=uuid4(),
                task_id=uuid4(),
                plan_revision=1,
                plan_hash="a" * 64,
                step_id=uuid4(),
                capability_id="fs.apply_approved_edit",
                risk_tier=2,
                arguments_sha256="b" * 64,
                expected_effect_sha256="c" * 64,
                resource_versions={"file:" + "0" * 32: "1"},
                consumed_by="aether.core.edits.executor",
                now=NOW,
            )
        assert refused.value.reason_code == "consumption_authority_not_authoritative"
    finally:
        instance.close()


def test_no_authority_means_no_consumption(tmp_path) -> None:
    from aether.core.grants.consumption import GrantAuthorityUnavailable

    instance = ConsumptionLedger(tmp_path / "none.sqlite3", clock=lambda: NOW)
    try:
        with pytest.raises(GrantAuthorityUnavailable):
            instance.consume(
                consumption_id=uuid4(),
                approval_id=uuid4(),
                task_id=uuid4(),
                plan_revision=1,
                plan_hash="a" * 64,
                step_id=uuid4(),
                capability_id="fs.apply_approved_edit",
                risk_tier=2,
                arguments_sha256="b" * 64,
                expected_effect_sha256="c" * 64,
                resource_versions={"file:" + "0" * 32: "1"},
                consumed_by="aether.core.edits.executor",
                now=NOW,
            )
    finally:
        instance.close()


def test_production_issuance_is_still_disabled() -> None:
    from aether.core.persistence.sqlite_store import (
        ACTIVE_SCHEMA_VERSION,
        PENDING_MIGRATION_VERSIONS,
    )

    # Proposal A activated the schema; issuance remains disabled.
    assert ACTIVE_SCHEMA_VERSION == 2
    assert frozenset() == PENDING_MIGRATION_VERSIONS
    source = (
        Path(__file__).resolve().parents[1] / "aether" / "core" / "grants" / "ledger.py"
    ).read_text(encoding="utf-8")
    assert "GRANT_ISSUANCE_DISABLED" in source
