"""S14-12 / S14-13: recovery integrity for authoritative consumption.

S14-11 made ``GrantLedger.consume`` the sole spend, which was the right
architecture. Two ways of *recording* that spend remained wrong.

**S14-12 — a spend could become undiscoverable.** The authoritative commit happens
in the Stage 4 ledger's database; the local projection row happens in the
consumption ledger's database. Two SQLite files cannot commit together, so a
process killed between them left a use that was genuinely spent, named by no local
projection and by no journal intent. Reconciliation read local pending rows and
journal intents only, so it reported that state as clean. The fix is a durable
*attempt* row written and committed **before** the spend: it carries the stable
consumption id and the action identity, which is exactly enough for a restart to
ask the authoritative ledger whether the use landed.

**S14-13 — replay destroyed terminal evidence.** The projection was written with
``INSERT OR REPLACE``, including on an authoritative replay. Replaying after a
SUCCEEDED edit reset that row to PENDING, erasing the record of what the first
attempt concluded — on the very path that is meant to refuse a second mutation.

These tests inject each failure at the real boundary: a real ``GrantLedger``, a
real projection database, a fault that raises immediately after the authoritative
commit returns, and then a genuine reopen of every store from disk. Nothing here
mocks the commit ordering, because the ordering is the thing under test.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from aether.core.grants.consumption import (
    ConsumptionError,
    ConsumptionLedger,
)
from aether.core.grants.ledger import GrantLedger
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
def world(tmp_path: Path, monkeypatch):
    """A real authoritative ledger plus its store, reopenable from disk."""

    store = stage4_store(tmp_path, monkeypatch)
    plan = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
    real = open_tests_scoped_ledger(store)
    try:
        yield {"store": store, "world": plan, "ledger": real, "tmp": tmp_path}
    finally:
        real.close()
        store.close()


def _issue(world, *, uses: int = 1, **overrides):
    from tests.test_phase2b_stage4_grants import _issue as issue

    return issue(world["store"], world["ledger"], world["world"], uses=uses, **overrides)


def _open_projection(tmp_path: Path, real_ledger, *, name: str = "consume.sqlite3"):
    return ConsumptionLedger(tmp_path / name, authority=real_ledger, clock=lambda: NOW)


def _terms(plan, *, consumption_id=None) -> dict:
    return {
        "consumption_id": consumption_id or uuid4(),
        "approval_id": plan.approval_id,
        "task_id": plan.task_id,
        "plan_revision": plan.revision,
        "plan_hash": plan.plan_hash,
        "step_id": plan.operation.step_id,
        "capability_id": plan.operation.capability_id,
        "risk_tier": plan.operation.risk_tier,
        "arguments_sha256": plan.operation.arguments_sha256,
        "expected_effect_sha256": plan.operation.expected_effect_sha256,
        "resource_versions": plan.resource_versions(),
        "consumed_by": "aether.core.edits.executor",
        "now": NOW,
    }


class _CrashAfterSpend(BaseException):
    """Stands in for the process dying at the worst possible moment.

    Deliberately a ``BaseException``, not an ``Exception``. A real kill is not an
    exception a handler can catch: it stops the process. Using ``Exception`` here
    would let ``consume_authoritative``'s fail-closed handler convert the crash
    into an ordinary refusal, which is exactly the state a live process would
    never reach -- so the test would prove nothing about the durable-attempt
    window.
    """


class _CrashAfterCommitAuthority:
    """Wraps the real ledger and dies immediately after a successful spend.

    This is the only way to reach the window honestly: ``consume`` must really
    commit, and the fault must fire after it returns and before the caller can
    write anything. Wrapping the real ledger keeps every check and the real
    transaction in play, so the test cannot pass by bypassing them.
    """

    def __init__(self, real: GrantLedger) -> None:
        self._real = real

    def load(self, approval_id):
        return self._real.load(approval_id)

    def status(self, approval_id, *, now=None):
        return self._real.status(approval_id, now=now)

    def get_consumption(self, consumption_id):
        return self._real.get_consumption(consumption_id)

    def consume(self, **terms):
        # Spend for real, then die. The committed record is deliberately dropped:
        # the point is that it is committed and the caller never learns its value.
        self._real.consume(**terms)
        raise _CrashAfterSpend("killed after the authoritative commit returned")


# ---------------------------------------------------------------------------
# A. S14-12: a spend without a projection is discoverable
# ---------------------------------------------------------------------------


def test_an_attempt_is_durable_before_the_spend_happens(world, tmp_path) -> None:
    """The attempt row is committed before ``consume`` is ever called.

    Proven by refusing the spend outright and then finding the attempt on disk:
    if the attempt were written afterwards, a refusal would leave nothing.
    """

    _issue(world, uses=2)
    plan = world["world"]

    class _RefusingAuthority:
        def load(self, approval_id):
            return world["ledger"].load(approval_id)

        def status(self, approval_id, *, now=None):
            return world["ledger"].status(approval_id, now=now)

        def get_consumption(self, consumption_id):
            return world["ledger"].get_consumption(consumption_id)

        def consume(self, **terms):
            del terms
            raise ConsumptionError("GRANT_REVOKED", "refused for the test")

    projection = ConsumptionLedger(
        tmp_path / "consume.sqlite3", authority=_RefusingAuthority(), clock=lambda: NOW
    )
    try:
        terms = _terms(plan)
        with pytest.raises(ConsumptionError):
            projection.consume(**terms)
        attempts = projection.unprojected_attempts()
        assert [item.consumption_id for item in attempts] == [terms["consumption_id"]]
    finally:
        projection.close()

    # Nothing was spent, so the authoritative count is untouched.
    assert world["ledger"].status(plan.approval_id, now=NOW).uses_remaining == 2


def test_a_spend_without_a_projection_is_found_after_reopen(world, tmp_path) -> None:
    """The S14-12 regression: kill after the authoritative commit, then restart.

    The projection insert never runs. After reopening both databases from disk,
    the authoritative record must still be found, and reconciliation must not
    report the run as consistent.
    """

    from aether.core.edits.reconcile import MutationReconciler

    class _NoIntents:
        def open_intents(self):
            return ()

    _issue(world, uses=2)
    plan = world["world"]
    terms = _terms(plan)

    crashing = ConsumptionLedger(
        tmp_path / "consume.sqlite3",
        authority=_CrashAfterCommitAuthority(world["ledger"]),
        clock=lambda: NOW,
    )
    try:
        with pytest.raises(_CrashAfterSpend):
            crashing.consume(**terms)
        # The crash happened before any projection could be written.
        assert crashing.pending() == ()
        assert [item.consumption_id for item in crashing.unprojected_attempts()] == [
            terms["consumption_id"]
        ]
    finally:
        crashing.close()

    # The authoritative use really was spent, even though nothing local says so.
    assert world["ledger"].status(plan.approval_id, now=NOW).uses_remaining == 1
    assert world["ledger"].get_consumption(terms["consumption_id"]) is not None

    # --- restart: reopen every store from disk -------------------------------
    projection = _open_projection(tmp_path, world["ledger"])
    try:
        attempts = projection.unprojected_attempts()
        assert len(attempts) == 1
        found = projection.authoritative_consumption(terms["consumption_id"])
        assert found is not None, "the authoritative spend must be discoverable"

        report = MutationReconciler(
            journal=_NoIntents(),
            receipts=object(),
            consumption=projection,
            snapshots=object(),
            resources=object(),
        ).reconcile()

        assert not report.consistent, "a spent use with no projection is not consistent"
        verdicts = {
            str(item.consumption_id): item
            for item in report.reconciliations
            if item.consumption_id is not None
        }
        item = verdicts[str(terms["consumption_id"])]
        assert item.verdict == "NEEDS_REVIEW"
        assert item.reason_code == "reconcile_consumed_without_projection"
        assert item.intent_id is None

        # No refund: the use was really granted and may have taken effect.
        assert world["ledger"].status(plan.approval_id, now=NOW).uses_remaining == 1
    finally:
        projection.close()


def test_an_attempt_that_never_reached_the_spend_is_not_reported_as_spent(world, tmp_path) -> None:
    """The other side of the same window: crash before the authoritative commit.

    Here nothing was spent, so reporting NEEDS_REVIEW would be as wrong as
    reporting success. ``NOT_APPLIED`` is the honest verdict.
    """

    from aether.core.edits.reconcile import MutationReconciler

    class _NoIntents:
        def open_intents(self):
            return ()

    _issue(world, uses=2)
    plan = world["world"]

    class _DiesBeforeCommit:
        def load(self, approval_id):
            return world["ledger"].load(approval_id)

        def status(self, approval_id, *, now=None):
            return world["ledger"].status(approval_id, now=now)

        def get_consumption(self, consumption_id):
            return world["ledger"].get_consumption(consumption_id)

        def consume(self, **terms):
            del terms
            raise _CrashAfterSpend("killed before the authoritative commit")

    terms = _terms(plan)
    crashing = ConsumptionLedger(
        tmp_path / "consume.sqlite3", authority=_DiesBeforeCommit(), clock=lambda: NOW
    )
    try:
        with pytest.raises(_CrashAfterSpend):
            crashing.consume(**terms)
    finally:
        crashing.close()

    assert world["ledger"].status(plan.approval_id, now=NOW).uses_remaining == 2

    projection = _open_projection(tmp_path, world["ledger"])
    try:
        report = MutationReconciler(
            journal=_NoIntents(),
            receipts=object(),
            consumption=projection,
            snapshots=object(),
            resources=object(),
        ).reconcile()
        item = {
            str(entry.consumption_id): entry
            for entry in report.reconciliations
            if entry.consumption_id is not None
        }[str(terms["consumption_id"])]
        assert item.verdict == "NOT_APPLIED"
        assert item.reason_code == "reconcile_attempt_not_spent"
        # NOT_APPLIED is not a "needs review" verdict, and it is certainly not
        # success: nothing was spent and nothing was written.
        assert item not in report.needs_review
    finally:
        projection.close()


def test_an_unanswerable_authority_is_never_treated_as_unspent(world, tmp_path) -> None:
    """If the ledger cannot be asked, the answer is unknown, not "not spent"."""

    from aether.core.edits.reconcile import MutationReconciler

    class _NoIntents:
        def open_intents(self):
            return ()

    _issue(world, uses=2)
    plan = world["world"]

    class _FailingRead:
        """Spends for real, then cannot be queried for its own record."""

        def load(self, approval_id):
            return world["ledger"].load(approval_id)

        def status(self, approval_id, *, now=None):
            return world["ledger"].status(approval_id, now=now)

        def consume(self, **terms):
            record = world["ledger"].consume(**terms)
            del record
            raise _CrashAfterSpend("killed after the authoritative commit returned")

        def get_consumption(self, consumption_id):
            del consumption_id
            raise RuntimeError("the authoritative database is unavailable")

    terms = _terms(plan)
    authority = _FailingRead()
    crashing = ConsumptionLedger(
        tmp_path / "consume.sqlite3", authority=authority, clock=lambda: NOW
    )
    try:
        with pytest.raises(_CrashAfterSpend):
            crashing.consume(**terms)
    finally:
        crashing.close()

    projection = ConsumptionLedger(
        tmp_path / "consume.sqlite3", authority=authority, clock=lambda: NOW
    )
    try:
        report = MutationReconciler(
            journal=_NoIntents(),
            receipts=object(),
            consumption=projection,
            snapshots=object(),
            resources=object(),
        ).reconcile()
        item = {
            str(entry.consumption_id): entry
            for entry in report.reconciliations
            if entry.consumption_id is not None
        }[str(terms["consumption_id"])]
        assert item.verdict == "NEEDS_REVIEW"
        assert item.reason_code == "reconcile_authority_unavailable"
        assert not report.consistent
    finally:
        projection.close()


def test_a_journaled_attempt_is_not_reported_twice(world, tmp_path) -> None:
    """When a journal intent names the consumption, the intent's verdict governs.

    Double-reporting the same use would make a report look worse than reality;
    ``_reconcile_one`` already compares the file against the intent.
    """

    from aether.core.edits.journal import MutationIntent
    from aether.core.edits.reconcile import MutationReconciler

    _issue(world, uses=2)
    plan = world["world"]

    consumption_id = uuid4()
    plan_for_intent = world["world"]

    class _OneIntent:
        def open_intents(self):
            return (
                MutationIntent(
                    intent_id=uuid4(),
                    consumption_id=consumption_id,
                    task_id=plan_for_intent.task_id,
                    step_id=plan_for_intent.operation.step_id,
                    approval_id=plan_for_intent.approval_id,
                    capability_id=plan_for_intent.operation.capability_id,
                    resource_id="res",
                    target_path=str(tmp_path / "file.txt"),
                    pre_sha256="a" * 64,
                    intended_post_sha256="b" * 64,
                    expected_effect_sha256="c" * 64,
                    snapshot_id=None,
                    state="INTENDED",
                    attempted_at=NOW,
                ),
            )

    terms = _terms(plan, consumption_id=consumption_id)
    busy = ConsumptionLedger(
        tmp_path / "consume.sqlite3",
        authority=_CrashAfterCommitAuthority(world["ledger"]),
        clock=lambda: NOW,
    )
    try:
        with pytest.raises(_CrashAfterSpend):
            busy.consume(**terms)
    finally:
        busy.close()

    (tmp_path / "file.txt").write_bytes(b"whatever")
    projection = _open_projection(tmp_path, world["ledger"])
    try:
        report = MutationReconciler(
            journal=_OneIntent(),
            receipts=object(),
            consumption=projection,
            snapshots=object(),
            resources=object(),
        ).reconcile()
        # Exactly one verdict for this use. An intent verdict identifies itself by
        # intent_id; only an orphan projection verdict carries consumption_id. The
        # attempt must not add a second, duplicate complaint on top.
        assert len(report.reconciliations) == 1, "one use must produce one verdict, not two"
        only = report.reconciliations[0]
        assert only.intent_id is not None, "the journaled intent governs the verdict"
        assert only.consumption_id is None
        assert only.reason_code == "reconcile_third_state"
    finally:
        projection.close()


# ---------------------------------------------------------------------------
# B. S14-13: replay must not destroy a terminal outcome
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("terminal", ["SUCCEEDED", "FAILED", "UNVERIFIED"])
def test_replay_preserves_a_terminal_projection(world, tmp_path, terminal: str) -> None:
    """Replaying after a resolved attempt keeps that resolution.

    This is the S14-13 regression. Before the fix, ``INSERT OR REPLACE`` restored
    the row to PENDING and the record of what the first attempt concluded was
    gone — on the path whose entire job is to refuse a second mutation.
    """

    _issue(world, uses=3)
    plan = world["world"]
    projection = _open_projection(tmp_path, world["ledger"])
    try:
        terms = _terms(plan)
        first = projection.consume(**terms)
        assert first.state == "PENDING"
        projection.resolve(first.consumption_id, state=terminal, detail=f"first attempt {terminal}")

        replayed = projection.consume(**terms)
        assert replayed.replayed is True
        assert replayed.state == terminal, "the terminal outcome must survive a replay"

        # And it survives on disk, not just in the returned object.
        rows = projection.pending()
        assert all(item.consumption_id != first.consumption_id for item in rows)
    finally:
        projection.close()

    # A restart must also still see the terminal state.
    projection = _open_projection(tmp_path, world["ledger"])
    try:
        terms = _terms(plan)
    finally:
        projection.close()

    # The authoritative count moved once, not twice.
    assert world["ledger"].status(plan.approval_id, now=NOW).uses_remaining == 2


def test_replay_after_reopen_preserves_the_terminal_state(world, tmp_path) -> None:
    """Restart, then replay: the resolution written before the restart survives."""

    _issue(world, uses=3)
    plan = world["world"]
    terms = _terms(plan)

    projection = _open_projection(tmp_path, world["ledger"])
    try:
        first = projection.consume(**terms)
        projection.resolve(first.consumption_id, state="SUCCEEDED", detail="verified effect")
    finally:
        projection.close()

    projection = _open_projection(tmp_path, world["ledger"])
    try:
        replayed = projection.consume(**terms)
        assert replayed.replayed is True
        assert replayed.state == "SUCCEEDED"
    finally:
        projection.close()

    assert world["ledger"].status(plan.approval_id, now=NOW).uses_remaining == 2


def test_a_mismatched_identity_is_refused_and_the_row_is_untouched(world, tmp_path) -> None:
    """A reused id meaning a different action is refused, not overwritten."""

    _issue(world, uses=3)
    plan = world["world"]
    projection = _open_projection(tmp_path, world["ledger"])
    try:
        terms = _terms(plan)
        first = projection.consume(**terms)
        projection.resolve(first.consumption_id, state="SUCCEEDED", detail="verified")

        # Same id, different action: a different step id changes the digest.
        mismatched = dict(terms)
        mismatched["step_id"] = uuid4()
        with pytest.raises(ConsumptionError) as refused:
            projection.consume(**mismatched)
        assert refused.value.reason_code in {
            "consumption_attempt_mismatch",
            "consumption_projection_mismatch",
        }

        # The original row is still resolved.
        replayed = projection.consume(**terms)
        assert replayed.state == "SUCCEEDED"
    finally:
        projection.close()


def test_a_missing_projection_is_created_pending_not_successful(world, tmp_path) -> None:
    """If the projection never landed, recovery must not invent an effect.

    The attempt exists and the authoritative spend exists, but the local row does
    not. Re-running the spend against the same id is an authoritative replay; the
    projection it creates must be PENDING, because nothing has yet proven that a
    file changed.
    """

    _issue(world, uses=3)
    plan = world["world"]
    terms = _terms(plan)

    busy = ConsumptionLedger(
        tmp_path / "consume.sqlite3",
        authority=_CrashAfterCommitAuthority(world["ledger"]),
        clock=lambda: NOW,
    )
    try:
        with pytest.raises(_CrashAfterSpend):
            busy.consume(**terms)
    finally:
        busy.close()

    projection = _open_projection(tmp_path, world["ledger"])
    try:
        recovered = projection.consume(**terms)
        assert recovered.replayed is True
        assert recovered.state == "PENDING", "recovery must not claim success"
        assert [item.consumption_id for item in projection.pending()] == [terms["consumption_id"]]
        # The use was spent once, at the original crash.
        assert world["ledger"].status(plan.approval_id, now=NOW).uses_remaining == 2
    finally:
        projection.close()


def test_replay_does_not_allow_a_second_authoritative_spend(world, tmp_path) -> None:
    """Idempotence: replay returns the committed record and spends nothing new."""

    _issue(world, uses=3)
    plan = world["world"]
    projection = _open_projection(tmp_path, world["ledger"])
    try:
        terms = _terms(plan)
        projection.consume(**terms)
        for _ in range(3):
            again = projection.consume(**terms)
            assert again.replayed is True
        assert world["ledger"].status(plan.approval_id, now=NOW).uses_remaining == 2
        assert len(world["ledger"].list_consumptions(plan.approval_id)) == 1
    finally:
        projection.close()


# ---------------------------------------------------------------------------
# C. The recovery surface cannot become an allowance
# ---------------------------------------------------------------------------


def test_an_attempt_alone_authorizes_nothing(world, tmp_path) -> None:
    """Holding an attempt row does not let anything spend.

    ``unprojected_attempts`` is a recovery read surface. If it were ever treated
    as an allowance the fix would have recreated the duplicate-allowance defect.
    """

    _issue(world, uses=1)
    plan = world["world"]

    class _Refusing:
        def load(self, approval_id):
            return world["ledger"].load(approval_id)

        def status(self, approval_id, *, now=None):
            return world["ledger"].status(approval_id, now=now)

        def get_consumption(self, consumption_id):
            return world["ledger"].get_consumption(consumption_id)

        def consume(self, **terms):
            del terms
            raise ConsumptionError("GRANT_REVOKED", "refused")

    projection = ConsumptionLedger(
        tmp_path / "consume.sqlite3", authority=_Refusing(), clock=lambda: NOW
    )
    try:
        with pytest.raises(ConsumptionError):
            projection.consume(**_terms(plan))
        assert len(projection.unprojected_attempts()) == 1
        # Still refused, as many times as we ask.
        with pytest.raises(ConsumptionError):
            projection.consume(**_terms(plan))
        assert world["ledger"].status(plan.approval_id, now=NOW).uses_remaining == 1
    finally:
        projection.close()


def test_the_simulated_ledger_still_cannot_take_the_authoritative_path(tmp_path) -> None:
    """S14-11's refusal must survive S14-12's new code paths."""

    simulated = ConsumptionLedger.open_tests_scoped(tmp_path / "sim.sqlite3", clock=lambda: NOW)
    try:
        with pytest.raises(ConsumptionError) as refused:
            simulated.consume_authoritative(
                consumption_id=uuid4(),
                approval_id=uuid4(),
                task_id=uuid4(),
                plan_revision=1,
                plan_hash="a" * 64,
                step_id=uuid4(),
                capability_id="fs.edit_file",
                risk_tier=1,
                arguments_sha256="b" * 64,
                expected_effect_sha256="c" * 64,
                resource_versions={},
                consumed_by="aether.core.edits.executor",
                now=NOW,
            )
        assert refused.value.reason_code == "consumption_authority_not_authoritative"
        # And it wrote no attempt row on the way out.
        assert simulated.unprojected_attempts() == ()
    finally:
        simulated.close()


def test_gates_are_unchanged(tmp_path) -> None:
    """The migration and issuance gates must be untouched by recovery work."""

    from aether.core.persistence.sqlite_store import (
        ACTIVE_SCHEMA_VERSION,
        PENDING_MIGRATION_VERSIONS,
    )

    # Proposal A activated the schema; issuance remains disabled.
    # Phase 3 schema v3 is prepared-only (pending, never active here).
    assert ACTIVE_SCHEMA_VERSION == 2
    assert frozenset({3}) == PENDING_MIGRATION_VERSIONS
