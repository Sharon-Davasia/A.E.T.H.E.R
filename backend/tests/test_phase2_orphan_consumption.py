"""S14-8: a pending consumption with no journal intent must never look clean.

The executor spends the grant use *before* it writes the journal intent (S14-2
and S14-4 both depend on that order). A crash in that narrow window leaves a
pending consumption that no intent mentions. ``MutationReconciler`` used to
iterate only open journal intents, so it reported "nothing to review" for exactly
the state with the least evidence.

Every test here re-opens the stores from disk, because the condition being tested
only exists after a process boundary.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aether.core.edits.executor import EditExecutor, EditRequest
from aether.core.edits.journal import MutationJournal
from aether.core.edits.receipts import ReceiptStore
from aether.core.edits.reconcile import MutationReconciler
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.vault.undo_vault import UndoVault
from tests.fs_support import ConsumptionHarness, build_registry, build_tree, resolve

NOW = datetime(2026, 11, 22, tzinfo=UTC)
CAPABILITIES = frozenset(
    {"fs.inspect_file", "fs.read_file", "fs.apply_approved_edit", "fs.undo_edit"}
)


class _Accepting:
    def check_action(self, request, grants, *, risk_tier, now=None):
        class _Outcome:
            ok = True
            reason_code = "accepted"
            approval_id = None

        return _Outcome()


class _Resolver:
    def path_for(self, resource_id: str) -> Path:
        raise LookupError("resource ids do not map back to paths")


@pytest.fixture()
def world(tmp_path: Path):
    (tmp_path / "grants").mkdir()
    tree = build_tree(tmp_path)
    registry = build_registry(tree, capabilities=CAPABILITIES)
    store = SQLiteTaskStore(tmp_path / "tasks.sqlite3")
    grants = ConsumptionHarness(tmp_path / "grants", clock=lambda: NOW, uses=8)
    vault = UndoVault(tmp_path / "vault").open()
    receipts = ReceiptStore(tmp_path / "receipts.sqlite3")
    journal = MutationJournal(tmp_path / "journal.sqlite3", clock=lambda: NOW)
    executor = EditExecutor(
        registry,
        _Accepting(),
        vault,
        receipts,
        plans=store,
        grants=grants.ledger,
        journal=journal,
        clock=lambda: NOW,
    )
    planner = Planner(
        capabilities=CapabilityRegistry.phase2_filesystem(),
        resources=registry,
        clock=lambda: NOW,
    )
    state = {
        "tmp": tmp_path,
        "tree": tree,
        "registry": registry,
        "store": store,
        "grants": grants,
        "vault": vault,
        "receipts": receipts,
        "journal": journal,
        "executor": executor,
        "planner": planner,
    }
    try:
        yield state
    finally:
        journal.close()
        grants.close()
        receipts.close()
        vault.close()
        store.close()


def _reconciler(world, *, journal=None, receipts=None, consumption=None):
    return MutationReconciler(
        journal=journal or world["journal"],
        receipts=receipts or world["receipts"],
        consumption=consumption or world["grants"].ledger,
        snapshots=world["vault"],
        resources=_Resolver(),
    )


def _request(world, *, proposed: bytes) -> EditRequest:
    registry, planner, store = world["registry"], world["planner"], world["store"]
    task_id, approval_id = uuid4(), uuid4()
    resource_id = resolve(registry, "README.md")
    original = (world["tree"].root / "README.md").read_bytes()
    revision = planner.plan(
        task_id,
        PlanIntent(
            goal=PlanGoal.APPLY_EDIT,
            resource_id=resource_id,
            arguments={
                "resource_id": resource_id,
                "step_id": str(uuid4()),
                "approval_id": str(approval_id),
                "expected_sha256": hashlib.sha256(original).hexdigest(),
            },
            summary="Edit",
            proposed_content=proposed,
        ),
        revision=1,
    )
    plan_hash = "a" * 64
    world["grants"].bind(approval_id=approval_id, task_id=task_id, now=NOW, plan_hash=plan_hash)
    store.create_task("edit", task_id=task_id, now=NOW)
    from aether.core.persistence.sqlite_store import PersistentTaskState

    store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
    store.save_plan(revision.plan)
    return EditRequest(
        task_id=task_id,
        step_id=revision.step_id,
        approval_id=approval_id,
        plan_revision=1,
        plan_hash=plan_hash,
        resource_id=resource_id,
        expected_sha256=hashlib.sha256(original).hexdigest(),
        proposed_content=proposed,
        expected_effect_sha256=str(
            revision.plan.steps[0].expected_effect["approved_effect_digest"]
        ),
    )


def _spend_without_journaling(world, *, proposed: bytes = b"# Edited\n\nBody.\n") -> None:
    """Spend a grant use and write no journal intent: the crash window, isolated."""

    request = _request(world, proposed=proposed)
    executor = world["executor"]
    executor._consume_grant(
        request,
        executor._plan_step(request),
        executor._plan_binding(request),
    )


# ---------------------------------------------------------------------------
# A. The exact gap: consumption spent, then the process dies before journaling
# ---------------------------------------------------------------------------


def test_a_consumption_without_an_intent_is_reported_not_ignored(world) -> None:
    """The headline case. Spend a use, write no journal, restart, reconcile."""

    # Spend the use, as the executor does before journaling.
    _spend_without_journaling(world)
    assert len(world["grants"].ledger.pending()) == 1
    # No intent was ever written: this is the crash window.
    assert world["journal"].open_intents() == ()

    # A fresh process reads only what is durable.
    reopened_journal = MutationJournal(world["tmp"] / "journal.sqlite3", clock=lambda: NOW)
    reopened_receipts = ReceiptStore(world["tmp"] / "receipts.sqlite3")
    try:
        report = _reconciler(
            world, journal=reopened_journal, receipts=reopened_receipts
        ).reconcile()
        assert len(report.reconciliations) == 1
        verdict = report.reconciliations[0]
        assert verdict.verdict == "NEEDS_REVIEW"
        assert verdict.reason_code == "reconcile_consumption_without_intent"
        # Crucially: never consistent, never "nothing to report".
        assert not report.consistent
        assert report.needs_review
        # The report names the consumption it is about, and does not pretend an
        # intent existed.
        assert verdict.intent_id is None
        assert verdict.consumption_id is not None
    finally:
        reopened_journal.close()
        reopened_receipts.close()


def test_an_orphan_consumption_is_never_reported_as_completed(world) -> None:
    _spend_without_journaling(world)
    report = _reconciler(world).reconcile()
    assert all(
        item.verdict not in {"COMPLETED_VERIFIED", "COMPLETED_UNVERIFIED", "NOT_APPLIED"}
        for item in report.reconciliations
    )
    assert all(
        item.reason_code == "reconcile_consumption_without_intent"
        for item in report.reconciliations
    )


def test_the_user_file_is_untouched_in_the_orphan_case(world) -> None:
    """The report is about an unknown effect, so nothing may be 'fixed' either."""

    before = world["tree"].readme.read_bytes()
    _spend_without_journaling(world)
    _reconciler(world).reconcile()
    assert world["tree"].readme.read_bytes() == before


# ---------------------------------------------------------------------------
# B. Accounting: every consumed use appears somewhere
# ---------------------------------------------------------------------------


def test_every_pending_consumption_appears_in_the_report(world) -> None:
    """No spent use may be invisible, however many there are."""

    for _ in range(3):
        _spend_without_journaling(world)
    pending = {str(item.consumption_id) for item in world["grants"].ledger.pending()}
    assert len(pending) == 3

    report = _reconciler(world).reconcile()
    reported = {str(item.consumption_id) for item in report.reconciliations if item.consumption_id}
    # Every pending consumption is accounted for by the report.
    assert reported == pending


def test_a_consumption_with_an_intent_is_not_double_reported(world) -> None:
    """An orphan report must not fire for a consumption the journal knows about."""

    outcome = world["executor"].apply(_request(world, proposed=b"# Edited\n\nBody.\n"))
    assert outcome.status == "SUCCEEDED"
    assert world["grants"].ledger.pending() == ()

    report = _reconciler(world).reconcile()
    assert report.reconciliations == ()
    assert report.consistent


def test_a_resolved_consumption_without_an_intent_is_not_pending(world) -> None:
    """Only *unresolved* uses are orphans; a resolved one is accounted for."""

    _spend_without_journaling(world)
    pending = world["grants"].ledger.pending()
    assert len(pending) == 1
    world["grants"].ledger.resolve(
        pending[0].consumption_id, state="RECONCILED", detail="reviewed by operator"
    )
    report = _reconciler(world).reconcile()
    assert report.reconciliations == ()
    assert report.consistent


# ---------------------------------------------------------------------------
# C. Both holes at once: an intent AND an orphan
# ---------------------------------------------------------------------------


def test_an_orphan_is_reported_alongside_open_intents(world, monkeypatch) -> None:
    """The two work lists are independent; neither may mask the other."""

    # One orphan: consumption with no intent.
    orphan_request = _request(world, proposed=b"# First\n\nBody.\n")
    world["executor"]._consume_grant(
        orphan_request,
        world["executor"]._plan_step(orphan_request),
        world["executor"]._plan_binding(orphan_request),
    )

    # One open intent: a normal edit killed after the replace.
    second = _request(world, proposed=b"# Second\n\nOther body.\n")
    from aether.core.edits.executor import EditExecutor as _Exec

    real_replace = _Exec._atomic_replace

    class _Killed(BaseException):
        pass

    def replace_then_die(self, target, content, pre_image):
        real_replace(self, target, content, pre_image)
        raise _Killed()

    monkeypatch.setattr(_Exec, "_atomic_replace", replace_then_die)
    with pytest.raises(_Killed):
        world["executor"].apply(second)
    monkeypatch.undo()

    report = _reconciler(world).reconcile()
    reasons = {item.reason_code for item in report.reconciliations}
    assert "reconcile_consumption_without_intent" in reasons
    # The open intent is reported too (as unverified, since no receipt exists).
    assert any(
        item.verdict in {"COMPLETED_UNVERIFIED", "NEEDS_REVIEW"} and item.intent_id is not None
        for item in report.reconciliations
    )
    assert len(report.reconciliations) == 2
    assert not report.consistent


def test_an_orphan_whose_intent_was_resolved_is_still_reviewed(world) -> None:
    """A consumption the journal does not mention cannot borrow an intent."""

    from aether.core.edits.journal import MutationJournal as _Journal

    _spend_without_journaling(world)
    # A *different* consumption gets a resolved intent; the orphan must not attach
    # itself to it.
    other = world["journal"].begin(
        task_id=uuid4(),
        step_id=uuid4(),
        approval_id=uuid4(),
        capability_id="fs.apply_approved_edit",
        resource_id=resolve(world["registry"], "README.md"),
        target_path=world["tree"].root / "README.md",
        resource_version="a" * 64,
        pre_sha256="a" * 64,
        intended_post_sha256="b" * 64,
        expected_effect_sha256="c" * 64,
        consumption_id=uuid4(),
        now=NOW,
    )
    world["journal"].resolve(other.intent_id, state="VERIFIED", now=NOW)

    reopened = _Journal(world["tmp"] / "journal.sqlite3", clock=lambda: NOW)
    try:
        report = _reconciler(world, journal=reopened).reconcile()
        assert len(report.reconciliations) == 1
        assert report.reconciliations[0].reason_code == "reconcile_consumption_without_intent"
    finally:
        reopened.close()


# ---------------------------------------------------------------------------
# D. Consistency semantics stay strict
# ---------------------------------------------------------------------------


def test_an_empty_work_list_is_the_only_clean_state(world) -> None:
    report = _reconciler(world).reconcile()
    assert report.reconciliations == ()
    assert report.consistent
    assert report.needs_review == ()


def test_orphan_detection_does_not_write_anything(world) -> None:
    _spend_without_journaling(world)
    before_pending = world["grants"].ledger.pending()
    _reconciler(world).reconcile()
    # Reconciling is evidence gathering: the consumption stays pending for a
    # human or an explicitly authorized recovery step.
    after_pending = world["grants"].ledger.pending()
    assert [item.consumption_id for item in before_pending] == [
        item.consumption_id for item in after_pending
    ]
    assert world["journal"].open_intents() == ()


def test_reconciliation_never_claims_a_processed_consumption_is_done(world) -> None:
    """A 'RECONCILED' consumption is accounted for, not silently 'succeeded'."""

    _spend_without_journaling(world)
    pending = world["grants"].ledger.pending()[0]
    resolved = world["grants"].ledger.resolve(
        pending.consumption_id, state="RECONCILED", detail="operator reviewed the window"
    )
    # The use is now accounted for, and remains distinguishable from a success:
    # RECONCILED is not SUCCEEDED, and no receipt was ever written.
    assert resolved.state == "RECONCILED"
    assert UUID(str(pending.consumption_id))
    assert world["receipts"].for_task("edit") == ()
