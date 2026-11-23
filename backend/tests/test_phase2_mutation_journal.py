"""S14-4: durable pre-mutation journal and restart reconciliation.

The failure this addresses is specific: the executor used to replace the file and
*then* write a receipt. A process kill in between left a changed file with no
durable record of why it changed, or with a spent grant and no evidence.

These tests assert the ordering and, more importantly, what a *restarted* process
concludes from disk alone. Nothing here claims that a crash was survived in
memory: every crash case re-opens the stores from scratch.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aether.core.edits.executor import EditDenied, EditExecutor, EditRequest
from aether.core.edits.journal import JournalError, MutationJournal
from aether.core.edits.receipts import ReceiptStore
from aether.core.edits.reconcile import MutationReconciler
from aether.core.persistence.sqlite_store import PersistentTaskState, SQLiteTaskStore
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.vault.undo_vault import UndoVault
from tests.fs_support import ConsumptionHarness, build_registry, build_tree, resolve

NOW = datetime(2026, 11, 22, tzinfo=UTC)
ORIGINAL = b"# Synthetic\n\nThe quick brown fox needs a needle.\n"
EDIT = b"# Journal\n\nEdited content that replaces the original exactly.\n"
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
    """Fallback resource id -> path, for intents that recorded no path."""

    def __init__(self, registry) -> None:
        self._registry = registry

    def path_for(self, resource_id: str) -> Path:
        del resource_id
        raise LookupError("resource ids do not map back to paths")


def _plan(world, *, proposed: bytes = EDIT):
    registry, planner, store = world["registry"], world["planner"], world["store"]
    task_id = uuid4()
    approval_id = uuid4()
    resource_id = resolve(registry, "README.md")
    revision = planner.plan(
        task_id,
        PlanIntent(
            goal=PlanGoal.APPLY_EDIT,
            resource_id=resource_id,
            arguments={
                "resource_id": resource_id,
                "step_id": str(uuid4()),
                "approval_id": str(approval_id),
                "expected_sha256": hashlib.sha256(
                    (world["tree"].root / "README.md").read_bytes()
                ).hexdigest(),
            },
            summary="Edit the readme",
            proposed_content=proposed,
        ),
        revision=1,
    )
    plan_hash = "a" * 64
    world["grants"].bind(approval_id=approval_id, task_id=task_id, now=NOW, plan_hash=plan_hash)
    store.create_task("edit", task_id=task_id, now=NOW)
    store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
    store.save_plan(revision.plan)
    request = EditRequest(
        task_id=task_id,
        step_id=revision.step_id,
        approval_id=approval_id,
        plan_revision=1,
        plan_hash=plan_hash,
        resource_id=resource_id,
        expected_sha256=hashlib.sha256((world["tree"].root / "README.md").read_bytes()).hexdigest(),
        proposed_content=proposed,
        expected_effect_sha256=str(
            revision.plan.steps[0].expected_effect["approved_effect_digest"]
        ),
    )
    return request


@pytest.fixture()
def world(tmp_path: Path):
    (tmp_path / "grants").mkdir()
    tree = build_tree(tmp_path)
    registry = build_registry(tree, capabilities=CAPABILITIES)
    store = SQLiteTaskStore(tmp_path / "tasks.sqlite3")
    grants = ConsumptionHarness(tmp_path / "grants", clock=lambda: NOW, uses=16)
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
        "tree": tree,
        "registry": registry,
        "store": store,
        "grants": grants,
        "vault": vault,
        "receipts": receipts,
        "journal": journal,
        "executor": executor,
        "planner": planner,
        "root": tmp_path,
    }
    try:
        yield state
    finally:
        journal.close()
        grants.close()
        receipts.close()
        vault.close()
        store.close()


def _reconciler(world, *, journal=None, receipts=None):
    return MutationReconciler(
        journal=journal or world["journal"],
        receipts=receipts or world["receipts"],
        consumption=world["grants"].ledger,
        snapshots=world["vault"],
        resources=_Resolver(world["registry"]),
    )


# ---------------------------------------------------------------------------
# A. Ordering: the intent is durable before the replace
# ---------------------------------------------------------------------------


def test_success_records_intent_then_verifies(world) -> None:
    request = _plan(world)
    outcome = world["executor"].apply(request)
    assert outcome.status == "SUCCEEDED"
    intents = world["journal"].open_intents()
    # A completed mutation leaves nothing open for reconciliation.
    assert intents == ()
    recorded = world["journal"].get(
        world["journal"]
        ._connection.execute("SELECT intent_id FROM mutation_intents")
        .fetchone()["intent_id"]
    )
    assert recorded.state == "VERIFIED"
    assert recorded.pre_sha256 == hashlib.sha256(ORIGINAL).hexdigest()
    assert recorded.intended_post_sha256 == hashlib.sha256(EDIT).hexdigest()
    assert recorded.snapshot_id is not None
    assert recorded.consumption_id is not None


def test_the_intent_is_written_before_the_target_is_replaced(world, monkeypatch) -> None:
    """The decisive ordering assertion, observed from inside the write path."""

    request = _plan(world)
    seen: list[tuple[str, bool]] = []
    real_replace = EditExecutor._atomic_replace

    def spy(self, target: Path, content: bytes, pre_image: bytes) -> None:
        # At the moment of replacement the intent must already be on disk.
        seen.append(("intent_exists", len(self._journal.open_intents()) == 1))
        real_replace(self, target, content, pre_image)

    monkeypatch.setattr(EditExecutor, "_atomic_replace", spy)
    outcome = world["executor"].apply(request)
    assert outcome.status == "SUCCEEDED"
    assert seen == [("intent_exists", True)]


def test_a_journal_that_cannot_record_the_intent_blocks_the_mutation(world, monkeypatch) -> None:
    """No record, no mutation -- an unrecorded change is the failure mode."""

    request = _plan(world)
    before = world["tree"].readme.read_bytes()

    def refuse(**_fields):
        raise JournalError("journal_unavailable", "disk full")

    monkeypatch.setattr(world["journal"], "begin", refuse)
    with pytest.raises(EditDenied) as denied:
        world["executor"].apply(request)
    assert denied.value.reason_code == "journal_unavailable"
    assert world["tree"].readme.read_bytes() == before


def test_one_step_cannot_open_two_intents(world) -> None:
    request = _plan(world)
    world["journal"].begin(
        task_id=request.task_id,
        step_id=request.step_id,
        approval_id=request.approval_id,
        capability_id="fs.apply_approved_edit",
        resource_id=request.resource_id,
        resource_version=request.expected_sha256,
        pre_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
        intended_post_sha256=hashlib.sha256(EDIT).hexdigest(),
        expected_effect_sha256=request.expected_effect_sha256,
        now=NOW,
    )
    with pytest.raises(JournalError) as refused:
        world["journal"].begin(
            task_id=request.task_id,
            step_id=request.step_id,
            approval_id=request.approval_id,
            capability_id="fs.apply_approved_edit",
            resource_id=request.resource_id,
            resource_version=request.expected_sha256,
            pre_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
            intended_post_sha256=hashlib.sha256(EDIT).hexdigest(),
            expected_effect_sha256=request.expected_effect_sha256,
            now=NOW,
        )
    assert refused.value.reason_code == "journal_intent_already_recorded"


def test_journal_rejects_naive_timestamps(world) -> None:
    with pytest.raises(JournalError) as refused:
        world["journal"].begin(
            task_id=uuid4(),
            step_id=uuid4(),
            approval_id=uuid4(),
            capability_id="fs.apply_approved_edit",
            resource_id="file:" + str(uuid4()),
            resource_version="a" * 64,
            pre_sha256="a" * 64,
            intended_post_sha256="b" * 64,
            expected_effect_sha256="c" * 64,
            now=datetime(2026, 11, 22),
        )
    assert refused.value.reason_code == "journal_timestamp_naive"


# ---------------------------------------------------------------------------
# B. The crash window: killed between replace and receipt
# ---------------------------------------------------------------------------


def test_kill_between_replace_and_receipt_is_not_a_phantom_success(world, monkeypatch) -> None:
    """Simulate a hard kill after the write and re-open everything from disk."""

    request = _plan(world)
    real_replace = EditExecutor._atomic_replace

    class _Killed(BaseException):
        """Stands in for the process dying: no cleanup, no receipt, no resolve."""

    def replace_then_die(self, target: Path, content: bytes, pre_image: bytes) -> None:
        real_replace(self, target, content, pre_image)
        raise _Killed()

    monkeypatch.setattr(EditExecutor, "_atomic_replace", replace_then_die)
    with pytest.raises(_Killed):
        world["executor"].apply(request)

    # The file really was changed by the "killed" process.
    assert world["tree"].readme.read_bytes() == EDIT

    # A fresh process sees only what is durable.
    restarted_journal = MutationJournal(world["root"] / "journal.sqlite3", clock=lambda: NOW)
    restarted_receipts = ReceiptStore(world["root"] / "receipts.sqlite3")
    try:
        open_intents = restarted_journal.open_intents()
        assert len(open_intents) == 1
        assert open_intents[0].state == "INTENT_RECORDED"
        # No receipt was ever written for this attempt.
        assert restarted_receipts.for_task(str(request.task_id)) == ()
        # The consumption is still PENDING: the use was spent, unexplained.
        pending = {str(item.consumption_id) for item in world["grants"].ledger.pending()}
        assert str(open_intents[0].consumption_id) in pending

        report = _reconciler(
            world, journal=restarted_journal, receipts=restarted_receipts
        ).reconcile()
        assert len(report.reconciliations) == 1
        verdict = report.reconciliations[0]
        # The bytes match the intent, but nothing proves the effect.
        assert verdict.verdict == "COMPLETED_UNVERIFIED"
        assert verdict.reason_code == "reconcile_no_verified_receipt"
        assert not report.consistent
    finally:
        restarted_journal.close()
        restarted_receipts.close()


def test_kill_before_the_replace_is_reported_as_not_applied(world, monkeypatch) -> None:
    request = _plan(world)

    class _Killed(BaseException):
        pass

    def die_before_replace(self, target: Path, content: bytes, pre_image: bytes) -> None:
        raise _Killed()

    monkeypatch.setattr(EditExecutor, "_atomic_replace", die_before_replace)
    with pytest.raises(_Killed):
        world["executor"].apply(request)
    monkeypatch.undo()

    assert world["tree"].readme.read_bytes() == ORIGINAL
    report = _reconciler(world).reconcile()
    assert len(report.reconciliations) == 1
    verdict = report.reconciliations[0]
    # One use was spent but no replacement happened: a human must reconcile it.
    assert verdict.verdict == "NEEDS_REVIEW"
    assert verdict.reason_code == "reconcile_consumed_but_not_applied"


def test_replaced_unverified_is_distinguishable_from_never_applied(world, monkeypatch) -> None:
    request = _plan(world)
    real_replace = EditExecutor._atomic_replace

    def replace_then_die(self, target: Path, content: bytes, pre_image: bytes) -> None:
        real_replace(self, target, content, pre_image)
        raise KeyboardInterrupt  # BaseException: no handler catches it

    monkeypatch.setattr(EditExecutor, "_atomic_replace", replace_then_die)
    with pytest.raises(KeyboardInterrupt):
        world["executor"].apply(request)
    monkeypatch.undo()

    intent = world["journal"].open_intents()[0]
    # Still INTENT_RECORDED: the "replaced" marker follows the replace call, and
    # the process died inside it. Either way reconciliation must not claim success.
    assert intent.state in {"INTENT_RECORDED", "REPLACED_UNVERIFIED"}
    report = _reconciler(world).reconcile()
    assert report.reconciliations[0].verdict == "COMPLETED_UNVERIFIED"


# ---------------------------------------------------------------------------
# C. Reconciliation verdicts
# ---------------------------------------------------------------------------


def test_verified_receipt_and_matching_bytes_is_the_only_clean_verdict(world) -> None:
    request = _plan(world)
    outcome = world["executor"].apply(request)
    assert outcome.status == "SUCCEEDED"
    # Force a reopen of the intent to exercise reconciliation on a finished edit.
    intent_id = (
        world["journal"]
        ._connection.execute("SELECT intent_id FROM mutation_intents")
        .fetchone()["intent_id"]
    )
    world["journal"]._connection.execute(
        "UPDATE mutation_intents SET state = 'REPLACED_UNVERIFIED' WHERE intent_id = ?",
        (intent_id,),
    )
    report = _reconciler(world).reconcile()
    assert report.reconciliations[0].verdict == "COMPLETED_VERIFIED"
    assert report.consistent


def test_a_user_edit_after_our_edit_is_never_explained_away(world) -> None:
    world["executor"].apply(_plan(world))
    intent_id = (
        world["journal"]
        ._connection.execute("SELECT intent_id FROM mutation_intents")
        .fetchone()["intent_id"]
    )
    world["journal"]._connection.execute(
        "UPDATE mutation_intents SET state = 'REPLACED_UNVERIFIED' WHERE intent_id = ?",
        (intent_id,),
    )
    world["tree"].readme.write_text("# the user kept working\n", encoding="utf-8")
    report = _reconciler(world).reconcile()
    verdict = report.reconciliations[0]
    assert verdict.verdict == "NEEDS_REVIEW"
    assert verdict.reason_code == "reconcile_third_state"
    assert not report.consistent


def test_an_unreadable_target_needs_review_rather_than_guessing(world) -> None:
    world["executor"].apply(_plan(world))
    intent_id = (
        world["journal"]
        ._connection.execute("SELECT intent_id FROM mutation_intents")
        .fetchone()["intent_id"]
    )
    world["journal"]._connection.execute(
        "UPDATE mutation_intents SET state = 'REPLACED_UNVERIFIED' WHERE intent_id = ?",
        (intent_id,),
    )
    (world["tree"].root / "README.md").unlink()
    # Without a target, the honest answer is "unknown".
    report = MutationReconciler(
        journal=world["journal"],
        receipts=world["receipts"],
        consumption=world["grants"].ledger,
        snapshots=world["vault"],
        resources=_Resolver(world["registry"]),
        read_target=lambda _path: (_ for _ in ()).throw(OSError(5, "gone")),
    ).reconcile()
    assert report.reconciliations[0].verdict == "NEEDS_REVIEW"
    assert report.reconciliations[0].reason_code == "reconcile_target_unreadable"


def test_reconciliation_never_mutates_the_file(world) -> None:
    world["executor"].apply(_plan(world))
    intent_id = (
        world["journal"]
        ._connection.execute("SELECT intent_id FROM mutation_intents")
        .fetchone()["intent_id"]
    )
    world["journal"]._connection.execute(
        "UPDATE mutation_intents SET state = 'REPLACED_UNVERIFIED' WHERE intent_id = ?",
        (intent_id,),
    )
    before = world["tree"].readme.read_bytes()
    _reconciler(world).reconcile()
    assert world["tree"].readme.read_bytes() == before
    # And the open intent is still open: reconciling is read-only evidence.
    assert len(world["journal"].open_intents()) == 1


# ---------------------------------------------------------------------------
# D. The journal is a real durable database, not memory
# ---------------------------------------------------------------------------


def test_the_journal_survives_process_death(world) -> None:
    intent = world["journal"].begin(
        task_id=uuid4(),
        step_id=uuid4(),
        approval_id=uuid4(),
        capability_id="fs.apply_approved_edit",
        resource_id="file:" + str(uuid4()),
        resource_version="a" * 64,
        pre_sha256="a" * 64,
        intended_post_sha256="b" * 64,
        expected_effect_sha256="c" * 64,
        now=NOW,
    )
    path = world["root"] / "journal.sqlite3"
    world["journal"].close()
    # A separate connection, as a new process would open.
    reopened = MutationJournal(path, clock=lambda: NOW)
    try:
        stored = reopened.get(intent.intent_id)
        assert stored.state == "INTENT_RECORDED"
        assert stored.pre_sha256 == "a" * 64
    finally:
        reopened.close()
        # Restore a live journal for the fixture teardown.
        world["journal"] = MutationJournal(path, clock=lambda: NOW)


def test_an_intent_cannot_be_resolved_twice(world) -> None:
    intent = world["journal"].begin(
        task_id=uuid4(),
        step_id=uuid4(),
        approval_id=uuid4(),
        capability_id="fs.apply_approved_edit",
        resource_id="file:" + str(uuid4()),
        resource_version="a" * 64,
        pre_sha256="a" * 64,
        intended_post_sha256="b" * 64,
        expected_effect_sha256="c" * 64,
        now=NOW,
    )
    world["journal"].resolve(intent.intent_id, state="VERIFIED", now=NOW)
    with pytest.raises(JournalError) as refused:
        world["journal"].resolve(intent.intent_id, state="FAILED", now=NOW)
    assert refused.value.reason_code == "journal_intent_already_resolved"


def test_an_intent_cannot_resolve_to_a_non_terminal_state(world) -> None:
    intent = world["journal"].begin(
        task_id=uuid4(),
        step_id=uuid4(),
        approval_id=uuid4(),
        capability_id="fs.apply_approved_edit",
        resource_id="file:" + str(uuid4()),
        resource_version="a" * 64,
        pre_sha256="a" * 64,
        intended_post_sha256="b" * 64,
        expected_effect_sha256="c" * 64,
        now=NOW,
    )
    with pytest.raises(JournalError) as refused:
        world["journal"].resolve(intent.intent_id, state="INTENT_RECORDED", now=NOW)
    assert refused.value.reason_code == "journal_state_invalid"


def test_the_journal_stores_no_file_content(world) -> None:
    """Only digests and identifiers: the journal must not become a second store."""

    world["executor"].apply(_plan(world))
    # WAL mode means recent writes live beside the database until a checkpoint,
    # so scan every file the journal owns.
    raw = b"".join(
        path.read_bytes() for path in world["root"].glob("journal.sqlite3*") if path.is_file()
    )
    assert raw
    assert ORIGINAL not in raw
    assert EDIT not in raw
    assert b"quick brown" not in raw
    # Digests are retained, which is what makes the journal useful.
    digests = {
        str(row["pre_sha256"])
        for row in world["journal"]._connection.execute("SELECT pre_sha256 FROM mutation_intents")
    }
    assert digests == {hashlib.sha256(ORIGINAL).hexdigest()}


def test_an_abandoned_intent_leaves_the_work_list(world) -> None:
    intent = world["journal"].begin(
        task_id=uuid4(),
        step_id=uuid4(),
        approval_id=uuid4(),
        capability_id="fs.apply_approved_edit",
        resource_id="file:" + str(uuid4()),
        resource_version="a" * 64,
        pre_sha256="a" * 64,
        intended_post_sha256="b" * 64,
        expected_effect_sha256="c" * 64,
        now=NOW,
    )
    assert len(world["journal"].open_intents()) == 1
    world["journal"].resolve(intent.intent_id, state="ABANDONED", now=NOW)
    assert world["journal"].open_intents() == ()


def test_the_journal_database_is_a_real_sqlite_file(world) -> None:
    path = world["root"] / "journal.sqlite3"
    assert path.exists()
    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert "mutation_intents" in tables


def test_an_unknown_intent_id_is_an_explicit_error(world) -> None:
    with pytest.raises(JournalError) as refused:
        world["journal"].get(uuid4())
    assert refused.value.reason_code == "journal_intent_missing"


def test_a_journal_less_executor_cannot_mutate_at_all(world) -> None:
    """S14-9 inverted this test: the journal is mandatory, not optional.

    S14-4 originally treated the journal as evidence produced alongside a
    mutation. That allowed a mutation-capable executor with no journal, whose
    writes would be invisible after a crash. It is now a precondition.
    """

    executor = EditExecutor(
        world["registry"],
        _Accepting(),
        world["vault"],
        world["receipts"],
        plans=world["store"],
        grants=world["grants"].ledger,
        clock=lambda: NOW,
    )
    before = world["tree"].readme.read_bytes()
    with pytest.raises(EditDenied) as refused:
        executor.apply(_plan(world))
    assert refused.value.reason_code == "journal_unavailable"
    # Nothing was written, and no use was spent: the refusal precedes all state.
    assert world["tree"].readme.read_bytes() == before
    assert world["grants"].ledger.pending() == ()


def test_the_reconciliation_report_lists_every_open_intent(world) -> None:
    for _ in range(3):
        world["journal"].begin(
            task_id=uuid4(),
            step_id=uuid4(),
            approval_id=uuid4(),
            capability_id="fs.apply_approved_edit",
            resource_id=resolve(world["registry"], "README.md"),
            resource_version="a" * 64,
            pre_sha256="a" * 64,
            intended_post_sha256="b" * 64,
            expected_effect_sha256="c" * 64,
            now=NOW,
        )
    report = _reconciler(world).reconcile()
    assert len(report.reconciliations) == 3
    assert all(item.verdict == "NEEDS_REVIEW" for item in report.reconciliations)


def test_undo_also_journals_its_intent(world) -> None:
    """Undo is a mutation too, so it gets the same pre-mutation record."""

    original = world["tree"].readme.read_bytes()
    request = _plan(world)
    applied = world["executor"].apply(request)
    assert applied.status == "SUCCEEDED"

    undo_request = _plan_undo(world, applied=applied, original=original)
    restored = world["executor"].undo(
        undo_request,
        snapshot_id=UUID(applied.snapshot_id),
        receipt_id=applied.receipt.receipt_id,
    )
    assert restored.status == "SUCCEEDED"
    states = [
        row["state"]
        for row in world["journal"]._connection.execute(
            "SELECT state FROM mutation_intents ORDER BY attempted_at"
        )
    ]
    assert states == ["VERIFIED", "VERIFIED"]


def _plan_undo(world, *, applied, original: bytes) -> EditRequest:
    registry, planner, store = world["registry"], world["planner"], world["store"]
    task_id, approval_id = uuid4(), uuid4()
    resource_id = resolve(registry, "README.md")
    revision = planner.plan(
        task_id,
        PlanIntent(
            goal=PlanGoal.UNDO_EDIT,
            resource_id=resource_id,
            arguments={
                "resource_id": resource_id,
                "step_id": str(uuid4()),
                "approval_id": str(approval_id),
                "expected_sha256": hashlib.sha256(
                    (world["tree"].root / "README.md").read_bytes()
                ).hexdigest(),
                "receipt_id": str(applied.receipt.receipt_id),
                "snapshot_id": str(applied.snapshot_id),
            },
            summary="Undo",
            proposed_content=original,
        ),
        revision=1,
    )
    plan_hash = "b" * 64
    world["grants"].bind(approval_id=approval_id, task_id=task_id, now=NOW, plan_hash=plan_hash)
    store.create_task("undo", task_id=task_id, now=NOW)
    store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
    store.save_plan(revision.plan)
    return EditRequest(
        task_id=task_id,
        step_id=revision.step_id,
        approval_id=approval_id,
        plan_revision=1,
        plan_hash=plan_hash,
        resource_id=resource_id,
        expected_sha256=hashlib.sha256((world["tree"].root / "README.md").read_bytes()).hexdigest(),
        proposed_content=original,
        expected_effect_sha256=str(
            revision.plan.steps[0].expected_effect["approved_effect_digest"]
        ),
    )
