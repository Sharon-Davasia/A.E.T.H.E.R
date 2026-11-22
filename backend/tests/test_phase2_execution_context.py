"""S14-9: execution-local state, and a mandatory durable journal.

Two defects are covered.

1. ``_consumption_id`` was mutable executor state. Two overlapping operations
   shared it, so operation B could resolve operation A's consumption, crediting a
   successful outcome to a use it never spent. Consumption identity is now
   created per attempt and passed explicitly; this suite proves the isolation by
   interleaving two real operations and checking each resolved only its own use.

2. The journal was optional. S14-4 wrote it only when configured, which left an
   executor shape that could mutate with no durable record. It is now mandatory:
   a journal-less executor refuses before it spends a use or touches a file.
"""

from __future__ import annotations

import hashlib
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aether.core.edits.executor import EditDenied, EditExecutor, EditRequest
from aether.core.edits.journal import MutationJournal
from aether.core.edits.receipts import ReceiptStore
from aether.core.persistence.sqlite_store import PersistentTaskState, SQLiteTaskStore
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


def _plan(world, *, relative: str = "README.md", proposed: bytes):
    registry, planner, store = world["registry"], world["planner"], world["store"]
    task_id, approval_id = uuid4(), uuid4()
    resource_id = resolve(registry, relative)
    original = (world["tree"].root / relative).read_bytes()
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
            summary=f"Edit {relative}",
            proposed_content=proposed,
        ),
        revision=1,
    )
    plan_hash = uuid4().hex + uuid4().hex
    world["grants"].bind(approval_id=approval_id, task_id=task_id, now=NOW, plan_hash=plan_hash)
    store.create_task(f"edit-{relative}", task_id=task_id, now=NOW)
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


# ---------------------------------------------------------------------------
# A. No shared mutable state
# ---------------------------------------------------------------------------


def test_the_executor_holds_no_consumption_state_between_operations(world) -> None:
    """The attribute that caused the defect must not exist at all."""

    assert not hasattr(world["executor"], "_consumption_id")
    outcome = world["executor"].apply(_plan(world, proposed=b"# One\n\nBody one.\n"))
    assert outcome.status == "SUCCEEDED"
    # Still nothing retained after a completed operation.
    assert not hasattr(world["executor"], "_consumption_id")


def test_two_interleaved_operations_each_resolve_their_own_consumption(world, monkeypatch) -> None:
    """The decisive test: operation B must not resolve operation A's use.

    Both operations consume, then are forced to interleave before either
    resolves. Each receipt must show its own mutation, and the consumption table
    must show two distinct SUCCEEDED consumptions rather than one consumed twice.
    """

    # Distinct targets: a second edit of the same file would legitimately be
    # stale, so using one file would test the freshness guard instead of the
    # shared-state defect.
    first = _plan(world, relative="README.md", proposed=b"# First\n\nFirst body.\n")
    second = _plan(world, relative="src/module.py", proposed=b"# Second\n\nSecond body.\n")
    executor = world["executor"]

    consumed: list[UUID] = []
    resolved: list[tuple[UUID, str]] = []
    first_consumed = threading.Event()
    second_consumed = threading.Event()

    real_consume = executor._consume_grant

    def interleaved_consume(request, step, binding, *, capability_id="fs.apply_approved_edit"):
        consumption_id = real_consume(request, step, binding, capability_id=capability_id)
        consumed.append(consumption_id)
        if len(consumed) == 1:
            first_consumed.set()
            # Hold the first operation until the second has also consumed.
            second_consumed.wait(timeout=5)
        else:
            second_consumed.set()
        return consumption_id

    real_resolve = executor._resolve_consumption

    def recording_resolve(consumption_id, state, detail):
        resolved.append((consumption_id, state))
        return real_resolve(consumption_id, state, detail)

    monkeypatch.setattr(executor, "_consume_grant", interleaved_consume)
    monkeypatch.setattr(executor, "_resolve_consumption", recording_resolve)

    outcomes: dict[str, object] = {}

    def run(label, request):
        try:
            outcomes[label] = executor.apply(request)
        except Exception as exc:  # pragma: no cover - surfaced by the asserts
            outcomes[label] = exc

    thread_a = threading.Thread(target=run, args=("a", first))
    thread_b = threading.Thread(target=run, args=("b", second))
    thread_a.start()
    thread_b.start()
    thread_a.join(timeout=20)
    thread_b.join(timeout=20)

    assert not thread_a.is_alive()
    assert not thread_b.is_alive()

    # Both operations completed and consumed distinct uses.
    assert len(consumed) == 2
    assert len(set(consumed)) == 2
    # And each resolved its OWN id exactly once -- this is the defect.
    resolved_ids = [item[0] for item in resolved]
    assert sorted(str(item) for item in resolved_ids) == sorted(str(item) for item in consumed)
    assert set(resolved_ids) == set(consumed)
    # Each consumption reached a terminal state exactly once: neither was
    # resolved twice, and neither was left PENDING by the interleaving.
    rows = list(
        world["grants"].ledger._connection.execute(
            "SELECT consumption_id, state FROM capability_grant_consumptions"
        )
    )
    by_id = {UUID(str(row["consumption_id"])): str(row["state"]) for row in rows}
    for consumption_id in consumed:
        assert by_id[consumption_id] == "SUCCEEDED"
    assert len(rows) == 2


def test_a_failed_operation_does_not_resolve_the_other_operations_consumption(
    world, monkeypatch
) -> None:
    """A failure in one attempt leaves the other attempt's accounting alone."""

    good = _plan(world, relative="README.md", proposed=b"# Good\n\nGood body.\n")
    bad = _plan(world, relative="src/module.py", proposed=b"# Bad\n\nBad body.\n")
    executor = world["executor"]

    real_replace = EditExecutor._atomic_replace
    state = {"calls": 0}

    def fail_second(self, target, content, pre_image):
        state["calls"] += 1
        if content == b"# Bad\n\nBad body.\n":
            raise EditDenied("synthetic_replace_failure", "injected failure")
        real_replace(self, target, content, pre_image)

    monkeypatch.setattr(EditExecutor, "_atomic_replace", fail_second)

    good_outcome = executor.apply(good)
    bad_outcome = executor.apply(bad)

    assert good_outcome.status == "SUCCEEDED"
    assert bad_outcome.status == "FAILED"
    # The good consumption resolved SUCCEEDED, the bad one FAILED, independently.
    rows = list(
        world["grants"].ledger._connection.execute(
            "SELECT approval_id, state FROM capability_grant_consumptions"
        )
    )
    by_approval = {str(row["approval_id"]): str(row["state"]) for row in rows}
    assert by_approval[str(good.approval_id)] == "SUCCEEDED"
    assert by_approval[str(bad.approval_id)] == "FAILED"


# ---------------------------------------------------------------------------
# B. The journal is mandatory
# ---------------------------------------------------------------------------


def test_a_journal_less_executor_refuses_before_any_state_changes(world) -> None:
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
    request = _plan(world, proposed=b"# Never\n\nNever written.\n")

    with pytest.raises(EditDenied) as refused:
        executor.apply(request)

    assert refused.value.reason_code == "journal_unavailable"
    # No file change, no snapshot, no receipt, no consumed use.
    assert world["tree"].readme.read_bytes() == before
    assert world["grants"].ledger.pending() == ()
    assert world["grants"].ledger.uses_remaining(request.approval_id) == world["grants"].uses
    assert world["receipts"].for_task("edit") == ()
    assert world["journal"].open_intents() == ()


def test_the_journal_refusal_precedes_grant_consumption(world, monkeypatch) -> None:
    """Ordering: journal availability is checked before a use is spent.

    Otherwise a refused mutation would leave a spent use behind, which is exactly
    the orphaned-consumption state S14-8 has to report.
    """

    journalless = EditExecutor(
        world["registry"],
        _Accepting(),
        world["vault"],
        world["receipts"],
        plans=world["store"],
        grants=world["grants"].ledger,
        clock=lambda: NOW,
    )
    consumed: list[object] = []
    real_consume = world["grants"].ledger.consume

    def recording_consume(**kwargs):
        consumed.append(kwargs.get("consumption_id"))
        return real_consume(**kwargs)

    monkeypatch.setattr(world["grants"].ledger, "consume", recording_consume)
    with pytest.raises(EditDenied):
        journalless.apply(_plan(world, proposed=b"# Never\n\nBody.\n"))
    assert consumed == []


def test_a_journal_that_fails_midway_still_blocks_the_mutation(world, monkeypatch) -> None:
    """Failure injection: an unwritable journal means no mutation."""

    def refuse(**_fields):
        raise EditDenied("journal_intent_failed", "simulated journal failure")

    monkeypatch.setattr(world["journal"], "begin", refuse)
    before = world["tree"].readme.read_bytes()
    with pytest.raises(Exception) as refused:
        world["executor"].apply(_plan(world, proposed=b"# Never\n\nBody.\n"))
    assert getattr(refused.value, "reason_code", "") in {
        "journal_intent_failed",
        "journal_unavailable",
    }
    assert world["tree"].readme.read_bytes() == before


def test_every_mutation_capable_executor_configuration_requires_a_journal(world) -> None:
    """There is no supported executor shape that mutates without a journal."""

    import inspect

    source = inspect.getsource(EditExecutor._mutate)
    # The refusal exists in the mutation path itself, not only in apply().
    assert "journal_unavailable" in source
    assert "self._journal is None" in source
    # And the mutation path is reached only through _mutate.
    for method in ("apply", "undo"):
        assert "_mutate(" in inspect.getsource(getattr(EditExecutor, method))


def test_undo_also_requires_a_journal(world) -> None:
    original = world["tree"].readme.read_bytes()
    applied = world["executor"].apply(_plan(world, proposed=b"# Edited\n\nBody.\n"))
    assert applied.status == "SUCCEEDED"

    journalless = EditExecutor(
        world["registry"],
        _Accepting(),
        world["vault"],
        world["receipts"],
        plans=world["store"],
        grants=world["grants"].ledger,
        clock=lambda: NOW,
    )
    undo_request = _plan_undo(world, applied=applied, original=original)
    before = world["tree"].readme.read_bytes()
    with pytest.raises(EditDenied) as refused:
        journalless.undo(
            undo_request,
            snapshot_id=UUID(applied.snapshot_id),
            receipt_id=applied.receipt.receipt_id,
        )
    assert refused.value.reason_code == "journal_unavailable"
    assert world["tree"].readme.read_bytes() == before


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
    plan_hash = uuid4().hex + uuid4().hex
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


# ---------------------------------------------------------------------------
# C. Both operations journal independently
# ---------------------------------------------------------------------------


def test_two_sequential_operations_produce_two_distinct_intents(world) -> None:
    first = world["executor"].apply(
        _plan(world, relative="README.md", proposed=b"# A\n\nBody A.\n")
    )
    second = world["executor"].apply(
        _plan(world, relative="src/module.py", proposed=b"# B\n\nBody B.\n")
    )
    assert first.status == "SUCCEEDED"
    assert second.status == "SUCCEEDED"
    rows = list(
        world["journal"]._connection.execute("SELECT intent_id, state FROM mutation_intents")
    )
    assert len(rows) == 2
    assert {str(row["state"]) for row in rows} == {"VERIFIED"}
    # Nothing is left for reconciliation.
    assert world["journal"].open_intents() == ()


def test_no_operation_may_begin_an_intent_for_another_operations_step(world) -> None:
    """Intent identity is bound to the step, so intents cannot be borrowed."""

    from aether.core.edits.journal import JournalError

    request = _plan(world, proposed=b"# A\n\nBody A.\n")
    world["journal"].begin(
        task_id=request.task_id,
        step_id=request.step_id,
        approval_id=request.approval_id,
        capability_id="fs.apply_approved_edit",
        resource_id=request.resource_id,
        target_path=world["tree"].root / "README.md",
        resource_version=request.expected_sha256,
        pre_sha256="a" * 64,
        intended_post_sha256="b" * 64,
        expected_effect_sha256="c" * 64,
        now=NOW,
    )
    with pytest.raises(JournalError) as refused:
        world["journal"].begin(
            task_id=request.task_id,
            step_id=request.step_id,
            approval_id=request.approval_id,
            capability_id="fs.apply_approved_edit",
            resource_id=request.resource_id,
            target_path=world["tree"].root / "README.md",
            resource_version=request.expected_sha256,
            pre_sha256="a" * 64,
            intended_post_sha256="d" * 64,
            expected_effect_sha256="e" * 64,
            now=NOW,
        )
    assert refused.value.reason_code == "journal_intent_already_recorded"
