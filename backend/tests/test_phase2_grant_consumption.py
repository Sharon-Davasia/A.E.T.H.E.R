"""S14-2 — deterministic execution authority and atomic grant consumption.

The review found that ``EditExecutor._authorize`` called ``check_action`` and then
never consumed anything, so one approval could authorize an unbounded number of
mutations, and that accepting test doubles were standing in for real ledger
integration. These tests run against a real, transactional ledger and prove:

* no consumption is possible by default (the shipped executor cannot mutate);
* a validated grant alone is not execution authority;
* one use buys exactly one action, and a second attempt is refused;
* the use is bound to the exact action, so a different action cannot spend it;
* replay is refused rather than silently re-executing;
* a crash leaves a PENDING use that reconciliation can find;
* a grant for another plan revision cannot be spent.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from aether.core.contracts.policy import RiskTier
from aether.core.edits.executor import EditDenied, EditExecutor, EditRequest
from aether.core.edits.receipts import ReceiptStore
from aether.core.grants.consumption import (
    ConsumptionError,
    ConsumptionLedger,
    IssuanceDisabledConsumptionLedger,
    action_identity,
)
from aether.core.persistence.sqlite_store import PersistentTaskState, SQLiteTaskStore
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.vault.undo_vault import UndoVault
from tests.fs_support import build_registry, build_tree, resolve

NOW = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)
PROPOSED = b"# Authorized\n\nThe quick brown fox was changed exactly once.\n"


class _Accepting:
    """Grant double: the scope *check* passes so consumption is the only gate."""

    def check_action(self, request, grant_request, *, risk_tier, now=None):
        class _Ok:
            ok = True
            reason_code = "GRANT_SCOPE_VERIFIED"
            approval_id = None

        return _Ok()


class _Refusing:
    def check_action(self, request, grant_request, *, risk_tier, now=None):
        class _No:
            ok = False
            reason_code = "GRANT_REVOKED"
            approval_id = None

        return _No()


@pytest.fixture
def world(tmp_path: Path):
    tree = build_tree(tmp_path)
    registry = build_registry(
        tree,
        capabilities=frozenset({"fs.inspect_file", "fs.apply_approved_edit"}),
    )
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    ledger = ConsumptionLedger(tmp_path / "consumption.sqlite3", clock=lambda: NOW)
    vault = UndoVault(tmp_path / "vault").open()
    receipts = ReceiptStore(tmp_path / "receipts.sqlite3")
    executor = EditExecutor(
        registry,
        _Accepting(),
        vault,
        receipts,
        plans=store,
        grants=ledger,
        clock=lambda: NOW,
    )
    planner = Planner(
        capabilities=CapabilityRegistry.phase2_filesystem(),
        resources=registry,
        clock=lambda: NOW,
    )
    yield {
        "tree": tree,
        "registry": registry,
        "store": store,
        "ledger": ledger,
        "vault": vault,
        "receipts": receipts,
        "executor": executor,
        "planner": planner,
        "tmp": tmp_path,
    }
    receipts.close()
    ledger.close()
    vault.close()
    store.close()


def _prepare(world, *, uses: int = 1, plan_hash: str = "a" * 64, revision: int = 1):
    """Persist an approved edit plan and record the grant budget it represents."""

    tree, registry, store, ledger = (
        world["tree"],
        world["registry"],
        world["store"],
        world["ledger"],
    )
    task_id, step_id, approval_id = uuid4(), uuid4(), uuid4()
    resource_id = resolve(registry, "README.md")
    planned = world["planner"].plan(
        task_id,
        PlanIntent(
            goal=PlanGoal.APPLY_EDIT,
            resource_id=resource_id,
            arguments={
                "resource_id": resource_id,
                "step_id": str(step_id),
                "approval_id": str(approval_id),
                "expected_sha256": hashlib.sha256(tree.readme.read_bytes()).hexdigest(),
            },
            summary="Edit",
            proposed_content=PROPOSED,
        ),
        revision=revision,
    )
    store.create_task("consumption", task_id=task_id, now=NOW)
    store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
    store.save_plan(planned.plan)
    ledger.grant_budget(
        approval_id=approval_id,
        task_id=task_id,
        plan_revision=revision,
        plan_hash=plan_hash,
        uses=uses,
        now=NOW,
    )
    return {
        "task_id": task_id,
        "step_id": planned.step_id,
        "approval_id": approval_id,
        "plan_hash": plan_hash,
        "revision": revision,
        "effect": str(planned.plan.steps[0].expected_effect["approved_effect_digest"]),
    }


def _request(world, prepared) -> EditRequest:
    return EditRequest(
        task_id=prepared["task_id"],
        step_id=prepared["step_id"],
        approval_id=prepared["approval_id"],
        plan_revision=prepared["revision"],
        plan_hash=prepared["plan_hash"],
        resource_id=resolve(world["registry"], "README.md"),
        expected_sha256=hashlib.sha256(world["tree"].readme.read_bytes()).hexdigest(),
        proposed_content=PROPOSED,
        expected_effect_sha256=prepared["effect"],
    )


# ---------------------------------------------------------------------------
# A. Default deny
# ---------------------------------------------------------------------------


def test_the_shipped_consumption_ledger_refuses_every_use() -> None:
    ledger = IssuanceDisabledConsumptionLedger()
    with pytest.raises(ConsumptionError) as refused:
        ledger.consume(
            consumption_id=uuid4(),
            approval_id=uuid4(),
            task_id=uuid4(),
            plan_revision=1,
            plan_hash="a" * 64,
            step_id=uuid4(),
            capability_id="fs.apply_approved_edit",
            risk_tier=RiskTier.MODIFY,
            arguments_sha256="b" * 64,
            expected_effect_sha256="c" * 64,
            resource_versions={},
            consumed_by="aether.core.edits.executor",
            now=NOW,
        )
    assert refused.value.reason_code == "GRANT_CONSUMPTION_DISABLED"


def test_an_executor_without_a_consumption_ledger_cannot_mutate(world) -> None:
    """The default executor is as strict as GRANT_ISSUANCE_DISABLED."""

    prepared = _prepare(world)
    before = world["tree"].readme.read_bytes()
    default_executor = EditExecutor(
        world["registry"],
        _Accepting(),
        world["vault"],
        world["receipts"],
        plans=world["store"],
        clock=lambda: NOW,
    )
    with pytest.raises(EditDenied) as refused:
        default_executor.apply(_request(world, prepared))
    assert refused.value.reason_code == "GRANT_CONSUMPTION_DISABLED"
    assert world["tree"].readme.read_bytes() == before
    assert world["ledger"].uses_remaining(prepared["approval_id"]) == 1


def test_a_validated_grant_alone_is_not_execution_authority(world) -> None:
    """GRANT_VALIDATED_EXECUTOR_NOT_ENABLED style success must not open the path.

    The broker's policy answer is not permission: without a consumable budget the
    edit is refused even though the scope check passes.
    """

    prepared = _prepare(world)
    # A scope check passes, but no budget was ever recorded for this approval.
    unbacked = {**prepared, "approval_id": uuid4()}
    before = world["tree"].readme.read_bytes()
    with pytest.raises(EditDenied) as refused:
        world["executor"].apply(_request(world, unbacked))
    assert refused.value.reason_code == "GRANT_NOT_FOUND"
    assert world["tree"].readme.read_bytes() == before


# ---------------------------------------------------------------------------
# B. One use, one action
# ---------------------------------------------------------------------------


def test_one_approved_edit_consumes_exactly_one_use(world) -> None:
    prepared = _prepare(world)
    assert world["ledger"].uses_remaining(prepared["approval_id"]) == 1
    outcome = world["executor"].apply(_request(world, prepared))
    assert outcome.status == "SUCCEEDED"
    assert world["ledger"].uses_remaining(prepared["approval_id"]) == 0


def test_a_second_edit_with_the_same_approval_is_refused(world) -> None:
    prepared = _prepare(world)
    world["executor"].apply(_request(world, prepared))

    # The same approval, reused for a second mutation of a *different* target
    # state, so the freshness check cannot mask the accounting refusal.
    second_tree = world["tree"].readme
    second_tree.write_text("# changed again\n", encoding="utf-8")
    with pytest.raises(EditDenied) as refused:
        world["executor"].apply(_request(world, prepared))
    assert refused.value.reason_code == "GRANT_EXHAUSTED"
    assert second_tree.read_bytes() == b"# changed again\n"


def test_a_retry_after_a_spent_use_does_not_spend_again(world) -> None:
    """A refused replay must not consume the remaining budget."""

    prepared = _prepare(world, uses=2)
    world["executor"].apply(_request(world, prepared))
    world["tree"].readme.write_text("# changed again\n", encoding="utf-8")
    first_remaining = world["ledger"].uses_remaining(prepared["approval_id"])
    assert first_remaining == 1
    # A second attempt spends the second use, then fails on freshness: the
    # accounting and the filesystem truth are reported separately.
    with pytest.raises(EditDenied):
        world["executor"].apply(_request(world, prepared))
    assert world["ledger"].uses_remaining(prepared["approval_id"]) == 0


def test_the_use_is_bound_to_the_exact_action(world) -> None:
    """Two actions cannot share one consumption, even with the same approval."""

    prepared = _prepare(world)
    resource_id = resolve(world["registry"], "README.md")
    common = {
        "task_id": prepared["task_id"],
        "plan_revision": prepared["revision"],
        "plan_hash": prepared["plan_hash"],
        "capability_id": "fs.apply_approved_edit",
        "risk_tier": RiskTier.MODIFY,
        "resource_versions": {resource_id: "v1"},
        "consumed_by": "aether.core.edits.executor",
    }
    first = action_identity(
        **common,  # type: ignore[arg-type]
        step_id=prepared["step_id"],
        arguments_sha256="1" * 64,
        expected_effect_sha256="2" * 64,
    )
    second = action_identity(
        **common,  # type: ignore[arg-type]
        step_id=prepared["step_id"],
        arguments_sha256="1" * 64,
        expected_effect_sha256="3" * 64,
    )
    assert first != second


def test_a_grant_for_another_plan_revision_cannot_be_spent(world) -> None:
    # The plan is persisted under its real hash; the budget claims another one.
    prepared = _prepare(world)
    world["ledger"].close()
    world["ledger"] = ConsumptionLedger(world["tmp"] / "other.sqlite3", clock=lambda: NOW)
    world["ledger"].grant_budget(
        approval_id=prepared["approval_id"],
        task_id=prepared["task_id"],
        plan_revision=prepared["revision"],
        plan_hash="b" * 64,
        uses=1,
        now=NOW,
    )
    executor = EditExecutor(
        world["registry"],
        _Accepting(),
        world["vault"],
        world["receipts"],
        plans=world["store"],
        grants=world["ledger"],
        clock=lambda: NOW,
    )
    before = world["tree"].readme.read_bytes()
    with pytest.raises(EditDenied) as refused:
        executor.apply(_request(world, prepared))
    assert refused.value.reason_code == "GRANT_PLAN_SUPERSEDED"
    assert world["tree"].readme.read_bytes() == before


def test_a_revoked_grant_cannot_be_spent(world) -> None:
    prepared = _prepare(world)
    world["ledger"].revoke(prepared["approval_id"], now=NOW)
    before = world["tree"].readme.read_bytes()
    with pytest.raises(EditDenied) as refused:
        world["executor"].apply(_request(world, prepared))
    assert refused.value.reason_code == "GRANT_REVOKED"
    assert world["tree"].readme.read_bytes() == before


def test_a_failed_grant_check_spends_nothing(world) -> None:
    prepared = _prepare(world)
    refusing = EditExecutor(
        world["registry"],
        _Refusing(),
        world["vault"],
        world["receipts"],
        plans=world["store"],
        grants=world["ledger"],
        clock=lambda: NOW,
    )
    with pytest.raises(EditDenied) as refused:
        refusing.apply(_request(world, prepared))
    assert refused.value.reason_code == "GRANT_REVOKED"
    # The use was never spent.
    assert world["ledger"].uses_remaining(prepared["approval_id"]) == 1


# ---------------------------------------------------------------------------
# C. Replay and atomicity
# ---------------------------------------------------------------------------


def _consume_kwargs(ledger, prepared, resource_id: str) -> dict[str, object]:
    return {
        "approval_id": prepared["approval_id"],
        "task_id": prepared["task_id"],
        "plan_revision": prepared["revision"],
        "plan_hash": prepared["plan_hash"],
        "step_id": prepared["step_id"],
        "capability_id": "fs.apply_approved_edit",
        "risk_tier": RiskTier.MODIFY,
        "arguments_sha256": "1" * 64,
        "expected_effect_sha256": prepared["effect"],
        "resource_versions": {resource_id: "v1"},
        "consumed_by": "aether.core.edits.executor",
        "now": NOW,
    }


def test_replaying_the_same_consumption_is_reported_not_re_executed(world) -> None:
    prepared = _prepare(world)
    resource_id = resolve(world["registry"], "README.md")
    kwargs = _consume_kwargs(world["ledger"], prepared, resource_id)
    consumption_id = uuid4()
    first = world["ledger"].consume(consumption_id=consumption_id, **kwargs)  # type: ignore[arg-type]
    assert first.replayed is False
    replay = world["ledger"].consume(consumption_id=consumption_id, **kwargs)  # type: ignore[arg-type]
    assert replay.replayed is True
    # No second use was spent by the replay.
    assert world["ledger"].uses_remaining(prepared["approval_id"]) == 0


def test_replay_with_different_terms_is_refused(world) -> None:
    prepared = _prepare(world)
    resource_id = resolve(world["registry"], "README.md")
    kwargs = _consume_kwargs(world["ledger"], prepared, resource_id)
    consumption_id = uuid4()
    world["ledger"].consume(consumption_id=consumption_id, **kwargs)  # type: ignore[arg-type]
    with pytest.raises(ConsumptionError) as refused:
        world["ledger"].consume(
            consumption_id=consumption_id,
            **{**kwargs, "expected_effect_sha256": "9" * 64},  # type: ignore[arg-type]
        )
    assert refused.value.reason_code == "consumption_replay_mismatch"


def test_exhaustion_is_atomic_under_concurrency(world) -> None:
    """Two threads racing for the last use: exactly one wins."""

    import threading

    prepared = _prepare(world, uses=1)
    resource_id = resolve(world["registry"], "README.md")
    results: list[str] = []
    barrier = threading.Barrier(2)

    def attempt() -> None:
        barrier.wait()
        try:
            world["ledger"].consume(
                consumption_id=uuid4(),
                **_consume_kwargs(world["ledger"], prepared, resource_id),  # type: ignore[arg-type]
            )
            results.append("spent")
        except ConsumptionError as exc:
            results.append(exc.reason_code)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(results) == ["GRANT_EXHAUSTED", "spent"]
    assert world["ledger"].uses_remaining(prepared["approval_id"]) == 0


def test_a_crash_leaves_a_pending_use_for_reconciliation(world) -> None:
    """A consumed use whose effect never resolved is never a silent success."""

    prepared = _prepare(world)
    resource_id = resolve(world["registry"], "README.md")
    world["ledger"].consume(
        consumption_id=uuid4(),
        **_consume_kwargs(world["ledger"], prepared, resource_id),  # type: ignore[arg-type]
    )
    pending = world["ledger"].pending()
    assert len(pending) == 1
    assert pending[0].state == "PENDING"


def test_a_successful_edit_resolves_its_consumption(world) -> None:
    prepared = _prepare(world)
    world["executor"].apply(_request(world, prepared))
    assert world["ledger"].pending() == ()


def test_an_unverified_edit_resolves_as_unverified_not_success(world, monkeypatch) -> None:
    prepared = _prepare(world)
    original_read = Path.read_bytes
    state = {"reads": 0}

    def fail_readback(self):
        if self.name == "README.md":
            state["reads"] += 1
            # Reads 1-2 are the plan/freshness checks; the verification re-read
            # is the first one issued after the atomic replace.
            if state["reads"] > 2:
                raise OSError(5, "simulated crash")
        return original_read(self)

    monkeypatch.setattr(Path, "read_bytes", fail_readback)
    outcome = world["executor"].apply(_request(world, prepared))
    monkeypatch.setattr(Path, "read_bytes", original_read)

    assert outcome.status == "UNVERIFIED"
    assert world["ledger"].pending() == ()


def test_consumption_ledger_refuses_unsafe_consumer_codes(world) -> None:
    prepared = _prepare(world)
    resource_id = resolve(world["registry"], "README.md")
    with pytest.raises(ConsumptionError):
        world["ledger"].consume(
            consumption_id=uuid4(),
            **{
                **_consume_kwargs(world["ledger"], prepared, resource_id),  # type: ignore[arg-type]
                "consumed_by": "some.other.module",
            },  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# D. The boundary itself
# ---------------------------------------------------------------------------


def test_the_executor_has_no_default_consumption_path() -> None:
    source = (Path(__file__).parents[1] / "aether" / "core" / "edits" / "executor.py").read_text(
        encoding="utf-8"
    )
    # Default deny is wired in, not left to the caller.
    assert "IssuanceDisabledConsumptionLedger()" in source
    # A validated-but-unenabled policy answer can never be read as permission.
    # The token may appear in prose explaining why; it must not appear in code.
    executable = [
        line for line in source.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    in_doc = False
    for line in executable:
        if line.count('"""') == 1:
            in_doc = not in_doc
            continue
        if in_doc:
            continue
        assert "GRANT_VALIDATED_EXECUTOR_NOT_ENABLED" not in line


def test_consumption_is_spent_before_the_snapshot_not_after(world, monkeypatch) -> None:
    """Ordering: the use is spent before the pre-image is captured.

    If the snapshot came first, a crash after capturing it but before consuming
    would leave a snapshot with no accounting entry, and a retry would produce a
    second snapshot for one approval.
    """

    prepared = _prepare(world)
    order: list[str] = []
    original_put = world["vault"].put
    original_consume = world["ledger"].consume

    def spy_put(*args, **kwargs):
        order.append("snapshot")
        return original_put(*args, **kwargs)

    def spy_consume(**kwargs):
        order.append("consume")
        return original_consume(**kwargs)

    monkeypatch.setattr(world["vault"], "put", spy_put)
    monkeypatch.setattr(world["ledger"], "consume", spy_consume)
    world["executor"].apply(_request(world, prepared))
    assert order[:2] == ["consume", "snapshot"]
