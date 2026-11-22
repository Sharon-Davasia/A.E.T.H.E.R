"""S14-3 — Undo is a distinct capability with its own exact authorization.

The review found that undo was authorized through ``fs.apply_approved_edit`` and
that it did not compare the current file against the original edit's verified
post-image before treating an ordinary undo as conflict-free.

This module proves:

* ``fs.undo_edit`` exists as its own registered, typed capability;
* an edit approval cannot authorize an undo, and an undo approval cannot
  authorize an edit;
* undo requires the matching receipt and the matching snapshot;
* undo refuses when the receipt names a different resource;
* undo refuses when the edit's effect was never verified (UNVERIFIED/FAILED);
* undo refuses when a newer user edit intervened, instead of silently
  overwriting it;
* a forged undo scope (wrong receipt, wrong snapshot, wrong current content) is
  refused;
* successful undo restores the exact original bytes and produces its own receipt.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aether.core.contracts.policy import RiskTier
from aether.core.edits.executor import EditDenied, EditExecutor, EditRequest
from aether.core.edits.receipts import ReceiptStore
from aether.core.persistence.sqlite_store import PersistentTaskState, SQLiteTaskStore
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner, PlannerError
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.vault.undo_vault import UndoVault
from tests.fs_support import ConsumptionHarness, build_registry, build_tree, resolve

NOW = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)
EDIT = b"# Edited\n\nThe quick brown fox was edited exactly once.\n"
# The fixture README as build_tree writes it.
ORIGINAL = b"# Synthetic\n\nThe quick brown fox needs a needle.\n"


class _Accepting:
    def __init__(self) -> None:
        self.capabilities: list[str] = []

    def check_action(self, request, grant_request, *, risk_tier, now=None):
        self.capabilities.append(request.capability_id)

        class _Ok:
            ok = True
            reason_code = "GRANT_SCOPE_VERIFIED"
            approval_id = None

        return _Ok()


@pytest.fixture
def world(tmp_path: Path):
    tree = build_tree(tmp_path)
    registry = build_registry(
        tree,
        capabilities=frozenset({"fs.inspect_file", "fs.apply_approved_edit", "fs.undo_edit"}),
    )
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    grants = ConsumptionHarness(tmp_path, clock=lambda: NOW, uses=16)
    vault = UndoVault(tmp_path / "vault").open()
    receipts = ReceiptStore(tmp_path / "receipts.sqlite3")
    authority = _Accepting()
    executor = EditExecutor(
        registry,
        authority,
        vault,
        receipts,
        plans=store,
        grants=grants.ledger,
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
        "grants": grants,
        "vault": vault,
        "receipts": receipts,
        "executor": executor,
        "authority": authority,
        "planner": planner,
        "tmp": tmp_path,
        "capabilities": CapabilityRegistry.phase2_filesystem(),
    }
    grants.close()
    receipts.close()
    vault.close()
    store.close()


def _plan(
    world,
    *,
    goal: PlanGoal,
    proposed: bytes | None = None,
    approval_id=None,
    extra_arguments: dict[str, object] | None = None,
):
    """Persist a plan for one intent and record the budget it represents."""

    registry, tree, store, grants = (
        world["registry"],
        world["tree"],
        world["store"],
        world["grants"],
    )
    task_id = uuid4()
    approval_id = approval_id or uuid4()
    resource_id = resolve(registry, "README.md")
    arguments: dict[str, object] = {
        "resource_id": resource_id,
        "step_id": str(uuid4()),
        "approval_id": str(approval_id),
        "expected_sha256": hashlib.sha256(tree.readme.read_bytes()).hexdigest(),
        **(extra_arguments or {}),
    }
    planned = world["planner"].plan(
        task_id,
        PlanIntent(
            goal=goal,
            resource_id=resource_id,
            arguments=arguments,
            summary=goal.value,
            proposed_content=proposed,
        ),
        revision=1,
    )
    store.create_task("undo", task_id=task_id, now=NOW)
    store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
    plan_hash = store.save_plan(planned.plan)
    grants.bind(approval_id=approval_id, task_id=task_id, now=NOW, plan_hash=plan_hash)
    return {
        "task_id": task_id,
        "approval_id": approval_id,
        "step_id": planned.step_id,
        "plan_hash": plan_hash,
        "plan": planned.plan,
        "effect": str(planned.plan.steps[0].expected_effect["approved_effect_digest"]),
    }


def _request(world, prepared, *, content: bytes = EDIT, expected: str | None = None):
    return EditRequest(
        task_id=prepared["task_id"],
        step_id=prepared["step_id"],
        approval_id=prepared["approval_id"],
        plan_revision=1,
        plan_hash=prepared["plan_hash"],
        resource_id=resolve(world["registry"], "README.md"),
        expected_sha256=expected or hashlib.sha256(world["tree"].readme.read_bytes()).hexdigest(),
        proposed_content=content,
        expected_effect_sha256=prepared["effect"],
    )


def _apply_an_edit(world):
    """Do one verified forward edit and return its outcome."""

    prepared = _plan(world, goal=PlanGoal.APPLY_EDIT, proposed=EDIT)
    outcome = world["executor"].apply(_request(world, prepared))
    assert outcome.status == "SUCCEEDED"
    return prepared, outcome


def _undo_plan(
    world,
    *,
    approval_id=None,
    restored: bytes | None = None,
    receipt_id=None,
    snapshot_id=None,
):
    """Plan an undo against the *current* content, as a user would re-preview.

    The proposed bytes are the snapshot plaintext being restored, which is what
    the undo plan binds and the grant covers.
    """

    return _plan(
        world,
        goal=PlanGoal.UNDO_EDIT,
        approval_id=approval_id,
        proposed=restored if restored is not None else ORIGINAL,
        extra_arguments={
            "receipt_id": str(receipt_id or uuid4()),
            "snapshot_id": str(snapshot_id or uuid4()),
        },
    )


# ---------------------------------------------------------------------------
# A. The capability is registered and distinct
# ---------------------------------------------------------------------------


def test_undo_is_its_own_registered_capability(world) -> None:
    definition = world["capabilities"].get("fs.undo_edit")
    assert definition.risk_tier is RiskTier.MODIFY
    assert definition.resource_kind == "file"
    assert definition.arguments_model.__name__ == "UndoEditArguments"


def test_undo_arguments_require_a_receipt_and_snapshot(world) -> None:
    from pydantic import ValidationError

    from aether.core.policy.capabilities import UndoEditArguments

    with pytest.raises(ValidationError):
        UndoEditArguments.model_validate({"resource_id": "file:" + str(uuid4())})
    valid = UndoEditArguments.model_validate(
        {
            "resource_id": "file:" + str(uuid4()),
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": "a" * 64,
            "receipt_id": str(uuid4()),
            "snapshot_id": str(uuid4()),
        }
    )
    assert valid.receipt_id


def test_undo_plans_against_the_undo_capability_not_the_edit_one(world) -> None:
    # A standalone undo plan still binds exact bytes; here the file is edited
    # first so the snapshot being restored genuinely differs from current content.
    _apply_an_edit(world)
    prepared = _undo_plan(world)
    assert prepared["plan"].steps[0].capability_id == "fs.undo_edit"


def test_an_edit_approval_cannot_authorize_an_undo(world) -> None:
    """The decisive separation: the two capabilities do not share authority."""

    edit_plan, applied = _apply_an_edit(world)
    before = world["tree"].readme.read_bytes()
    with pytest.raises(EditDenied) as refused:
        # An *edit* request carrying undo's snapshot restoration.
        world["executor"].undo(
            _request(
                world,
                edit_plan,
                content=b"# restored\n",
                expected=hashlib.sha256(before).hexdigest(),
            ),
            snapshot_id=UUID(applied.snapshot_id),
            receipt_id=applied.receipt.receipt_id,
        )
    # The persisted step is an fs.apply_approved_edit step, so it cannot
    # authorize an fs.undo_edit action.
    assert refused.value.reason_code == "approved_capability_mismatch"
    assert world["tree"].readme.read_bytes() == before


def test_undo_capability_is_checked_on_the_authority(world) -> None:
    _, applied = _apply_an_edit(world)
    undo_plan = _undo_plan(world)
    world["executor"].undo(
        _request(world, undo_plan, content=ORIGINAL),
        snapshot_id=UUID(applied.snapshot_id),
        receipt_id=applied.receipt.receipt_id,
    )
    assert "fs.undo_edit" in world["authority"].capabilities
    assert "fs.apply_approved_edit" in world["authority"].capabilities


# ---------------------------------------------------------------------------
# B. Successful undo
# ---------------------------------------------------------------------------


def test_undo_restores_the_exact_original_bytes(world) -> None:
    original = world["tree"].readme.read_bytes()
    _, applied = _apply_an_edit(world)
    assert world["tree"].readme.read_bytes() == EDIT

    undo_plan = _undo_plan(world, restored=original)
    restored = world["executor"].undo(
        _request(world, undo_plan, content=original),
        snapshot_id=UUID(applied.snapshot_id),
        receipt_id=applied.receipt.receipt_id,
    )
    assert restored.status == "SUCCEEDED"
    assert world["tree"].readme.read_bytes() == original
    assert hashlib.sha256(original).hexdigest() == restored.post_sha256


def test_undo_produces_its_own_receipt_linked_to_the_original(world) -> None:
    _, applied = _apply_an_edit(world)
    undo_plan = _undo_plan(world)
    restored = world["executor"].undo(
        _request(world, undo_plan, content=ORIGINAL),
        snapshot_id=UUID(applied.snapshot_id),
        receipt_id=applied.receipt.receipt_id,
    )
    assert restored.receipt.receipt_id != applied.receipt.receipt_id
    assert restored.receipt.detail.get("undo_of") == str(applied.receipt.receipt_id)
    assert world["receipts"].get(restored.receipt.receipt_id).status == "SUCCEEDED"
    # Both receipts remain retrievable from the append-only store.
    assert world["receipts"].get(applied.receipt.receipt_id).status == "SUCCEEDED"
    assert world["receipts"].get(restored.receipt.receipt_id).status == "SUCCEEDED"


def test_a_root_without_undo_scope_refuses_undo(world, tmp_path: Path) -> None:
    narrow_root = tmp_path / "narrow"
    narrow_root.mkdir()
    tree = build_tree(narrow_root)
    registry = build_registry(
        tree, capabilities=frozenset({"fs.inspect_file", "fs.apply_approved_edit"})
    )
    store = SQLiteTaskStore(tmp_path / "narrow-store.sqlite3")
    grants_dir = tmp_path / "narrow-grants"
    grants_dir.mkdir()
    grants = ConsumptionHarness(grants_dir, clock=lambda: NOW, uses=4)
    vault = UndoVault(tmp_path / "narrow-vault").open()
    receipts = ReceiptStore(tmp_path / "narrow-receipts.sqlite3")
    executor = EditExecutor(
        registry,
        _Accepting(),
        vault,
        receipts,
        plans=store,
        grants=grants.ledger,
        clock=lambda: NOW,
    )
    try:
        narrow_world = {
            **world,
            "tree": tree,
            "registry": registry,
            "store": store,
            "grants": grants,
            "vault": vault,
            "receipts": receipts,
            "executor": executor,
            "planner": Planner(
                capabilities=CapabilityRegistry.phase2_filesystem(),
                resources=registry,
                clock=lambda: NOW,
            ),
        }
        _apply_an_edit(narrow_world)
        # The refusal happens at *planning*: a root that does not permit
        # fs.undo_edit cannot even produce an undo plan, which is earlier and
        # stronger than refusing at execution.
        with pytest.raises(PlannerError) as refused:
            _undo_plan(narrow_world)
        assert refused.value.reason_code == "PLAN_CAPABILITY_OUT_OF_SCOPE"
        # And the file is untouched by the attempt.
        assert narrow_world["tree"].readme.read_bytes() == EDIT
    finally:
        grants.close()
        receipts.close()
        vault.close()
        store.close()


# ---------------------------------------------------------------------------
# C. Conflict and forged scope
# ---------------------------------------------------------------------------


def test_undo_refuses_to_overwrite_a_newer_user_edit(world) -> None:
    original = world["tree"].readme.read_bytes()
    _, applied = _apply_an_edit(world)
    # The user edits again after the edit being undone.
    world["tree"].readme.write_text("# user wrote this afterwards\n", encoding="utf-8")
    newer = world["tree"].readme.read_bytes()

    undo_plan = _undo_plan(world)
    with pytest.raises(EditDenied) as refused:
        world["executor"].undo(
            _request(world, undo_plan, content=ORIGINAL),
            snapshot_id=UUID(applied.snapshot_id),
            receipt_id=applied.receipt.receipt_id,
        )
    assert refused.value.reason_code == "undo_conflict_newer_content"
    assert world["tree"].readme.read_bytes() == newer
    assert world["tree"].readme.read_bytes() != original


def test_undo_refuses_a_receipt_that_names_another_snapshot(world) -> None:
    _, applied = _apply_an_edit(world)
    undo_plan = _undo_plan(world)
    with pytest.raises(EditDenied) as refused:
        world["executor"].undo(
            _request(world, undo_plan, content=ORIGINAL),
            snapshot_id=uuid4(),
            receipt_id=applied.receipt.receipt_id,
        )
    assert refused.value.reason_code == "undo_receipt_snapshot_mismatch"


def test_undo_refuses_an_unknown_receipt(world) -> None:
    _, applied = _apply_an_edit(world)
    undo_plan = _undo_plan(world)
    with pytest.raises(EditDenied) as refused:
        world["executor"].undo(
            _request(world, undo_plan, content=ORIGINAL),
            snapshot_id=UUID(applied.snapshot_id),
            receipt_id=uuid4(),
        )
    assert refused.value.reason_code == "undo_receipt_unavailable"


def test_undo_refuses_a_receipt_for_another_resource(world) -> None:
    from aether.core.edits.receipts import ActionReceiptRecord

    _, applied = _apply_an_edit(world)
    # A receipt that exists, has a snapshot, but names a different resource.
    impostor = ActionReceiptRecord(
        receipt_id=uuid4(),
        task_id=applied.receipt.task_id,
        step_id=applied.receipt.step_id,
        approval_id=applied.receipt.approval_id,
        capability_id="fs.apply_approved_edit",
        status="SUCCEEDED",
        recovery_class="SNAPSHOT_RESTORABLE",
        resource_id=resolve(world["registry"], "src/module.py"),
        attempted_path="module.py",
        pre_sha256="a" * 64,
        post_sha256="b" * 64,
        snapshot_id=str(uuid4()),
        warnings=(),
        detail={},
        created_at=NOW,
        verified_at=NOW,
    )
    world["receipts"].record(impostor)
    undo_plan = _undo_plan(world)
    with pytest.raises(EditDenied) as refused:
        world["executor"].undo(
            _request(world, undo_plan, content=ORIGINAL),
            snapshot_id=UUID(impostor.snapshot_id),
            receipt_id=impostor.receipt_id,
        )
    assert refused.value.reason_code in {
        "undo_receipt_snapshot_mismatch",
        "undo_receipt_resource_mismatch",
    }


def test_undo_refuses_an_unverified_edit(world, monkeypatch) -> None:
    """Only a verified effect can be undone as an ordinary action."""

    prepared = _plan(world, goal=PlanGoal.APPLY_EDIT, proposed=EDIT)
    original_read = Path.read_bytes
    state = {"reads": 0}

    def fail_readback(self):
        if self.name == "README.md":
            state["reads"] += 1
            if state["reads"] > 2:
                raise OSError(5, "simulated crash")
        return original_read(self)

    monkeypatch.setattr(Path, "read_bytes", fail_readback)
    outcome = world["executor"].apply(_request(world, prepared))
    monkeypatch.setattr(Path, "read_bytes", original_read)
    assert outcome.status == "UNVERIFIED"

    undo_plan = _undo_plan(world)
    with pytest.raises(EditDenied) as refused:
        world["executor"].undo(
            _request(world, undo_plan, content=ORIGINAL),
            snapshot_id=UUID(outcome.snapshot_id),
            receipt_id=outcome.receipt.receipt_id,
        )
    assert refused.value.reason_code == "undo_receipt_not_verified"


def test_undo_refuses_content_that_drifted_since_its_preview(world) -> None:
    original = world["tree"].readme.read_bytes()
    _, applied = _apply_an_edit(world)
    undo_plan = _undo_plan(world)
    approved_current = original
    # Something changed after the undo preview but before execution.
    world["tree"].readme.write_text("# drifted\n", encoding="utf-8")
    with pytest.raises(EditDenied) as refused:
        world["executor"].undo(
            _request(
                world,
                undo_plan,
                content=ORIGINAL,
                expected=hashlib.sha256(approved_current).hexdigest(),
            ),
            snapshot_id=UUID(applied.snapshot_id),
            receipt_id=applied.receipt.receipt_id,
        )
    assert refused.value.reason_code in {
        "undo_conflict_newer_content",
        "STALE_TARGET",
    }


def test_undo_spends_an_undo_use_not_an_edit_use(world) -> None:
    edit_plan, applied = _apply_an_edit(world)
    edit_uses_after_edit = world["grants"].ledger.uses_remaining(edit_plan["approval_id"])
    undo_plan = _undo_plan(world)
    world["executor"].undo(
        _request(world, undo_plan, content=ORIGINAL),
        snapshot_id=UUID(applied.snapshot_id),
        receipt_id=applied.receipt.receipt_id,
    )
    # The undo spent ITS OWN approval's use, and left the edit's budget alone.
    undo_remaining = world["grants"].ledger.uses_remaining(undo_plan["approval_id"])
    assert undo_remaining == world["grants"].uses - 1, (
        f"undo approval {undo_plan['approval_id']} remaining={undo_remaining}"
    )
    assert world["grants"].ledger.uses_remaining(edit_plan["approval_id"]) == edit_uses_after_edit


def test_an_undo_plan_without_approved_bytes_is_refused(world) -> None:
    """Undo also binds exact bytes; it cannot be planned as a vague intention."""

    with pytest.raises(PlannerError) as refused:
        _plan(world, goal=PlanGoal.UNDO_EDIT, proposed=None)
    assert refused.value.reason_code == "PLAN_APPROVED_BYTES_REQUIRED"
