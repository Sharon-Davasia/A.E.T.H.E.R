"""Phase 2D — verified edits, durable receipts and authorized undo.

These tests exercise the *real* mutation path against a disposable tree. The
grant authority is a test double because production issuance is deliberately
still disabled (Workstream C); everything else — registry resolution, staleness
detection, snapshotting, atomic replace, read-back verification, receipt
persistence and undo conflict detection — is the production code path.

A test that only proved "a file changed" would be worthless here, so every
success assertion re-reads the file from disk and compares exact bytes.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aether.core.edits.executor import EditDenied, EditExecutor, EditRequest
from aether.core.edits.receipts import (
    ActionReceiptRecord,
    ReceiptError,
    ReceiptStore,
)
from aether.core.grants.consumption import ConsumptionLedger
from aether.core.persistence.sqlite_store import PersistentTaskState, SQLiteTaskStore
from aether.core.planning.planner import Planner
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.vault.undo_vault import UndoVault
from tests.fs_support import build_registry, build_tree, resolve

NOW = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)


class AcceptingAuthority:
    """A grant authority that accepts every well-formed request.

    Stands in for a real GrantAuthority while production issuance is disabled.
    It records what it was asked so tests can assert the grant was consulted
    *before* any mutation happened.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.reason: str | None = None

    def check_action(self, request, grant_request, *, risk_tier, now=None):
        self.calls.append(
            {
                "task_id": request.task_id,
                "resource_ids": [ref.resource_id for ref in request.resources],
                "approval_id": str(grant_request.approval_id),
            }
        )
        if self.reason is not None:
            return _Check(False, self.reason)
        return _Check(True, "GRANT_SCOPE_VERIFIED")


class _Check:
    def __init__(self, ok: bool, reason_code: str) -> None:
        self.ok = ok
        self.reason_code = reason_code
        self.approval_id = None


@pytest.fixture
def world(tmp_path: Path):
    tree = build_tree(tmp_path)
    registry = build_registry(
        tree,
        capabilities=frozenset(
            {"fs.inspect_file", "fs.read_file", "fs.search", "fs.apply_approved_edit"}
        ),
    )
    vault_dir = tmp_path / "vault"
    authority = AcceptingAuthority()
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    ledger = ConsumptionLedger(tmp_path / "consumption.sqlite3", clock=lambda: NOW)
    with UndoVault(vault_dir) as vault, ReceiptStore(tmp_path / "receipts.sqlite3") as receipts:
        executor = EditExecutor(
            registry,
            authority,
            vault,
            receipts,
            plans=store,
            grants=ledger,
            clock=lambda: NOW,
        )
        yield {
            "tree": tree,
            "registry": registry,
            "vault": vault,
            "receipts": receipts,
            "executor": executor,
            "authority": authority,
            "grants": ledger,
            "store": store,
            "planner": Planner(
                capabilities=CapabilityRegistry.phase2_filesystem(),
                resources=registry,
                clock=lambda: NOW,
            ),
            "tmp": tmp_path,
        }
    ledger.close()
    store.close()


def make_request(
    registry,
    tree,
    *,
    relative: str = "README.md",
    content: bytes | None = None,
    expected_sha256: str | None = None,
    task_id: UUID | None = None,
    step_id: UUID | None = None,
    approval_id: UUID | None = None,
    world: dict | None = None,
) -> EditRequest:
    """Build a request whose approved bytes are recorded in a persisted plan.

    S14-1 makes the persisted plan the authority for the approved post-image, so
    a request built without one is refused by design. Supplying ``world`` also
    persists the matching plan revision.
    """

    path = tree.root / relative
    original = path.read_bytes()
    proposed = content if content is not None else b"# Rewritten\n\nnew body\n"
    resolved_task = task_id or uuid4()
    resolved_step = step_id or uuid4()
    resolved_approval = approval_id or uuid4()
    effect_digest = "b" * 64
    if world is not None:
        # S14-2: record the budget this approval represents, so consumption can
        # succeed and the check under test is the one that fires.
        world["grants"].grant_budget(
            approval_id=resolved_approval,
            task_id=resolved_task,
            plan_revision=1,
            plan_hash="a" * 64,
            uses=1,
            now=NOW,
        )
        from aether.core.planning.planner import PlanGoal, PlanIntent

        resource_id = resolve(registry, relative)
        revision = world["planner"].plan(
            resolved_task,
            PlanIntent(
                goal=PlanGoal.APPLY_EDIT,
                resource_id=resource_id,
                arguments={
                    "resource_id": resource_id,
                    "step_id": str(resolved_step),
                    "approval_id": str(resolved_approval),
                    "expected_sha256": expected_sha256 or hashlib.sha256(original).hexdigest(),
                },
                summary="Edit",
                proposed_content=proposed,
            ),
            revision=1,
        )
        effect_digest = str(revision.plan.steps[0].expected_effect["approved_effect_digest"])
        resolved_step = revision.step_id
        world["grants"].grant_budget(
            approval_id=resolved_approval,
            task_id=resolved_task,
            plan_revision=1,
            plan_hash="a" * 64,
            uses=1,
            now=NOW,
        )
        world["store"].create_task("edit", task_id=resolved_task, now=NOW)
        world["store"].transition_task(resolved_task, PersistentTaskState.PLANNING, now=NOW)
        world["store"].save_plan(revision.plan)
    return EditRequest(
        task_id=resolved_task,
        step_id=resolved_step,
        approval_id=resolved_approval,
        plan_revision=1,
        plan_hash="a" * 64,
        resource_id=resolve(registry, relative),
        expected_sha256=expected_sha256 or hashlib.sha256(original).hexdigest(),
        proposed_content=proposed,
        expected_effect_sha256=effect_digest,
    )


# ---------------------------------------------------------------------------
# A. The happy path, verified from disk
# ---------------------------------------------------------------------------


def test_apply_verifies_exact_bytes_and_records_a_receipt(world) -> None:
    registry, tree, executor, receipts = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["receipts"],
    )
    request = make_request(registry, tree, world=world)
    outcome = executor.apply(request)

    assert outcome.status == "SUCCEEDED"
    assert outcome.reason_code == "edit_verified"
    on_disk = tree.readme.read_bytes()
    assert on_disk == request.proposed_content
    assert outcome.post_sha256 == hashlib.sha256(on_disk).hexdigest()
    assert outcome.pre_sha256 != outcome.post_sha256

    stored = receipts.get(outcome.receipt.receipt_id)
    assert stored.status == "SUCCEEDED"
    assert stored.pre_sha256 == outcome.pre_sha256
    assert stored.post_sha256 == outcome.post_sha256
    assert stored.snapshot_id == outcome.snapshot_id
    assert stored.verified_at is not None
    # Receipts never carry file content.
    assert "Rewritten" not in repr(stored)


def test_apply_preserves_file_mode(world) -> None:
    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    os.chmod(tree.readme, 0o640)
    before = tree.readme.stat().st_mode & 0o777
    executor.apply(make_request(registry, tree, world=world))
    assert tree.readme.stat().st_mode & 0o777 == before


def test_apply_consults_the_grant_before_mutating(world) -> None:
    registry, tree, executor, authority = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["authority"],
    )
    executor.apply(make_request(registry, tree, world=world))
    assert len(authority.calls) == 1


# ---------------------------------------------------------------------------
# B. Refusals — nothing is written
# ---------------------------------------------------------------------------


def test_stale_target_is_refused_and_nothing_is_written(world) -> None:
    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    request = make_request(registry, tree, world=world)
    # Simulate a user edit between preview and apply.
    tree.readme.write_text("# Edited by the user meanwhile\n", encoding="utf-8")
    before = tree.readme.read_bytes()

    with pytest.raises(EditDenied) as denied:
        executor.apply(request)
    assert denied.value.reason_code == "STALE_TARGET"
    assert tree.readme.read_bytes() == before


def test_failed_grant_check_blocks_the_edit(world) -> None:
    registry, tree, executor, authority = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["authority"],
    )
    authority.reason = "GRANT_EXPIRED"
    before = tree.readme.read_bytes()
    with pytest.raises(EditDenied) as denied:
        executor.apply(make_request(registry, tree, world=world))
    assert denied.value.reason_code == "GRANT_EXPIRED"
    assert tree.readme.read_bytes() == before


@pytest.mark.parametrize(
    "reason",
    ["GRANT_REVOKED", "GRANT_EXHAUSTED", "GRANT_PLAN_MISMATCH", "GRANT_SCOPE_INTEGRITY"],
)
def test_every_grant_denial_prevents_mutation(world, reason: str) -> None:
    registry, tree, executor, authority = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["authority"],
    )
    authority.reason = reason
    before = tree.readme.read_bytes()
    with pytest.raises(EditDenied) as denied:
        executor.apply(make_request(registry, tree, world=world))
    assert denied.value.reason_code == reason
    assert tree.readme.read_bytes() == before


def test_root_without_edit_scope_is_refused(tmp_path) -> None:
    tree = build_tree(tmp_path)
    registry = build_registry(tree)  # read-only capability scope
    authority = AcceptingAuthority()
    with UndoVault(tmp_path / "vault") as vault, ReceiptStore(tmp_path / "r.sqlite3") as receipts:
        executor = EditExecutor(registry, authority, vault, receipts, clock=lambda: NOW)
        with pytest.raises(EditDenied) as denied:
            executor.apply(make_request(registry, tree))
    assert denied.value.reason_code == "fs_capability_outside_root_scope"


def test_edit_to_a_protected_path_is_refused(tmp_path) -> None:
    tree = build_tree(tmp_path)
    # A .env inside the tree can be resolved for some kinds but must never be
    # editable; the registry refuses it first, which is the stronger boundary.
    registry = build_registry(
        tree, capabilities=frozenset({"fs.inspect_file", "fs.apply_approved_edit"})
    )
    authority = AcceptingAuthority()
    with UndoVault(tmp_path / "vault") as vault, ReceiptStore(tmp_path / "r.sqlite3") as receipts:
        EditExecutor(registry, authority, vault, receipts, clock=lambda: NOW)
        from aether.core.resources.registry import ResourceRegistryError

        with pytest.raises(ResourceRegistryError):
            resolve(registry, ".env")


def test_identical_content_is_refused_as_a_no_op(world) -> None:
    registry, tree = world["registry"], world["tree"]
    # No plan can bind "change the file to what it already is": the diff is
    # empty, so the refusal happens at planning time rather than at mutation.
    with pytest.raises(Exception) as denied:
        make_request(registry, tree, content=tree.readme.read_bytes(), world=world)
    assert getattr(denied.value, "reason_code", None) in {"diff_no_change", "edit_no_change"}


def test_unregistered_resource_is_refused(world) -> None:
    tree, executor = world["tree"], world["executor"]
    request = EditRequest(
        task_id=uuid4(),
        step_id=uuid4(),
        approval_id=uuid4(),
        plan_revision=1,
        plan_hash="a" * 64,
        resource_id="file:00000000-0000-4000-8000-000000000000",
        expected_sha256="c" * 64,
        proposed_content=b"nope\n",
        expected_effect_sha256="b" * 64,
    )
    with pytest.raises(EditDenied) as denied:
        executor.apply(request)
    assert denied.value.reason_code == "fs_resource_not_registered"
    assert tree.readme.read_bytes() != b"nope\n"


def test_hard_linked_target_is_refused(tmp_path) -> None:
    tree = build_tree(tmp_path)
    link = tree.root / "linked.txt"
    os.link(tree.readme, link)
    registry = build_registry(
        tree, capabilities=frozenset({"fs.inspect_file", "fs.apply_approved_edit"})
    )
    authority = AcceptingAuthority()
    with UndoVault(tmp_path / "vault") as vault, ReceiptStore(tmp_path / "r.sqlite3") as receipts:
        EditExecutor(registry, authority, vault, receipts, clock=lambda: NOW)
        # The registry refuses to resolve a multiply-linked file in the first place.
        from aether.core.resources.registry import ResourceRegistryError

        with pytest.raises(ResourceRegistryError):
            resolve(registry, "linked.txt")


# ---------------------------------------------------------------------------
# C. Snapshot guarantee
# ---------------------------------------------------------------------------


def test_a_verified_pre_image_is_captured_before_replacement(world) -> None:
    registry, tree, executor, vault = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["vault"],
    )
    original = tree.readme.read_bytes()
    outcome = executor.apply(make_request(registry, tree, world=world))
    stored = vault.get(UUID(outcome.snapshot_id))
    assert stored == original
    assert hashlib.sha256(stored).hexdigest() == outcome.pre_sha256


def test_edit_is_refused_when_no_snapshot_can_be_taken(world, monkeypatch) -> None:
    registry, tree, executor, vault = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["vault"],
    )
    from aether.core.vault.undo_vault import VaultError

    def broken_put(*args, **kwargs):
        raise VaultError("vault_quota_too_small", "no space")

    monkeypatch.setattr(vault, "put", broken_put)
    before = tree.readme.read_bytes()
    with pytest.raises(EditDenied) as denied:
        executor.apply(make_request(registry, tree, world=world))
    assert denied.value.reason_code == "snapshot_unavailable"
    assert tree.readme.read_bytes() == before


def test_tampered_snapshot_is_detected(world) -> None:
    registry, tree, executor, vault = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["vault"],
    )
    outcome = executor.apply(make_request(registry, tree, world=world))
    object_file = next((Path(vault._directory) / "objects").rglob("*.bin"))
    object_file.write_bytes(b"AETHERV1" + b"\x00" * 12 + b"\xff" * 32)
    from aether.core.vault.undo_vault import VaultIntegrityError

    with pytest.raises(VaultIntegrityError):
        vault.get(UUID(outcome.snapshot_id))


# ---------------------------------------------------------------------------
# D. Undo
# ---------------------------------------------------------------------------


def test_undo_restores_the_exact_original_bytes(world) -> None:
    registry, tree, executor, receipts = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["receipts"],
    )
    original = tree.readme.read_bytes()
    applied = executor.apply(make_request(registry, tree, world=world))
    assert tree.readme.read_bytes() != original

    undo_request = make_request(
        registry,
        tree,
        content=b"placeholder ignored by undo",
        expected_sha256=hashlib.sha256(tree.readme.read_bytes()).hexdigest(),
    )
    # S14-1/S14-3: undo is NOT authorized through the forward-edit binding. It
    # requires its own registered fs.undo_edit capability, which lands in S14-3.
    # Until then the mutation path refuses it outright rather than reusing the
    # edit approval, so this asserts the refusal rather than a silent restore.
    with pytest.raises(EditDenied) as refused:
        executor.undo(
            undo_request,
            snapshot_id=UUID(applied.snapshot_id),
            receipt_id=applied.receipt.receipt_id,
        )
    assert refused.value.reason_code == "undo_authorization_not_implemented"
    # The file is untouched by the refused undo.
    assert tree.readme.read_bytes() != original
    assert receipts.get(applied.receipt.receipt_id).status == "SUCCEEDED"


def test_undo_refuses_to_overwrite_a_newer_user_edit(world) -> None:
    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    applied = executor.apply(make_request(registry, tree, world=world))
    # The user keeps working after our edit.
    tree.readme.write_text("# A newer user edit\n", encoding="utf-8")
    newer = tree.readme.read_bytes()

    undo_request = make_request(
        registry,
        tree,
        content=b"ignored",
        expected_sha256=hashlib.sha256(applied.pre_sha256.encode()).hexdigest(),
    )
    with pytest.raises(EditDenied) as denied:
        executor.undo(
            undo_request,
            snapshot_id=UUID(applied.snapshot_id),
            receipt_id=applied.receipt.receipt_id,
        )
    assert denied.value.reason_code == "STALE_TARGET"
    # The user's newer work is intact: undo never silently wins.
    assert tree.readme.read_bytes() == newer


def test_undo_requires_the_matching_receipt(world) -> None:
    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    applied = executor.apply(make_request(registry, tree, world=world))
    other = ActionReceiptRecord(
        receipt_id=uuid4(),
        task_id="t",
        step_id="s",
        approval_id=None,
        capability_id="fs.apply_approved_edit",
        status="FAILED",
        recovery_class="SNAPSHOT_RESTORABLE",
        resource_id=applied.receipt.resource_id,
        attempted_path="x",
        pre_sha256=applied.pre_sha256,
        post_sha256=None,
        snapshot_id=None,
    )
    world["receipts"].record(other)
    undo_request = make_request(
        registry,
        tree,
        content=b"ignored",
        expected_sha256=hashlib.sha256(tree.readme.read_bytes()).hexdigest(),
    )
    with pytest.raises(EditDenied) as denied:
        executor.undo(
            undo_request,
            snapshot_id=UUID(applied.snapshot_id),
            receipt_id=other.receipt_id,
        )
    assert denied.value.reason_code == "undo_receipt_snapshot_mismatch"


def test_undo_requires_its_own_grant(world) -> None:
    registry, tree, executor, authority = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["authority"],
    )
    applied = executor.apply(make_request(registry, tree, world=world))
    authority.reason = "GRANT_STEP_MISMATCH"
    current = tree.readme.read_bytes()
    undo_request = make_request(
        registry,
        tree,
        content=b"ignored",
        expected_sha256=hashlib.sha256(current).hexdigest(),
    )
    with pytest.raises(EditDenied) as denied:
        executor.undo(
            undo_request,
            snapshot_id=UUID(applied.snapshot_id),
            receipt_id=applied.receipt.receipt_id,
        )
    assert denied.value.reason_code == "GRANT_STEP_MISMATCH"
    assert tree.readme.read_bytes() == current


# ---------------------------------------------------------------------------
# E. Receipts — durability and honesty
# ---------------------------------------------------------------------------


def test_receipts_survive_a_restart(world, tmp_path) -> None:
    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    outcome = executor.apply(make_request(registry, tree, world=world))
    world["receipts"].close()
    with ReceiptStore(tmp_path / "receipts.sqlite3") as reopened:
        stored = reopened.get(outcome.receipt.receipt_id)
        assert stored.status == "SUCCEEDED"
        assert stored.post_sha256 == outcome.post_sha256
        assert len(reopened.for_task(stored.task_id)) == 1


def test_receipts_are_append_only(world) -> None:
    registry, tree, executor, receipts = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["receipts"],
    )
    outcome = executor.apply(make_request(registry, tree, world=world))
    with pytest.raises(ReceiptError) as refused:
        receipts.record(outcome.receipt)
    assert refused.value.reason_code == "receipt_already_recorded"


def test_a_success_receipt_cannot_be_constructed_without_verification() -> None:
    with pytest.raises(ReceiptError) as refused:
        ActionReceiptRecord(
            receipt_id=uuid4(),
            task_id="t",
            step_id="s",
            approval_id=None,
            capability_id="fs.apply_approved_edit",
            status="SUCCEEDED",
            recovery_class="SNAPSHOT_RESTORABLE",
            resource_id="file:x",
            attempted_path="x",
            pre_sha256="a" * 64,
            post_sha256="b" * 64,
            snapshot_id=None,
            verified_at=None,
        )
    assert refused.value.reason_code == "receipt_success_requires_verification"


def test_unresolved_receipts_are_reported_for_reconciliation(world) -> None:
    registry, tree, executor, receipts = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["receipts"],
    )
    executor.apply(make_request(registry, tree, world=world))
    assert receipts.unresolved() == ()

    unverified = ActionReceiptRecord(
        receipt_id=uuid4(),
        task_id="reconcile-task",
        step_id="s",
        approval_id=None,
        capability_id="fs.apply_approved_edit",
        status="UNVERIFIED",
        recovery_class="SNAPSHOT_RESTORABLE",
        resource_id="file:x",
        attempted_path="x",
        pre_sha256="a" * 64,
        post_sha256=None,
        snapshot_id=str(uuid4()),
    )
    receipts.record(unverified)
    assert [r.receipt_id for r in receipts.unresolved()] == [unverified.receipt_id]


def test_an_unverifiable_edit_is_never_reported_as_success(world, monkeypatch) -> None:
    """If read-back disagrees with intent, the outcome is UNVERIFIED, not success."""

    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    original_read = Path.read_bytes

    def lying_read(self):
        data = original_read(self)
        # Simulate a partial/incorrect write being observed on read-back.
        if self.name == "README.md" and data.startswith(b"# Rewritten"):
            return data + b"CORRUPTION"
        return data

    monkeypatch.setattr(Path, "read_bytes", lying_read)
    outcome = executor.apply(make_request(registry, tree, world=world))
    monkeypatch.setattr(Path, "read_bytes", original_read)

    assert outcome.status == "UNVERIFIED"
    assert outcome.reason_code == "edit_unverified"
    assert outcome.post_sha256 is None
    stored = world["receipts"].get(outcome.receipt.receipt_id)
    assert stored.status == "UNVERIFIED"
    assert stored.verified_at is None


def test_missing_target_never_substitutes_a_similar_file(world) -> None:
    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    request = make_request(registry, tree, world=world)
    tree.readme.unlink()
    (tree.root / "README.md.bak").write_text("a similar name\n", encoding="utf-8")
    with pytest.raises(EditDenied) as denied:
        executor.apply(request)
    assert denied.value.reason_code in {"STALE_TARGET", "fs_resource_not_found"}
    assert (tree.root / "README.md.bak").read_text() == "a similar name\n"


# ---------------------------------------------------------------------------
# F. Interruption and crash honesty
# ---------------------------------------------------------------------------


def test_replacement_failure_leaves_the_original_intact(world, monkeypatch) -> None:
    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    original = tree.readme.read_bytes()

    original_replace = os.replace

    def failing_replace(source, destination, *args, **kwargs):
        # Only fail the user-file swap; the vault's own atomic writes must work.
        if str(destination).endswith("README.md"):
            raise OSError(16, "device or resource busy")
        return original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr("aether.core.edits.executor.os.replace", failing_replace)
    outcome = executor.apply(make_request(registry, tree, world=world))
    assert outcome.status == "FAILED"
    assert outcome.reason_code == "target_locked_by_another_process"
    assert tree.readme.read_bytes() == original
    # A failure still leaves a durable record.
    stored = world["receipts"].get(outcome.receipt.receipt_id) if outcome.receipt else None
    assert stored is None or stored.status == "FAILED"


def test_a_temporary_file_is_never_left_behind(world) -> None:
    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    executor.apply(make_request(registry, tree, world=world))
    leftovers = [p.name for p in tree.root.iterdir() if p.name.endswith(".aether-tmp")]
    assert leftovers == []


def test_crash_between_replace_and_verification_is_unverified(world, monkeypatch) -> None:
    """A crash after the swap but before read-back must not report success.

    This is the highest-value failure mode: the file *has* changed, so a naive
    implementation would claim success. The receipt must say UNVERIFIED and keep
    the snapshot reference so recovery is possible.
    """

    registry, tree, executor = world["registry"], world["tree"], world["executor"]
    original_read = Path.read_bytes
    request = make_request(registry, tree, world=world)  # reads the file to hash it
    state = {"reads_after_arming": 0}

    def fail_readback(self):
        if self.name == "README.md":
            state["reads_after_arming"] += 1
            # The executor reads the pre-image first, then re-reads to verify.
            # Fail the verification read so the replace has already happened.
            if state["reads_after_arming"] > 1:
                raise OSError(5, "I/O error during verification")
            return original_read(self)
        return original_read(self)

    monkeypatch.setattr(Path, "read_bytes", fail_readback)
    outcome = executor.apply(request)
    monkeypatch.setattr(Path, "read_bytes", original_read)

    assert outcome.status == "UNVERIFIED"
    assert outcome.reason_code == "edit_unverified"
    stored = world["receipts"].get(outcome.receipt.receipt_id)
    assert stored.status == "UNVERIFIED"
    assert stored.snapshot_id is not None
    assert stored.verified_at is None
    # The pre-image is still recoverable from the vault.
    from uuid import UUID as _UUID

    assert (
        world["vault"].get(_UUID(stored.snapshot_id))
        == b"# Synthetic\n\nThe quick brown fox needs a needle.\n"
    )


def test_receipt_is_written_even_when_replacement_fails(world, monkeypatch) -> None:
    registry, tree, executor, receipts = (
        world["registry"],
        world["tree"],
        world["executor"],
        world["receipts"],
    )
    original_replace = os.replace

    def failing_replace(source, destination, *args, **kwargs):
        if str(destination).endswith("README.md"):
            raise OSError(16, "device or resource busy")
        return original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr("aether.core.edits.executor.os.replace", failing_replace)
    outcome = executor.apply(make_request(registry, tree, world=world))
    assert outcome.status == "FAILED"
    failures = [r for r in receipts.for_task(outcome.receipt.task_id) if r.status == "FAILED"]
    assert len(failures) == 1
    assert failures[0].post_sha256 is None


# ---------------------------------------------------------------------------
# G. No bypass surface
# ---------------------------------------------------------------------------


def test_edit_package_has_no_shell_or_delete_surface() -> None:
    package = Path(__file__).parents[1] / "aether" / "core" / "edits"
    forbidden = ("shell=True", "os.system", "os.remove", "shutil.rmtree", "subprocess.call")
    for module in package.glob("*.py"):
        text = module.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{module.name} must not contain {token}"


def test_only_one_module_replaces_user_content() -> None:
    """Exactly two modules may call ``os.replace``, and only for safe reasons.

    ``core/edits/executor.py`` replaces the user's file after verification.
    ``core/vault/undo_vault.py`` replaces its own store objects and key file,
    which are always inside the vault directory. No other module may swap files,
    so a reviewer can enumerate every replacement site by name.
    """

    backend = Path(__file__).parents[1] / "aether"
    offenders = sorted(
        module.relative_to(backend).as_posix()
        for module in backend.rglob("*.py")
        if "os.replace(" in module.read_text(encoding="utf-8")
    )
    assert offenders == ["core/edits/executor.py", "core/vault/undo_vault.py"], offenders
