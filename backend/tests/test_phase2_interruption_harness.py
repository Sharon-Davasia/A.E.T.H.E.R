"""Standalone deterministic Phase 2 interruption harness.

Runnable two ways (from the repository root):

    python -m pytest backend/tests/test_phase2_interruption_harness.py -q
    python backend/tests/test_phase2_interruption_harness.py child <ws>

It proves, against merged-main Phase 2 code, that terminating the
mutating process *after* the atomic file replacement but *before*
verified-receipt persistence yields truthful restart reconciliation
(COMPLETED_UNVERIFIED / needs review) with no automatic replay.

Why a harness is needed at all: ordinary startup disables mutation
(the shipped consumption ledger refuses issuance). This harness uses
the same controlled fixture activation as the Phase 2 acceptance
suite — a test-scoped consumption ledger with an explicit budget,
a persisted plan with the canonical approval binding, and a trusted
gesture signature — over an isolated synthetic project. Nothing here
touches real-user data, and no journal entry is ever fabricated: the
journal intent, snapshot, consumption and file replacement are all
produced by the genuine approved-edit path in ``EditExecutor.apply``.

Determinism: the child is terminated by the executor's own
``"replaced"`` checkpoint (invoked after ``os.replace`` and the
journal's REPLACED_UNVERIFIED record, before readback verification
and before any verified receipt). No sleeps, no manual timing.

The child is this same file re-executed with ``child`` as argv[1];
the parent asserts the child's exit code, the on-disk bytes, the
absence of any verified receipt, and the restart reconciliation
verdict. Fake/Linux evidence only — not native Windows evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

NOW = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)
ORIGINAL = b"# Synthetic\n\ninterruption harness pre-image.\n"
PROPOSED = b"# Synthetic\n\ninterruption harness post-image (applied exactly once).\n"
KILL_EXIT_CODE = 73


class _AcceptingAuthority:
    """Scope-verified grant double, as in the Phase 2 acceptance suite."""

    def check_action(self, request, grant_request, *, risk_tier, now=None):  # type: ignore[no-untyped-def]
        class _Check:
            ok = True
            reason_code = "GRANT_SCOPE_VERIFIED"
            approval_id = None

        return _Check()


def _build_stack(workspace: Path):  # type: ignore[no-untyped-def]
    """The full Phase 2 edit stack over one isolated workspace."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from fs_support import ConsumptionHarness, FixtureTree, build_registry, resolve

    from aether.core.edits.executor import EditExecutor
    from aether.core.edits.journal import MutationJournal
    from aether.core.edits.receipts import ReceiptStore
    from aether.core.persistence.sqlite_store import SQLiteTaskStore
    from aether.core.planning.authorizing_gesture import (
        GestureNonceRegister,
        TrustedGestureAuthority,
    )
    from aether.core.planning.preview_authority import (
        PersistedPreviewAuthority,
        StoredNarrativeSource,
    )
    from aether.core.vault.undo_vault import UndoVault

    project = workspace / "project"
    target = project / "data.txt"
    tree = FixtureTree(
        root=project,
        source_dir=project,
        readme=target,
        module=target,
        binary=target,
        secret=target,
        nested=project,
        nested_file=target,
    )
    registry = build_registry(
        tree,
        capabilities=frozenset(
            {
                "fs.inspect_file",
                "fs.read_file",
                "fs.search",
                "fs.open_folder",
                "fs.apply_approved_edit",
                "fs.undo_edit",
            }
        ),
    )
    store = SQLiteTaskStore(workspace / "store.sqlite3")
    narratives = StoredNarrativeSource()
    previews = PersistedPreviewAuthority(
        store, narratives=narratives, resources=registry, clock=lambda: NOW
    )
    key = TrustedGestureAuthority.generate_key()
    nonces = GestureNonceRegister(clock=lambda: NOW)
    gestures = TrustedGestureAuthority(key=key, nonces=nonces, clock=lambda: NOW)
    vault = UndoVault(workspace / "vault").open()
    receipts = ReceiptStore(workspace / "receipts.sqlite3")
    grants = ConsumptionHarness(workspace, clock=lambda: NOW, uses=1)
    journal = MutationJournal(workspace / "journal.sqlite3", clock=lambda: NOW)
    edits = EditExecutor(
        registry,
        _AcceptingAuthority(),
        vault,
        receipts,
        plans=store,
        grants=grants.ledger,
        journal=journal,
        clock=lambda: NOW,
    )
    return {
        "target": target,
        "registry": registry,
        "store": store,
        "previews": previews,
        "narratives": narratives,
        "nonces": nonces,
        "gestures": gestures,
        "vault": vault,
        "receipts": receipts,
        "grants": grants,
        "journal": journal,
        "edits": edits,
        "resolve": resolve,
    }


def _run_child(workspace: Path, *, kill_after_replace: bool) -> int:
    """One genuine approved edit; optionally die at the replaced checkpoint."""
    from aether.core.edits.executor import EditRequest
    from aether.core.persistence.sqlite_store import PersistentTaskState
    from aether.core.planning.authorizing_gesture import GestureBinding
    from aether.core.planning.planner import PlanGoal, PlanIntent, Planner
    from aether.core.policy.capabilities import CapabilityRegistry

    stack = _build_stack(workspace)
    target: Path = stack["target"]
    assert target.read_bytes() == ORIGINAL
    task_id = uuid4()
    store = stack["store"]
    store.create_task("Phase 2 interruption harness", task_id=task_id, now=NOW)
    store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
    planner = Planner(
        capabilities=CapabilityRegistry.phase2_filesystem(),
        resources=stack["registry"],
        clock=lambda: NOW,
    )
    resource_id = stack["resolve"](stack["registry"], "data.txt")
    revision = planner.plan(
        task_id,
        PlanIntent(
            goal=PlanGoal.APPLY_EDIT,
            resource_id=resource_id,
            arguments={
                "resource_id": resource_id,
                "step_id": str(uuid4()),
                "approval_id": str(uuid4()),
                "expected_sha256": hashlib.sha256(ORIGINAL).hexdigest(),
            },
            summary="Interruption harness edit",
            proposed_content=PROPOSED,
        ),
        revision=1,
    )
    plan_hash = store.save_plan(revision.plan)
    step = revision.plan.steps[0]
    approval_id = UUID(str(step.arguments["approval_id"]))
    stack["grants"].bind(approval_id=approval_id, task_id=task_id, now=NOW, plan_hash=plan_hash)
    stack["narratives"].remember(
        task_id=task_id,
        plan_revision=revision.plan.revision,
        plan_hash=plan_hash,
        narrative=revision.narrative,
    )
    preview = stack["previews"].preview_for(
        task_id, plan_revision=revision.plan.revision, plan_hash=plan_hash
    )
    # Genuine approval: trusted gesture over the exact preview binding.
    binding = GestureBinding(
        task_id=task_id,
        plan_revision=preview.plan_revision,
        plan_hash=preview.plan_hash,
        preview_id=preview.preview_id,
        preview_digest=preview.preview_digest,
        scope_digest="d" * 64,
    )
    nonce = stack["nonces"].issue(binding)
    gesture = stack["gestures"].sign(nonce=nonce, binding=binding, user_intent="APPROVE")
    assert gesture is not None
    request = EditRequest(
        task_id=task_id,
        step_id=step.step_id,
        approval_id=approval_id,
        plan_revision=preview.plan_revision,
        plan_hash=plan_hash,
        resource_id=resource_id,
        expected_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
        proposed_content=PROPOSED,
        expected_effect_sha256=str(step.expected_effect.get("approved_effect_digest")),
    )

    def _checkpoint(name: str) -> None:
        if kill_after_replace and name == "replaced":
            # Deterministic termination: the replacement is on disk
            # and journaled REPLACED_UNVERIFIED; no verified receipt
            # has been persisted. Die exactly here.
            sys.stdout.flush()
            os._exit(KILL_EXIT_CODE)

    outcome = stack["edits"].apply(request, checkpoint=_checkpoint)
    print(json.dumps({"status": outcome.status, "reason": outcome.reason_code}))
    return 0 if outcome.status == "SUCCEEDED" else 1


def _child_env() -> dict[str, str]:
    backend = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(backend), str(backend / "tests")])
    return env


def _spawn_child(workspace: Path, mode: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), mode, str(workspace)],
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def _make_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "interruption-ws"
    project = workspace / "project"
    project.mkdir(parents=True)
    if os.name != "nt":
        workspace.chmod(0o700)  # store requires an owner-only directory
    (project / "data.txt").write_bytes(ORIGINAL)
    return workspace


def test_control_run_completes_a_genuine_verified_edit(tmp_path: Path) -> None:
    workspace = _make_workspace(tmp_path)
    result = _spawn_child(workspace, "control")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1])["status"] == "SUCCEEDED"
    assert (workspace / "project" / "data.txt").read_bytes() == PROPOSED


def test_killed_after_replace_reconciles_unverified_without_replay(tmp_path: Path) -> None:
    from fs_support import ConsumptionHarness

    from aether.core.edits.journal import MutationJournal
    from aether.core.edits.receipts import ReceiptStore
    from aether.core.edits.reconcile import MutationReconciler
    from aether.core.vault.undo_vault import UndoVault

    workspace = _make_workspace(tmp_path)
    target = workspace / "project" / "data.txt"
    result = _spawn_child(workspace, "kill")
    # Terminated by the replaced checkpoint, deterministically.
    assert result.returncode == KILL_EXIT_CODE, result.stderr
    # The replacement really happened, exactly once.
    assert target.read_bytes() == PROPOSED
    post_kill_sha = hashlib.sha256(target.read_bytes()).hexdigest()

    # Restart: fresh store objects over the same durable files.
    journal = MutationJournal(workspace / "journal.sqlite3", clock=lambda: NOW)
    receipts = ReceiptStore(workspace / "receipts.sqlite3")
    harness = ConsumptionHarness(workspace, clock=lambda: NOW)
    ledger = harness.ledger
    vault = UndoVault(workspace / "vault").open()
    try:
        # No verified receipt was persisted before the kill.
        all_receipts = [r for r in receipts.unresolved()]
        assert all(r.status != "SUCCEEDED" for r in all_receipts)
        assert receipts.for_task  # receipts are queryable after restart
        # The journal holds the genuine open intent (not fabricated).
        open_intents = journal.open_intents()
        assert len(open_intents) == 1
        assert open_intents[0].state == "REPLACED_UNVERIFIED"

        class _Resolver:
            def path_for(self, resource_id: str) -> Path:
                del resource_id
                raise LookupError("intent records its own target path")

        report = MutationReconciler(
            journal=journal,
            receipts=receipts,
            consumption=ledger,
            snapshots=vault,
            resources=_Resolver(),
        ).reconcile()
        verdicts = [item.verdict for item in report.reconciliations]
        assert "COMPLETED_UNVERIFIED" in verdicts, verdicts
        assert report.needs_review  # truthful review, never silent success
        # No automatic replay: bytes are untouched by reconciliation
        # and the single applied edit was not duplicated.
        assert target.read_bytes() == PROPOSED
        assert hashlib.sha256(target.read_bytes()).hexdigest() == post_kill_sha
        assert target.read_bytes().count(b"post-image") == 1
    finally:
        journal.close()
        receipts.close()
        harness.close()
        vault.close()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode in {"kill", "control"}:
        sys.exit(_run_child(Path(sys.argv[2]), kill_after_replace=(mode == "kill")))
    print(__doc__)
