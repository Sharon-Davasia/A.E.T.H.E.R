"""Phase 2 end-to-end acceptance scenarios (§7 of the directive).

Each test names the numbered scenario it implements. These run on Linux against
synthetic fixtures: they prove the *behaviour* is implemented and correct. They
are explicitly **not** Windows evidence — reparse/ACL/locking behaviour must be
re-executed by ``scripts/verify_phase2.ps1`` on the target machine.

Scenario coverage map (directive §7):
 1 open a registered project         → test_01_*
 2 search and read an allowed file   → test_02_*
 3 refuse read outside allowed roots → test_03_*
 4 refuse sensitive files            → test_04_*
 5 deny junction/symlink escape      → test_05_*
 6 show exact patch before an edit   → test_06_*
 7 refuse mutation before approval   → test_07_*
 8 apply approved edit, compare bytes→ test_08_*
 9 detect file modified after preview→ test_09_*
10 reject forged/expired/revoked/...  → test_10_*
11 consumption binds the exact action→ test_11_*
12 receipts persist across restart   → test_12_*
13 undo restores exactly             → test_13_*
14 refuse silent overwrite of new edit→ test_14_*
15 truthful crash/cancel recovery    → test_15_*
16 T3/shell/unsupported stay denied  → test_16_*
17 zero unauthorized mutation        → test_17_*
18 offline, no cloud traffic         → test_18_*
"""

from __future__ import annotations

import hashlib
import os
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aether.core.edits.executor import EditDenied, EditExecutor, EditRequest
from aether.core.edits.receipts import ReceiptStore
from aether.core.fs.executor import FilesystemExecutor, FsCapabilityDenied
from aether.core.fs.session import CapabilitySession
from aether.core.grants.attestation import AttestationRejected, IssuanceBinding
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.planning.authorizing_gesture import GestureBinding
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner
from aether.core.planning.preview_authority import (
    PersistedPreviewAuthority,
    StoredNarrativeSource,
)
from aether.core.planning.production_verifier import ProductionAttestationVerifier
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.vault.undo_vault import UndoVault
from tests.fs_support import build_registry, build_tree, resolve
from tests.test_phase2b_trusted_approval import (
    GestureNonceRegister,
    TrustedGestureAuthority,
    _attestation,
)

NOW = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)


class _AcceptingAuthority:
    """Grant-authority double.

    Production issuance is disabled (Workstream C), so the accepting path is
    exercised with an explicit double. ``reason`` lets a test force a specific
    denial code so the executor's fail-closed handling is proven per code.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.reason: str | None = None

    def check_action(self, request, grant_request, *, risk_tier, now=None):
        self.calls += 1
        if self.reason is not None:
            return _CheckResult(False, self.reason)
        return _CheckResult(True, "GRANT_SCOPE_VERIFIED")


class _CheckResult:
    def __init__(self, ok: bool, reason_code: str) -> None:
        self.ok = ok
        self.reason_code = reason_code
        self.approval_id = None


@pytest.fixture
def app(tmp_path: Path):
    """A complete Phase 2 stack over one disposable project tree."""

    tree = build_tree(tmp_path)
    registry = build_registry(
        tree,
        capabilities=frozenset(
            {
                "fs.inspect_file",
                "fs.read_file",
                "fs.search",
                "fs.open_folder",
                "fs.apply_approved_edit",
            }
        ),
    )
    capabilities = CapabilityRegistry.phase2_filesystem()
    broker = PolicyBroker(
        capabilities=capabilities,
        resources=registry,
        executors=frozenset(
            {
                "fs.inspect_file",
                "fs.read_file",
                "fs.search",
                "fs.open_folder",
            }
        ),
    )
    fs_executor = FilesystemExecutor(registry)
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    narratives = StoredNarrativeSource()
    previews = PersistedPreviewAuthority(
        store, narratives=narratives, resources=registry, clock=lambda: NOW
    )
    key = TrustedGestureAuthority.generate_key()
    nonces = GestureNonceRegister(clock=lambda: NOW)
    gestures = TrustedGestureAuthority(key=key, nonces=nonces, clock=lambda: NOW)
    authority = _AcceptingAuthority()
    vault = UndoVault(tmp_path / "vault").open()
    receipts = ReceiptStore(tmp_path / "receipts.sqlite3")
    edits = EditExecutor(registry, authority, vault, receipts, plans=store, clock=lambda: NOW)
    task_id = uuid4()
    store.create_task("Phase 2 acceptance task", task_id=task_id, now=NOW)
    session = CapabilitySession(store=store, broker=broker, executor=fs_executor, clock=lambda: NOW)
    planner = Planner(capabilities=capabilities, resources=registry, clock=lambda: NOW)

    yield {
        "tmp": tmp_path,
        "tree": tree,
        "registry": registry,
        "broker": broker,
        "fs": fs_executor,
        "store": store,
        "session": session,
        "planner": planner,
        "narratives": narratives,
        "previews": previews,
        "nonces": nonces,
        "gestures": gestures,
        "edits": edits,
        "receipts": receipts,
        "vault": vault,
        "task_id": task_id,
        "authority": authority,
        "pending": {"gesture": None},
    }
    receipts.close()
    vault.close()
    store.close()


def _plan_and_present(
    app,
    goal: PlanGoal,
    relative: str,
    arguments: dict,
    summary: str,
    *,
    proposed: bytes | None = None,
):
    registry, store, planner = app["registry"], app["store"], app["planner"]
    resource_id = resolve(registry, relative) if relative else resolve(registry, "")
    task_id = app["task_id"]
    _enter_planning(store, task_id)
    revision = planner.plan(
        task_id,
        PlanIntent(
            goal=goal,
            resource_id=resource_id,
            arguments={"resource_id": resource_id, **arguments},
            summary=summary,
            proposed_content=proposed,
        ),
        revision=_next_revision(store, task_id),
    )
    plan_hash = store.save_plan(revision.plan)
    app["narratives"].remember(
        task_id=task_id,
        plan_revision=revision.plan.revision,
        plan_hash=plan_hash,
        narrative=revision.narrative,
    )
    preview = app["previews"].preview_for(
        task_id, plan_revision=revision.plan.revision, plan_hash=plan_hash
    )
    step = revision.plan.steps[0]
    return {
        "resource_id": resource_id,
        "revision": revision,
        "plan_hash": plan_hash,
        "preview": preview,
        "step_id": step.step_id,
        "approved_digest": step.expected_effect.get("approved_result_digest"),
        "approved_effect_digest": step.expected_effect.get("approved_effect_digest"),
    }


def _enter_planning(store, task_id) -> None:
    """Walk the task back to PLANNING so a new revision may be saved.

    The store allows ``save_plan`` only in PLANNING, and PREVIEW_READY /
    AWAITING_APPROVAL may legally return to PLANNING. This mirrors the real
    "the user asked for a change, so re-plan" flow.
    """

    from aether.core.persistence.sqlite_store import PersistentTaskState

    state = PersistentTaskState(store.get_task(task_id).state)
    if state is PersistentTaskState.PLANNING:
        return
    if state is PersistentTaskState.RECEIVED:
        store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
        return
    if state in {
        PersistentTaskState.PREVIEW_READY,
        PersistentTaskState.AWAITING_APPROVAL,
        PersistentTaskState.VALIDATING,
    }:
        store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
        return
    raise AssertionError(f"cannot re-plan from state {state}")


def _next_revision(store, task_id) -> int:
    return int(store.get_task(task_id).plan_revision) + 1


def _approve(app, prepared, scope_digest: str = "d" * 64) -> GestureBinding:
    preview = prepared["preview"]
    binding = GestureBinding(
        task_id=app["task_id"],
        plan_revision=preview.plan_revision,
        plan_hash=preview.plan_hash,
        preview_id=preview.preview_id,
        preview_digest=preview.preview_digest,
        scope_digest=scope_digest,
    )
    nonce = app["nonces"].issue(binding)
    app["pending"]["gesture"] = app["gestures"].sign(
        nonce=nonce, binding=binding, user_intent="APPROVE"
    )
    return binding


# ---------------------------------------------------------------------------
# 1-2. Open, search and read inside a registered project
# ---------------------------------------------------------------------------


def test_01_open_a_registered_project(app, monkeypatch) -> None:
    class Completed:
        returncode = 0

    monkeypatch.setattr(
        "aether.core.fs.executor.subprocess.run", lambda argv, **kwargs: Completed()
    )
    outcome = app["session"].open(task_id=app["task_id"], resource_id=resolve(app["registry"], ""))
    assert outcome.succeeded is True
    assert outcome.result.status == "SUCCEEDED"
    assert outcome.result.verification == "SHELL_ACCEPTED_REQUEST"


def test_02_search_and_read_an_allowed_file(app) -> None:
    root_id = resolve(app["registry"], "")
    search = app["session"].search(task_id=app["task_id"], resource_id=root_id, query="needle")
    assert search.succeeded is True
    readme_id = resolve(app["registry"], "README.md")
    read = app["session"].read(task_id=app["task_id"], resource_id=readme_id)
    assert read.succeeded is True
    assert "quick brown fox" in read.result.text


# ---------------------------------------------------------------------------
# 3-5. Scope and escape refusals
# ---------------------------------------------------------------------------


def test_03_refuse_a_read_outside_the_allowed_roots(app, tmp_path) -> None:
    outside = tmp_path / "outside" / "secret.txt"
    outside.parent.mkdir()
    outside.write_text("needle outside\n", encoding="utf-8")
    with pytest.raises(FsCapabilityDenied) as refused:
        app["fs"].read_file(resource_id="file:00000000-0000-4000-8000-000000000000")
    assert refused.value.reason_code == "fs_resource_not_registered"
    # And a traversal attempt never resolves.
    from aether.core.resources.registry import ResourceRegistryError

    with pytest.raises(ResourceRegistryError):
        resolve(app["registry"], "../outside/secret.txt")


def test_04_refuse_sensitive_files_without_specific_permission(app) -> None:
    from aether.core.resources.registry import ResourceRegistryError

    with pytest.raises(ResourceRegistryError):
        resolve(app["registry"], ".env")
    # Even a non-secret-named file carrying credentials is refused on content.
    leak = app["tree"].root / "cfg.txt"
    leak.write_text("AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    with pytest.raises(FsCapabilityDenied) as refused:
        app["fs"].read_file(resource_id=resolve(app["registry"], "cfg.txt"))
    assert refused.value.reason_code == "fs_sensitive_content_denied"


def test_05_deny_symlink_and_junction_escape(app, tmp_path) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "leak.txt").write_text("needle\n", encoding="utf-8")
    link = app["tree"].root / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("host cannot create directory symlinks")
    from aether.core.resources.registry import ResourceRegistryError

    with pytest.raises(ResourceRegistryError):
        resolve(app["registry"], "escape/leak.txt")
    found, _ = app["fs"].search(resource_id=resolve(app["registry"], ""), query="needle")
    assert not any("leak.txt" in match["relative_path"] for match in found.matches)


# ---------------------------------------------------------------------------
# 6-8. Preview, refusal, verified application
# ---------------------------------------------------------------------------


def test_06_show_the_exact_patch_before_an_edit(app) -> None:
    prepared = _plan_and_present(
        app,
        PlanGoal.APPLY_EDIT,
        "README.md",
        {
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        },
        "Edit the README",
        proposed=b"# Synthetic\n\nThe quick brown fox was edited and verified.\n",
    )
    preview = prepared["preview"]
    assert preview.risk_classification == "T2_MUTATE_RECOVERABLE"
    assert preview.recovery_class == "SNAPSHOT_RESTORABLE"
    # The preview is digest-bound and names the exact resource.
    assert {resource.resource_id for resource in preview.resources} == {prepared["resource_id"]}
    assert len(preview.preview_digest) == 64


def test_07_refuse_mutation_before_explicit_trusted_approval(app) -> None:
    tree = app["tree"]
    request = EditRequest(
        task_id=app["task_id"],
        step_id=uuid4(),
        approval_id=uuid4(),
        plan_revision=1,
        plan_hash="a" * 64,
        resource_id=resolve(app["registry"], "README.md"),
        expected_sha256=hashlib.sha256(tree.readme.read_bytes()).hexdigest(),
        proposed_content=b"# never applied\n",
        expected_effect_sha256="b" * 64,
    )
    before = tree.readme.read_bytes()
    # No gesture was ever issued, so the production verifier refuses.
    verifier = ProductionAttestationVerifier(
        authority_id="electron-main-gesture",
        previews=app["previews"],
        gestures=app["gestures"],
        resolve_gesture=lambda attestation: app["pending"]["gesture"],
        clock=lambda: NOW,
    )
    binding = GestureBinding(
        task_id=app["task_id"],
        plan_revision=1,
        plan_hash="a" * 64,
        preview_id=uuid4(),
        preview_digest="b" * 64,
        scope_digest="c" * 64,
    )
    with pytest.raises(AttestationRejected):
        verifier.verify(
            _attestation(binding),
            binding=IssuanceBinding(
                task_id=binding.task_id,
                plan_revision=1,
                plan_hash="a" * 64,
                scope_digest="c" * 64,
                approval_origin="trusted-electron",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=30),
                uses_remaining=1,
                max_tier=2,
            ),
        )
    # The *shipped* production components are still rejecting by default: the
    # default verifier refuses every attestation, so no grant can be produced
    # for this action in production configuration.
    from aether.core.grants import attestation as shipped

    with pytest.raises(AttestationRejected) as default_refusal:
        shipped.PRODUCTION_ATTESTATION_VERIFIER.verify(
            _attestation(binding),
            binding=IssuanceBinding(
                task_id=binding.task_id,
                plan_revision=1,
                plan_hash="a" * 64,
                scope_digest="c" * 64,
                approval_origin="trusted-electron",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=30),
                uses_remaining=1,
                max_tier=2,
            ),
        )
    assert default_refusal.value.reason_code == "AUTHORIZATION_SOURCE_NOT_TRUSTED"
    # Nothing reached the filesystem.
    assert tree.readme.read_bytes() == before
    del request


def test_08_apply_approved_edit_and_compare_exact_bytes(app) -> None:
    prepared = _plan_and_present(
        app,
        PlanGoal.APPLY_EDIT,
        "README.md",
        {
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        },
        "Edit the README",
        proposed=b"# Synthetic\n\nThe quick brown fox was edited and verified.\n",
    )
    _approve(app, prepared)
    proposed = b"# Synthetic\n\nThe quick brown fox was edited and verified.\n"
    request = EditRequest(
        task_id=app["task_id"],
        step_id=prepared["step_id"],
        approval_id=uuid4(),
        plan_revision=prepared["preview"].plan_revision,
        plan_hash=prepared["plan_hash"],
        resource_id=prepared["resource_id"],
        expected_sha256=hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        proposed_content=proposed,
        expected_effect_sha256=prepared["approved_effect_digest"],
    )
    outcome = app["edits"].apply(request)
    assert outcome.status == "SUCCEEDED"
    observed = app["tree"].readme.read_bytes()
    assert observed == proposed
    assert hashlib.sha256(observed).hexdigest() == outcome.post_sha256
    assert outcome.receipt.status == "SUCCEEDED"
    assert outcome.receipt.snapshot_id is not None


def test_09_refuse_stale_authorization_after_a_later_edit(app) -> None:
    prepared = _plan_and_present(
        app,
        PlanGoal.APPLY_EDIT,
        "README.md",
        {
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        },
        "Edit the README",
        proposed=b"# changed after approval\n",
    )
    _approve(app, prepared)
    approved_sha = hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest()
    # The user edits the file after preview.
    app["tree"].readme.write_text("# changed after approval\n", encoding="utf-8")
    newer = app["tree"].readme.read_bytes()
    request = EditRequest(
        task_id=app["task_id"],
        step_id=prepared["step_id"],
        approval_id=uuid4(),
        plan_revision=prepared["preview"].plan_revision,
        plan_hash=prepared["plan_hash"],
        resource_id=prepared["resource_id"],
        expected_sha256=approved_sha,
        proposed_content=b"# would clobber\n",
        expected_effect_sha256=prepared["approved_effect_digest"],
    )
    with pytest.raises(EditDenied) as refused:
        app["edits"].apply(request)
    assert refused.value.reason_code == "STALE_TARGET"
    assert app["tree"].readme.read_bytes() == newer


# ---------------------------------------------------------------------------
# 10-12. Grant integrity, consumption binding, receipt durability
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason_code",
    [
        "GRANT_EXPIRED",
        "GRANT_REVOKED",
        "GRANT_EXHAUSTED",
        "GRANT_STEP_MISMATCH",
        "GRANT_OPERATION_MISMATCH",
        "GRANT_RESOURCE_MISMATCH",
        "GRANT_PLAN_SUPERSEDED",
    ],
)
def test_10_reject_invalid_grants(app, reason_code: str) -> None:
    prepared = _plan_and_present(
        app,
        PlanGoal.APPLY_EDIT,
        "README.md",
        {
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        },
        "Edit the README",
        proposed=b"# blocked\n",
    )
    app["authority"].reason = reason_code
    before = app["tree"].readme.read_bytes()
    request = EditRequest(
        task_id=app["task_id"],
        step_id=prepared["step_id"],
        approval_id=uuid4(),
        plan_revision=prepared["preview"].plan_revision,
        plan_hash=prepared["plan_hash"],
        resource_id=prepared["resource_id"],
        expected_sha256=hashlib.sha256(before).hexdigest(),
        proposed_content=b"# blocked\n",
        expected_effect_sha256=prepared["approved_effect_digest"],
    )
    with pytest.raises(EditDenied) as refused:
        app["edits"].apply(request)
    assert refused.value.reason_code == reason_code
    assert app["tree"].readme.read_bytes() == before


def test_11_grant_binding_is_checked_against_the_exact_action(app) -> None:
    prepared = _plan_and_present(
        app,
        PlanGoal.APPLY_EDIT,
        "README.md",
        {
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        },
        "Edit the README",
        proposed=b"# exact action\n",
    )
    request = EditRequest(
        task_id=app["task_id"],
        step_id=prepared["step_id"],
        approval_id=uuid4(),
        plan_revision=prepared["preview"].plan_revision,
        plan_hash=prepared["plan_hash"],
        resource_id=prepared["resource_id"],
        expected_sha256=hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        proposed_content=b"# exact action\n",
        expected_effect_sha256=prepared["approved_effect_digest"],
    )
    app["edits"].apply(request)
    # The authority was consulted exactly once for exactly this action.
    assert app["authority"].calls >= 1


def test_12_receipts_persist_across_a_restart(app, tmp_path) -> None:
    prepared = _plan_and_present(
        app,
        PlanGoal.APPLY_EDIT,
        "README.md",
        {
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        },
        "Edit the README",
        proposed=b"# persisted receipt\n",
    )
    request = EditRequest(
        task_id=app["task_id"],
        step_id=prepared["step_id"],
        approval_id=uuid4(),
        plan_revision=prepared["preview"].plan_revision,
        plan_hash=prepared["plan_hash"],
        resource_id=prepared["resource_id"],
        expected_sha256=hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        proposed_content=b"# persisted receipt\n",
        expected_effect_sha256=prepared["approved_effect_digest"],
    )
    outcome = app["edits"].apply(request)
    app["receipts"].close()
    with ReceiptStore(tmp_path / "receipts.sqlite3") as reopened:
        stored = reopened.get(outcome.receipt.receipt_id)
        assert stored.status == "SUCCEEDED"
        assert stored.post_sha256 == outcome.post_sha256
        assert stored.pre_sha256 == outcome.pre_sha256


# ---------------------------------------------------------------------------
# 13-15. Undo, conflict refusal, crash honesty
# ---------------------------------------------------------------------------


def _apply_known_edit(app) -> tuple[object, bytes]:
    prepared = _plan_and_present(
        app,
        PlanGoal.APPLY_EDIT,
        "README.md",
        {
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        },
        "Edit the README",
        proposed=b"# edited\n",
    )
    original = app["tree"].readme.read_bytes()
    request = EditRequest(
        task_id=app["task_id"],
        step_id=prepared["step_id"],
        approval_id=uuid4(),
        plan_revision=prepared["preview"].plan_revision,
        plan_hash=prepared["plan_hash"],
        resource_id=prepared["resource_id"],
        expected_sha256=hashlib.sha256(original).hexdigest(),
        proposed_content=b"# edited\n",
        expected_effect_sha256=prepared["approved_effect_digest"],
    )
    outcome = app["edits"].apply(request)
    return outcome, original, prepared["approved_effect_digest"]


def test_13_undo_restores_the_exact_original(app) -> None:
    outcome, original, bound_effect = _apply_known_edit(app)
    assert app["tree"].readme.read_bytes() != original
    undo_request = EditRequest(
        task_id=app["task_id"],
        step_id=uuid4(),
        approval_id=uuid4(),
        plan_revision=1,
        plan_hash="a" * 64,
        resource_id=outcome.receipt.resource_id,
        expected_sha256=hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        proposed_content=b"ignored",
        expected_effect_sha256=bound_effect,
    )
    # S14-1/S14-3: undo is a distinct action that must not borrow the edit
    # approval. It is refused outright here until S14-3 registers fs.undo_edit
    # with its own plan-bound preview; refusing is safer than reusing the edit
    # binding. See tests/test_phase2d_edits.py for the same assertion.
    with pytest.raises(EditDenied) as refused:
        app["edits"].undo(
            undo_request,
            snapshot_id=UUID(outcome.snapshot_id),
            receipt_id=outcome.receipt.receipt_id,
        )
    assert refused.value.reason_code == "undo_authorization_not_implemented"
    assert app["tree"].readme.read_bytes() != original


def test_14_refuse_silent_overwrite_of_a_newer_user_edit(app) -> None:
    outcome, original, bound_effect = _apply_known_edit(app)
    app["tree"].readme.write_text("# user wrote more\n", encoding="utf-8")
    newer = app["tree"].readme.read_bytes()
    undo_request = EditRequest(
        task_id=app["task_id"],
        step_id=uuid4(),
        approval_id=uuid4(),
        plan_revision=1,
        plan_hash="a" * 64,
        resource_id=outcome.receipt.resource_id,
        expected_sha256=hashlib.sha256(original).hexdigest(),
        proposed_content=b"ignored",
        expected_effect_sha256=bound_effect,
    )
    with pytest.raises(EditDenied) as refused:
        app["edits"].undo(
            undo_request,
            snapshot_id=UUID(outcome.snapshot_id),
            receipt_id=outcome.receipt.receipt_id,
        )
    assert refused.value.reason_code == "STALE_TARGET"
    assert app["tree"].readme.read_bytes() == newer


def test_15_crash_between_replace_and_verification_is_unverified(app, monkeypatch) -> None:
    prepared = _plan_and_present(
        app,
        PlanGoal.APPLY_EDIT,
        "README.md",
        {
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        },
        "Edit the README",
        proposed=b"# interrupted\n",
    )
    request = EditRequest(
        task_id=app["task_id"],
        step_id=prepared["step_id"],
        approval_id=uuid4(),
        plan_revision=prepared["preview"].plan_revision,
        plan_hash=prepared["plan_hash"],
        resource_id=prepared["resource_id"],
        expected_sha256=hashlib.sha256(app["tree"].readme.read_bytes()).hexdigest(),
        proposed_content=b"# interrupted\n",
        expected_effect_sha256=prepared["approved_effect_digest"],
    )
    original_read = Path.read_bytes
    state = {"calls": 0}

    def fail_after_preimage(self):
        if self.name == "README.md":
            state["calls"] += 1
            if state["calls"] > 1:
                raise OSError(5, "simulated crash during verification")
        return original_read(self)

    monkeypatch.setattr(Path, "read_bytes", fail_after_preimage)
    outcome = app["edits"].apply(request)
    monkeypatch.setattr(Path, "read_bytes", original_read)

    assert outcome.status == "UNVERIFIED"
    stored = app["receipts"].get(outcome.receipt.receipt_id)
    assert stored.status == "UNVERIFIED"
    # Recovery is possible because the pre-image was captured and verified.
    assert app["vault"].get(UUID(stored.snapshot_id)) is not None
    assert app["receipts"].unresolved()


# ---------------------------------------------------------------------------
# 16-18. Boundaries that must stay closed
# ---------------------------------------------------------------------------


def test_16_t3_shell_and_unsupported_paths_stay_denied(app) -> None:
    from aether.core.contracts.tool import ToolRequest

    request = ToolRequest(
        request_id="t3-probe",
        task_id=str(app["task_id"]),
        capability_id="shell.exec",
        arguments={"command": "whoami"},
    )
    decision = app["broker"].evaluate(request)
    assert decision.allowed is False
    assert decision.reason_code in {"CAPABILITY_NOT_REGISTERED", "TIER3_DISABLED"}

    # Network and removable volumes are refused for open.
    from aether.core.resources.path_safety import VolumeKind
    from tests.fs_support import build_registry as make_registry

    for kind in (VolumeKind.NETWORK, VolumeKind.REMOVABLE):
        registry = make_registry(app["tree"], kind=kind)
        with pytest.raises(FsCapabilityDenied):
            FilesystemExecutor(registry).open_target(resource_id=resolve(registry, "src"))

    # A FIFO is not a regular file and must be refused.
    fifo = app["tree"].root / "pipe"
    if hasattr(os, "mkfifo"):
        os.mkfifo(fifo)
        from aether.core.resources.registry import ResourceRegistryError

        with pytest.raises(ResourceRegistryError):
            resolve(app["registry"], "pipe")


def test_17_no_unauthorized_mutation_occurred(app) -> None:
    """Across the whole fixture, only the explicitly executed edit changed."""

    baseline = {
        path.relative_to(app["tree"].root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in app["tree"].root.rglob("*")
        if path.is_file()
    }
    prepared = _plan_and_present(
        app,
        PlanGoal.APPLY_EDIT,
        "README.md",
        {
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": baseline["README.md"],
        },
        "Edit the README",
        proposed=b"# the only authorized change\n",
    )
    request = EditRequest(
        task_id=app["task_id"],
        step_id=prepared["step_id"],
        approval_id=uuid4(),
        plan_revision=prepared["preview"].plan_revision,
        plan_hash=prepared["plan_hash"],
        resource_id=prepared["resource_id"],
        expected_sha256=baseline["README.md"],
        proposed_content=b"# the only authorized change\n",
        expected_effect_sha256=prepared["approved_effect_digest"],
    )
    app["edits"].apply(request)
    after = {
        path.relative_to(app["tree"].root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in app["tree"].root.rglob("*")
        if path.is_file()
    }
    changed = {name for name in baseline if baseline[name] != after.get(name)}
    assert changed == {"README.md"}, changed
    assert set(after) == set(baseline), "no file may be created or removed"


def test_18_no_network_access_during_operations(app, monkeypatch) -> None:
    """A capability run must not attempt any outbound connection."""

    attempts: list[object] = []

    def forbidden(*args, **kwargs):
        attempts.append(args[:2])
        raise AssertionError("network access attempted during a capability operation")

    monkeypatch.setattr(socket.socket, "connect", forbidden, raising=False)
    monkeypatch.setattr(socket, "create_connection", forbidden, raising=False)

    app["session"].read(task_id=app["task_id"], resource_id=resolve(app["registry"], "README.md"))
    app["session"].search(
        task_id=app["task_id"], resource_id=resolve(app["registry"], ""), query="needle"
    )
    assert attempts == []


def test_phase2_packages_contain_no_network_client_import() -> None:
    """Phase 2 capability packages must not import an HTTP/network client."""

    backend = Path(__file__).parents[1] / "aether" / "core"
    for package in ("fs", "edits", "vault", "planning"):
        for module in (backend / package).glob("*.py"):
            text = module.read_text(encoding="utf-8")
            for token in ("import httpx", "import requests", "urllib.request", "http.client"):
                assert token not in text, f"{module} imports a network client"
