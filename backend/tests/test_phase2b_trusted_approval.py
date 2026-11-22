"""Phase 2B — production planner, authoritative preview and trusted approval.

This suite proves the chain the Master Specification requires:

    persisted plan → exact preview → authenticated gesture → attestation

and, just as importantly, that the chain is **not enabled**: the shipped
production verifier still rejects everything and the ledger still refuses to
issue. Every test that exercises the accepting path uses an explicitly
constructed verifier, never the shipped default.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aether.core.contracts.policy import RiskTier
from aether.core.grants.attestation import (
    PRODUCTION_ATTESTATION_VERIFIER,
    PRODUCTION_PREVIEW_AUTHORITY,
    AttestationRejected,
    AuthorizationAttestation,
    IssuanceBinding,
    NullPreviewAuthority,
    PreviewSourceUnavailable,
)
from aether.core.persistence.sqlite_store import PersistentTaskState, SQLiteTaskStore
from aether.core.planning.authorizing_gesture import (
    GestureBinding,
    GestureNonceRegister,
    GestureRejected,
    SignedGesture,
    TrustedGestureAuthority,
)
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner, PlannerError
from aether.core.planning.preview_authority import (
    PersistedPreviewAuthority,
    StoredNarrativeSource,
)
from aether.core.planning.production_verifier import (
    ProductionAttestationVerifier,
    UnavailableGestureResolver,
)
from aether.core.policy.capabilities import CapabilityRegistry
from tests.fs_support import build_registry, build_tree, resolve

NOW = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def world(tmp_path: Path):
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
    planner = Planner(capabilities=capabilities, resources=registry, clock=lambda: NOW)
    narratives = StoredNarrativeSource()
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    previews = PersistedPreviewAuthority(
        store, narratives=narratives, resources=registry, clock=lambda: NOW
    )
    key = TrustedGestureAuthority.generate_key()
    nonces = GestureNonceRegister(clock=lambda: NOW)
    gestures = TrustedGestureAuthority(key=key, nonces=nonces, clock=lambda: NOW)
    yield {
        "tree": tree,
        "registry": registry,
        "capabilities": capabilities,
        "planner": planner,
        "narratives": narratives,
        "store": store,
        "previews": previews,
        "nonces": nonces,
        "gestures": gestures,
        "tmp": tmp_path,
    }
    store.close()


def _persist_plan(world, intent: PlanIntent, task_id: UUID | None = None) -> dict[str, object]:
    """Plan, persist, and register the narrative — the full producer path."""

    store = world["store"]
    planner = world["planner"]
    task_id = task_id or uuid4()
    try:
        store.get_task(task_id)
    except KeyError:
        store.create_task("synthetic goal", task_id=task_id, now=NOW)
    store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
    revision = planner.plan(task_id, intent, revision=1)
    plan_hash = store.save_plan(revision.plan)
    world["narratives"].remember(
        task_id=task_id,
        plan_revision=revision.plan.revision,
        plan_hash=plan_hash,
        narrative=revision.narrative,
    )
    store.transition_task(task_id, PersistentTaskState.PREVIEW_READY, now=NOW)
    return {"task_id": task_id, "revision": revision, "plan_hash": plan_hash}


# ---------------------------------------------------------------------------
# A. Planner: typed, bounded, no self-granted authority
# ---------------------------------------------------------------------------


def test_planner_builds_a_typed_single_step_plan(world) -> None:
    registry, planner = world["registry"], world["planner"]
    resource_id = resolve(registry, "README.md")
    intent = PlanIntent(
        goal=PlanGoal.READ_FILE,
        resource_id=resource_id,
        arguments={"resource_id": resource_id, "max_bytes": 4096},
        summary="Read the synthetic README",
    )
    revision = planner.plan(uuid4(), intent)
    assert len(revision.plan.steps) == 1
    step = revision.plan.steps[0]
    assert step.capability_id == "fs.read_file"
    assert step.risk_tier == RiskTier.NAVIGATE
    assert step.recovery_class == "REVERSIBLE"
    assert step.resources[0].resource_id == resource_id
    assert len(revision.plan_hash) == 64


def test_planner_rejects_arguments_the_capability_does_not_accept(world) -> None:
    registry, planner = world["registry"], world["planner"]
    resource_id = resolve(registry, "README.md")
    intent = PlanIntent(
        goal=PlanGoal.READ_FILE,
        resource_id=resource_id,
        arguments={"resource_id": resource_id, "max_bytes": 999_999_999},
        summary="oversized read",
    )
    with pytest.raises(PlannerError) as refused:
        planner.plan(uuid4(), intent)
    assert refused.value.reason_code == "PLAN_ARGUMENTS_INVALID"


def test_planner_refuses_an_unregistered_resource(world) -> None:
    planner = world["planner"]
    intent = PlanIntent(
        goal=PlanGoal.READ_FILE,
        resource_id="file:00000000-0000-4000-8000-000000000000",
        arguments={"resource_id": "file:00000000-0000-4000-8000-000000000000"},
        summary="unknown",
    )
    with pytest.raises(PlannerError) as refused:
        planner.plan(uuid4(), intent)
    assert refused.value.reason_code == "PLAN_RESOURCE_UNKNOWN"


def test_planner_refuses_a_capability_outside_root_scope(tmp_path) -> None:
    tree = build_tree(tmp_path)
    registry = build_registry(tree, capabilities=frozenset({"fs.inspect_file"}))
    planner = Planner(
        capabilities=CapabilityRegistry.phase2_filesystem(),
        resources=registry,
        clock=lambda: NOW,
    )
    resource_id = resolve(registry, "src")
    intent = PlanIntent(
        goal=PlanGoal.SEARCH_PROJECT,
        resource_id=resource_id,
        arguments={"resource_id": resource_id, "query": "needle"},
        summary="search somewhere not permitted",
    )
    with pytest.raises(PlannerError) as refused:
        planner.plan(uuid4(), intent)
    assert refused.value.reason_code == "PLAN_CAPABILITY_OUT_OF_SCOPE"


def test_planner_never_adds_writes_after_approval(world) -> None:
    registry, planner = world["registry"], world["planner"]
    read_id = resolve(registry, "README.md")
    base = planner.plan(
        uuid4(),
        PlanIntent(
            goal=PlanGoal.READ_FILE,
            resource_id=read_id,
            arguments={"resource_id": read_id},
            summary="read",
        ),
    )
    approved = frozenset({base.plan.steps[0].step_id})
    edit_intent = PlanIntent(
        goal=PlanGoal.APPLY_EDIT,
        resource_id=read_id,
        arguments={
            "resource_id": read_id,
            "step_id": str(uuid4()),
            "approval_id": str(uuid4()),
            "expected_sha256": "a" * 64,
        },
        summary="edit",
        # S14-1: an edit plan must carry the exact approved bytes.
        proposed_content=b"# changed\n",
    )
    revised = planner.revision_for_change(
        existing=base.plan, intent=edit_intent, approved_steps=approved
    )
    # The approved step survives untouched, and the new step is genuinely new.
    assert approved.issubset({step.step_id for step in revised.plan.steps})
    assert revised.step_id not in approved
    assert revised.plan.revision == base.plan.revision + 1


# ---------------------------------------------------------------------------
# B. Persisted preview authority
# ---------------------------------------------------------------------------


def test_preview_authority_resolves_the_persisted_preview(world) -> None:
    registry = world["registry"]
    resource_id = resolve(registry, "README.md")
    planned = _persist_plan(
        world,
        PlanIntent(
            goal=PlanGoal.READ_FILE,
            resource_id=resource_id,
            arguments={"resource_id": resource_id},
            summary="read",
        ),
    )
    authoritative = world["previews"].resolve(
        task_id=planned["task_id"],
        plan_revision=planned["revision"].plan.revision,
        plan_hash=planned["plan_hash"],
    )
    preview = world["previews"].preview_for(
        planned["task_id"],
        plan_revision=planned["revision"].plan.revision,
        plan_hash=planned["plan_hash"],
    )
    assert authoritative.preview_id == preview.preview_id
    assert authoritative.preview_digest == preview.preview_digest


def test_preview_authority_refuses_a_superseded_revision(world) -> None:
    registry = world["registry"]
    resource_id = resolve(registry, "README.md")
    planned = _persist_plan(
        world,
        PlanIntent(
            goal=PlanGoal.READ_FILE,
            resource_id=resource_id,
            arguments={"resource_id": resource_id},
            summary="read",
        ),
    )
    with pytest.raises(PreviewSourceUnavailable) as refused:
        world["previews"].resolve(
            task_id=planned["task_id"],
            plan_revision=2,  # no such revision
            plan_hash=planned["plan_hash"],
        )
    assert refused.value.reason_code == "PREVIEW_PLAN_SUPERSEDED"


def test_preview_authority_refuses_a_wrong_plan_hash(world) -> None:
    registry = world["registry"]
    resource_id = resolve(registry, "README.md")
    planned = _persist_plan(
        world,
        PlanIntent(
            goal=PlanGoal.READ_FILE,
            resource_id=resource_id,
            arguments={"resource_id": resource_id},
            summary="read",
        ),
    )
    with pytest.raises(PreviewSourceUnavailable):
        world["previews"].resolve(
            task_id=planned["task_id"],
            plan_revision=planned["revision"].plan.revision,
            plan_hash="0" * 64,
        )


def test_preview_authority_refuses_when_the_narrative_is_missing(world) -> None:
    registry = world["registry"]
    resource_id = resolve(registry, "README.md")
    planned = _persist_plan(
        world,
        PlanIntent(
            goal=PlanGoal.READ_FILE,
            resource_id=resource_id,
            arguments={"resource_id": resource_id},
            summary="read",
        ),
    )
    world["narratives"]._entries.clear()
    with pytest.raises(PreviewSourceUnavailable) as refused:
        world["previews"].resolve(
            task_id=planned["task_id"],
            plan_revision=planned["revision"].plan.revision,
            plan_hash=planned["plan_hash"],
        )
    assert refused.value.reason_code == "PREVIEW_NARRATIVE_UNAVAILABLE"


def test_stale_resource_versions_are_detectable(world) -> None:
    registry, tree = world["registry"], world["tree"]
    resource_id = resolve(registry, "README.md")
    planned = _persist_plan(
        world,
        PlanIntent(
            goal=PlanGoal.APPLY_EDIT,
            resource_id=resource_id,
            arguments={
                "resource_id": resource_id,
                "step_id": str(uuid4()),
                "approval_id": str(uuid4()),
                "expected_sha256": hashlib.sha256(tree.readme.read_bytes()).hexdigest(),
            },
            summary="edit",
            proposed_content=b"# changed by the assistant\n",
        ),
    )
    before = world["previews"].live_resource_versions(
        planned["task_id"], plan_revision=planned["revision"].plan.revision
    )
    tree.readme.write_text("# changed by the user\n", encoding="utf-8")
    registry.resolve(registry.root_by_alias("synthetic-project").root_id, "README.md")
    after = world["previews"].live_resource_versions(
        planned["task_id"], plan_revision=planned["revision"].plan.revision
    )
    assert before != after, "a changed file must produce a different live version"


# ---------------------------------------------------------------------------
# C. The authenticating gesture
# ---------------------------------------------------------------------------


def _binding(**overrides) -> GestureBinding:
    base = {
        "task_id": uuid4(),
        "plan_revision": 1,
        "plan_hash": "a" * 64,
        "preview_id": uuid4(),
        "preview_digest": "b" * 64,
        "scope_digest": "c" * 64,
    }
    base.update(overrides)
    return GestureBinding(**base)


def test_nonce_is_single_use(world) -> None:
    nonces, gestures = world["nonces"], world["gestures"]
    binding = _binding()
    nonce = nonces.issue(binding)
    gesture = gestures.sign(nonce=nonce, binding=binding, user_intent="APPROVE")
    gestures.verify(gesture, expected=binding)
    with pytest.raises(GestureRejected) as replayed:
        gestures.verify(gesture, expected=binding)
    assert replayed.value.reason_code == "GESTURE_NONCE_UNKNOWN"


def test_nonce_bound_to_one_action_cannot_authorize_another(world) -> None:
    nonces, gestures = world["nonces"], world["gestures"]
    issued_for = _binding()
    nonce = nonces.issue(issued_for)
    other = _binding()
    gesture = gestures.sign(nonce=nonce, binding=other, user_intent="APPROVE")
    with pytest.raises(GestureRejected) as refused:
        gestures.verify(gesture, expected=other)
    assert refused.value.reason_code == "GESTURE_BINDING_MISMATCH"


def test_unissued_nonce_cannot_be_forged(world) -> None:
    gestures = world["gestures"]
    binding = _binding()
    gesture = gestures.sign(nonce="f" * 64, binding=binding, user_intent="APPROVE")
    with pytest.raises(GestureRejected) as refused:
        gestures.verify(gesture, expected=binding)
    assert refused.value.reason_code == "GESTURE_NONCE_UNKNOWN"


def test_wrong_key_signature_is_rejected(world) -> None:
    nonces = world["nonces"]
    binding = _binding()
    nonce = nonces.issue(binding)
    attacker = TrustedGestureAuthority(
        key=TrustedGestureAuthority.generate_key(), nonces=nonces, clock=lambda: NOW
    )
    forged = attacker.sign(nonce=nonce, binding=binding, user_intent="APPROVE")
    with pytest.raises(GestureRejected) as refused:
        world["gestures"].verify(forged, expected=binding)
    assert refused.value.reason_code == "GESTURE_SIGNATURE_INVALID"


def test_reject_and_revise_are_not_approvals(world) -> None:
    nonces, gestures = world["nonces"], world["gestures"]
    binding = _binding()
    for intent in ("REJECT", "REVISE", "CANCEL", "DISMISS"):
        nonce = nonces.issue(binding)
        gesture = gestures.sign(nonce=nonce, binding=binding, user_intent=intent)
        with pytest.raises(GestureRejected) as refused:
            gestures.verify(gesture, expected=binding)
        assert refused.value.reason_code == "GESTURE_NOT_APPROVAL"


def test_expired_gesture_is_rejected() -> None:
    """A prompt left open past its window cannot be approved later."""

    binding = _binding()
    clock = {"now": NOW - timedelta(minutes=10)}
    nonces = GestureNonceRegister(clock=lambda: clock["now"])
    gestures = TrustedGestureAuthority(
        key=TrustedGestureAuthority.generate_key(),
        nonces=nonces,
        clock=lambda: clock["now"],
    )
    nonce = nonces.issue(binding)
    gesture = gestures.sign(nonce=nonce, binding=binding, user_intent="APPROVE")

    clock["now"] = NOW  # ten minutes pass while the dialog sits open
    with pytest.raises(GestureRejected) as refused:
        gestures.verify(gesture, expected=binding)
    # Two independent checks both catch this: the gesture is outside its
    # freshness window (checked first) and the nonce has expired behind it.
    assert refused.value.reason_code in {"GESTURE_STALE", "GESTURE_EXPIRED"}
    with pytest.raises(GestureRejected) as burned:
        nonces.consume(nonce, binding)
    assert burned.value.reason_code == "GESTURE_NONCE_UNKNOWN"


def test_gesture_outside_its_freshness_window_is_rejected() -> None:
    """A correctly signed but stale signature is still refused."""

    binding = _binding()
    register_clock = {"now": NOW}
    nonces = GestureNonceRegister(clock=lambda: register_clock["now"])
    signer = TrustedGestureAuthority(
        key=TrustedGestureAuthority.generate_key(),
        nonces=nonces,
        clock=lambda: NOW - timedelta(minutes=30),
    )
    verifier = TrustedGestureAuthority(
        key=signer._key,
        nonces=nonces,
        clock=lambda: NOW,
    )
    nonce = nonces.issue(binding)
    gesture = signer.sign(nonce=nonce, binding=binding, user_intent="APPROVE")
    with pytest.raises(GestureRejected) as refused:
        verifier.verify(gesture, expected=binding)
    assert refused.value.reason_code == "GESTURE_STALE"


def test_concurrent_approvals_of_one_dialog_cannot_both_succeed(world) -> None:
    nonces, gestures = world["nonces"], world["gestures"]
    binding = _binding()
    nonce = nonces.issue(binding)
    gesture = gestures.sign(nonce=nonce, binding=binding, user_intent="APPROVE")
    gestures.verify(gesture, expected=binding)
    with pytest.raises(GestureRejected):
        gestures.verify(gesture, expected=binding)


# ---------------------------------------------------------------------------
# D. Production verifier: accepts only a complete, matching chain
# ---------------------------------------------------------------------------


def _verifier(world, *, key_owner=True):
    return ProductionAttestationVerifier(
        authority_id="electron-main-gesture",
        previews=world["previews"],
        gestures=world["gestures"],
        resolve_gesture=lambda attestation: world.get("pending_gesture"),
        clock=lambda: NOW,
    )


def _attestation(binding: GestureBinding) -> AuthorizationAttestation:
    return AuthorizationAttestation(
        authorization_id=uuid4(),
        authority_id="electron-main-gesture",
        approval_origin="trusted-electron",
        task_id=binding.task_id,
        plan_revision=binding.plan_revision,
        plan_hash=binding.plan_hash,
        preview_id=binding.preview_id,
        preview_digest=binding.preview_digest,
        scope_digest=binding.scope_digest,
        authorized_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=30),
    )


def _issuance(binding: GestureBinding) -> IssuanceBinding:
    return IssuanceBinding(
        task_id=binding.task_id,
        plan_revision=binding.plan_revision,
        plan_hash=binding.plan_hash,
        scope_digest=binding.scope_digest,
        approval_origin="trusted-electron",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        uses_remaining=1,
        max_tier=2,
    )


def test_verifier_accepts_a_complete_matching_chain(world) -> None:
    registry = world["registry"]
    resource_id = resolve(registry, "README.md")
    planned = _persist_plan(
        world,
        PlanIntent(
            goal=PlanGoal.READ_FILE,
            resource_id=resource_id,
            arguments={"resource_id": resource_id},
            summary="read",
        ),
    )
    preview = world["previews"].preview_for(
        planned["task_id"],
        plan_revision=planned["revision"].plan.revision,
        plan_hash=planned["plan_hash"],
    )
    binding = GestureBinding(
        task_id=planned["task_id"],
        plan_revision=planned["revision"].plan.revision,
        plan_hash=planned["plan_hash"],
        preview_id=preview.preview_id,
        preview_digest=preview.preview_digest,
        scope_digest="d" * 64,
    )
    nonce = world["nonces"].issue(binding)
    world["pending_gesture"] = world["gestures"].sign(
        nonce=nonce, binding=binding, user_intent="APPROVE"
    )
    # Must not raise.
    _verifier(world).verify(_attestation(binding), binding=_issuance(binding))


def _prepared_chain(world) -> tuple[GestureBinding, AuthorizationAttestation, IssuanceBinding]:
    registry = world["registry"]
    resource_id = resolve(registry, "README.md")
    planned = _persist_plan(
        world,
        PlanIntent(
            goal=PlanGoal.READ_FILE,
            resource_id=resource_id,
            arguments={"resource_id": resource_id},
            summary="read",
        ),
    )
    preview = world["previews"].preview_for(
        planned["task_id"],
        plan_revision=planned["revision"].plan.revision,
        plan_hash=planned["plan_hash"],
    )
    binding = GestureBinding(
        task_id=planned["task_id"],
        plan_revision=planned["revision"].plan.revision,
        plan_hash=planned["plan_hash"],
        preview_id=preview.preview_id,
        preview_digest=preview.preview_digest,
        scope_digest="d" * 64,
    )
    nonce = world["nonces"].issue(binding)
    world["pending_gesture"] = world["gestures"].sign(
        nonce=nonce, binding=binding, user_intent="APPROVE"
    )
    return binding, _attestation(binding), _issuance(binding)


def test_verifier_rejects_a_missing_gesture(world) -> None:
    _unused, attestation, issuance = _prepared_chain(world)
    world["pending_gesture"] = None
    with pytest.raises(AttestationRejected) as refused:
        _verifier(world).verify(attestation, binding=issuance)
    assert refused.value.reason_code == "AUTHORIZATION_EVIDENCE_MISSING"


def test_verifier_rejects_a_wrong_authority_label(world) -> None:
    _unused, attestation, issuance = _prepared_chain(world)
    forged = attestation.model_copy(update={"authority_id": "some-other-component"})
    with pytest.raises(AttestationRejected) as refused:
        _verifier(world).verify(forged, binding=issuance)
    assert refused.value.reason_code == "AUTHORIZATION_SOURCE_NOT_TRUSTED"


def test_verifier_rejects_task_substitution(world) -> None:
    _unused, attestation, issuance = _prepared_chain(world)
    other_task = replace(issuance, task_id=uuid4())
    with pytest.raises(AttestationRejected) as refused:
        _verifier(world).verify(attestation, binding=other_task)
    assert refused.value.reason_code == "AUTHORIZATION_TASK_MISMATCH"


def test_verifier_rejects_scope_widening(world) -> None:
    _unused, attestation, issuance = _prepared_chain(world)
    wider = replace(issuance, scope_digest="e" * 64)
    with pytest.raises(AttestationRejected) as refused:
        _verifier(world).verify(attestation, binding=wider)
    assert refused.value.reason_code == "AUTHORIZATION_SCOPE_MISMATCH"


def test_verifier_rejects_a_preview_the_backend_never_presented(world) -> None:
    _unused, attestation, issuance = _prepared_chain(world)
    forged = attestation.model_copy(update={"preview_digest": "9" * 64})
    with pytest.raises(AttestationRejected) as refused:
        _verifier(world).verify(forged, binding=issuance)
    assert refused.value.reason_code == "AUTHORIZATION_PREVIEW_MISMATCH"


def test_verifier_rejects_an_expired_attestation(world) -> None:
    _unused, attestation, issuance = _prepared_chain(world)
    expired = attestation.model_copy(update={"expires_at": NOW - timedelta(seconds=1)})
    with pytest.raises(AttestationRejected) as refused:
        _verifier(world).verify(expired, binding=issuance)
    assert refused.value.reason_code == "AUTHORIZATION_EXPIRED"


def test_verifier_rejects_a_tampered_gesture(world) -> None:
    _unused, attestation, issuance = _prepared_chain(world)
    original = world["pending_gesture"]
    world["pending_gesture"] = SignedGesture(
        nonce=original.nonce,
        binding=original.binding,
        asserted_at=original.asserted_at,
        user_intent=original.user_intent,
        signature="0" * 64,
    )
    with pytest.raises(AttestationRejected) as refused:
        _verifier(world).verify(attestation, binding=issuance)
    assert refused.value.reason_code == "GESTURE_SIGNATURE_INVALID"


def test_verifier_refuses_when_no_preview_source_exists(world) -> None:
    _unused, attestation, issuance = _prepared_chain(world)
    verifier = ProductionAttestationVerifier(
        authority_id="electron-main-gesture",
        previews=NullPreviewAuthority(),
        gestures=world["gestures"],
        resolve_gesture=lambda a: world.get("pending_gesture"),
        clock=lambda: NOW,
    )
    with pytest.raises(AttestationRejected) as refused:
        verifier.verify(attestation, binding=issuance)
    assert refused.value.reason_code == "PREVIEW_SOURCE_UNAVAILABLE"


def test_unavailable_gesture_resolver_never_authorizes() -> None:
    resolver = UnavailableGestureResolver()
    assert resolver(_attestation(_binding())) is None


# ---------------------------------------------------------------------------
# E. Shipped defaults remain disabled
# ---------------------------------------------------------------------------


def test_shipped_production_verifier_still_rejects_everything() -> None:
    binding = _binding()
    with pytest.raises(AttestationRejected) as refused:
        PRODUCTION_ATTESTATION_VERIFIER.verify(_attestation(binding), binding=_issuance(binding))
    assert refused.value.reason_code == "AUTHORIZATION_SOURCE_NOT_TRUSTED"


def test_shipped_production_preview_authority_has_no_source() -> None:
    with pytest.raises(PreviewSourceUnavailable) as refused:
        PRODUCTION_PREVIEW_AUTHORITY.resolve(task_id=uuid4(), plan_revision=1, plan_hash="a" * 64)
    assert refused.value.reason_code == "PREVIEW_SOURCE_UNAVAILABLE"


def test_production_verifier_cannot_have_a_placeholder_identity() -> None:
    for identity in ("", "none"):
        with pytest.raises(ValueError):
            ProductionAttestationVerifier(
                authority_id=identity,
                previews=NullPreviewAuthority(),
                gestures=None,  # type: ignore[arg-type]
                resolve_gesture=lambda a: None,
            )


def test_planning_package_exports_no_enabled_issuance_path() -> None:
    """The planning package must not flip the ledger gate or issue grants."""

    package = Path(__file__).parents[1] / "aether" / "core" / "planning"
    forbidden = (
        "GRANT_ISSUANCE_DISABLED",
        "_persist_verified_grant",
        "GrantIssuer(",
        "test_scoped",
    )
    for module in package.glob("*.py"):
        # Scan executable lines only: the docstrings legitimately *describe* the
        # disabled gate they must not touch.
        code = [
            line
            for line in module.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        body = "\n".join(code)
        # Strip docstrings by dropping lines that only appear inside triple quotes.
        in_doc = False
        executable: list[str] = []
        for line in module.read_text(encoding="utf-8").splitlines():
            if line.count('"""') == 1:
                in_doc = not in_doc
                continue
            if in_doc or line.lstrip().startswith("#"):
                continue
            executable.append(line)
        body = "\n".join(executable)
        for token in forbidden:
            assert token not in body, f"{module.name} must not contain {token}"
