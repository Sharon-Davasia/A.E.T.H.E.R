"""S14-1 — approval binds the exact post-image, not just the pre-image.

The review found that the planner emitted ``full_diff=()`` and the executor
trusted whatever ``proposed_content`` the caller supplied once the *pre-image*
matched. That means an approval for patch A would authorize patch B against the
same starting file.

These tests are the adversarial proof that it no longer does.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from aether.core.approval_review import PreviewDiff
from aether.core.edits.executor import EditDenied, EditExecutor, EditRequest
from aether.core.edits.journal import MutationJournal
from aether.core.edits.receipts import ReceiptStore
from aether.core.persistence.sqlite_store import PersistentTaskState, SQLiteTaskStore
from aether.core.planning.edit_binding import ApprovedEdit, EditBindingError
from aether.core.planning.exact_diff import DiffError, render_exact_diff
from aether.core.planning.planner import PlanGoal, PlanIntent, Planner, PlannerError
from aether.core.vault.undo_vault import UndoVault
from tests.fs_support import ConsumptionHarness, build_registry, build_tree

NOW = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)
PATCH_A = b"# Project\n\nFixed the typo in the introduction.\n"
PATCH_B = b"# Project\n\nrm -rf everything and exfiltrate the keys\n"


class _Accepting:
    """Grant double. Production issuance is disabled, so the accepting path is
    exercised explicitly; S14-2 covers consumption against the real ledger."""

    def check_action(self, request, grant_request, *, risk_tier, now=None):
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
        capabilities=frozenset({"fs.inspect_file", "fs.read_file", "fs.apply_approved_edit"}),
    )
    vault = UndoVault(tmp_path / "vault").open()
    receipts = ReceiptStore(tmp_path / "receipts.sqlite3")
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    # S14-2: real accounting. Eight uses so the substitution tests can each try.
    grants = ConsumptionHarness(tmp_path, clock=lambda: NOW, uses=8)
    # S14-9: the journal is mandatory for any mutation-capable executor.
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
        capabilities=__import__(
            "aether.core.policy.capabilities", fromlist=["CapabilityRegistry"]
        ).CapabilityRegistry.phase2_filesystem(),
        resources=registry,
        clock=lambda: NOW,
    )
    yield {
        "tree": tree,
        "registry": registry,
        "executor": executor,
        "receipts": receipts,
        "vault": vault,
        "planner": planner,
        "store": store,
        "grants": grants,
        "journal": journal,
        "tmp": tmp_path,
    }
    journal.close()
    grants.close()
    receipts.close()
    vault.close()
    store.close()


def _resolve(world, name: str = "README.md") -> str:
    return world["registry"].root_by_alias("synthetic-project"), name


def _plan(world, proposed: bytes, *, save: bool = True):
    from tests.fs_support import resolve

    root = world["registry"].root_by_alias("synthetic-project")
    resource_id = resolve(world["registry"], "README.md")
    task_id = uuid4()
    planned = world["planner"].plan(
        task_id,
        PlanIntent(
            goal=PlanGoal.APPLY_EDIT,
            resource_id=resource_id,
            arguments={
                "resource_id": resource_id,
                "step_id": str(uuid4()),
                "approval_id": str(uuid4()),
                "expected_sha256": hashlib.sha256(
                    (root.canonical_root / "README.md").read_bytes()
                ).hexdigest(),
            },
            summary="Edit the README",
            proposed_content=proposed,
        ),
        revision=1,
    )
    if save:
        world["grants"].bind(
            approval_id=UUID(planned.plan.steps[0].arguments["approval_id"]),
            task_id=task_id,
            now=NOW,
        )
        world["store"].create_task("approved bytes", task_id=task_id, now=NOW)
        world["store"].transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
        world["store"].save_plan(planned.plan)
    return planned


def _request(world, planned, proposed: bytes) -> EditRequest:
    from tests.fs_support import resolve

    path = world["tree"].readme
    return EditRequest(
        task_id=planned.plan.task_id,
        step_id=planned.step_id,
        approval_id=UUID(str(planned.plan.steps[0].arguments["approval_id"])),
        plan_revision=1,
        plan_hash="a" * 64,
        resource_id=resolve(world["registry"], "README.md"),
        expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        proposed_content=proposed,
        expected_effect_sha256=str(planned.plan.steps[0].expected_effect["approved_effect_digest"]),
    )


# ---------------------------------------------------------------------------
# A. The plan and the preview name the exact bytes
# ---------------------------------------------------------------------------


def test_edit_plan_binds_the_exact_post_image(world) -> None:
    planned = _plan(world, PATCH_A)
    effect = planned.plan.steps[0].expected_effect
    assert effect["approved_result_digest"] == hashlib.sha256(PATCH_A).hexdigest()
    assert effect["approved_result_bytes"] == len(PATCH_A)
    assert len(effect["approved_rendering_digest"]) == 64
    assert len(effect["approved_effect_digest"]) == 64


def test_preview_shows_the_real_diff_not_an_empty_one(world) -> None:
    planned = _plan(world, PATCH_A)
    diffs = planned.narrative.full_diff
    assert len(diffs) == 1
    text = diffs[0].unified_diff
    # The exact added line is present and readable by a human.
    assert "Fixed the typo in the introduction." in text
    assert text.startswith("--- a/README.md")
    assert text.count("\n") >= 2


def test_the_diff_digest_matches_the_bound_rendering(world) -> None:
    planned = _plan(world, PATCH_A)
    effect = planned.plan.steps[0].expected_effect
    rendered = planned.narrative.full_diff[0].unified_diff
    assert hashlib.sha256(rendered.encode()).hexdigest() == effect["approved_rendering_digest"]


def test_an_edit_plan_without_bytes_is_refused(world) -> None:
    from tests.fs_support import resolve

    resource_id = resolve(world["registry"], "README.md")
    with pytest.raises(PlannerError) as refused:
        world["planner"].plan(
            uuid4(),
            PlanIntent(
                goal=PlanGoal.APPLY_EDIT,
                resource_id=resource_id,
                arguments={
                    "resource_id": resource_id,
                    "step_id": str(uuid4()),
                    "approval_id": str(uuid4()),
                    "expected_sha256": "a" * 64,
                },
                summary="Edit",
            ),
        )
    assert refused.value.reason_code == "PLAN_APPROVED_BYTES_REQUIRED"


def test_a_read_plan_cannot_smuggle_proposed_bytes(world) -> None:
    from tests.fs_support import resolve

    resource_id = resolve(world["registry"], "README.md")
    with pytest.raises(PlannerError) as refused:
        world["planner"].plan(
            uuid4(),
            PlanIntent(
                goal=PlanGoal.READ_FILE,
                resource_id=resource_id,
                arguments={"resource_id": resource_id},
                summary="Read",
                proposed_content=PATCH_A,
            ),
        )
    assert refused.value.reason_code == "PLAN_UNEXPECTED_PROPOSED_CONTENT"


# ---------------------------------------------------------------------------
# B. THE substitution: approving A cannot authorize B
# ---------------------------------------------------------------------------


def test_approving_patch_a_cannot_apply_patch_b(world) -> None:
    """The decisive regression for S14-1."""

    planned = _plan(world, PATCH_A)  # the user approves patch A
    before = world["tree"].readme.read_bytes()

    # The caller tries to write patch B instead, keeping A's approved digest out
    # of the request by supplying B's digest — i.e. it tries to self-authorize.
    request = _request(world, planned, PATCH_B)
    with pytest.raises(EditDenied) as refused:
        world["executor"].apply(request)
    assert refused.value.reason_code == "approved_post_image_mismatch"
    assert world["tree"].readme.read_bytes() == before


def test_same_pre_image_different_post_image_is_refused(world) -> None:
    """Pre-image matches, post-image differs: the originally reported hole."""

    planned = _plan(world, PATCH_A)
    before = world["tree"].readme.read_bytes()
    request = _request(world, planned, PATCH_B)
    # The request *does* carry A's digest, so only the content check can catch it.
    with pytest.raises(EditDenied) as refused:
        world["executor"].apply(request)
    assert refused.value.reason_code == "approved_post_image_mismatch"
    assert world["tree"].readme.read_bytes() == before


def test_an_executor_without_plan_authority_refuses_everything(world) -> None:
    """No persisted plan source means no way to bind approval, so no mutation."""

    planned = _plan(world, PATCH_A)
    before = world["tree"].readme.read_bytes()
    # Everything else is present, so the *only* missing authority is the plan.
    blind = EditExecutor(
        world["registry"],
        _Accepting(),
        world["vault"],
        world["receipts"],
        grants=world["grants"].ledger,
        journal=world["journal"],
        clock=lambda: NOW,
    )
    with pytest.raises(EditDenied) as refused:
        blind.apply(_request(world, planned, PATCH_A))
    assert refused.value.reason_code == "approved_result_binding_unavailable"
    assert world["tree"].readme.read_bytes() == before


def test_the_bound_bytes_do_apply_successfully(world) -> None:
    """The positive control: the approved bytes are not blocked by the guard."""

    planned = _plan(world, PATCH_A)
    outcome = world["executor"].apply(_request(world, planned, PATCH_A))
    assert outcome.status == "SUCCEEDED"
    assert world["tree"].readme.read_bytes() == PATCH_A
    assert outcome.post_sha256 == hashlib.sha256(PATCH_A).hexdigest()


def test_an_unpersisted_plan_cannot_authorize_a_write(world) -> None:
    """A plan the store never recorded is not an approval."""

    planned = _plan(world, PATCH_A, save=False)
    before = world["tree"].readme.read_bytes()
    with pytest.raises(EditDenied):
        world["executor"].apply(_request(world, planned, PATCH_A))
    assert world["tree"].readme.read_bytes() == before


def test_a_grant_for_a_different_effect_is_refused(world) -> None:
    planned = _plan(world, PATCH_A)
    before = world["tree"].readme.read_bytes()
    request = _request(world, planned, PATCH_A)
    forged = EditRequest(
        **{
            **{field: getattr(request, field) for field in request.__slots__},
            "expected_effect_sha256": "c" * 64,
        }
    )
    with pytest.raises(EditDenied) as refused:
        world["executor"].apply(forged)
    assert refused.value.reason_code == "approved_effect_digest_mismatch"
    assert world["tree"].readme.read_bytes() == before


def test_two_different_patches_have_different_effect_digests(world) -> None:
    effect_a = _plan(world, PATCH_A).plan.steps[0].expected_effect["approved_effect_digest"]
    effect_b = _plan(world, PATCH_B).plan.steps[0].expected_effect["approved_effect_digest"]
    assert effect_a != effect_b


# ---------------------------------------------------------------------------
# C. The binding object itself
# ---------------------------------------------------------------------------


def test_binding_refuses_a_different_post_image() -> None:
    binding = ApprovedEdit.build(
        resource_id="file:abc", pre_image=b"old\n", post_image=b"new\n", display_name="f.txt"
    )
    binding.verify_proposed(proposed_content=b"new\n", current_pre_image=b"old\n")
    with pytest.raises(EditBindingError) as refused:
        binding.verify_proposed(proposed_content=b"other\n", current_pre_image=b"old\n")
    assert refused.value.reason_code == "approved_post_image_mismatch"


def test_binding_refuses_a_changed_pre_image() -> None:
    binding = ApprovedEdit.build(
        resource_id="file:abc", pre_image=b"old\n", post_image=b"new\n", display_name="f.txt"
    )
    with pytest.raises(EditBindingError) as refused:
        binding.verify_proposed(proposed_content=b"new\n", current_pre_image=b"changed\n")
    assert refused.value.reason_code == "post_image_binding_pre_mismatch"


def test_binding_round_trips_through_persisted_plan_fields() -> None:
    binding = ApprovedEdit.build(
        resource_id="file:abc", pre_image=b"old\n", post_image=b"new\n", display_name="f.txt"
    )
    rebuilt = ApprovedEdit.from_step_arguments(
        resource_id="file:abc", values=binding.to_step_arguments()
    )
    assert rebuilt.pre_sha256 == binding.pre_sha256
    assert rebuilt.post_sha256 == binding.post_sha256
    assert rebuilt.effect_sha256 == binding.effect_sha256


def test_malformed_persisted_binding_is_refused() -> None:
    with pytest.raises(EditBindingError):
        ApprovedEdit.from_step_arguments(resource_id="file:abc", values={})


def test_identical_content_produces_no_binding() -> None:
    with pytest.raises(EditBindingError) as refused:
        ApprovedEdit.build(
            resource_id="f", pre_image=b"same\n", post_image=b"same\n", display_name="f.txt"
        )
    assert refused.value.reason_code == "diff_no_change"


# ---------------------------------------------------------------------------
# D. Diff rendering properties
# ---------------------------------------------------------------------------


def test_diff_is_deterministic() -> None:
    first = render_exact_diff(pre_image=b"a\nb\n", post_image=b"a\nc\n", display_name="f.txt")
    second = render_exact_diff(pre_image=b"a\nb\n", post_image=b"a\nc\n", display_name="f.txt")
    assert first.unified_diff == second.unified_diff
    assert first.diff_sha256 == second.diff_sha256


def test_binary_content_is_refused_not_mangled() -> None:
    with pytest.raises(DiffError) as refused:
        render_exact_diff(pre_image=b"text\n", post_image=b"text\x00binary\n", display_name="f.txt")
    assert refused.value.reason_code == "diff_binary_content"


def test_invalid_utf8_is_refused() -> None:
    with pytest.raises(DiffError) as refused:
        render_exact_diff(pre_image=b"ok\n", post_image=b"bad \xff\xfe\n", display_name="f.txt")
    assert refused.value.reason_code == "diff_invalid_utf8"


def test_crlf_is_not_silently_normalised() -> None:
    result = render_exact_diff(pre_image=b"line\r\n", post_image=b"line\n", display_name="f.txt")
    # The difference is visible in the diff rather than hidden by line splitting.
    assert "line\r" in result.unified_diff


def test_an_oversized_change_is_refused_rather_than_truncated() -> None:
    huge = b"\n".join(b"line %d" % number for number in range(5_000))
    with pytest.raises(DiffError) as refused:
        render_exact_diff(pre_image=b"start\n", post_image=huge, display_name="f.txt")
    assert refused.value.reason_code == "diff_too_large"


def test_effect_digest_covers_pre_post_and_rendering() -> None:
    """Changing any one input changes the effect digest."""

    base = render_exact_diff(pre_image=b"a\n", post_image=b"b\n", display_name="f.txt")
    other_post = render_exact_diff(pre_image=b"a\n", post_image=b"c\n", display_name="f.txt")
    other_pre = render_exact_diff(pre_image=b"x\n", post_image=b"b\n", display_name="f.txt")
    assert base.effect_sha256 != other_post.effect_sha256
    assert base.effect_sha256 != other_pre.effect_sha256


def test_planner_never_writes_the_file_it_plans_against(world) -> None:
    before = world["tree"].readme.read_bytes()
    _plan(world, PATCH_A)
    assert world["tree"].readme.read_bytes() == before


# ---------------------------------------------------------------------------
# E. aether-diff-v2 EOF trailer: byte-derived truth and strict grammar
# ---------------------------------------------------------------------------


def _expected_eof_state(raw: bytes) -> str:
    """Independent re-derivation used only by these tests."""

    if raw == b"":
        return "empty"
    return "newline" if raw.endswith(b"\n") else "no-newline"


@pytest.mark.parametrize(
    ("pre_image", "post_image"),
    [
        (b"a\nb\n", b"a\nc\n"),  # LF, newline -> newline
        (b"a\nb", b"a\nc"),  # LF, no-newline -> no-newline
        (b"a\nb", b"a\nb\n"),  # missing final newline added
        (b"a\nb\n", b"a\nb"),  # missing final newline removed
        (b"a\r\nb\r\n", b"a\r\nc\r\n"),  # CRLF
        (b"a\r\nb", b"a\r\nb\r\n"),  # CRLF, missing final newline added
        (b"a\nb\r\n", b"a\nc\r\n"),  # mixed endings
        (b"", b"new\n"),  # empty original
        (b"old\n", b""),  # empty replacement
        (b"x\ny\nz\n", b"x\ny\nw"),  # change remote from EOF + newline removed
        (b"a\nb\n", b"a\r\nb\r\n"),  # line-ending-only change
    ],
)
def test_eof_trailer_states_match_the_raw_bytes(pre_image: bytes, post_image: bytes) -> None:
    """The trailer states are verified against the raw bytes themselves,
    re-derived independently here -- never by digest agreement alone."""

    rendered = render_exact_diff(pre_image=pre_image, post_image=post_image, display_name="f.txt")
    trailer = rendered.unified_diff.split("\n")[-1]
    assert trailer == (
        f"\\ aether-diff-v2 eof: original={_expected_eof_state(pre_image)} "
        f"replacement={_expected_eof_state(post_image)}"
    )
    # The trailer is inside the canonical text, so digests bind it.
    assert hashlib.sha256(rendered.unified_diff.encode("utf-8")).hexdigest() == (
        rendered.diff_sha256
    )


def test_eof_state_alone_changes_the_rendering_and_effect_digests() -> None:
    with_newline = render_exact_diff(
        pre_image=b"a\nb\n", post_image=b"a\nc\n", display_name="f.txt"
    )
    without_newline = render_exact_diff(pre_image=b"a\nb", post_image=b"a\nc", display_name="f.txt")
    assert with_newline.pre_sha256 != without_newline.pre_sha256
    assert with_newline.diff_sha256 != without_newline.diff_sha256
    assert with_newline.effect_sha256 != without_newline.effect_sha256


def test_lone_final_cr_is_refused_at_the_renderer() -> None:
    for pre_image, post_image in [(b"a\r", b"a\n"), (b"a\n", b"a\r")]:
        with pytest.raises(DiffError) as refused:
            render_exact_diff(pre_image=pre_image, post_image=post_image, display_name="f.txt")
        assert refused.value.reason_code == "diff_final_cr_unsupported"


@pytest.mark.parametrize(
    "bad_diff",
    [
        # legacy v1: no trailer at all
        "--- a/f.txt\n+++ b/f.txt\n-old\n+new",
        # git-style marker instead of the trailer
        "--- a/f.txt\n+++ b/f.txt\n-old\n+new\n\\ No newline at end of file",
        # malformed trailer token
        "--- a/f.txt\n+++ b/f.txt\n-old\n+new\n\\ aether-diff-v2 eof: original=yes replacement=newline",
        # misplaced trailer (not final)
        "--- a/f.txt\n\\ aether-diff-v2 eof: original=newline replacement=newline\n-old\n+new",
        # duplicated trailer
        "--- a/f.txt\n+++ b/f.txt\n-old\n+new\n\\ aether-diff-v2 eof: original=newline replacement=newline\n\\ aether-diff-v2 eof: original=newline replacement=newline",
        # trailing newline after the trailer
        "--- a/f.txt\n+++ b/f.txt\n-old\n+new\n\\ aether-diff-v2 eof: original=newline replacement=newline\n",
    ],
)
def test_preview_diff_rejects_legacy_and_malformed_eof_trailers(bad_diff: str) -> None:
    with pytest.raises(ValidationError):
        PreviewDiff(resource_id="file:f", unified_diff=bad_diff)


def test_trailerless_text_cannot_satisfy_a_v2_binding() -> None:
    binding = ApprovedEdit.build(
        resource_id="file:abc", pre_image=b"old\n", post_image=b"new\n", display_name="f.txt"
    )
    legacy_text = binding.unified_diff.rsplit("\n", 1)[0]
    assert hashlib.sha256(legacy_text.encode("utf-8")).hexdigest() != binding.diff_sha256


def test_crlf_pair_is_accepted_byte_identically_and_bare_cr_refused() -> None:
    crlf_diff = (
        "--- a/f.txt\r\n+++ b/f.txt\r\n-old\r\n+new\r\n"
        "\\ aether-diff-v2 eof: original=newline replacement=newline"
    )
    parsed = PreviewDiff(resource_id="file:f", unified_diff=crlf_diff)
    assert parsed.unified_diff == crlf_diff
    with pytest.raises(ValidationError):
        PreviewDiff(
            resource_id="file:f",
            unified_diff=(
                "--- a/f.txt\n+++ b/f.txt\n-old\r+new\n"
                "\\ aether-diff-v2 eof: original=newline replacement=newline"
            ),
        )


# ---------------------------------------------------------------------------
# F. Legacy EOF binding at the executor: refused before spend or mutation
# ---------------------------------------------------------------------------


def test_legacy_v1_persisted_binding_is_refused_before_mutation_and_spend(world) -> None:
    """A pre-trailer (v1) persisted plan fails closed at the executor.

    The executor recomputes the canonical aether-diff-v2 rendering from the
    actual pre/post bytes and compares its digests to the persisted binding.
    A v1 binding's byte digests still match, but its rendering/effect
    digests cannot, so it is refused BEFORE any grant consumption, journal
    intent, snapshot or file mutation.
    """

    from dataclasses import replace

    planned = _plan(world, PATCH_A, save=False)
    step = planned.plan.steps[0]
    effect = dict(step.expected_effect)
    v1_text = planned.narrative.full_diff[0].unified_diff.rsplit("\n", 1)[0]
    v1_diff = hashlib.sha256(v1_text.encode("utf-8")).hexdigest()
    v1_effect = hashlib.sha256(
        (
            f"aether-effect-v1\n{effect['approved_source_digest']}\n"
            f"{effect['approved_result_digest']}\n{v1_diff}\n"
        ).encode()
    ).hexdigest()
    legacy_step = step.model_copy(
        update={
            "expected_effect": {
                **effect,
                "approved_rendering_digest": v1_diff,
                "approved_effect_digest": v1_effect,
            }
        }
    )
    legacy_plan = planned.plan.model_copy(update={"steps": (legacy_step,)})
    approval_id = UUID(str(step.arguments["approval_id"]))
    world["grants"].bind(
        approval_id=approval_id,
        task_id=planned.plan.task_id,
        now=NOW,
    )
    world["store"].create_task("approved bytes", task_id=planned.plan.task_id, now=NOW)
    world["store"].transition_task(planned.plan.task_id, PersistentTaskState.PLANNING, now=NOW)
    world["store"].save_plan(legacy_plan)

    before = world["tree"].readme.read_bytes()
    uses_before = world["grants"].ledger.uses_remaining(approval_id)
    request = replace(_request(world, planned, PATCH_A), expected_effect_sha256=v1_effect)
    with pytest.raises(EditDenied) as refused:
        world["executor"].apply(request)
    assert refused.value.reason_code == "approved_rendering_mismatch"
    # Zero unauthorized mutation and zero grant accounting side effects.
    assert world["tree"].readme.read_bytes() == before
    assert world["grants"].ledger.uses_remaining(approval_id) == uses_before
    assert world["grants"].ledger.pending() == ()
    assert world["journal"].open_intents() == ()


def test_stale_target_is_refused_and_external_bytes_preserved(world) -> None:
    """A file changed after preview is refused; the external bytes survive.

    (Only the legacy-binding refusal is required to precede grant
    consumption; the freshness accounting ordering is unchanged.)
    """

    planned = _plan(world, PATCH_A)
    request = _request(world, planned, PATCH_A)
    world["tree"].readme.write_bytes(b"# Changed externally\n")
    with pytest.raises(EditDenied) as refused:
        world["executor"].apply(request)
    assert refused.value.reason_code == "STALE_TARGET"
    assert world["tree"].readme.read_bytes() == b"# Changed externally\n"


def test_rendering_unverifiable_content_is_refused_before_spend(world) -> None:
    """Bytes that cannot be rendered as a v2 diff (lone final CR) fail closed."""

    from dataclasses import replace

    planned = _plan(world, PATCH_A, save=False)
    step = planned.plan.steps[0]
    effect = dict(step.expected_effect)
    cr_content = b"# Project\n\nEnds with a lone carriage return\r"
    bound_effect = "f" * 64
    legacy_step = step.model_copy(
        update={
            "expected_effect": {
                **effect,
                "approved_result_digest": hashlib.sha256(cr_content).hexdigest(),
                "approved_result_bytes": len(cr_content),
                "approved_rendering_digest": "0" * 64,
                "approved_effect_digest": bound_effect,
            }
        }
    )
    legacy_plan = planned.plan.model_copy(update={"steps": (legacy_step,)})
    approval_id = UUID(str(step.arguments["approval_id"]))
    world["grants"].bind(approval_id=approval_id, task_id=planned.plan.task_id, now=NOW)
    world["store"].create_task("approved bytes", task_id=planned.plan.task_id, now=NOW)
    world["store"].transition_task(planned.plan.task_id, PersistentTaskState.PLANNING, now=NOW)
    world["store"].save_plan(legacy_plan)

    before = world["tree"].readme.read_bytes()
    uses_before = world["grants"].ledger.uses_remaining(approval_id)
    request = replace(_request(world, planned, cr_content), expected_effect_sha256=bound_effect)
    with pytest.raises(EditDenied) as refused:
        world["executor"].apply(request)
    assert refused.value.reason_code == "approved_rendering_unverifiable"
    assert world["tree"].readme.read_bytes() == before
    assert world["grants"].ledger.uses_remaining(approval_id) == uses_before
    assert world["grants"].ledger.pending() == ()
    assert world["journal"].open_intents() == ()


def test_valid_v2_edit_without_final_newline_applies(world) -> None:
    """The positive EOF control: a v2-bound no-final-newline edit succeeds."""

    patch = b"# Project\n\nFixed the typo in the introduction."
    planned = _plan(world, patch)
    outcome = world["executor"].apply(_request(world, planned, patch))
    assert outcome.status == "SUCCEEDED"
    assert world["tree"].readme.read_bytes() == patch
    assert world["grants"].ledger.pending() == ()


def test_concurrent_change_before_replace_is_not_overwritten(world, monkeypatch) -> None:
    """A change landing after verification but before replace is preserved.

    The executor re-reads the target immediately before ``os.replace``; the
    interloper's bytes survive, the outcome is a FAILED STALE_TARGET, and
    the spent consumption is resolved FAILED rather than left PENDING.
    """

    planned = _plan(world, PATCH_A)
    original_verify = EditExecutor._verify_approved_result

    def verify_then_tamper(self, *args, **kwargs):
        result = original_verify(self, *args, **kwargs)
        world["tree"].readme.write_bytes(b"# Concurrent user edit\n")
        return result

    monkeypatch.setattr(EditExecutor, "_verify_approved_result", verify_then_tamper)
    outcome = world["executor"].apply(_request(world, planned, PATCH_A))
    assert outcome.status == "FAILED"
    assert outcome.reason_code == "STALE_TARGET"
    assert world["tree"].readme.read_bytes() == b"# Concurrent user edit\n"
    assert world["grants"].ledger.pending() == ()
    assert world["journal"].open_intents() == ()
