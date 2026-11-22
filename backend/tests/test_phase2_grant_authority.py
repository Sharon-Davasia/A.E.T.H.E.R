"""S14-7: a consumption budget is not a second source of grant authority.

The defect: ``ConsumptionLedger.grant_budget()`` could create a spendable
allowance for any approval id a caller chose, including one that no authoritative
Stage 4 grant ever covered. Combined with accepting grant-authority doubles in the
tests, the executor's "authorization" could be demonstrated end to end without a
real grant behind it.

The correction: a budget is a *copy* of an allowance the authoritative Stage 4
grant ledger already records. Registering a budget without a live grant behind it
is refused, spending is re-checked against the grant every time, and simulated
authority is reachable only from allow-listed test modules.

These tests are negative first. The most important ones assert that an invented
approval id, or an independently populated budget, cannot authorize a production
file mutation.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aether.core.grants.consumption import (
    CONSUMPTION_TEST_MODULES,
    ConsumptionError,
    ConsumptionLedger,
    GrantAuthorityUnavailable,
)
from aether.core.grants.ledger import TEST_AUTHORIZATION_MODULES

NOW = datetime(2026, 11, 22, tzinfo=UTC)


class _Grant:
    """A minimal authoritative grant value object, as ``GrantLedger.load`` returns."""

    def __init__(
        self,
        *,
        approval_id,
        task_id,
        plan_revision=1,
        plan_hash="a" * 64,
        uses_remaining=1,
    ) -> None:
        self.approval_id = approval_id
        self.task_id = task_id
        self.plan_revision = plan_revision
        self.plan_hash = plan_hash
        self.uses_remaining = uses_remaining


class _GrantStatus:
    def __init__(self, state: str) -> None:
        self.state = state


class FakeGrantAuthority:
    """A double for the *read* surface only.

    S14-11 makes the authoritative ledger the thing that *spends*, so a double
    that can only answer load/status can no longer authorize anything: it lacks a
    real ``consume``. That is exactly the property these negative tests rely on.
    ``consume`` here is deliberately present but unimplemented, so any test that
    accidentally routes a spend through it fails loudly instead of passing.
    """

    def __init__(self) -> None:
        self.grants: dict[object, _Grant] = {}
        self.states: dict[object, str] = {}

    def consume(self, **terms: object) -> object:
        del terms
        raise AssertionError(
            "a read-only fake authority cannot spend: authoritative consumption "
            "requires the real Stage 4 GrantLedger"
        )

    def issue(self, grant: _Grant, *, state: str = "ACTIVE") -> _Grant:
        self.grants[grant.approval_id] = grant
        self.states[grant.approval_id] = state
        return grant

    def load(self, approval_id):
        from aether.core.grants.ledger import GrantNotFoundError

        if approval_id not in self.grants:
            raise GrantNotFoundError("no persisted grant exists for the given approval id")
        return self.grants[approval_id]

    def status(self, approval_id, *, now=None):
        from aether.core.grants.ledger import GrantNotFoundError

        del now
        if approval_id not in self.states:
            raise GrantNotFoundError("no persisted grant exists for the given approval id")
        return _GrantStatus(self.states[approval_id])


@pytest.fixture()
def authority() -> FakeGrantAuthority:
    return FakeGrantAuthority()


@pytest.fixture()
def ledger(tmp_path: Path, authority: FakeGrantAuthority):
    instance = ConsumptionLedger(
        tmp_path / "consumption.sqlite3", authority=authority, clock=lambda: NOW
    )
    try:
        yield instance
    finally:
        instance.close()


def _consume_kwargs(approval_id, task_id, *, step_id=None, plan_hash="a" * 64):
    from uuid import uuid4

    return {
        "consumption_id": uuid4(),
        "approval_id": approval_id,
        "task_id": task_id,
        "plan_revision": 1,
        "plan_hash": plan_hash,
        "step_id": step_id or uuid4(),
        "capability_id": "fs.apply_approved_edit",
        "risk_tier": 2,
        "arguments_sha256": "c" * 64,
        "expected_effect_sha256": "d" * 64,
        "resource_versions": {"file:" + "0" * 32: "1"},
        "consumed_by": "aether.core.edits.executor",
        "now": NOW,
    }


# ---------------------------------------------------------------------------
# A. Without an authoritative grant source, nothing is spendable
# ---------------------------------------------------------------------------


def test_a_ledger_with_no_authority_refuses_a_budget(tmp_path: Path) -> None:
    """The shipped-constructor default must not be able to invent an allowance."""

    instance = ConsumptionLedger(tmp_path / "bare.sqlite3", clock=lambda: NOW)
    try:
        from uuid import uuid4

        with pytest.raises(GrantAuthorityUnavailable) as refused:
            instance.grant_budget(
                approval_id=uuid4(),
                task_id=uuid4(),
                plan_revision=1,
                plan_hash="a" * 64,
                uses=1,
                now=NOW,
            )
        assert refused.value.reason_code == "GRANT_AUTHORITY_UNAVAILABLE"
    finally:
        instance.close()


def test_a_ledger_with_no_authority_refuses_to_spend(tmp_path: Path) -> None:
    instance = ConsumptionLedger(tmp_path / "bare2.sqlite3", clock=lambda: NOW)
    try:
        from uuid import uuid4

        with pytest.raises(GrantAuthorityUnavailable):
            instance.consume(**_consume_kwargs(uuid4(), uuid4()))
    finally:
        instance.close()


def test_simulated_authority_is_not_reachable_from_core_modules() -> None:
    """Production code must not be able to obtain a simulated ledger.

    The guard walks the call stack for an allow-listed test module. A frame whose
    module name is a shipped ``aether.*`` module is not allow-listed, so the
    check refuses rather than degrading to "trust the caller".
    """

    from aether.core.grants.consumption import _caller_is_permitted_test_module

    # This test module is not on the allow-list, and neither is consumption.py.
    assert not _caller_is_permitted_test_module()
    with pytest.raises(ConsumptionError) as refused:
        ConsumptionLedger.open_tests_scoped("/tmp/__should_not_exist__.sqlite3")
    assert "test-only consumption" in str(refused.value)


def test_a_core_module_frame_does_not_satisfy_the_guard() -> None:
    """Even a call *from* a shipped package module is refused."""

    module_globals = {"__name__": "aether.core.edits.executor"}
    with pytest.raises(ConsumptionError):
        exec(
            "from aether.core.grants.consumption import ConsumptionLedger as C\n"
            "C.open_tests_scoped('/tmp/__should_not_exist_core__.sqlite3')\n",
            module_globals,
        )


def test_the_consumption_allow_list_does_not_widen_the_stage4_list() -> None:
    """Simulated consumption and simulated grants stay separate capabilities."""

    # Neither list may name a shipped package module.
    assert not any(name.startswith("aether.") for name in CONSUMPTION_TEST_MODULES)
    assert not any(name.startswith("aether.") for name in TEST_AUTHORIZATION_MODULES)
    # The Stage 4 list is unchanged by S14-7: same four entries, no additions.
    assert (
        frozenset(
            {
                "tests.stage4_support",
                "tests.test_phase2b_stage4_grants",
                "stage4_support",
                "test_phase2b_stage4_grants",
            }
        )
        == TEST_AUTHORIZATION_MODULES
    )


# ---------------------------------------------------------------------------
# B. An invented approval id cannot become a spendable budget
# ---------------------------------------------------------------------------


def test_an_invented_approval_id_cannot_register_a_budget(
    ledger: ConsumptionLedger,
) -> None:
    """The headline negative: a made-up approval is not an allowance."""

    from uuid import uuid4

    invented = uuid4()
    with pytest.raises(ConsumptionError) as refused:
        ledger.grant_budget(
            approval_id=invented,
            task_id=uuid4(),
            plan_revision=1,
            plan_hash="a" * 64,
            uses=1,
            now=NOW,
        )
    assert refused.value.reason_code == "GRANT_NOT_FOUND"


def test_a_budget_cannot_exceed_the_authoritative_grant(
    ledger: ConsumptionLedger, authority: FakeGrantAuthority
) -> None:
    """A budget is a copy, so it may not be larger than what was granted."""

    from uuid import uuid4

    approval_id, task_id = uuid4(), uuid4()
    authority.issue(_Grant(approval_id=approval_id, task_id=task_id, uses_remaining=1))
    with pytest.raises(ConsumptionError) as refused:
        ledger.grant_budget(
            approval_id=approval_id,
            task_id=task_id,
            plan_revision=1,
            plan_hash="a" * 64,
            uses=8,
            now=NOW,
        )
    assert refused.value.reason_code == "consumption_budget_exceeds_grant"


def test_a_budget_for_another_task_is_refused(
    ledger: ConsumptionLedger, authority: FakeGrantAuthority
) -> None:
    from uuid import uuid4

    approval_id = uuid4()
    authority.issue(_Grant(approval_id=approval_id, task_id=uuid4(), uses_remaining=4))
    with pytest.raises(ConsumptionError) as refused:
        ledger.grant_budget(
            approval_id=approval_id,
            task_id=uuid4(),
            plan_revision=1,
            plan_hash="a" * 64,
            uses=1,
            now=NOW,
        )
    assert refused.value.reason_code == "consumption_budget_grant_mismatch"


def test_a_budget_for_another_plan_hash_is_refused(
    ledger: ConsumptionLedger, authority: FakeGrantAuthority
) -> None:
    from uuid import uuid4

    approval_id, task_id = uuid4(), uuid4()
    authority.issue(_Grant(approval_id=approval_id, task_id=task_id, uses_remaining=4))
    with pytest.raises(ConsumptionError) as refused:
        ledger.grant_budget(
            approval_id=approval_id,
            task_id=task_id,
            plan_revision=1,
            plan_hash="b" * 64,
            uses=1,
            now=NOW,
        )
    assert refused.value.reason_code == "consumption_budget_grant_mismatch"


def test_a_budget_requires_a_live_authoritative_grant(ledger, authority) -> None:
    """Budget registration still refuses without an authoritative grant.

    S14-11 removed the *spendable* role of a budget, but registration still must
    prove the grant exists and still permits that many uses.
    """

    from uuid import uuid4

    approval_id, task_id = uuid4(), uuid4()
    authority.issue(_Grant(approval_id=approval_id, task_id=task_id, uses_remaining=2))
    ledger.grant_budget(
        approval_id=approval_id,
        task_id=task_id,
        plan_revision=1,
        plan_hash="a" * 64,
        uses=2,
        now=NOW,
    )
    # The budget row exists, but it is not a spendable allowance: the spend is
    # routed to the authority, and this fake cannot spend.
    with pytest.raises(ConsumptionError):
        ledger.consume(**_consume_kwargs(approval_id, task_id))


@pytest.mark.parametrize("state", ["EXPIRED", "REVOKED", "EXHAUSTED", "NOT_YET_VALID", "UNKNOWN"])
def test_a_budget_is_refused_when_the_grant_is_not_active(ledger, authority, state: str) -> None:
    """Registration refuses a grant that is not live *now*."""

    from uuid import uuid4

    approval_id, task_id = uuid4(), uuid4()
    authority.issue(_Grant(approval_id=approval_id, task_id=task_id, uses_remaining=2), state=state)
    with pytest.raises(ConsumptionError) as refused:
        ledger.grant_budget(
            approval_id=approval_id,
            task_id=task_id,
            plan_revision=1,
            plan_hash="a" * 64,
            uses=2,
            now=NOW,
        )
    assert refused.value.reason_code.startswith("GRANT_")


def test_a_grant_deleted_before_registration_is_refused(ledger, authority) -> None:
    from uuid import uuid4

    approval_id, task_id = uuid4(), uuid4()
    authority.issue(_Grant(approval_id=approval_id, task_id=task_id, uses_remaining=2))
    del authority.grants[approval_id]
    del authority.states[approval_id]

    with pytest.raises(ConsumptionError) as refused:
        ledger.grant_budget(
            approval_id=approval_id,
            task_id=task_id,
            plan_revision=1,
            plan_hash="a" * 64,
            uses=2,
            now=NOW,
        )
    assert refused.value.reason_code == "GRANT_NOT_FOUND"


# ---------------------------------------------------------------------------
# D. End to end: a production-configured executor cannot be authorized this way
# ---------------------------------------------------------------------------


def test_an_invented_budget_cannot_authorize_a_real_file_mutation(tmp_path: Path) -> None:
    """The whole finding, asserted against the real executor and a real file.

    A caller who fabricates an approval id and tries to give it a budget through
    the shipped constructor gets no budget, so the executor refuses before the
    file is touched.
    """

    from uuid import uuid4

    from aether.core.edits.executor import EditDenied, EditExecutor
    from aether.core.edits.journal import MutationJournal
    from aether.core.edits.receipts import ReceiptStore
    from aether.core.persistence.sqlite_store import PersistentTaskState, SQLiteTaskStore
    from aether.core.planning.planner import PlanGoal, PlanIntent, Planner
    from aether.core.policy.capabilities import CapabilityRegistry
    from aether.core.vault.undo_vault import UndoVault
    from tests.fs_support import build_registry, build_tree, resolve

    tree = build_tree(tmp_path)
    registry = build_registry(
        tree,
        capabilities=frozenset(
            {"fs.inspect_file", "fs.read_file", "fs.apply_approved_edit", "fs.undo_edit"}
        ),
    )
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    receipts = ReceiptStore(tmp_path / "receipts.sqlite3")
    vault = UndoVault(tmp_path / "vault").open()
    # The SHIPPED constructor: no authoritative grant source, so no allowance.
    ledger = ConsumptionLedger(tmp_path / "consume.sqlite3", clock=lambda: NOW)

    class _Accepting:
        def check_action(self, request, grants, *, risk_tier, now=None):
            class _Outcome:
                ok = True
                reason_code = "accepted"
                approval_id = None

            return _Outcome()

    executor = EditExecutor(
        registry,
        _Accepting(),
        vault,
        receipts,
        plans=store,
        grants=ledger,
        # S14-9: a journal is mandatory, so it is present; the only missing
        # authority in this test is the grant source.
        journal=MutationJournal(tmp_path / "journal.sqlite3", clock=lambda: NOW),
        clock=lambda: NOW,
    )
    planner = Planner(
        capabilities=CapabilityRegistry.phase2_filesystem(),
        resources=registry,
        clock=lambda: NOW,
    )

    original = tree.readme.read_bytes()
    edited = b"# Approved\n\nA replacement that must never be written.\n"
    task_id, approval_id = uuid4(), uuid4()
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
                "expected_sha256": hashlib.sha256(original).hexdigest(),
            },
            summary="Edit",
            proposed_content=edited,
        ),
        revision=1,
    )
    store.create_task("t", task_id=task_id, now=NOW)
    store.transition_task(task_id, PersistentTaskState.PLANNING, now=NOW)
    plan_hash = store.save_plan(revision.plan)

    from aether.core.edits.executor import EditRequest

    request = EditRequest(
        task_id=task_id,
        step_id=revision.step_id,
        approval_id=approval_id,
        plan_revision=1,
        plan_hash=plan_hash,
        resource_id=resource_id,
        expected_sha256=hashlib.sha256(original).hexdigest(),
        proposed_content=edited,
        expected_effect_sha256=str(
            revision.plan.steps[0].expected_effect["approved_effect_digest"]
        ),
    )

    try:
        # There is no budget for this approval, and none can be created without a
        # real grant, so the executor must refuse.
        with pytest.raises(EditDenied) as refused:
            executor.apply(request)
        assert refused.value.reason_code in {
            "GRANT_AUTHORITY_UNAVAILABLE",
            "GRANT_NOT_FOUND",
            "GRANT_CONSUMPTION_DISABLED",
        }
        # The decisive assertion: the user's file is untouched.
        assert tree.readme.read_bytes() == original
        assert tree.readme.read_bytes() != edited
    finally:
        ledger.close()
        vault.close()
        receipts.close()
        store.close()


def test_production_issuance_stays_disabled() -> None:
    """S14-7 must not become a reason to enable issuance."""

    source = (
        Path(__file__).resolve().parents[1] / "aether" / "core" / "grants" / "ledger.py"
    ).read_text(encoding="utf-8")
    assert "GRANT_ISSUANCE_DISABLED" in source
