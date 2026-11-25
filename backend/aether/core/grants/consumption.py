"""Grant consumption accounting for the executor boundary (S14-2).

The review found that ``EditExecutor._authorize`` *checked* a grant and then
never consumed it, so the same approval could authorize an unbounded number of
mutations. This module supplies the accounting the executor needs.

Why this is not the Stage 4 :class:`GrantLedger`
------------------------------------------------
The Stage 4 ledger is the production authority, and it requires schema v2, which
is deliberately **not activated**. Binding the edit executor to it would force
that activation, and this change is explicitly not that decision.

So this module implements the two properties the executor actually needs --
atomic single-use accounting and replay rejection -- against schema v1 table
space, and it keeps the same default-deny shape as the rest of Phase 2:

* :class:`IssuanceDisabledConsumptionLedger` is what ships and what a default
  construction gets. Every ``consume`` raises, so no edit is ever authorized.
* :class:`ConsumptionLedger` is only reachable when a caller explicitly enables
  it **and** it has been verified against a real budget record.

That keeps the shipped default exactly as strict as before (no mutation), while
making the accounting path real, testable and independently reviewable.

Safety properties enforced here
-------------------------------
* **Atomic.** The budget decrement and the consumption record are written in one
  transaction. A crash leaves neither or both.
* **Single use.** The ``UPDATE ... WHERE uses_remaining > 0`` row count is the
  gate: a lost race returns ``GRANT_EXHAUSTED`` rather than authorizing twice.
* **Exact action identity.** The consumption is keyed by a digest over the task,
  plan revision, plan hash, step, capability, tier and the arguments and effect
  digests. Spending a use for one action can never cover another.
* **Replay rejection.** Re-submitting the same ``consumption_id`` for the same
  action returns ``replayed=True`` (the action already happened and must not
  happen again); re-submitting it for *different* terms raises.
* **Crash-safe.** A consumption whose filesystem effect was interrupted stays in
  a ``PENDING`` state that reconciliation can find, so it is never silently
  treated as spent-and-successful.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import threading
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from aether.core.contracts.policy import RiskTier
from aether.core.grants.ledger import _is_permitted_test_authorizer

CONSUMPTION_STATES = frozenset({"PENDING", "SUCCEEDED", "FAILED", "UNVERIFIED", "RECONCILED"})

# The local projection's own consumer vocabulary.
CONSUMED_BY_CODES = frozenset({"aether.core.edits.executor"})

# How the *authoritative* Stage 4 ledger names the same actor. The two ledgers keep
# separate bounded vocabularies on purpose, so S14-11 maps explicitly rather than
# passing one ledger's code to the other and being refused.
AUTHORITATIVE_CONSUMER_CODES = {
    "aether.core.edits.executor": "execution_adapter",
}

ConsumptionState = Literal["PENDING", "SUCCEEDED", "FAILED", "UNVERIFIED", "RECONCILED"]


# The only states in which an authoritative grant may be spent against.
_SPENDABLE_GRANT_STATES = frozenset({"ACTIVE"})


# S14-7: the modules permitted to open simulated consumption authority. This is
# a separate allow-list from the Stage 4 grant one and deliberately does not
# extend it: simulated *persistence* for the authoritative ledger and simulated
# *consumption* are different capabilities, and widening the Stage 4 list would
# let more tests fabricate trusted grants. Both lists are assert-checked below.
CONSUMPTION_TEST_MODULES = frozenset(
    {
        "tests.fs_support",
        "tests.test_phase2_grant_consumption",
        "tests.test_phase2_mutation_journal",
        "tests.test_phase2_undo_authorization",
        "tests.test_phase2_approved_bytes",
        "tests.test_phase2_end_to_end",
        "tests.test_phase2d_edits",
        "tests.test_phase2_authoritative_consumption",
        "tests.test_phase2_consumption_recovery",
        "fs_support",
        "test_phase2_grant_consumption",
        "test_phase2_mutation_journal",
        "test_phase2_undo_authorization",
        "test_phase2_approved_bytes",
        "test_phase2_end_to_end",
        "test_phase2d_edits",
        "test_phase2_authoritative_consumption",
        "test_phase2_consumption_recovery",
    }
)

assert not any(name.startswith("aether.") for name in CONSUMPTION_TEST_MODULES), (
    "simulated consumption must never be reachable from the shipped package"
)


def _caller_is_permitted_test_module() -> bool:
    """Whether any frame in the calling stack may open simulated consumption.

    A fixed frame offset is fragile: the factory is reached through fixtures and
    helpers of differing depth. Scanning the stack is not weaker here, because it
    still requires an allow-listed test module to be *in* the call chain, and the
    shipped package contains none of those names by construction.
    """

    import sys

    frame: Any = sys._getframe(1)
    while frame is not None:
        name = frame.f_globals.get("__name__", "")
        if isinstance(name, str) and (
            name in CONSUMPTION_TEST_MODULES or _is_permitted_test_authorizer(name)
        ):
            return True
        frame = frame.f_back
    return False


_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS capability_grant_budgets (
        approval_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        plan_revision INTEGER NOT NULL,
        plan_hash TEXT NOT NULL,
        initial_uses INTEGER NOT NULL CHECK (initial_uses >= 0),
        uses_remaining INTEGER NOT NULL CHECK (uses_remaining >= 0),
        revoked_at TEXT,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS capability_grant_consumptions (
        consumption_id TEXT PRIMARY KEY,
        approval_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        plan_revision INTEGER NOT NULL,
        plan_hash TEXT NOT NULL,
        step_id TEXT NOT NULL,
        capability_id TEXT NOT NULL,
        risk_tier INTEGER NOT NULL,
        action_digest TEXT NOT NULL,
        consumed_by TEXT NOT NULL,
        consumed_at TEXT NOT NULL,
        uses_remaining_after INTEGER NOT NULL,
        state TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS capability_grant_consumptions_by_action
        ON capability_grant_consumptions(approval_id, action_digest)
    """,
    """
    CREATE TABLE IF NOT EXISTS capability_grant_attempts (
        consumption_id TEXT PRIMARY KEY,
        approval_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        plan_revision INTEGER NOT NULL,
        plan_hash TEXT NOT NULL,
        step_id TEXT NOT NULL,
        capability_id TEXT NOT NULL,
        risk_tier INTEGER NOT NULL,
        action_digest TEXT NOT NULL,
        consumed_by TEXT NOT NULL,
        started_at TEXT NOT NULL
    )
    """,
)


class ConsumptionError(Exception):
    """Consumption was refused; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


class GrantAuthoritySource(Protocol):
    """The authoritative Stage 4 grant ledger, as consumption uses it (S14-11).

    S14-7 made consumption *check* the authoritative ledger but still decrement a
    local budget. That left two spendable allowances: two independently created
    consumption databases could each pass the check and each spend, while the real
    grant's ``uses_remaining`` never moved. Checking authority is not holding it.

    Consumption therefore delegates the spend itself. ``consume`` must:
    * re-validate scope, current-plan binding, fresh consent, revocation and
      expiry;
    * decrement the *global* use count exactly once, in one transaction;
    * persist the consumption record and append the audit event;
    * be replay-safe: the same ``consumption_id`` with the same action terms
      returns the committed record marked ``replayed``, and with different terms
      raises.
    ``GrantLedger.consume`` already provides exactly this; the protocol exists so
    the requirement is written down and so a fake cannot satisfy it by accident.
    """

    def load(self, approval_id: UUID) -> object:
        """The persisted grant, or raise if there is none."""

    def status(self, approval_id: UUID, *, now: datetime | None = None) -> object:
        """Current lifecycle state of the grant, or raise if there is none."""

    def consume(self, **terms: object) -> object:
        """Spend one authoritative use against this exact action, atomically."""


class GrantAuthorityUnavailable(ConsumptionError):
    """No authoritative grant source is configured, so nothing may be spent."""

    def __init__(self) -> None:
        super().__init__(
            "GRANT_AUTHORITY_UNAVAILABLE",
            "consumption requires the authoritative Stage 4 grant ledger; without it a "
            "budget would be a second, unverified approval source",
        )


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ConsumptionError(
            "consumption_timestamp_naive", "consumption requires an aware timestamp"
        )
    return value.astimezone(UTC).isoformat()


def _digest(value: object) -> str:
    material = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def action_identity(
    *,
    task_id: UUID,
    plan_revision: int,
    plan_hash: str,
    step_id: UUID,
    capability_id: str,
    risk_tier: RiskTier,
    arguments_sha256: str,
    expected_effect_sha256: str,
    resource_versions: dict[str, str],
    consumed_by: str,
) -> str:
    """The exact action a single consumption authorizes, as a digest.

    Everything that could distinguish one action from another is included, so a
    grant use spent here is meaningless for any other action.
    """

    if unicodedata.normalize("NFC", plan_hash) != plan_hash:
        raise ConsumptionError("consumption_plan_hash_not_normalised", "plan hash must be NFC")
    return _digest(
        {
            "task_id": str(task_id),
            "plan_revision": plan_revision,
            "plan_hash": plan_hash.casefold(),
            "step_id": str(step_id),
            "capability_id": capability_id,
            "risk_tier": int(risk_tier),
            "arguments_sha256": arguments_sha256,
            "expected_effect_sha256": expected_effect_sha256,
            "resource_versions": dict(sorted(resource_versions.items())),
            "consumed_by": consumed_by,
        }
    )


@dataclass(frozen=True, slots=True)
class Consumption:
    consumption_id: UUID
    approval_id: UUID
    action_digest: str
    uses_remaining_after: int
    consumed_at: datetime
    state: ConsumptionState
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ConsumptionAttempt:
    """A spend this process began, durable before the spend happened (S14-12).

    It exists so a crash between the authoritative commit and the local projection
    leaves something a restart can find. It carries the stable ``consumption_id``
    and the action identity, which is exactly enough to ask the authoritative
    ledger whether the use was actually spent. It is *not* an allowance: nothing
    reads it to decide permission, and holding one authorizes nothing.
    """

    consumption_id: UUID
    approval_id: UUID
    action_digest: str
    started_at: datetime


class IssuanceDisabledConsumptionLedger:
    """The shipped default: no consumption is possible, so no edit is authorized.

    This mirrors ``GRANT_ISSUANCE_DISABLED``. It is not an ordering nuisance: it
    is the guarantee that a default-constructed executor cannot mutate anything,
    and that enabling real accounting is a visible, reviewable act.
    """

    def consume(self, **_: object) -> Consumption:
        raise ConsumptionError(
            "GRANT_CONSUMPTION_DISABLED",
            "grant consumption is disabled: no approval has been issued that a "
            "consumption could spend, and enabling it requires explicit review",
        )

    def status(self, approval_id: UUID) -> Consumption:
        del approval_id
        raise ConsumptionError("GRANT_CONSUMPTION_DISABLED", "consumption is disabled")


class ConsumptionLedger:
    """Atomic, replay-safe single-use accounting backed by SQLite.

    Constructed only by a caller that has already decided to enable accounting
    for this process. It cannot issue a grant, widen a scope, or create a budget:
    a budget must have been recorded beforehand, so this object can only spend
    what already exists.
    """

    def __init__(
        self,
        database: Path | str,
        *,
        authority: GrantAuthoritySource | None = None,
        clock: object | None = None,
    ) -> None:
        self._lock = threading.RLock()
        # S14-7: this ledger records what an already-issued grant allows. It is
        # NOT a second authority. Without the authoritative grant ledger it can
        # neither register a budget nor spend one, so a consumption database on
        # its own can never authorize a mutation.
        self._authority = authority
        self._simulated_authority = False
        self._clock = clock or (lambda: datetime.now(UTC))
        connection = sqlite3.connect(str(database), isolation_level=None, check_same_thread=False)
        try:
            connection.row_factory = sqlite3.Row
            with self._lock:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA foreign_keys=ON")
                for statement in _SCHEMA:
                    connection.execute(statement)
        except BaseException:
            # W-A3: deterministic constructor cleanup (see ReceiptStore):
            # a partially constructed ledger is owned by no one, so its
            # connection must be closed here, preserving the failure.
            connection.close()
            raise
        self._connection = connection

    @classmethod
    def open_tests_scoped(
        cls,
        database: Path | str,
        *,
        clock: object | None = None,
    ) -> ConsumptionLedger:
        """Open a **test-only** ledger that accepts simulated grant authority.

        S14-7 keeps the authoritative Stage 4 grant ledger as the only source of
        a spendable allowance. Some accounting semantics (replay, races, crash
        windows, reconciliation) must be tested without fabricating a trusted
        attestation, which the Stage 4 ledger rightly refuses.

        This factory mirrors ``GrantLedger.open_tests_scoped``: it is reachable
        only from allow-listed test modules, grants nothing, and cannot be
        obtained from the shipped package. The instance it returns is marked as
        simulated so a caller can see that its authority was not production.
        """

        if not _caller_is_permitted_test_module():
            raise ConsumptionError(
                "test-only consumption is not available to core modules",
                "simulated consumption authority is reachable only from tests",
            )
        ledger = cls(database, clock=clock)
        ledger._simulated_authority = True
        return ledger

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> ConsumptionLedger:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- budget ------------------------------------------------------------

    def grant_budget(
        self,
        *,
        approval_id: UUID,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        uses: int,
        now: datetime | None = None,
    ) -> None:
        """Record the *existing* budget a grant represents. Cannot widen it."""

        timestamp = _timestamp(now or self._clock())  # type: ignore[operator]
        if uses < 0:
            raise ConsumptionError("consumption_uses_invalid", "uses must not be negative")
        # S14-7: a budget is a *copy* of an authoritative allowance, never a
        # source of one. Refuse to register a budget the real grant ledger does
        # not back, and refuse one larger than that grant actually permits.
        authoritative = self._authoritative_scope(
            approval_id,
            now=now or self._clock(),  # type: ignore[operator]
        )
        if authoritative is not None:
            self._check_budget_against_grant(
                authoritative,
                approval_id=approval_id,
                task_id=task_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                uses=uses,
            )
        with self._lock, self._transaction() as connection:
            row = connection.execute(
                "SELECT initial_uses FROM capability_grant_budgets WHERE approval_id = ?",
                (str(approval_id),),
            ).fetchone()
            if row is not None:
                if int(row["initial_uses"]) != uses:
                    raise ConsumptionError(
                        "consumption_budget_conflict",
                        "a budget for this approval already exists with a different size",
                    )
                return
            connection.execute(
                "INSERT INTO capability_grant_budgets (approval_id, task_id, plan_revision,"
                " plan_hash, initial_uses, uses_remaining, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(approval_id),
                    str(task_id),
                    plan_revision,
                    plan_hash.casefold(),
                    uses,
                    uses,
                    timestamp,
                ),
            )

    @staticmethod
    def _check_budget_against_grant(
        grant: object,
        *,
        approval_id: UUID,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        uses: int,
    ) -> None:
        """A budget may not describe an allowance the grant does not contain."""

        if getattr(grant, "approval_id", None) != approval_id:
            raise ConsumptionError(
                "consumption_budget_grant_mismatch",
                "the authoritative grant is for a different approval",
            )
        if getattr(grant, "task_id", None) != task_id:
            raise ConsumptionError(
                "consumption_budget_grant_mismatch",
                "the authoritative grant is for a different task",
            )
        if getattr(grant, "plan_revision", None) != plan_revision:
            raise ConsumptionError(
                "consumption_budget_grant_mismatch",
                "the authoritative grant covers a different plan revision",
            )
        granted_hash = str(getattr(grant, "plan_hash", "")).casefold()
        if granted_hash != plan_hash.casefold():
            raise ConsumptionError(
                "consumption_budget_grant_mismatch",
                "the authoritative grant covers a different plan hash",
            )
        granted_uses = int(getattr(grant, "uses_remaining", 0) or 0)
        if uses > granted_uses:
            # Never widen: a budget larger than the grant would allow more
            # spendable uses than the approval actually granted.
            raise ConsumptionError(
                "consumption_budget_exceeds_grant",
                "the requested budget allows more uses than the authoritative grant",
            )

    def revoke(self, approval_id: UUID, *, now: datetime | None = None) -> None:
        timestamp = _timestamp(now or self._clock())  # type: ignore[operator]
        with self._lock, self._transaction() as connection:
            updated = connection.execute(
                "UPDATE capability_grant_budgets SET revoked_at = ?, uses_remaining = 0"
                " WHERE approval_id = ?",
                (timestamp, str(approval_id)),
            )
            if updated.rowcount != 1:
                raise ConsumptionError(
                    "consumption_budget_missing", "no budget exists for this approval"
                )

    # -- consumption -------------------------------------------------------

    def consume(
        self,
        *,
        consumption_id: UUID,
        approval_id: UUID,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        step_id: UUID,
        capability_id: str,
        risk_tier: RiskTier,
        arguments_sha256: str,
        expected_effect_sha256: str,
        resource_versions: dict[str, str],
        consumed_by: str,
        now: datetime | None = None,
    ) -> Consumption:
        if consumed_by not in CONSUMED_BY_CODES:
            raise ConsumptionError(
                "consumption_consumer_invalid", "consumed_by must be an allow-listed code"
            )
        # S14-11: when an authoritative ledger is configured, the spend IS the
        # authoritative transaction. Dispatching here means a production caller
        # cannot reach the local-only path by forgetting to call the right method.
        if self._authority is not None:
            return self.consume_authoritative(
                consumption_id=consumption_id,
                approval_id=approval_id,
                task_id=task_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                step_id=step_id,
                capability_id=capability_id,
                risk_tier=risk_tier,
                arguments_sha256=arguments_sha256,
                expected_effect_sha256=expected_effect_sha256,
                resource_versions=resource_versions,
                consumed_by=consumed_by,
                now=now,
            )
        timestamp = _timestamp(now or self._clock())  # type: ignore[operator]
        # Simulated (test-scoped) authority only: re-check so the accounting
        # semantics under test still behave, but note that the authoritative
        # ledger is not involved by construction.
        self._authoritative_scope(approval_id, now=now or self._clock())  # type: ignore[operator]
        identity = action_identity(
            task_id=task_id,
            plan_revision=plan_revision,
            plan_hash=plan_hash,
            step_id=step_id,
            capability_id=capability_id,
            risk_tier=risk_tier,
            arguments_sha256=arguments_sha256,
            expected_effect_sha256=expected_effect_sha256,
            resource_versions=resource_versions,
            consumed_by=consumed_by,
        )
        with self._lock, self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM capability_grant_consumptions WHERE consumption_id = ?",
                (str(consumption_id),),
            ).fetchone()
            if existing is not None:
                if existing["action_digest"] != identity:
                    raise ConsumptionError(
                        "consumption_replay_mismatch",
                        "this consumption id was already used for a different action",
                    )
                return _consumption_from_row(existing, replayed=True)

            budget = connection.execute(
                "SELECT * FROM capability_grant_budgets WHERE approval_id = ?",
                (str(approval_id),),
            ).fetchone()
            if budget is None:
                raise ConsumptionError(
                    "GRANT_NOT_FOUND",
                    "no recorded budget exists for this approval, so no use can be spent",
                )
            if budget["revoked_at"] is not None:
                raise ConsumptionError("GRANT_REVOKED", "the grant was revoked")
            if (
                budget["task_id"] != str(task_id)
                or int(budget["plan_revision"]) != plan_revision
                or budget["plan_hash"] != plan_hash.casefold()
            ):
                raise ConsumptionError(
                    "GRANT_PLAN_SUPERSEDED",
                    "the grant does not belong to this task and plan revision",
                )
            decremented = connection.execute(
                "UPDATE capability_grant_budgets"
                " SET uses_remaining = uses_remaining - 1"
                " WHERE approval_id = ? AND uses_remaining > 0 AND revoked_at IS NULL",
                (str(approval_id),),
            )
            if decremented.rowcount != 1:
                raise ConsumptionError("GRANT_EXHAUSTED", "the grant has no uses remaining")
            after = int(budget["uses_remaining"]) - 1
            connection.execute(
                "INSERT INTO capability_grant_consumptions (consumption_id, approval_id,"
                " task_id, plan_revision, plan_hash, step_id, capability_id, risk_tier,"
                " action_digest, consumed_by, consumed_at, uses_remaining_after, state)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')",
                (
                    str(consumption_id),
                    str(approval_id),
                    str(task_id),
                    plan_revision,
                    plan_hash.casefold(),
                    str(step_id),
                    capability_id,
                    int(risk_tier),
                    identity,
                    consumed_by,
                    timestamp,
                    after,
                ),
            )
            return Consumption(
                consumption_id=consumption_id,
                approval_id=approval_id,
                action_digest=identity,
                uses_remaining_after=after,
                consumed_at=datetime.fromisoformat(timestamp),
                state="PENDING",
            )

    def resolve(
        self,
        consumption_id: UUID,
        *,
        state: ConsumptionState,
        detail: str = "",
    ) -> Consumption:
        """Record what actually happened to a consumed use.

        A consumption left ``PENDING`` by a crash is exactly what reconciliation
        looks for, so this is never inferred from the filesystem.
        """

        if state == "PENDING":
            raise ConsumptionError("consumption_state_invalid", "cannot resolve to PENDING")
        if state not in CONSUMPTION_STATES:
            raise ConsumptionError("consumption_state_invalid", "unknown consumption state")
        with self._lock, self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM capability_grant_consumptions WHERE consumption_id = ?",
                (str(consumption_id),),
            ).fetchone()
            if row is None:
                raise ConsumptionError("consumption_missing", "no such consumption")
            if row["state"] != "PENDING" and row["state"] != state:
                raise ConsumptionError(
                    "consumption_already_resolved",
                    "this consumption was already resolved to a different state",
                )
            connection.execute(
                "UPDATE capability_grant_consumptions SET state = ?, detail = ?"
                " WHERE consumption_id = ?",
                (state, detail[:512], str(consumption_id)),
            )
            return _consumption_from_row(
                connection.execute(
                    "SELECT * FROM capability_grant_consumptions WHERE consumption_id = ?",
                    (str(consumption_id),),
                ).fetchone(),
                replayed=False,
            )

    def pending(self) -> tuple[Consumption, ...]:
        """Consumptions whose effect is unknown: the crash-recovery work list."""

        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM capability_grant_consumptions WHERE state = 'PENDING'"
                " ORDER BY consumed_at"
            ).fetchall()
        return tuple(_consumption_from_row(row, replayed=False) for row in rows)

    def uses_remaining(self, approval_id: UUID) -> int:
        """Remaining uses. Authoritative when a real ledger is configured.

        Reading the local projection first would let two consumption databases
        each report the full count while the global grant was already exhausted,
        which is the second-allowance defect S14-11 removes.
        """

        if self._authority is not None:
            return self.authoritative_uses_remaining(approval_id)
        with self._lock:
            row = self._connection.execute(
                "SELECT uses_remaining FROM capability_grant_budgets WHERE approval_id = ?",
                (str(approval_id),),
            ).fetchone()
        if row is None:
            raise ConsumptionError("GRANT_NOT_FOUND", "no budget exists for this approval")
        return int(row["uses_remaining"])

    # -- internals ---------------------------------------------------------

    # -- authoritative execution path (S14-11) ----------------------------

    def consume_authoritative(
        self,
        *,
        consumption_id: UUID,
        approval_id: UUID,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        step_id: UUID,
        capability_id: str,
        risk_tier: RiskTier,
        arguments_sha256: str,
        expected_effect_sha256: str,
        resource_versions: dict[str, str],
        consumed_by: str,
        now: datetime | None = None,
    ) -> Consumption:
        """Spend one use of the *authoritative* grant, atomically.

        This is the only path production execution may use. The spend happens in
        ``GrantLedger.consume``'s own transaction, so the global use count is
        decremented exactly once, the consumption record is written, and the audit
        event is appended as one unit. There is no local allowance to spend, so
        two independently created consumption databases share the single global
        count instead of each holding a copy of it.

        **The two databases cannot commit together** (S14-12). The authoritative
        ledger owns its file; this projection owns another. A crash between the
        authorititative commit and the projection insert is therefore *possible*,
        and pretending otherwise was the bug: the spend was real, but nothing
        local named it, so restart reconciliation could not find it.

        The order below is chosen so that crash is always discoverable:

        1. write a durable **attempt** row, committed *before* the spend. It
           carries the stable ``consumption_id`` and the full action identity, so
           a restart can ask the authoritative ledger "was this spent?" without
           having to trust anything local;
        2. spend, via the authoritative ledger;
        3. record the projection, which tracks only the *outcome* of the
           filesystem effect and never decides permission.

        A crash after (1) but before (2) leaves an attempt the ledger has no
        consumption for, and reconciliation reports it as not-spent. A crash after
        (2) but before (3) leaves an attempt the ledger *does* have a consumption
        for, and reconciliation reports it NEEDS_REVIEW. Neither can be mistaken
        for success.
        """

        authority = self._require_authority()
        if authority is None:
            # Test-scoped simulated authority has no authoritative ledger behind
            # it, so it must not take this path: that would be the parallel
            # allowance this method exists to remove.
            raise ConsumptionError(
                "consumption_authority_not_authoritative",
                "authoritative consumption requires the real Stage 4 grant ledger, "
                "not a simulated one",
            )
        timestamp = _timestamp(now or self._clock())  # type: ignore[operator]
        if consumed_by not in CONSUMED_BY_CODES:
            raise ConsumptionError(
                "consumption_consumer_invalid", "consumed_by must be an allow-listed code"
            )
        identity = action_identity(
            task_id=task_id,
            plan_revision=plan_revision,
            plan_hash=plan_hash,
            step_id=step_id,
            capability_id=capability_id,
            risk_tier=risk_tier,
            arguments_sha256=arguments_sha256,
            expected_effect_sha256=expected_effect_sha256,
            resource_versions=resource_versions,
            consumed_by=consumed_by,
        )

        # --- 1. durable attempt, committed before any spend -----------------
        # Refuse a reused id that means a different action *before* touching the
        # authoritative ledger: a mismatched identity must never reach a spend.
        existing_attempt = self._attempt(consumption_id)
        if existing_attempt is not None and str(existing_attempt["action_digest"]) != identity:
            raise ConsumptionError(
                "consumption_attempt_mismatch",
                "this consumption id was already begun for a different action",
            )
        if existing_attempt is None:
            with self._lock, self._transaction() as connection:
                connection.execute(
                    "INSERT INTO capability_grant_attempts"
                    " (consumption_id, approval_id, task_id, plan_revision, plan_hash,"
                    " step_id, capability_id, risk_tier, action_digest, consumed_by,"
                    " started_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        str(consumption_id),
                        str(approval_id),
                        str(task_id),
                        plan_revision,
                        plan_hash.casefold(),
                        str(step_id),
                        capability_id,
                        int(risk_tier),
                        identity,
                        consumed_by,
                        timestamp,
                    ),
                )

        # --- 2. the authoritative transaction -------------------------------
        # Everything below mirrors a refusal from the ledger verbatim so the
        # executor's reason codes stay meaningful.
        try:
            record = authority.consume(
                consumption_id=consumption_id,
                approval_id=approval_id,
                task_id=task_id,
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                step_id=step_id,
                capability_id=capability_id,
                risk_tier=risk_tier,
                arguments_sha256=arguments_sha256,
                expected_effect_sha256=expected_effect_sha256,
                resource_versions=dict(resource_versions),
                consumed_by=AUTHORITATIVE_CONSUMER_CODES.get(consumed_by, consumed_by),
                now=now or self._clock(),  # type: ignore[operator]
            )
        except Exception as exc:
            reason = getattr(exc, "reason_code", None)
            if reason:
                raise ConsumptionError(str(reason), str(exc)) from exc
            raise ConsumptionError(
                "GRANT_CONSUMPTION_FAILED", "the authoritative ledger refused the spend"
            ) from exc

        replayed = bool(getattr(record, "replayed", False))
        uses_remaining_after = int(getattr(record, "uses_remaining_after", 0))

        # --- 3. projection, which must never overwrite a terminal outcome ----
        return self._record_projection(
            consumption_id=consumption_id,
            approval_id=approval_id,
            task_id=task_id,
            plan_revision=plan_revision,
            plan_hash=plan_hash,
            step_id=step_id,
            capability_id=capability_id,
            risk_tier=risk_tier,
            identity=identity,
            consumed_by=consumed_by,
            timestamp=timestamp,
            uses_remaining_after=uses_remaining_after,
            replayed=replayed,
        )

    def _record_projection(
        self,
        *,
        consumption_id: UUID,
        approval_id: UUID,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        step_id: UUID,
        capability_id: str,
        risk_tier: RiskTier,
        identity: str,
        consumed_by: str,
        timestamp: str,
        uses_remaining_after: int,
        replayed: bool,
    ) -> Consumption:
        """Attach the spend to the local outcome row without destroying it.

        S14-13: this used to be ``INSERT OR REPLACE``, so replaying a consumption
        id reset a resolved ``SUCCEEDED`` / ``FAILED`` / ``UNVERIFIED`` row back to
        ``PENDING``. That is silent evidence loss on the exact path that is
        supposed to refuse a second mutation: the executor's replay guard reads
        ``replayed``, but the durable record of what happened to the *first*
        attempt had already been overwritten by the time anything could look.

        So an existing row is validated, never replaced:

        * a mismatched identity is refused outright;
        * a terminal state and its detail are preserved verbatim;
        * a PENDING row stays PENDING (the effect is still unknown).

        A genuinely missing projection is created as PENDING. It is never created
        as success: the caller has spent a use but has not yet proven an effect.
        """

        with self._lock, self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM capability_grant_consumptions WHERE consumption_id = ?",
                (str(consumption_id),),
            ).fetchone()
            if existing is not None:
                if str(existing["action_digest"]) != identity:
                    raise ConsumptionError(
                        "consumption_projection_mismatch",
                        "a local projection exists for this id with a different action; "
                        "refusing to overwrite it",
                    )
                # Preserve whatever the first attempt concluded. A replay must not
                # resurrect a resolved consumption, and must not erase its detail.
                return _consumption_from_row(existing, replayed=replayed)

            connection.execute(
                "INSERT INTO capability_grant_consumptions"
                " (consumption_id, approval_id, task_id, plan_revision, plan_hash,"
                " step_id, capability_id, risk_tier, action_digest, consumed_by,"
                " consumed_at, uses_remaining_after, state, detail)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(consumption_id),
                    str(approval_id),
                    str(task_id),
                    plan_revision,
                    plan_hash.casefold(),
                    str(step_id),
                    capability_id,
                    int(risk_tier),
                    identity,
                    consumed_by,
                    timestamp,
                    uses_remaining_after,
                    "PENDING",
                    "",
                ),
            )
        return Consumption(
            consumption_id=consumption_id,
            approval_id=approval_id,
            action_digest=identity,
            uses_remaining_after=uses_remaining_after,
            consumed_at=datetime.fromisoformat(timestamp),
            state="PENDING",
            replayed=replayed,
        )

    # -- recovery surface (S14-12) ----------------------------------------

    def _attempt(self, consumption_id: UUID) -> sqlite3.Row | None:
        with self._lock:
            row: sqlite3.Row | None = self._connection.execute(
                "SELECT * FROM capability_grant_attempts WHERE consumption_id = ?",
                (str(consumption_id),),
            ).fetchone()
            return row

    def unprojected_attempts(self) -> tuple[ConsumptionAttempt, ...]:
        """Attempts that reached the spend but have no local projection.

        These are the crash window S14-12 exists for: the authoritative ledger may
        hold a consumption that no local row and no journal intent names. Returned
        oldest-first so a restart walks them deterministically.
        """

        with self._lock:
            rows = self._connection.execute(
                "SELECT a.* FROM capability_grant_attempts AS a"
                " LEFT JOIN capability_grant_consumptions AS c"
                "   ON c.consumption_id = a.consumption_id"
                " WHERE c.consumption_id IS NULL"
                " ORDER BY a.started_at, a.consumption_id"
            ).fetchall()
            return tuple(_attempt_from_row(row) for row in rows)

    def authoritative_consumption(self, consumption_id: UUID) -> object | None:
        """The authoritative ledger's record for an id, or ``None`` if unspent.

        This is the question reconciliation must be able to ask. It is answered by
        the authoritative ledger itself, never by the local projection, so a
        missing local row cannot hide a real spend.
        """

        authority = self._require_authority()
        if authority is None:
            raise ConsumptionError(
                "consumption_authority_not_authoritative",
                "no authoritative grant ledger is configured",
            )
        reader = getattr(authority, "get_consumption", None)
        if reader is None:
            raise ConsumptionError(
                "consumption_authority_incomplete",
                "the authoritative ledger cannot be queried by consumption id, so a "
                "spend it holds without a local projection is undiscoverable",
            )
        try:
            found: object | None = reader(consumption_id)
            return found
        except Exception as exc:
            # Absent is an answer: it means the attempt never reached the spend,
            # or the spend was refused. Anything else is a failure to ask.
            if type(exc).__name__ == "GrantNotFoundError":
                return None
            raise

    def grant_budget_simulated(
        self,
        *,
        approval_id: UUID,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        uses: int,
        now: datetime | None = None,
    ) -> None:
        """Write a local budget row directly, bypassing all authority.

        This exists so a test can prove the local projection is *inert*: a row
        invented here must not allow a single spend, because permission comes from
        the authoritative ledger alone (S14-11). It is not a supported way to
        obtain an allowance, and ``consume_authoritative`` never reads it.
        """

        timestamp = _timestamp(now or self._clock())  # type: ignore[operator]
        with self._lock, self._transaction() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO capability_grant_budgets"
                " (approval_id, task_id, plan_revision, plan_hash, initial_uses,"
                " uses_remaining, revoked_at, created_at) VALUES (?,?,?,?,?,?,NULL,?)",
                (
                    str(approval_id),
                    str(task_id),
                    plan_revision,
                    plan_hash.casefold(),
                    uses,
                    uses,
                    timestamp,
                ),
            )

    def authoritative_uses_remaining(self, approval_id: UUID) -> int:
        """The real remaining count, read from the authoritative ledger."""

        authority = self._require_authority()
        if authority is None:
            raise ConsumptionError(
                "consumption_authority_not_authoritative",
                "no authoritative grant ledger is configured",
            )
        status = authority.status(approval_id)
        return int(getattr(status, "uses_remaining", 0))

    def _require_authority(self) -> GrantAuthoritySource | None:
        if self._authority is not None:
            return self._authority
        if self._simulated_authority:
            # Test-scoped only: no authoritative grant is consulted, and the
            # instance is reachable solely through ``open_tests_scoped``.
            return None
        raise GrantAuthorityUnavailable()

    def _authoritative_scope(self, approval_id: UUID, *, now: datetime) -> object:
        """The persisted grant, proven usable, or a refusal.

        Every spend goes through here before a budget is touched, so a budget row
        that exists without a live grant behind it is inert.
        """

        authority = self._require_authority()
        if authority is None:
            return None
        try:
            grant = authority.load(approval_id)
        except Exception as exc:
            raise ConsumptionError(
                "GRANT_NOT_FOUND", "no authoritative grant exists for this approval"
            ) from exc
        try:
            status = authority.status(approval_id, now=now)
        except Exception as exc:
            raise ConsumptionError(
                "GRANT_NOT_FOUND", "the authoritative grant state is unavailable"
            ) from exc
        state = str(getattr(status, "state", ""))
        if state not in _SPENDABLE_GRANT_STATES:
            # EXPIRED / REVOKED / EXHAUSTED / NOT_YET_VALID / unknown: all refuse.
            raise ConsumptionError(
                f"GRANT_{state}" if state else "GRANT_STATE_UNKNOWN",
                "the authoritative grant does not permit a spend now",
            )
        return grant

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """One immediate transaction: the decrement and record commit together."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield self._connection
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        self._connection.execute("COMMIT")


def _attempt_from_row(row: sqlite3.Row) -> ConsumptionAttempt:
    return ConsumptionAttempt(
        consumption_id=UUID(str(row["consumption_id"])),
        approval_id=UUID(str(row["approval_id"])),
        action_digest=str(row["action_digest"]),
        started_at=datetime.fromisoformat(str(row["started_at"])),
    )


def _consumption_from_row(row: sqlite3.Row, *, replayed: bool) -> Consumption:
    state = str(row["state"])
    if state not in CONSUMPTION_STATES:
        raise ConsumptionError("consumption_state_invalid", "stored consumption state is invalid")
    return Consumption(
        consumption_id=UUID(row["consumption_id"]),
        approval_id=UUID(row["approval_id"]),
        action_digest=str(row["action_digest"]),
        uses_remaining_after=int(row["uses_remaining_after"]),
        consumed_at=datetime.fromisoformat(str(row["consumed_at"])),
        state=state,  # type: ignore[arg-type]
        replayed=replayed,
    )


def new_consumption_id() -> UUID:
    return uuid4()


__all__ = [
    "CONSUMED_BY_CODES",
    "CONSUMPTION_STATES",
    "Consumption",
    "ConsumptionAttempt",
    "ConsumptionError",
    "ConsumptionLedger",
    "IssuanceDisabledConsumptionLedger",
    "action_identity",
    "new_consumption_id",
]
