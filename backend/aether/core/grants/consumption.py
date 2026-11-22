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
from typing import Literal
from uuid import UUID, uuid4

from aether.core.contracts.policy import RiskTier

CONSUMPTION_STATES = frozenset({"PENDING", "SUCCEEDED", "FAILED", "UNVERIFIED", "RECONCILED"})
CONSUMED_BY_CODES = frozenset({"aether.core.edits.executor"})

ConsumptionState = Literal["PENDING", "SUCCEEDED", "FAILED", "UNVERIFIED", "RECONCILED"]

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
)


class ConsumptionError(Exception):
    """Consumption was refused; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


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

    def __init__(self, database: Path | str, *, clock: object | None = None) -> None:
        self._lock = threading.RLock()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._connection = sqlite3.connect(
            str(database), isolation_level=None, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            for statement in _SCHEMA:
                self._connection.execute(statement)

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
        timestamp = _timestamp(now or self._clock())  # type: ignore[operator]
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
        with self._lock:
            row = self._connection.execute(
                "SELECT uses_remaining FROM capability_grant_budgets WHERE approval_id = ?",
                (str(approval_id),),
            ).fetchone()
        if row is None:
            raise ConsumptionError("GRANT_NOT_FOUND", "no budget exists for this approval")
        return int(row["uses_remaining"])

    # -- internals ---------------------------------------------------------

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
    "ConsumptionError",
    "ConsumptionLedger",
    "IssuanceDisabledConsumptionLedger",
    "action_identity",
    "new_consumption_id",
]
