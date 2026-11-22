"""Trusted backend-side preview source and outcome sink for the channel.

Exact previews are derived from the *persisted* plan (SQLite) plus a
human-facing narrative. Narratives are deliberately not persisted in the audit
database (Stage 2 keeps full-diff content out of the database entirely), so a
preview narrative must be supplied by a trusted backend-side source. Two
sources are supported, checked in this order:

1. ``AETHER_REVIEW_NARRATIVE`` — absolute path to a JSON seed file of the form
   ``{"task_id": "<uuid>", "narrative": {...}}``. The narrative is validated as
   ``PreviewNarrative`` (all Stage 2 bounds and content screening apply) and
   must name the exact task being presented; it is never visible to the
   renderer. Used for custom synthetic/review scenarios.
2. ``AETHER_REVIEW_DEV_SEED=synthetic-review`` — the built-in development
   scenario in ``aether.channel.dev_seed`` (stand-in for the future planner).

When neither is usable, review operations fail closed with
``review_unavailable``. Once the Phase 2 planner exists, the narrative producer
swaps in behind this same boundary; no protocol or schema change is required.

Every failure mode here fails closed. Outcomes are recorded only through
``PreviewReviewService`` (audit-only, ``NON_AUTHORIZING_AUDIT_RECORD``); any
failure to persist reports a machine error code and never a success
acknowledgement.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError

from aether.channel import dev_seed
from aether.core.approval_review import (
    NON_AUTHORIZING_AUDIT_RECORD,
    PreviewNarrative,
    PreviewReviewService,
    ReviewOutcome,
    ReviewOutcomeRequest,
    ReviewUnavailableError,
)
from aether.core.persistence.sqlite_store import (
    PersistenceError,
    PersistenceIntegrityError,
    ReviewConflictError,
    SQLiteTaskStore,
)
from aether.core.review_contract import electron_preview_payload

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NARRATIVE_MAX_BYTES = 256 * 1024
_OUTCOME_BY_VALUE = {
    "APPROVE": ReviewOutcome.APPROVE,
    "REVISE": ReviewOutcome.REVISE,
    "REJECT": ReviewOutcome.REJECT,
    "CANCELLED": ReviewOutcome.CANCELLED,
}
_OUTCOME_REQUEST_KEYS = (
    "reviewRequestId",
    "taskId",
    "planRevision",
    "planHash",
    "previewId",
    "previewDigest",
    "outcome",
    "fullDiffAcknowledged",
)


def _is_well_formed_uuid(value: str) -> bool:
    return _UUID.fullmatch(value) is not None


def _absolute_regular_file(path: str) -> bool:
    try:
        candidate = Path(path)
        return candidate.is_absolute() and candidate.is_file() and not candidate.is_symlink()
    except OSError:
        return False


def _read_bounded(path: str, maximum: int) -> bytes:
    with open(path, "rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("seed file exceeds its bound")
    return data


class ReviewBridge:
    """Serves exact previews and records audit-only outcomes from the store."""

    def __init__(
        self,
        db_path: str,
        narrative_seed_path: str | None,
        *,
        dev_seed_requested: bool = False,
    ) -> None:
        self._store = SQLiteTaskStore(Path(db_path))
        self._service = PreviewReviewService(self._store)
        self._narrative_seed_path = narrative_seed_path
        self._dev_narrative: PreviewNarrative | None = None
        self._dev_task_id: UUID | None = None
        if dev_seed_requested:
            try:
                self._dev_task_id, self._dev_narrative = dev_seed.ensure_synthetic_scenario(
                    self._store
                )
            except Exception:
                # Fail closed: the dev scenario stays unavailable but the
                # authenticated ping path keeps working.
                self._dev_task_id = None
                self._dev_narrative = None

    @classmethod
    def from_env(cls, env: dict[str, str]) -> ReviewBridge | None:
        """Build a bridge from explicit environment paths, or fail closed."""

        db_path = env.get("AETHER_REVIEW_DB")
        if not db_path:
            return None
        dev_seed_requested = dev_seed.dev_seed_requested(env.get(dev_seed.DEV_SEED_ENV))
        candidate = Path(db_path)
        if not candidate.is_absolute():
            return None
        if not dev_seed_requested and not _absolute_regular_file(db_path):
            # Without the dev seed, never create or grow a database implicitly.
            return None
        narrative = env.get("AETHER_REVIEW_NARRATIVE")
        if narrative is not None and not _absolute_regular_file(narrative):
            return None
        try:
            return cls(db_path, narrative, dev_seed_requested=dev_seed_requested)
        except Exception:
            return None

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._store.close()

    # ------------------------------------------------------------------
    # Wire-payload entry points (fully defensive; never raise)
    # ------------------------------------------------------------------
    def get_preview_payload(self, value: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != {"task_id"}:
            return {"status": "unavailable", "reason": "invalid_task"}
        return self.get_preview(value["task_id"])

    # ------------------------------------------------------------------
    # Narrative sourcing (trusted; never renderer-controlled)
    # ------------------------------------------------------------------
    def _load_narrative(self, task_id: UUID) -> PreviewNarrative:
        if self._narrative_seed_path:
            raw = _read_bounded(self._narrative_seed_path, _NARRATIVE_MAX_BYTES)
            try:
                seed = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ReviewUnavailableError("the trusted preview source is unreadable") from exc
            if not isinstance(seed, dict) or set(seed) != {"task_id", "narrative"}:
                raise ReviewUnavailableError("the trusted preview source is malformed")
            if not isinstance(seed["task_id"], str) or seed["task_id"] != str(task_id):
                # Cross-task narrative sources never disclose which task they hold.
                raise ReviewUnavailableError("the trusted preview source does not match this task")
            try:
                return PreviewNarrative.model_validate(seed["narrative"])
            except (ValidationError, ValueError) as exc:
                raise ReviewUnavailableError("the trusted preview source is invalid") from exc
        if self._dev_narrative is not None and self._dev_task_id == task_id:
            return self._dev_narrative
        raise ReviewUnavailableError("no trusted preview source is configured")

    # ------------------------------------------------------------------
    # Preview retrieval
    # ------------------------------------------------------------------
    def get_preview(self, task_id: object) -> dict[str, object]:
        """Return the exact preview for one reviewable persisted task.

        Always returns a bounded machine-readable payload; it never raises for
        expected failure modes.
        """

        if not isinstance(task_id, str) or not _is_well_formed_uuid(task_id):
            return {"status": "unavailable", "reason": "invalid_task"}
        try:
            narrative = self._load_narrative(UUID(task_id))
            preview = self._service.present(UUID(task_id), narrative)
        except ReviewUnavailableError:
            return {"status": "unavailable", "reason": "review_unavailable"}
        except (KeyError, PersistenceError, PersistenceIntegrityError):
            return {"status": "unavailable", "reason": "review_unavailable"}
        except (ValueError, ValidationError):
            return {"status": "unavailable", "reason": "review_unavailable"}
        return {"status": "ready", "preview": electron_preview_payload(preview)}

    # ------------------------------------------------------------------
    # Outcome recording (audit-only)
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_outcome_request(value: object) -> ReviewOutcomeRequest:
        if not isinstance(value, dict) or set(value) != set(_OUTCOME_REQUEST_KEYS):
            raise ValueError("review outcome request is malformed")
        raw = value
        review_request_id = raw["reviewRequestId"]
        task_id = raw["taskId"]
        plan_revision = raw["planRevision"]
        plan_hash = raw["planHash"]
        preview_id = raw["previewId"]
        preview_digest = raw["previewDigest"]
        outcome = raw["outcome"]
        full_diff_acknowledged = raw["fullDiffAcknowledged"]
        if not isinstance(review_request_id, str) or not _is_well_formed_uuid(review_request_id):
            raise ValueError("review outcome request identity is malformed")
        if not isinstance(task_id, str) or not _is_well_formed_uuid(task_id):
            raise ValueError("review outcome request identity is malformed")
        if type(plan_revision) is not int or plan_revision < 1:
            raise ValueError("review outcome request plan revision is malformed")
        if not isinstance(plan_hash, str) or _SHA256.fullmatch(plan_hash) is None:
            raise ValueError("review outcome request plan hash is malformed")
        if not isinstance(preview_id, str) or not _is_well_formed_uuid(preview_id):
            raise ValueError("review outcome request identity is malformed")
        if not isinstance(preview_digest, str) or _SHA256.fullmatch(preview_digest) is None:
            raise ValueError("review outcome request preview digest is malformed")
        if not isinstance(outcome, str) or outcome not in _OUTCOME_BY_VALUE:
            raise ValueError("review outcome request outcome is malformed")
        if not isinstance(full_diff_acknowledged, bool):
            raise ValueError("review outcome request acknowledgement is malformed")
        return ReviewOutcomeRequest(
            review_request_id=UUID(review_request_id),
            task_id=UUID(task_id),
            plan_revision=plan_revision,
            plan_hash=plan_hash,
            preview_id=UUID(preview_id),
            preview_digest=preview_digest,
            outcome=_OUTCOME_BY_VALUE[outcome],
            full_diff_acknowledged=full_diff_acknowledged,
        )

    def record_outcome(self, value: object) -> tuple[dict[str, object] | None, str | None]:
        """Record one exact bounded outcome; returns (ack, None) or (None, reason)."""

        try:
            request = self._parse_outcome_request(value)
        except ValueError:
            return None, "invalid_review_request"
        try:
            narrative = self._load_narrative(request.task_id)
        except ReviewUnavailableError:
            return None, "review_unavailable"
        try:
            result = self._service.record_outcome(request.task_id, narrative, request)
        except ReviewUnavailableError:
            return None, "review_unavailable"
        except ReviewConflictError:
            return None, "review_conflict"
        except ValueError:
            # Includes the full-diff acknowledgement gate and request identity
            # mismatches; nothing is persisted on those paths.
            return None, "invalid_review_request"
        except (KeyError, PersistenceError, PersistenceIntegrityError):
            return None, "review_unavailable"
        acknowledgement: dict[str, object] = {
            "resolution": result.resolution.value,
            "requestedOutcome": result.requested_outcome.value,
            "authority": NON_AUTHORIZING_AUDIT_RECORD,
            "auditPersisted": True,
            "granted": False,
            "executionAvailable": False,
            "idempotentReplay": result.idempotent_replay,
            "message": result.message,
        }
        return acknowledgement, None


def from_env() -> ReviewBridge | None:
    """Module-level convenience matching ``ReviewBridge.from_env(os.environ)``."""

    return ReviewBridge.from_env(dict(os.environ))


__all__ = ["ReviewBridge", "from_env"]
