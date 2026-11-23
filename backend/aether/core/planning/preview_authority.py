"""Authoritative preview source backed by the persisted plan store (Phase 2B).

Stage 4 defined :class:`~aether.core.grants.attestation.PreviewAuthority` as a
protocol and shipped only a rejecting implementation, because no real preview
source existed. This module is that source: it recomputes the exact preview
from the *persisted* plan revision and refuses to answer when anything about
the request does not match what is stored.

Why recomputation rather than storage: a stored digest can go stale or be
written by the wrong component. Recomputing from the immutable plan and the
planner's narrative producer means the digest an attestation claims must equal
a value derived from state the user cannot influence through the renderer.

The authority answers three questions, and only these:

* Does this task/plan revision/hash exist and is it the current one?
* Does the recomputed preview match the plan revision exactly?
* What are the live resource versions *now*, so a stale preview can be refused?

It never issues a grant and never records an approval.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from aether.core.approval_review import (
    ExactPreview,
    PreviewNarrative,
    build_preview,
    preview_id_for_digest,
)
from aether.core.grants.attestation import AuthoritativePreview, PreviewSourceUnavailable
from aether.core.persistence.sqlite_store import (
    PersistenceError,
    SQLiteTaskStore,
    StoredTask,
)
from aether.core.resources.registry import ResourceRegistry, ResourceRegistryError


class NarrativeSource(Protocol):
    """Supplies the display narrative for a persisted plan revision.

    Implemented by the planner's cached output in development, and by the
    production narrative producer that derives text from the plan itself. A
    narrative is display evidence only; the preview digest binds it to the plan
    so it cannot describe a different action.
    """

    def narrative_for(
        self, *, task_id: UUID, plan_revision: int, plan_hash: str
    ) -> PreviewNarrative: ...


class StoredNarrativeSource:
    """An in-memory, process-local narrative registry.

    Deliberately not persisted: Stage 2 keeps full-diff text out of the audit
    database on purpose. Losing the narrative forces a re-plan and a fresh
    preview, which is the safe failure mode.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, int, str], PreviewNarrative] = {}

    def remember(
        self, *, task_id: UUID, plan_revision: int, plan_hash: str, narrative: PreviewNarrative
    ) -> None:
        self._entries[(str(task_id), plan_revision, plan_hash.casefold())] = narrative

    def narrative_for(
        self, *, task_id: UUID, plan_revision: int, plan_hash: str
    ) -> PreviewNarrative:
        narrative = self._entries.get((str(task_id), plan_revision, plan_hash.casefold()))
        if narrative is None:
            raise PreviewSourceUnavailable(
                "PREVIEW_NARRATIVE_UNAVAILABLE",
                "no narrative is available for this plan revision; the task must be re-planned",
            )
        return narrative


class PersistedPreviewAuthority:
    """Resolves preview identity from the persisted plan, fail-closed."""

    authority_id = "persisted-plan-store"

    def __init__(
        self,
        store: SQLiteTaskStore,
        *,
        narratives: NarrativeSource,
        resources: ResourceRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._narratives = narratives
        self._resources = resources
        self._clock = clock or (lambda: datetime.now(UTC))

    def resolve(self, *, task_id: UUID, plan_revision: int, plan_hash: str) -> AuthoritativePreview:
        task = self._current_task(task_id)
        if int(task.plan_revision) != plan_revision or (task.plan_hash or "").casefold() != (
            plan_hash.casefold()
        ):
            raise PreviewSourceUnavailable(
                "PREVIEW_PLAN_SUPERSEDED",
                "the requested plan revision is not the task's current revision",
            )
        preview = self.preview_for(task_id, plan_revision=plan_revision, plan_hash=plan_hash)
        return AuthoritativePreview(
            task_id=task_id,
            plan_revision=plan_revision,
            plan_hash=plan_hash,
            preview_id=preview.preview_id,
            preview_digest=preview.preview_digest,
        )

    def preview_for(self, task_id: UUID, *, plan_revision: int, plan_hash: str) -> ExactPreview:
        """Recompute the exact preview for one persisted revision."""

        try:
            plan = self._store.get_plan(task_id, plan_revision)
        except (KeyError, PersistenceError) as exc:
            raise PreviewSourceUnavailable(
                "PREVIEW_PLAN_UNAVAILABLE", "the plan revision is not persisted"
            ) from exc
        except Exception as exc:  # fail closed on any store failure
            raise PreviewSourceUnavailable(
                "PREVIEW_PLAN_UNAVAILABLE", "the plan revision could not be read"
            ) from exc
        if plan.plan_hash.casefold() != plan_hash.casefold():
            raise PreviewSourceUnavailable(
                "PREVIEW_PLAN_HASH_MISMATCH", "the stored plan does not match the claimed hash"
            )
        narrative = self._narratives.narrative_for(
            task_id=task_id, plan_revision=plan_revision, plan_hash=plan_hash
        )
        try:
            preview = build_preview(plan, narrative)
        except ValueError as exc:
            raise PreviewSourceUnavailable(
                "PREVIEW_NARRATIVE_INVALID", "the narrative does not describe this plan"
            ) from exc
        if preview.preview_id != preview_id_for_digest(preview.preview_digest):
            raise PreviewSourceUnavailable(
                "PREVIEW_IDENTITY_MISMATCH", "the preview identity does not match its digest"
            )
        return preview

    def live_resource_versions(self, task_id: UUID, *, plan_revision: int) -> dict[str, str]:
        """Return the *current* versions for a plan's resources.

        A caller compares this with the persisted plan's expected versions; a
        difference means the preview is stale and must be recomputed. Absent a
        registry this returns an empty mapping, which callers treat as
        "cannot verify freshness" rather than "no changes".
        """

        if self._resources is None:
            return {}
        try:
            plan = self._store.get_plan(task_id, plan_revision)
        except Exception:
            return {}
        current: dict[str, str] = {}
        for step in plan.steps:
            for resource in step.resources:
                try:
                    resolved = self._resources.resource_by_id(resource.resource_id)
                    current[resource.resource_id] = resolved.version_token
                except ResourceRegistryError:
                    current[resource.resource_id] = "unavailable"
        return current

    def _current_task(self, task_id: UUID) -> StoredTask:
        try:
            return self._store.get_task(task_id)
        except KeyError as exc:
            raise PreviewSourceUnavailable(
                "PREVIEW_TASK_UNKNOWN", "the task is not persisted"
            ) from exc
        except Exception as exc:
            raise PreviewSourceUnavailable(
                "PREVIEW_STORE_UNAVAILABLE", "the task store is unavailable"
            ) from exc


__all__ = [
    "NarrativeSource",
    "PersistedPreviewAuthority",
    "StoredNarrativeSource",
]


def preview_digest(preview: ExactPreview) -> str:
    """Return the canonical digest of a preview (single source of truth)."""

    digest = hashlib.sha256(preview.canonical_json().encode("utf-8")).hexdigest()
    if digest != preview.preview_digest:
        raise PreviewSourceUnavailable(
            "PREVIEW_DIGEST_MISMATCH", "the preview digest is not canonical"
        )
    return digest
