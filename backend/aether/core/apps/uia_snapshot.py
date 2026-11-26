"""Bounded, privacy-aware UIA snapshot service (CP4, CP4-R3).

The service resolves the *current* authorized window reference via
the existing application/window resource authority, obtains the UIA
root from the injected backend (real native backend behind disabled
activation on Windows; deterministic fake in tests), and performs a
bounded traversal. Snapshot text is untrusted data: it is stored only
in memory, never persisted, and never treated as instructions.

Failure outcomes are typed (``UiaOutcome``): unknown/stale window,
privacy denial, provider unavailable/timeout, truncation. Truncation
is always explicit; it never implies absence of further elements.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import uuid4

from aether.adapters.windows.uia_backend import (
    RawElement,
    UiaBackend,
    UiaBackendError,
    UiaElementStale,
)
from aether.core.contracts.resource import ResourceRef
from aether.core.contracts.uia import (
    MAX_RETAINED_SNAPSHOTS,
    SNAPSHOT_TTL_SECONDS,
    SUPPORTED_PATTERNS,
    SnapshotPrivacy,
    UiaElement,
    UiaLimits,
    UiaSnapshot,
)
from aether.core.resources.app_window_authority import (
    AppWindowAuthorityError,
    AppWindowResourceAuthority,
)
from aether.world_state.privacy import ContextClassification, classify_context


class UiaOutcome(StrEnum):
    OK = "ok"
    WINDOW_NOT_FOUND = "window_not_found"
    WINDOW_STALE = "window_stale"
    PRIVACY_DENIED = "privacy_denied"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TIMED_OUT = "timed_out"
    TRUNCATED = "truncated"
    ELEMENT_STALE = "element_stale"
    ELEMENT_NOT_FOUND = "element_not_found"
    SNAPSHOT_EXPIRED = "snapshot_expired"
    UNSUPPORTED = "unsupported"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class SnapshotResult:
    outcome: UiaOutcome
    snapshot: UiaSnapshot | None = None
    detail: str | None = None


@dataclass(slots=True)
class UiaSnapshotService:
    """Bounded snapshot collection over an injected UIA backend."""

    authority: AppWindowResourceAuthority
    backend_factory: Callable[[], UiaBackend]
    session_id: str
    # F11: when a supervised worker is configured, native collection
    # routes through the subprocess supervisor; the direct backend
    # factory remains only for injected test doubles.
    worker: object | None = None  # SubprocessWorkerSupervisor
    clock: Callable[[], datetime] | None = None
    content_inspection_permitted: Callable[[str], bool] | None = None
    monotonic: Callable[[], float] = time.monotonic
    _snapshots: OrderedDict[str, UiaSnapshot] = field(default_factory=OrderedDict)
    # Privacy/observation generation: any privacy-mode change, sensor
    # pause or session change bumps this and purges retained snapshots.
    privacy_generation: int = 0

    # -- lifecycle ---------------------------------------------------------

    def note_privacy_change(self) -> None:
        """Privacy mode/opt-in changed: retained snapshots are void."""
        self.privacy_generation += 1
        self._snapshots.clear()

    def on_sensor_pause(self) -> None:
        self.note_privacy_change()

    def on_session_end(self) -> None:
        self.note_privacy_change()

    def on_takeover(self, window_resource_id: str) -> None:
        for key in [
            k for k, v in self._snapshots.items() if v.window_resource_id == window_resource_id
        ]:
            self._snapshots.pop(key, None)

    def on_dialog(self, window_resource_id: str) -> None:
        self.on_takeover(window_resource_id)

    def _now(self) -> datetime:
        return self.clock() if self.clock else datetime.now(UTC)

    # -- inspection --------------------------------------------------------

    def inspect(
        self,
        window_resource_id: str,
        *,
        require_content: bool = False,
        limits: UiaLimits | None = None,
    ) -> SnapshotResult:
        """Collect a bounded snapshot of one authorized window.

        ``require_content`` (accessible names / text) additionally
        requires the caller's content-inspection permission seam;
        metadata-shaped inspection runs under the metadata privacy
        gate. Sensitive controls never expose values either way.
        """
        limits = limits or UiaLimits()
        now = self._now()
        try:
            self.authority.authorize_ref(
                ResourceRef(kind="window", resource_id=window_resource_id),
                expected_kind="window",
                now=now,
            )
            binding = self.authority.resolve_window(window_resource_id)
        except AppWindowAuthorityError:
            return SnapshotResult(UiaOutcome.WINDOW_NOT_FOUND)
        if binding.expires_at is not None and binding.expires_at <= now:
            return SnapshotResult(UiaOutcome.WINDOW_STALE, detail="observation expired")
        adapter_classification = binding.classification
        if not isinstance(adapter_classification, ContextClassification):
            adapter_classification = ContextClassification.UNKNOWN
        classification = classify_context(
            None, adapter_classification=adapter_classification, elevated=binding.elevated
        )
        if classification is not ContextClassification.PERMITTED_METADATA:
            return SnapshotResult(UiaOutcome.PRIVACY_DENIED, detail=classification.value)
        # F12: missing content-authorization authority denies content
        # inspection outright; metadata-only collection never reads
        # unrestricted accessible text.
        if require_content and (
            self.content_inspection_permitted is None
            or not self.content_inspection_permitted(binding.app_resource_id or "")
        ):
            return SnapshotResult(UiaOutcome.PRIVACY_DENIED, detail="content inspection")

        if self.worker is not None:
            return self._inspect_via_worker(binding, window_resource_id, limits, require_content)
        backend = self.backend_factory()
        started = self.monotonic()
        try:
            root = backend.find_root(hwnd=binding.hwnd)
            if root is None:
                return SnapshotResult(UiaOutcome.PROVIDER_UNAVAILABLE, detail="no_uia_root")
            collected, truncated_reason = self._walk(
                backend, root, limits, started, include_text=require_content
            )
        except TimeoutError:
            return SnapshotResult(UiaOutcome.TIMED_OUT)
        except UiaElementStale:
            return SnapshotResult(UiaOutcome.ELEMENT_STALE)
        except UiaBackendError as exc:
            return SnapshotResult(UiaOutcome.PROVIDER_UNAVAILABLE, detail=str(exc)[:120])
        finally:
            backend.close()

        retained_text = sum(len(e.name or "") for e in collected)
        snapshot = UiaSnapshot(
            snapshot_id=f"snap:{uuid4()}",
            session_id=self.session_id,
            app_resource_id=binding.app_resource_id or "",
            window_resource_id=window_resource_id,
            window_version_token=binding.version_token,
            process_token=binding.process_token,
            observed_at=now,
            expires_at=now + timedelta(seconds=SNAPSHOT_TTL_SECONDS),
            generation=binding.instance_generation,
            privacy_generation=self.privacy_generation,
            privacy_classification=SnapshotPrivacy.CONTENT
            if require_content
            else SnapshotPrivacy.METADATA,
            completeness="truncated" if truncated_reason else "complete",
            truncated=truncated_reason is not None,
            truncated_reason=truncated_reason,
            elements=tuple(collected),
            retained_text_chars=retained_text,
            root_element_ref=collected[0].element_ref if collected else None,
        )
        self._retain(snapshot)
        return SnapshotResult(
            UiaOutcome.TRUNCATED if truncated_reason else UiaOutcome.OK, snapshot=snapshot
        )

    def _inspect_via_worker(
        self, binding, window_resource_id, limits, require_content
    ) -> SnapshotResult:  # type: ignore[no-untyped-def]
        from aether.core.workers.uia_worker import WorkerOutcome

        now = self._now()
        result = self.worker.execute(  # type: ignore[attr-defined]
            "inspect",
            {
                "hwnd": binding.hwnd,
                "max_depth": limits.max_depth,
                "max_elements": limits.max_elements,
                "max_total_text_chars": limits.max_total_text_chars,
            },
            timeout=limits.budget_seconds + 2.0,
        )
        if result.outcome is WorkerOutcome.TIMED_OUT:
            return SnapshotResult(UiaOutcome.TIMED_OUT)
        if result.outcome is not WorkerOutcome.OK or result.response is None:
            return SnapshotResult(UiaOutcome.PROVIDER_UNAVAILABLE, detail=result.detail)
        raw_elements = result.response.get("elements")
        if not isinstance(raw_elements, list):
            return SnapshotResult(UiaOutcome.PROVIDER_UNAVAILABLE, detail="malformed_worker_result")
        elements: list[UiaElement] = []
        ref_by_key: dict[str, str] = {}
        for raw in raw_elements[: limits.max_elements]:
            if not isinstance(raw, dict):
                continue
            ref = f"el:{len(elements) + 1}"
            ref_by_key[str(raw.get("key"))] = ref
            is_password = bool(raw.get("is_password"))
            name = raw.get("name") if (require_content and not is_password) else None
            elements.append(
                UiaElement(
                    element_ref=ref,
                    runtime_id=str(raw.get("key")),
                    control_type=str(raw.get("control_type", "unknown")),
                    automation_id=raw.get("automation_id") or None,
                    name=name if isinstance(name, str) else None,
                    patterns=frozenset(
                        p for p in raw.get("patterns", []) if p in SUPPORTED_PATTERNS
                    ),
                    is_enabled=bool(raw.get("is_enabled", False)),
                    is_offscreen=bool(raw.get("is_offscreen", False)),
                    is_password=is_password,
                    depth=int(raw.get("depth", 0)),
                    child_count=int(raw.get("child_count", 0)),
                    value_present=False,
                )
            )
        truncated = len(raw_elements) >= limits.max_elements
        snapshot = UiaSnapshot(
            snapshot_id=f"snap:{uuid4()}",
            session_id=self.session_id,
            app_resource_id=binding.app_resource_id or "",
            window_resource_id=window_resource_id,
            window_version_token=binding.version_token,
            process_token=binding.process_token,
            observed_at=now,
            expires_at=now + timedelta(seconds=SNAPSHOT_TTL_SECONDS),
            generation=binding.instance_generation,
            privacy_generation=self.privacy_generation,
            privacy_classification=(
                SnapshotPrivacy.CONTENT if require_content else SnapshotPrivacy.METADATA
            ),
            completeness="truncated" if truncated else "complete",
            truncated=truncated,
            truncated_reason="element_limit" if truncated else None,
            elements=tuple(elements),
            retained_text_chars=sum(len(e.name or "") for e in elements),
            root_element_ref=elements[0].element_ref if elements else None,
        )
        self._retain(snapshot)
        return SnapshotResult(
            UiaOutcome.TRUNCATED if truncated else UiaOutcome.OK, snapshot=snapshot
        )

    def _walk(
        self,
        backend: UiaBackend,
        root: RawElement,
        limits: UiaLimits,
        started: float,
        *,
        include_text: bool = False,
    ) -> tuple[list[UiaElement], str | None]:
        elements: list[UiaElement] = []
        ref_by_key: dict[str, str] = {}
        ancestors_by_key: dict[str, tuple[str, ...]] = {}
        text_budget = limits.max_total_text_chars
        truncated: str | None = None
        queue: deque[tuple[RawElement, str | None, int]] = deque([(root, None, 0)])
        # Bound actual traversal work and provider calls, not just the
        # retained element count (F12).
        work_bound = limits.max_elements * 8 + 64
        visited = 0
        while queue:
            visited += 1
            if visited > work_bound:
                return elements, "work_limit"
            raw, parent_ref, depth = queue.popleft()
            if self.monotonic() - started > limits.budget_seconds:
                return elements, "time_budget"
            if depth > limits.max_depth:
                truncated = truncated or "depth_limit"
                continue
            if len(elements) >= limits.max_elements:
                return elements, "element_limit"
            ref = f"el:{len(elements) + 1}"
            ref_by_key[raw.key] = ref
            ancestors = (
                (ancestors_by_key.get(parent_ref or "", ()) + ((parent_ref,) if parent_ref else ()))
                if parent_ref
                else ()
            )
            if parent_ref:
                ancestors_by_key[raw.key] = ancestors
            name = None
            if raw.name and include_text:
                if len(raw.name) <= text_budget:
                    name = raw.name
                    text_budget -= len(raw.name)
                else:
                    truncated = truncated or "text_limit"
            element = UiaElement(
                element_ref=ref,
                runtime_id=raw.key,
                control_type=raw.control_type,
                automation_id=raw.automation_id,
                name=name if not raw.is_password else None,
                patterns=frozenset(p for p in raw.patterns if p in SUPPORTED_PATTERNS),
                is_enabled=raw.is_enabled,
                is_offscreen=raw.is_offscreen,
                is_password=raw.is_password,
                depth=depth,
                parent_ref=parent_ref,
                ancestor_refs=ancestors,
                child_count=len(raw.children_keys),
                bounding_rect=raw.bounding_rect,
                # A password control's value is never read or retained.
                value_present=False if raw.is_password else raw.value_present,
            )
            elements.append(element)
            try:
                children = backend.children(raw)
            except UiaElementStale:
                truncated = truncated or "stale_child"
                continue
            for child in children:
                queue.append((child, ref, depth + 1))
        return elements, truncated

    # -- retained snapshots (memory only, bounded, expiring) ---------------

    def _retain(self, snapshot: UiaSnapshot) -> None:
        now = self._now()
        for stale in [k for k, v in self._snapshots.items() if v.expires_at <= now]:
            self._snapshots.pop(stale, None)
        self._snapshots[snapshot.snapshot_id] = snapshot
        while len(self._snapshots) > MAX_RETAINED_SNAPSHOTS:
            self._snapshots.popitem(last=False)

    def get(self, snapshot_id: str) -> SnapshotResult:
        snapshot = self._snapshots.get(snapshot_id)
        if snapshot is None or snapshot.expires_at <= self._now():
            return SnapshotResult(UiaOutcome.SNAPSHOT_EXPIRED)
        if snapshot.session_id != self.session_id:
            return SnapshotResult(UiaOutcome.SNAPSHOT_EXPIRED, detail="session_changed")
        if snapshot.privacy_generation != self.privacy_generation:
            return SnapshotResult(UiaOutcome.SNAPSHOT_EXPIRED, detail="privacy_changed")
        if (
            snapshot.privacy_classification == "content"
            and self.content_inspection_permitted is not None
            and not self.content_inspection_permitted(snapshot.app_resource_id)
        ):
            return SnapshotResult(UiaOutcome.PRIVACY_DENIED, detail="content permission revoked")
        # Revalidate the bound window instance: a replaced window
        # invalidates every snapshot taken against the old instance.
        try:
            binding = self.authority.resolve_window(snapshot.window_resource_id)
        except AppWindowAuthorityError:
            return SnapshotResult(UiaOutcome.WINDOW_STALE)
        if binding.version_token != snapshot.window_version_token:
            return SnapshotResult(UiaOutcome.WINDOW_STALE)
        return SnapshotResult(UiaOutcome.OK, snapshot=snapshot)

    def validate_element(self, snapshot_id: str, element_ref: str) -> SnapshotResult:
        """Typed read-only element inspection by transient snapshot ref."""
        result = self.get(snapshot_id)
        if result.snapshot is None:
            return result
        element = result.snapshot.find(element_ref)
        if element is None:
            return SnapshotResult(UiaOutcome.ELEMENT_NOT_FOUND)
        return result

    def purge(self) -> None:
        self._snapshots.clear()
