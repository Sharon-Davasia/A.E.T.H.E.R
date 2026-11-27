"""Current-project detection and reference resolution (CP6, Master Spec).

Evidence comes only from permitted boundaries: explicit registered
AETHER project roots, authorized Explorer folder context, workspace
manifest metadata *inside registered roots* (root-level probes only —
no recursive scanning, no terminal scraping), and recent task focus.
Detection never creates filesystem permissions and never expands an
authorized root: an unregistered discovery is reported as a candidate
with explicit limitations and no registry-issued identity.

Candidates carry canonical identity, evidence source, provenance,
observation time, expiry, strength and availability. Ranking is
deterministic; ambiguous evidence requires clarification rather than
an automatic choice. References such as "this project" resolve only
against fresh authoritative observations.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

CANDIDATE_TTL = timedelta(seconds=120)
_MANIFEST_MARKERS = (".git", "pyproject.toml", "package.json")
# Deterministic evidence-source strengths (never permission authority).
_STRENGTH = {
    "registered_project": 0.9,
    "explorer_registered": 0.8,
    "recent_task_focus": 0.6,
    "explorer_discovered": 0.4,
}
_AMBIGUITY_MARGIN = 0.15


@dataclass(frozen=True, slots=True)
class ProjectCandidate:
    candidate_id: str
    resource_id: str | None  # registry-issued identity, when registered
    root_alias: str | None
    display_path: str
    evidence_source: str
    provenance: str
    observed_at: datetime
    expires_at: datetime
    evidence_strength: float
    available: bool
    limitations: tuple[str, ...]
    manifests: tuple[str, ...] = ()

    def fresh(self, now: datetime) -> bool:
        return self.observed_at <= now < self.expires_at


@dataclass(frozen=True, slots=True)
class ReferenceResolution:
    candidate: ProjectCandidate | None
    clarification_required: bool
    reason: str


@dataclass(slots=True)
class ProjectDetector:
    """Bounded, deterministic current-project detection."""

    registry: object  # ResourceRegistry
    explorer_folder: Callable[[], Path | None] | None = None
    recent_focus_root: Callable[[], str | None] | None = None
    clock: Callable[[], datetime] | None = None
    # Authoritative collection gate (privacy + authorization lifetime
    # + composition lifecycle), supplied by trusted composition.
    # When present and False, detection performs NO collection at
    # all: the Explorer provider is never invoked and no registered
    # root is probed. Reference resolution inherits the same gate.
    collection_permitted: Callable[[], bool] | None = None

    def _collection_allowed(self) -> bool:
        return self.collection_permitted is None or bool(self.collection_permitted())

    def _now(self) -> datetime:
        from datetime import UTC

        return self.clock() if self.clock else datetime.now(UTC)

    def _manifests(self, root: Path) -> tuple[str, ...]:
        """Root-level manifest probes only; never recursive."""
        found = []
        for marker in _MANIFEST_MARKERS:
            try:
                if (root / marker).exists():
                    found.append(marker)
            except OSError:
                continue
        return tuple(found)

    def detect(self) -> tuple[ProjectCandidate, ...]:
        if not self._collection_allowed():
            return ()
        now = self._now()
        candidates: dict[str, ProjectCandidate] = {}
        roots = list(self.registry.known_roots())  # type: ignore[attr-defined]
        explorer = self.explorer_folder() if self.explorer_folder else None
        focus_alias = self.recent_focus_root() if self.recent_focus_root else None
        for root in roots:
            # G06: the root's canonical resource identity is issued by
            # resolving the registered root itself through the existing
            # resource/path authorization checks - never an arbitrary
            # known resource that happens to sit under the root.
            root_resource = None
            try:
                root_resource = self.registry.resolve(root.root_id, "")  # type: ignore[attr-defined]
            except Exception:
                root_resource = None
            manifests = (
                self._manifests(root_resource.canonical_path) if root_resource is not None else ()
            )
            source = "registered_project"
            if explorer is not None and _same_path(root.canonical_root, explorer):
                source = "explorer_registered"
            elif focus_alias is not None and focus_alias == root.alias:
                source = "recent_task_focus"
            resource_id = root_resource.ref.resource_id if root_resource is not None else None
            candidates[str(root.root_id)] = ProjectCandidate(
                candidate_id=f"project:{root.root_id}",
                resource_id=resource_id,
                root_alias=root.alias,
                display_path=str(root.canonical_root),
                evidence_source=source,
                provenance="system_observed",
                observed_at=now,
                expires_at=now + CANDIDATE_TTL,
                evidence_strength=_STRENGTH[source],
                available=root_resource is not None,
                limitations=(
                    ()
                    if root_resource is not None and manifests
                    else ("registered_root_unavailable",)
                    if root_resource is None
                    else ("no_workspace_manifest",)
                ),
                manifests=manifests,
            )
        if explorer is not None and not any(
            _same_path(root.canonical_root, explorer) for root in roots
        ):
            # Discovered but NOT registered: detection creates no
            # permission and issues no resource identity.
            candidates[f"discovered:{explorer}"] = ProjectCandidate(
                candidate_id=f"project:discovered:{abs(hash(str(explorer))) % 10**8}",
                resource_id=None,
                root_alias=None,
                display_path=str(explorer),
                evidence_source="explorer_discovered",
                provenance="system_observed",
                observed_at=now,
                expires_at=now + CANDIDATE_TTL,
                evidence_strength=_STRENGTH["explorer_discovered"],
                available=False,
                limitations=("unregistered_root", "registration_required_before_use"),
                # G06: no filesystem probing of unregistered locations.
                manifests=(),
            )
        return tuple(
            sorted(
                candidates.values(),
                key=lambda c: (-c.evidence_strength, c.candidate_id),
            )
        )

    def resolve_reference(
        self, reference: str, *, now: datetime | None = None
    ) -> ReferenceResolution:
        """Resolve "this project" against fresh evidence only."""
        if reference.strip().casefold() not in (
            "this project",
            "current project",
            "this workspace",
        ):
            return ReferenceResolution(None, True, "unsupported_reference")
        detected = self.detect()
        # Freshness is evaluated against the moment AFTER collection:
        # sampling the reference time before detection would make
        # every freshly observed candidate stale by construction.
        moment = now or self._now()
        fresh = [c for c in detected if c.fresh(moment) and c.available]
        if not fresh:
            return ReferenceResolution(None, True, "no_fresh_project_evidence")
        if len(fresh) > 1 and (
            fresh[0].evidence_strength - fresh[1].evidence_strength < _AMBIGUITY_MARGIN
        ):
            return ReferenceResolution(None, True, "ambiguous_project_evidence")
        return ReferenceResolution(fresh[0], False, "resolved")


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return str(left) == str(right)
