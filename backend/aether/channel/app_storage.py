"""Supported application storage initialization (FI-02A).

The shipped desktop passes ``AETHER_APP_DB`` (an absolute path inside
the OS per-user application-data directory, chosen by Electron main)
for every build — packaged or development. This module opens that
database as *the* application store, independent of the development
review seed (``AETHER_REVIEW_DB``), which remains a dev-only fixture
mechanism.

Safety properties are inherited from ``SQLiteTaskStore`` and not
re-implemented here:

* exclusive owner lock (a second live store on the same file fails);
* private storage permissions (owner-only directory/database);
* explicit migration authorization: only the shipped
  ``ACTIVE_SCHEMA_VERSION`` is applied — pending migrations are never
  applied implicitly, so opening an existing database never silently
  upgrades it;
* fail-closed startup recovery and integrity checks.

Any misconfiguration (relative path, unusable location, locked or
corrupt database) returns ``None``: the channel service keeps its
ping path working and answers live kinds with
``composition_unavailable``. Nothing is created anywhere else, and no
fallback path is invented.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.resources.path_safety import PathSafetyError, reject_reparse_components

APP_DB_ENV = "AETHER_APP_DB"
ACCEPTANCE_MODE_ENV = "AETHER_ACCEPTANCE_MODE"
FIXTURE_DB_ENV = "AETHER_FIXTURE_DB"
FIXTURE_MARKER = "AETHER-Phase2-Fixture-"


class AcceptanceStorageError(RuntimeError):
    """Acceptance-launch fixture storage is invalid: refuse startup.

    Raised instead of falling back to the real application database.
    The channel service turns this into a startup refusal (the backend
    never becomes ready), so an acceptance launch can never silently
    run against user storage.
    """


def _is_fixture_path(candidate: Path) -> bool:
    return any(part.startswith(FIXTURE_MARKER) for part in candidate.parts)


def fixture_root_for(candidate: Path) -> Path | None:
    """Locate the designated fixture root of a fixture path, if any.

    Provenance discipline: the ``AETHER-Phase2-Fixture-*`` name only
    *locates* the root the operator designated for this launch; a name
    prefix is never evidence of ownership or safety. Safety comes
    solely from the canonical validation in :func:`fixture_layout`
    (exact designated subtrees, reparse rejection before and after
    resolution, canonical containment).
    """

    for parent in (candidate, *candidate.parents):
        if parent.name.startswith(FIXTURE_MARKER):
            return parent
    return None


@dataclass(frozen=True, slots=True)
class FixtureLayout:
    """The canonical controlled-activation fixture layout.

    ``fixture_root`` is the ``AETHER-Phase2-Fixture-*`` directory. Only
    ``project_dir`` (``<root>/project``) holds resources the workflow
    may register or mutate; ``storage_dir`` (``<root>/storage``) is
    private application persistence; anything else under or beside the
    root (e.g. ``<root>/outside``) is unauthorized test material and
    must never be registered.
    """

    fixture_root: Path
    project_dir: Path
    storage_dir: Path


def fixture_layout(env: dict[str, str]) -> FixtureLayout:
    """Derive and validate the canonical fixture layout, or refuse.

    Runs before storage is opened and before Activation B is enabled:
    a misconfigured layout refuses the launch, never falls back.

    Validation order matters and is deliberate:

    1. reparse components are rejected on the *original lexical*
       root, project, storage and database paths before anything is
       resolved — a junction/symlink redirect (e.g. ``project``
       pointing at a sibling inside the fixture) must not be concealed
       by resolution;
    2. after resolution, the canonical results are re-checked and the
       canonical project must be *exactly* the designated
       ``<canonical-root>/project`` directory, with project/storage
       separation preserved.

    The fixture name locates the designated root (see
    :func:`fixture_root_for`); it does not prove ownership. These
    canonical checks are the safety evidence.
    """

    if env.get("AETHER_REVIEW_DB"):
        raise AcceptanceStorageError(
            "development review-seed configuration must not redirect an acceptance launch"
        )
    raw = env.get(FIXTURE_DB_ENV)
    if not raw:
        raise AcceptanceStorageError("acceptance launch requires explicit fixture storage")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise AcceptanceStorageError("fixture storage path must be absolute")
    root = fixture_root_for(candidate)
    if root is None:
        raise AcceptanceStorageError(
            "fixture storage must live under an AETHER-Phase2-Fixture-* directory"
        )
    storage_dir = candidate.parent
    if storage_dir.parent != root or storage_dir.name != "storage":
        raise AcceptanceStorageError(
            "fixture storage must live in the designated storage directory (<root>/storage)"
        )
    project_dir = root / "project"
    # 1. Reparse rejection on the original lexical paths, BEFORE any
    #    resolution can conceal a redirect.
    try:
        reject_reparse_components(candidate)
        reject_reparse_components(root)
        reject_reparse_components(project_dir)
        reject_reparse_components(storage_dir)
    except (OSError, PathSafetyError) as exc:
        raise AcceptanceStorageError(
            "fixture layout contains a reparse point in its original paths"
        ) from exc
    if not project_dir.is_dir():
        raise AcceptanceStorageError(
            "the designated fixture project directory (<root>/project) does not exist"
        )
    # 2. Post-resolution validation: re-check the canonical results and
    #    require exact designated subtrees.
    try:
        canonical_root = root.resolve(strict=True)
        reject_reparse_components(canonical_root)
        canonical_project = project_dir.resolve(strict=True)
        reject_reparse_components(canonical_project)
        canonical_storage = (
            storage_dir.resolve(strict=True) if storage_dir.exists() else storage_dir
        )
        if storage_dir.exists():
            reject_reparse_components(canonical_storage)
    except (OSError, PathSafetyError) as exc:
        raise AcceptanceStorageError("fixture layout could not be validated") from exc
    if canonical_project != canonical_root / "project":
        raise AcceptanceStorageError(
            "the canonical project directory is not exactly the designated <root>/project"
        )
    if storage_dir.exists() and canonical_storage != canonical_root / "storage":
        raise AcceptanceStorageError(
            "the canonical storage directory is not exactly the designated <root>/storage"
        )
    if canonical_project == canonical_storage or canonical_project.is_relative_to(
        canonical_storage
    ):
        raise AcceptanceStorageError("fixture project and storage must remain separate")
    return FixtureLayout(
        fixture_root=canonical_root,
        project_dir=canonical_project,
        storage_dir=canonical_storage,
    )


def open_fixture_store(env: dict[str, str]) -> SQLiteTaskStore:
    """Open the explicitly configured acceptance fixture store.

    Dedicated fixture storage only: the path must be absolute and live
    under an ``AETHER-Phase2-Fixture-*`` directory. A development
    review seed must not redirect an acceptance launch, so its
    presence is itself a refusal.
    """

    if env.get("AETHER_REVIEW_DB"):
        raise AcceptanceStorageError(
            "development review-seed configuration must not redirect an acceptance launch"
        )
    raw = env.get(FIXTURE_DB_ENV)
    if not raw:
        raise AcceptanceStorageError("acceptance launch requires explicit fixture storage")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise AcceptanceStorageError("fixture storage path must be absolute")
    if not _is_fixture_path(candidate):
        raise AcceptanceStorageError(
            "fixture storage must live under an AETHER-Phase2-Fixture-* directory"
        )
    try:
        return SQLiteTaskStore(candidate)
    except Exception as exc:
        raise AcceptanceStorageError("fixture storage could not be opened") from exc


def open_application_store(env: dict[str, str]) -> SQLiteTaskStore | None:
    """Open the supported application store, or fail closed to None."""

    raw = env.get(APP_DB_ENV)
    if raw is None:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        return None
    try:
        return SQLiteTaskStore(candidate)
    except Exception:
        return None


__all__ = [
    "ACCEPTANCE_MODE_ENV",
    "APP_DB_ENV",
    "FIXTURE_DB_ENV",
    "AcceptanceStorageError",
    "FixtureLayout",
    "fixture_layout",
    "fixture_root_for",
    "open_application_store",
    "open_fixture_store",
]
