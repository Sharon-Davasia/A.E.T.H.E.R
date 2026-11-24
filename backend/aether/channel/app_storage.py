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

from pathlib import Path

from aether.core.persistence.sqlite_store import SQLiteTaskStore

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
    "open_application_store",
    "open_fixture_store",
]
