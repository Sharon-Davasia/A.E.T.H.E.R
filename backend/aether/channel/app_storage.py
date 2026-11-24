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


__all__ = ["APP_DB_ENV", "open_application_store"]
