"""The one configured Phase 2 workspace: explicit, bounded, read-tier only.

This module is the *only* place that builds a usable Phase 2 stack. Keeping it
in one small module makes the authorization surface reviewable: a reviewer reads
this file and knows exactly which capabilities have a real adapter wired in, and
can confirm that no mutation, no shell, and no T3 capability can reach a disk.

It is deliberately not wired into the running chat service. Enabling it there is
an integration decision that requires the trusted approval boundary to be
accepted first (Workstream C).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from aether.core.fs.executor import FilesystemExecutor
from aether.core.fs.session import CapabilitySession
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.resources.registry import ResourceRegistry

#: Capabilities with a real, bounded, read-only adapter in this build.
READ_TIER_EXECUTORS: frozenset[str] = frozenset(
    {
        "fs.inspect_file",
        "fs.read_file",
        "fs.search",
        "fs.open_folder",
    }
)

#: Capabilities that exist in the contract registry but have NO adapter wired.
#: ``fs.apply_approved_edit`` is implemented and tested, but its adapter is
#: enabled only by a caller that supplies a verified grant authority and an
#: accepted approval boundary. This factory never does.
UNADAPTED_CAPABILITIES: frozenset[str] = frozenset({"fs.apply_approved_edit"})


@dataclass(frozen=True, slots=True)
class ReadOnlyWorkspace:
    session: CapabilitySession
    store: SQLiteTaskStore
    registry: ResourceRegistry
    broker: PolicyBroker

    def close(self) -> None:
        self.store.close()


def open_read_only_workspace(
    *,
    database: Path,
    roots: dict[str, Path],
    clock: object | None = None,
) -> ReadOnlyWorkspace:
    """Build the read-only Phase 2 workspace for an explicit set of roots.

    ``roots`` maps a root id to an absolute directory. The resource registry
    validates each root (volume kind, protection, existence) and refuses
    everything outside them, so this function never needs a path filter of its
    own -- and deliberately has none, so there is no second, weaker check to
    drift out of sync.
    """

    now = clock or (lambda: datetime.now(UTC))
    registry = ResourceRegistry()
    for root_id, root in roots.items():
        # Each root must name, explicitly, the capability ids it admits. There
        # is no wildcard: a root that does not list ``fs.read_file`` cannot be
        # read, even though the broker has an adapter for it.
        registry.register_root(root_id, root, allowed_capabilities=READ_TIER_EXECUTORS)
    capabilities = CapabilityRegistry.phase2_filesystem()
    broker = PolicyBroker(
        capabilities=capabilities,
        resources=registry,
        executors=READ_TIER_EXECUTORS,
    )
    store = SQLiteTaskStore(database)
    session = CapabilitySession(
        store=store,
        broker=broker,
        executor=FilesystemExecutor(registry),
        clock=now,
    )
    return ReadOnlyWorkspace(session=session, store=store, registry=registry, broker=broker)


__all__ = [
    "READ_TIER_EXECUTORS",
    "UNADAPTED_CAPABILITIES",
    "ReadOnlyWorkspace",
    "open_read_only_workspace",
]
