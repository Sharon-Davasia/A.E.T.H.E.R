"""Synthetic filesystem fixtures for Phase 2C capability tests.

Everything here is disposable: a temporary directory tree with representative
text files, a binary blob, a secret-looking file, a nested project and (where
the host permits it) symlinks that must be refused. No test touches a real user
document, and no fixture requires Windows.

The volume inspector is stubbed to report a *fixed* volume so the suite runs
identically on POSIX CI, where a temporary directory's real volume type is
whatever the host says. Volume-kind refusal is exercised separately with an
explicitly configured stub.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aether.core.resources.path_safety import VolumeInfo, VolumeKind
from aether.core.resources.registry import ResourceRegistry

READ_CAPABILITIES = frozenset(
    {
        "fs.inspect_file",
        "fs.read_file",
        "fs.search",
        "fs.open_folder",
    }
)

ALL_CAPABILITIES = READ_CAPABILITIES | {"fs.preview_edit", "fs.apply_approved_edit"}


@dataclass(frozen=True, slots=True)
class FixedVolumeInspector:
    """Report one fixed volume identity; optionally a different kind."""

    kind: VolumeKind = VolumeKind.FIXED
    volume_id: str = "test-volume-0001"

    def inspect(self, path: Path) -> VolumeInfo:
        del path
        return VolumeInfo(self.volume_id, self.kind)


@dataclass(frozen=True, slots=True)
class FixtureTree:
    """Paths inside one synthetic project tree."""

    root: Path
    source_dir: Path
    readme: Path
    module: Path
    binary: Path
    secret: Path
    nested: Path
    nested_file: Path


def build_tree(base: Path) -> FixtureTree:
    """Create a disposable project tree and return its interesting paths."""

    root = base / "Projects" / "SyntheticProject"
    source_dir = root / "src"
    source_dir.mkdir(parents=True)
    readme = root / "README.md"
    readme.write_text("# Synthetic\n\nThe quick brown fox needs a needle.\n", encoding="utf-8")
    module = source_dir / "module.py"
    module.write_text(
        "def needle(value: int) -> int:\n"
        '    """Return the needle unchanged."""\n'
        "    return value\n",
        encoding="utf-8",
    )
    binary = root / "blob.bin"
    binary.write_bytes(b"\x00\x01\x02\x03needle\x00\xff")
    secret = root / ".env"
    secret.write_text("NEEDLE_TOKEN=super-secret-value\n", encoding="utf-8")
    nested = root / "docs" / "deep"
    nested.mkdir(parents=True)
    nested_file = nested / "notes.txt"
    nested_file.write_text("nested needle appears here\n", encoding="utf-8")
    return FixtureTree(
        root=root,
        source_dir=source_dir,
        readme=readme,
        module=module,
        binary=binary,
        secret=secret,
        nested=nested,
        nested_file=nested_file,
    )


def build_registry(
    tree: FixtureTree,
    *,
    capabilities: frozenset[str] = READ_CAPABILITIES,
    kind: VolumeKind = VolumeKind.FIXED,
) -> ResourceRegistry:
    """Register the fixture root with an explicit capability scope."""

    # The registry's own allowed-kind set must admit the fixture's kind so that
    # the *executor* is what refuses it (the boundary under test).
    registry = ResourceRegistry(
        volume_inspector=FixedVolumeInspector(kind=kind),
        allowed_volume_kinds=frozenset({kind}),
    )
    registry.register_root(
        "synthetic-project",
        tree.root,
        allowed_capabilities=capabilities,
    )
    return registry


def resolve(registry: ResourceRegistry, *parts: str) -> str:
    """Resolve a relative path inside the synthetic root and return its id."""

    root = registry.root_by_alias("synthetic-project")
    resource = registry.resolve(root.root_id, "/".join(parts))
    return resource.ref.resource_id


class ConsumptionHarness:
    """A real consumption ledger plus the budget an edit will spend.

    Tests that exercise the executor need genuine accounting, because S14-2
    makes a validated grant without a spendable budget a refusal. This harness
    creates no grant and widens no scope: it records a budget of a given size,
    which is exactly what an accepted approval would have produced.
    """

    def __init__(self, tmp_path, *, clock=None, uses: int = 1, plan_hash: str = "a" * 64):
        from aether.core.grants.consumption import ConsumptionLedger

        self.ledger = ConsumptionLedger(tmp_path / "consumption.sqlite3", clock=clock)
        self.uses = uses
        self.plan_hash = plan_hash

    def bind(
        self, *, approval_id, task_id, plan_revision: int = 1, now=None, plan_hash=None
    ) -> None:
        self.ledger.grant_budget(
            approval_id=approval_id,
            task_id=task_id,
            plan_revision=plan_revision,
            plan_hash=plan_hash or self.plan_hash,
            uses=self.uses,
            now=now,
        )

    def close(self) -> None:
        self.ledger.close()


__all__ = [
    "ALL_CAPABILITIES",
    "READ_CAPABILITIES",
    "ConsumptionHarness",
    "FixedVolumeInspector",
    "FixtureTree",
    "build_registry",
    "build_tree",
    "resolve",
]
