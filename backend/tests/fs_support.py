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


def skip_if_symlink_unavailable(exc: BaseException) -> None:
    """Skip only when this host genuinely cannot create a symlink.

    Mirrors the repository convention (test_phase2b_persistence): on
    Windows, WinError 5/1314 means the account lacks the symlink
    privilege (no Developer Mode / elevation) — the capability is
    unavailable, so the test skips with the reason recorded. Anything
    else is a real failure and is re-raised. A skip here is never
    evidence that the Windows security scenario passed.
    """

    import os

    import pytest

    if isinstance(exc, NotImplementedError) or os.name != "nt":
        pytest.skip("symlink creation is unavailable on this host")
    if getattr(exc, "winerror", None) in {5, 1314}:
        pytest.skip(f"Windows denied symlink creation (WinError {exc.winerror})")
    raise exc


def make_junction(link: Path, target: Path) -> None:
    """Create a directory junction (no privilege required on Windows).

    Used for non-elevated native reparse-point coverage on Windows;
    skips anywhere junctions cannot be created.
    """

    import os
    import subprocess

    import pytest

    if os.name != "nt":
        pytest.skip("directory junctions are a Windows reparse-point mechanism")
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 or not link.exists():
        pytest.skip(f"junction creation unavailable: {result.stdout} {result.stderr}")


def build_tree(base: Path) -> FixtureTree:
    """Create a disposable project tree and return its interesting paths."""

    root = base / "Projects" / "SyntheticProject"
    source_dir = root / "src"
    source_dir.mkdir(parents=True)
    readme = root / "README.md"
    readme.write_bytes(b"# Synthetic\n\nThe quick brown fox needs a needle.\n")
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
    makes a validated grant without a spendable budget a refusal.

    S14-7 changed what this harness may claim. The ledger it opens is
    **test-scoped**: it does not consult the authoritative Stage 4 grant ledger,
    which is exactly why production code cannot obtain one this way. A budget
    registered here proves nothing about production authorization, and the
    S14-7 suite asserts that the production constructor refuses without a real
    grant behind it.
    """

    def __init__(self, tmp_path, *, clock=None, uses: int = 1, plan_hash: str = "a" * 64):
        from aether.core.grants.consumption import ConsumptionLedger

        self.ledger = ConsumptionLedger.open_tests_scoped(
            tmp_path / "consumption.sqlite3", clock=clock
        )
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
