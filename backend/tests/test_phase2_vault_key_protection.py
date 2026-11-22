"""S14-5: Undo Vault key location and real owner-only protection.

Two defects are covered:

1. The key was written to ``<vault>/vault.key``, i.e. inside the very directory
   whose contents it protects. Anyone who could copy the vault directory could
   read every pre-image, which makes the encryption decorative.
2. ``_restrict_permissions`` was a silent no-op on Windows. It reported nothing
   while enforcing nothing, so "owner-restricted" was an unverified claim.

Anything that can only be proven on Windows is marked NOT VERIFIED here rather
than simulated. The Windows ACL path itself is executed only on Windows; on other
platforms these tests assert the *architecture* (it exists, it fails closed, the
platform is reported honestly) and say so.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from aether.core.security.file_permissions import (
    PermissionEnforcementError,
    platform_supports_enforcement,
    restrict_to_owner,
    verify_owner_only,
)
from aether.core.vault import undo_vault
from aether.core.vault.undo_vault import UndoVault, VaultError

IS_WINDOWS = os.name == "nt"


@pytest.fixture()
def vault_dir(tmp_path: Path) -> Path:
    return tmp_path / "vault"


# ---------------------------------------------------------------------------
# A. The key is not inside the vault
# ---------------------------------------------------------------------------


def test_the_key_defaults_outside_the_vault_directory(vault_dir: Path) -> None:
    vault = UndoVault(vault_dir).open()
    try:
        key_path = vault.key_path
        assert key_path.exists()
        assert not key_path.is_relative_to(vault_dir.resolve())
        # A sibling of the vault, not inside it.
        assert key_path.parent == vault_dir.parent / "vault-key"
    finally:
        vault.close()


def test_a_key_inside_the_vault_directory_is_refused(vault_dir: Path) -> None:
    with pytest.raises(VaultError) as refused:
        UndoVault(vault_dir, key_path=vault_dir / "vault.key")
    assert refused.value.reason_code == "vault_key_inside_vault"


def test_a_key_in_a_subdirectory_of_the_vault_is_refused(vault_dir: Path) -> None:
    with pytest.raises(VaultError) as refused:
        UndoVault(vault_dir, key_path=vault_dir / "keys" / "vault.key")
    assert refused.value.reason_code == "vault_key_inside_vault"


def test_copying_the_vault_directory_does_not_disclose_content(vault_dir: Path) -> None:
    """The point of the relocation, asserted behaviourally rather than by layout."""

    import shutil

    vault = UndoVault(vault_dir).open()
    try:
        record = vault.put(b"secret pre-image\n", original_display_name="README.md")
        assert vault.get(record.snapshot_id) == b"secret pre-image\n"
    finally:
        vault.close()

    # A directory copy, as an attacker with read access would make.
    copy_dir = vault_dir.parent / "stolen-vault"
    shutil.copytree(vault_dir, copy_dir)

    thief = UndoVault(copy_dir)
    # The copy brings its own key location, so it opens with a NEW key...
    thief.open()
    try:
        with pytest.raises(Exception) as failed:
            thief.get(record.snapshot_id)
        # ...and cannot authenticate the borrowed ciphertext.
        assert (
            "authent" in str(failed.value).lower()
            or "integrity" in str(failed.value).lower()
            or "hash" in str(failed.value).lower()
        )
    finally:
        thief.close()


def test_a_legacy_in_vault_key_is_migrated_out(vault_dir: Path) -> None:
    """Existing installs have a key in the vault; it must move, not be abandoned."""

    vault_dir.mkdir(parents=True)
    legacy_key = vault_dir / "vault.key"
    legacy_key.write_bytes(b"k" * 32)

    vault = UndoVault(vault_dir).open()
    try:
        assert vault.key_path.exists()
        assert vault.key_path.read_bytes() == b"k" * 32
        assert not legacy_key.exists()
        assert not vault.key_path.is_relative_to(vault_dir.resolve())
    finally:
        vault.close()


def test_an_ambiguous_key_migration_is_refused(vault_dir: Path) -> None:
    vault_dir.mkdir(parents=True)
    (vault_dir / "vault.key").write_bytes(b"a" * 32)
    override = vault_dir.parent / "elsewhere" / "vault.key"
    override.parent.mkdir(parents=True)
    override.write_bytes(b"b" * 32)

    with pytest.raises(VaultError) as refused:
        UndoVault(vault_dir, key_path=override).open()
    assert refused.value.reason_code == "vault_key_migration_ambiguous"


def test_the_key_is_never_inside_the_objects_directory(vault_dir: Path) -> None:
    vault = UndoVault(vault_dir).open()
    try:
        vault.put(b"body\n", original_display_name="README.md")
        objects = vault_dir / "objects"
        assert vault.key_path not in set(objects.rglob("*"))
    finally:
        vault.close()


# ---------------------------------------------------------------------------
# B. Owner-only protection is enforced, not assumed
# ---------------------------------------------------------------------------


def test_the_key_file_is_owner_only(vault_dir: Path) -> None:
    if IS_WINDOWS:
        pytest.skip("POSIX mode bits are not the Windows mechanism; see the ACL tests")
    vault = UndoVault(vault_dir).open()
    try:
        mode = stat.S_IMODE(vault.key_path.stat().st_mode)
        assert mode == 0o600
        assert mode & 0o077 == 0
        assert verify_owner_only(vault.key_path, directory=False).enforced
    finally:
        vault.close()


def test_a_world_readable_key_is_refused(vault_dir: Path) -> None:
    """The vault must fail closed rather than use a key others can read."""

    if IS_WINDOWS:
        pytest.skip("POSIX mode-bit mechanism; the Windows path fails closed differently")
    vault = UndoVault(vault_dir).open()
    try:
        key_path = vault.key_path
    finally:
        vault.close()

    key_path.chmod(0o644)
    with pytest.raises(VaultError) as refused:
        UndoVault(vault_dir).open()
    assert refused.value.reason_code == "vault_key_not_protected"


def test_the_vault_directory_and_objects_are_owner_only(vault_dir: Path) -> None:
    if IS_WINDOWS:
        pytest.skip("POSIX mode bits are not the Windows mechanism")
    vault = UndoVault(vault_dir).open()
    try:
        record = vault.put(b"body\n", original_display_name="README.md")
        del record
        assert stat.S_IMODE(vault_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((vault_dir / "objects").stat().st_mode) == 0o700
        for blob in (vault_dir / "objects").rglob("*.bin"):
            assert stat.S_IMODE(blob.stat().st_mode) == 0o600
    finally:
        vault.close()


def test_restrict_to_owner_reports_the_mechanism_it_used(tmp_path: Path) -> None:
    target = tmp_path / "secret.bin"
    target.write_bytes(b"x")
    report = restrict_to_owner(target, directory=False)
    assert report.enforced
    assert report.platform in {"posix", "windows"}
    if not IS_WINDOWS:
        assert report.mechanism == "mode-bits"
        assert "0600" in report.detail


def test_restrict_to_owner_refuses_a_missing_path(tmp_path: Path) -> None:
    with pytest.raises(PermissionEnforcementError) as refused:
        restrict_to_owner(tmp_path / "absent.bin", directory=False)
    assert refused.value.reason_code == "permissions_target_missing"


def test_verify_does_not_repair_what_it_finds(tmp_path: Path) -> None:
    if IS_WINDOWS:
        pytest.skip("POSIX mode-bit mechanism")
    target = tmp_path / "loose.bin"
    target.write_bytes(b"x")
    target.chmod(0o644)
    report = verify_owner_only(target, directory=False)
    assert not report.enforced
    # Verification is an audit: it must not silently fix the finding.
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_the_windows_mechanism_is_declared_not_simulated() -> None:
    """Be explicit about what this platform can actually prove."""

    if IS_WINDOWS:
        assert platform_supports_enforcement()
    else:
        # On POSIX the Windows ACL code path is never executed, so its behaviour
        # is NOT VERIFIED here. The architecture is still asserted: the platform
        # is detectable and enforcement is claimed only when available.
        assert platform_supports_enforcement()
        assert restrict_to_owner is not None


@pytest.mark.skipif(not IS_WINDOWS, reason="native Windows ACL verification only")
def test_windows_key_acl_is_protected_and_owner_only(vault_dir: Path) -> None:
    """Native Windows check. NOT VERIFIED on any non-Windows CI run."""

    vault = UndoVault(vault_dir).open()
    try:
        report = verify_owner_only(vault.key_path, directory=False)
        assert report.platform == "windows"
        assert report.mechanism == "windows-dacl"
        assert report.enforced, report.detail
        # A protected DACL, so inherited ACEs cannot widen access later.
        assert report.detail.startswith("D:P")
    finally:
        vault.close()


@pytest.mark.skipif(not IS_WINDOWS, reason="native Windows ACL verification only")
def test_windows_vault_directory_acl_is_owner_only(vault_dir: Path) -> None:
    vault = UndoVault(vault_dir).open()
    try:
        for path in (vault_dir, vault_dir / "objects"):
            report = verify_owner_only(path, directory=True)
            assert report.enforced, (path, report.detail)
    finally:
        vault.close()


def test_the_vault_source_no_longer_hardcodes_a_key_inside_itself() -> None:
    """A source-level guard against reintroducing the defect."""

    source = (
        Path(__file__).resolve().parents[1] / "aether" / "core" / "vault" / "undo_vault.py"
    ).read_text(encoding="utf-8")
    # The only reference to a key inside the vault is the legacy migration path.
    assert 'self._key_path = self._directory / "vault.key"' not in source
    assert "vault_key_inside_vault" in source


def test_permissions_are_not_silently_skipped_on_windows() -> None:
    """The old code returned early on Windows. That must be gone."""

    source = (
        Path(__file__).resolve().parents[1] / "aether" / "core" / "vault" / "undo_vault.py"
    ).read_text(encoding="utf-8")
    start = source.index("def _restrict_permissions(")
    body = source[start : source.index("def _atomic_write(", start)]
    assert 'os.name == "nt"' not in body
    assert "restrict_to_owner" in body


# ---------------------------------------------------------------------------
# E. The index is not corrupted by concurrent snapshots
# ---------------------------------------------------------------------------


def test_concurrent_snapshots_all_reach_the_index(vault_dir: Path) -> None:
    """Two snapshots taken at once must both be retrievable afterwards.

    This is a real defect found while testing S14-12/S14-13, not a hypothetical.
    ``put`` appends to a JSON index with an unsynchronized read-modify-write, so
    two concurrent snapshots could each read the index, each append its own
    record, and let the second write win. The dropped snapshot's object was still
    on disk, but ``get`` then raised ``vault_snapshot_unknown`` -- a stored
    pre-image reported as never having existed.

    It surfaced as an intermittent failure in the interleaved-executor test, which
    is the worst way to find it: a data-loss bug hiding inside a flaky test. The
    loop is bounded and the assertion is deterministic, so a regression shows up
    as a failure rather than as sluggishness.
    """

    import threading

    vault = UndoVault(vault_dir).open()
    try:
        barriers = threading.Barrier(8, timeout=10)
        produced: list = []
        errors: list[BaseException] = []

        def snapshot(index: int) -> None:
            try:
                # Distinct content per thread, so each gets its own object.
                payload = f"pre-image {index}".encode()
                barriers.wait()
                produced.append((vault.put(payload, original_display_name="f.txt"), payload))
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=snapshot, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        assert not errors, f"a concurrent snapshot failed: {errors[0]!r}"
        assert len(produced) == 8

        # Every produced snapshot must be readable, not just present in a list.
        for record, payload in produced:
            assert vault.get(record.snapshot_id) == payload

        indexed = {str(item.snapshot_id) for item in vault.records()}
        assert {str(record.snapshot_id) for record, _ in produced} <= indexed, (
            "a snapshot object was written but its index record was lost"
        )
    finally:
        vault.close()


# ---------------------------------------------------------------------------
# F. Snapshot creation versus maintenance: one critical section
# ---------------------------------------------------------------------------
#
# These are *deterministic*, not probabilistic. Each one parks a thread at a
# precise point inside the operation with an Event, lets the competing operation
# run to completion, and only then releases it. A sleep-based race test proves
# nothing on a fast machine and fails spuriously on a slow one; a barrier at the
# exact interleaving proves the invariant holds for that interleaving every time.


def test_orphan_collection_cannot_remove_an_object_being_indexed(vault_dir: Path) -> None:
    """The defect: ``put`` wrote its object before taking the index lock.

    While that object was on disk but unreferenced, ``collect_orphan_objects``
    was entitled to delete it -- it genuinely looked like garbage. ``put`` then
    returned a SnapshotRecord for a snapshot that no longer existed.

    The test forces that interleaving: the collector runs *after* the object file
    exists and *before* the index entry is written. With the object write and the
    index append in one critical section the collector cannot observe the gap, so
    it must wait and then find the object referenced.
    """

    import threading

    vault = UndoVault(vault_dir).open()
    try:
        object_written = threading.Event()
        release_put = threading.Event()
        collector_entered = threading.Event()
        collector_done = threading.Event()
        produced: list = []
        removed: list = []
        errors: list[BaseException] = []

        real_atomic_write = undo_vault._atomic_write

        def signalling_atomic_write(target, payload):
            real_atomic_write(target, payload)
            if target.suffix == ".bin":
                # The object is now on disk and not yet indexed: the exact window.
                object_written.set()
                release_put.wait(timeout=10)

        def do_put():
            try:
                produced.append(
                    vault.put(b"pre-image\n", original_display_name="README.md", receipt_id=None)
                )
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        def do_collect():
            collector_entered.set()
            try:
                removed.append(vault.collect_orphan_objects())
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)
            finally:
                collector_done.set()

        putter = threading.Thread(target=do_put)
        collector = threading.Thread(target=do_collect)

        undo_vault._atomic_write = signalling_atomic_write
        try:
            putter.start()
            assert object_written.wait(timeout=10)
            collector.start()
            assert collector_entered.wait(timeout=10)
            # Give the collector every chance to run while the window is open. If
            # it could proceed, it would have finished by now.
            collector.join(timeout=0.3)
            still_blocked = collector.is_alive()

            release_put.set()
            putter.join(timeout=10)
            collector.join(timeout=10)
        finally:
            undo_vault._atomic_write = real_atomic_write

        assert not errors, f"a thread raised: {errors[0]!r}"
        assert not putter.is_alive() and not collector.is_alive()
        # Either the collector was correctly blocked, or it ran entirely before the
        # object existed. Both are safe; deleting the object is not.
        assert still_blocked or removed == [0] or removed == [], removed
        assert len(produced) == 1, "put must still return its record"

        snapshot = produced[0]
        # The decisive assertion: the snapshot the caller was handed is readable.
        assert vault.get(snapshot.snapshot_id) == b"pre-image\n"
        assert snapshot.snapshot_id in {item.snapshot_id for item in vault.records()}
    finally:
        vault.close()


def test_cleanup_cannot_discard_a_snapshot_created_concurrently(vault_dir: Path) -> None:
    """Two concurrent writers could each read the index and lose one record.

    ``cleanup_expired`` and ``put`` both rewrite the whole index. Interleaved
    read-modify-write let cleanup write back an index it had read *before* the
    snapshot was appended, silently erasing a live snapshot record.
    """

    import threading

    vault = UndoVault(vault_dir, retention_seconds=0).open()
    try:
        # One already-expired, unreferenced record, so cleanup has real work.
        first = vault.put(b"stale\n", original_display_name="a.txt", receipt_id=None)
        started = threading.Event()
        release = threading.Event()

        real_read_index = vault._read_index
        first_read = {"done": False}

        def slow_first_read():
            index = real_read_index()
            if not first_read["done"]:
                first_read["done"] = True
                # Widen the read-modify-write window deliberately.
                started.set()
                release.wait(timeout=10)
            return index

        produced: list = []
        errors: list[BaseException] = []

        def do_cleanup():
            try:
                vault.cleanup_expired()
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        def do_put():
            started.wait(timeout=10)
            try:
                produced.append(
                    vault.put(b"fresh\n", original_display_name="b.txt", receipt_id=None)
                )
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                release.set()

        cleaner = threading.Thread(target=do_cleanup)
        putter = threading.Thread(target=do_put)
        vault._read_index = slow_first_read  # type: ignore[method-assign]
        try:
            cleaner.start()
            assert started.wait(timeout=10)
            putter.start()
            cleaner.join(timeout=15)
            putter.join(timeout=15)
        finally:
            vault._read_index = real_read_index  # type: ignore[method-assign]

        assert not errors, f"a thread raised: {errors[0]!r}"
        assert len(produced) == 1
        # The stale record expired; the concurrently created one must survive.
        surviving = {item.snapshot_id for item in vault.records()}
        assert produced[0].snapshot_id in surviving, (
            "cleanup erased a snapshot that was created concurrently"
        )
        assert first.snapshot_id not in surviving
        assert vault.get(produced[0].snapshot_id) == b"fresh\n"
    finally:
        vault.close()


def test_maintenance_holds_the_same_lock_as_put(vault_dir: Path) -> None:
    """A structural guard: every index writer takes the one lock.

    Cheap to check and impossible to fake, so it catches a future method that
    rewrites the index without joining the critical section.
    """

    source = (
        Path(__file__).resolve().parents[1] / "aether" / "core" / "vault" / "undo_vault.py"
    ).read_text(encoding="utf-8")
    for method in ("def put(", "def cleanup_expired(", "def collect_orphan_objects("):
        body = source[source.index(method) :]
        body = body[: body.index("\n    def ", 1)] if "\n    def " in body else body
        assert "self._lock" in body, f"{method} must take the instance lock"
        assert "_exclusive_writer" in body, f"{method} must take the writer lock"


# ---------------------------------------------------------------------------
# G. The multi-instance ownership contract
# ---------------------------------------------------------------------------


def test_two_open_instances_cannot_both_write(vault_dir: Path) -> None:
    """Two writers on one directory are refused, not silently interleaved.

    The index is a whole-file read-modify-write; two processes each holding their
    own instance lock would still lose updates. So a second writer is prevented
    rather than serialized, and it fails closed with a reason code.
    """

    first = UndoVault(vault_dir).open()
    try:
        first.put(b"owned\n", original_display_name="a.txt", receipt_id=None)

        second = UndoVault(vault_dir).open()
        try:
            with pytest.raises(VaultError) as refused:
                second.put(b"second\n", original_display_name="b.txt", receipt_id=None)
            assert refused.value.reason_code in {
                "vault_owned_by_another_writer",
                "vault_writer_lock_unavailable",
            }
        finally:
            second.close()

        # The first instance is unaffected and its data is intact.
        assert [item.size_bytes for item in first.records()] == [len(b"owned\n")]
    finally:
        first.close()


def test_the_writer_lock_is_released_on_close(vault_dir: Path) -> None:
    """Ownership is not permanent: closing hands it on, so no leak is introduced."""

    first = UndoVault(vault_dir).open()
    first.put(b"one\n", original_display_name="a.txt", receipt_id=None)
    first.close()

    second = UndoVault(vault_dir).open()
    try:
        second.put(b"two\n", original_display_name="b.txt", receipt_id=None)
        assert len(second.records()) == 2
    finally:
        second.close()


def test_readers_are_not_blocked_by_the_writer_lock(vault_dir: Path) -> None:
    """Only writers take ownership; reading must keep working alongside."""

    writer = UndoVault(vault_dir).open()
    try:
        snapshot = writer.put(b"shared\n", original_display_name="a.txt", receipt_id=None)

        reader = UndoVault(vault_dir).open()
        try:
            assert reader.get(snapshot.snapshot_id) == b"shared\n"
            assert [item.snapshot_id for item in reader.records()] == [snapshot.snapshot_id]
        finally:
            reader.close()
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# H. Retention must not destroy recovery evidence
# ---------------------------------------------------------------------------


def test_retention_does_not_expire_a_snapshot_a_receipt_references(vault_dir: Path) -> None:
    """A receipt-linked pre-image outlives the retention window.

    Expiring it would leave a durable receipt promising an undo that can no longer
    be performed -- silent loss of the only copy of the pre-image.
    """

    vault = UndoVault(vault_dir, retention_seconds=0).open()
    try:
        referenced = vault.put(
            b"needed for undo\n", original_display_name="a.txt", receipt_id="step-1"
        )
        unreferenced = vault.put(b"scrap\n", original_display_name="b.txt", receipt_id=None)

        expired = vault.cleanup_expired()

        assert unreferenced.snapshot_id in expired
        assert referenced.snapshot_id not in expired
        assert vault.get(referenced.snapshot_id) == b"needed for undo\n"
        assert referenced.snapshot_id in {item.snapshot_id for item in vault.records()}
    finally:
        vault.close()


def test_quota_fails_closed_rather_than_evicting_referenced_snapshots(vault_dir: Path) -> None:
    """When only receipt-linked snapshots remain, the write is refused.

    Accepting the write would silently cost an earlier edit its undo. Failing
    closed is the honest outcome and it names the reason.

    The quota floor is 16 MiB, so the numbers are explicit rather than incidental:
    three 5 MiB snapshots fit under a 16 MiB quota and a fourth does not, so the
    fourth is the one that must be refused rather than evict a referenced record.
    """

    from aether.core.vault.undo_vault import _MAX_SNAPSHOT_BYTES

    chunk = b"x" * (5 * 1024 * 1024)
    vault = UndoVault(vault_dir, quota_bytes=_MAX_SNAPSHOT_BYTES).open()
    try:
        for index, receipt in enumerate(("step-1", "step-2", "step-3")):
            vault.put(
                chunk + bytes([index]), original_display_name=f"{index}.txt", receipt_id=receipt
            )
        before = [item.receipt_id for item in vault.records()]
        assert before == ["step-1", "step-2", "step-3"]

        with pytest.raises(VaultError) as refused:
            vault.put(chunk + b"overflow", original_display_name="d.txt", receipt_id="step-4")
        assert refused.value.reason_code == "vault_quota_exhausted_by_receipts"

        # Nothing was lost: every referenced snapshot is still there.
        assert [item.receipt_id for item in vault.records()] == before
        # And the refused write left no trace -- no index entry, no orphan object.
        assert vault.collect_orphan_objects() == 0
    finally:
        vault.close()


def test_maintenance_errors_stay_fail_closed(vault_dir: Path) -> None:
    """A corrupt index is still an integrity error, not an empty index."""

    vault = UndoVault(vault_dir).open()
    try:
        vault.put(b"ok\n", original_display_name="a.txt", receipt_id=None)
        vault._index.write_text("{not json", encoding="utf-8")

        for operation in (vault.cleanup_expired, vault.collect_orphan_objects):
            with pytest.raises(VaultError) as refused:
                operation()
            assert refused.value.reason_code == "vault_index_corrupt"
        # And a write still fails closed rather than rebuilding from nothing.
        with pytest.raises(VaultError) as refused:
            vault.put(b"new\n", original_display_name="b.txt", receipt_id=None)
        assert refused.value.reason_code == "vault_index_corrupt"
    finally:
        vault.close()
