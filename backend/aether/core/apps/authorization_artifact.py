"""Owner-side controlled-acceptance authorization artifact tool.

Run on the owner's Windows machine (after independent review and
explicit approval) — it discovers the approved applications through
the reviewed discovery path, derives the fixture identity from the
built fixture executable, generates session/epoch/storage identity,
writes the authorization artifact and initializes the isolated
acceptance storage. The owner supplies only the decision reference,
campaign name and which installed applications to authorize; no
internal identifier is constructed by hand.

    python -m aether.core.apps.authorization_artifact \
        --decision-reference "owner decision 2026-11-15" \
        --campaign campaign-2026-11 \
        --apps "Notepad,Calculator,File Explorer" \
        --acceptance-root D:\AETHER-acceptance
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

MAX_HOURS = 4.0


def _fixture_record(executable: str, *, now: datetime):  # type: ignore[no-untyped-def]
    from aether.core.contracts.app_window import (
        ApplicationRecord,
        DiscoverySource,
        LaunchMethod,
        location_identity_digest,
        registration_app_id,
    )

    return ApplicationRecord(
        app_id=registration_app_id(
            display_name="AETHER Fixture",
            executable_identity=executable,
            launch_method=LaunchMethod.APPROVED_EXECUTABLE,
        ),
        display_name="AETHER Fixture",
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
        executable_identity=executable,
        location_digest=location_identity_digest(executable),
        discovery_source=DiscoverySource.USER_REGISTERED_PORTABLE,
        discovered_at=now,
        fresh_until=now + timedelta(hours=2),
    )


def build_authorization(
    *,
    decision_reference: str,
    campaign_id: str,
    app_display_names: list[str],
    acceptance_root: Path,
    now: datetime,
    expires_hours: float = 4.0,
    discovered_records: list[object] | None = None,
    fixture_executable: str | None = None,
    integrity_verifier: object | None = None,
    commit: str | None = None,
    app_ids: list[str] | None = None,
) -> tuple[dict[str, object], Path]:
    """Compose the artifact dict + storage path from discovered apps."""
    from aether.core.apps.launch_authority import app_version_token

    if not (0 < expires_hours <= MAX_HOURS):
        raise ValueError("authorization lifetime must be within (0, 4] hours")
    if discovered_records is None or fixture_executable is None or integrity_verifier is None:
        raise ValueError("discovery, fixture executable and verifier are required")
    wanted = {name.casefold() for name in app_display_names}
    from aether.core.contracts.app_window import ApplicationRecord as _Record

    records = [r for r in discovered_records if isinstance(r, _Record)]
    if app_ids is not None:
        # Explicit identity selection: exact app ids, never names.
        by_id = {r.app_id: r for r in records}
        unknown = [app_id for app_id in app_ids if app_id not in by_id]
        if unknown:
            raise ValueError(f"requested application ids were not discovered: {unknown}")
        selected = [by_id[app_id] for app_id in app_ids]
    else:
        selected = [r for r in records if r.display_name.casefold() in wanted]
        found = {r.display_name.casefold() for r in selected}
        missing = wanted - found
        if missing:
            raise ValueError(f"requested applications were not discovered: {sorted(missing)}")
        # A shared display name must never silently authorize several
        # distinct application identities: selection must be exact.
        ambiguous: dict[str, set[str]] = {}
        for record in selected:
            ambiguous.setdefault(record.display_name.casefold(), set()).add(record.app_id)
        conflicts = {name: sorted(ids) for name, ids in ambiguous.items() if len(ids) > 1}
        if conflicts:
            raise ValueError(
                f"requested application names are ambiguous; re-run with --app-ids: {conflicts}"
            )
    fixture = _fixture_record(fixture_executable, now=now)
    evidence = integrity_verifier.verify(fixture)  # type: ignore[attr-defined]
    if evidence is None:
        raise ValueError("fixture integrity evidence is unavailable; build the fixture first")
    if commit is None:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False, timeout=10
        ).stdout.strip()
    if len(commit) < 40:
        raise ValueError("candidate commit could not be determined")
    storage_path = Path(acceptance_root) / f"aether-phase3-acceptance-{campaign_id}"
    # R2: the synthetic project workspace is a SEPARATE sibling
    # directory - project evidence never lives inside the schema-v3
    # database directory (whose content allowlist stays closed).
    workspace_path = Path(acceptance_root) / f"aether-phase3-workspace-{campaign_id}"
    artifact: dict[str, object] = {
        "approved_commit": commit,
        "decision_reference": decision_reference,
        "campaign_id": campaign_id,
        "storage_id": str(uuid.uuid4()),
        "storage_path": str(storage_path),
        "workspace_path": str(workspace_path),
        "authorized_app_ids": sorted({r.app_id for r in selected} | {fixture.app_id}),
        "capability_allowlist": [
            "app.launch",
            "window.activate",
            "uia.inspect_snapshot",
            "uia.inspect_element",
            "uia.invoke_fixture",
        ],
        "session_id": f"session-{uuid.uuid4()}",
        "activation_epoch": f"epoch-{uuid.uuid4()}",
        "expires_at": (now + timedelta(hours=expires_hours)).isoformat(),
        "privacy_mode": "metadata_only",
        "fixture_app_id": fixture.app_id,
        "fixture_identity_token": app_version_token(evidence),
    }
    return artifact, storage_path


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - owner CLI
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decision-reference", required=True)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--apps", default="Notepad,Calculator,File Explorer")
    parser.add_argument("--app-ids", default="")
    parser.add_argument("--acceptance-root", required=True)
    parser.add_argument("--expires-hours", type=float, default=4.0)
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        print("authorization tool requires Windows (native discovery)", file=sys.stderr)
        return 2
    from aether.adapters.windows.discovery import (
        StdlibWindowsDiscoveryProviders,
        discover_applications,
    )
    from aether.adapters.windows.native_launcher import NativeIntegrityProvider
    from aether.core.apps.discovery_normalize import normalize_discovery
    from aether.core.apps.fixture_contract import FIXTURE_EXECUTABLE_NAME
    from aether.core.persistence.acceptance_storage import (
        OwnerAcceptanceAuthorization,
        open_acceptance_store,
    )

    now = datetime.now(UTC)
    root = Path(args.acceptance_root)
    fixture_executable = str(
        Path(__file__).resolve().parents[4] / "tools" / "windows-fixture" / FIXTURE_EXECUTABLE_NAME
    )
    records = normalize_discovery(discover_applications(StdlibWindowsDiscoveryProviders()), now=now)
    artifact, storage_path = build_authorization(
        decision_reference=args.decision_reference,
        campaign_id=args.campaign,
        app_display_names=[n.strip() for n in args.apps.split(",") if n.strip()],
        acceptance_root=root,
        now=now,
        expires_hours=args.expires_hours,
        discovered_records=list(records),
        fixture_executable=fixture_executable,
        integrity_verifier=NativeIntegrityProvider(),
        app_ids=[item.strip() for item in args.app_ids.split(",") if item.strip()] or None,
    )
    root.mkdir(parents=True, exist_ok=True)
    # Campaign-scoped artifact path: each campaign writes its own
    # file, and creation is exclusive - an earlier campaign artifact
    # is evidence and is never overwritten.
    artifact_path = root / f"authorization-{args.campaign}.json"
    if artifact_path.exists() or artifact_path.is_symlink():
        print(
            f"authorization artifact already exists: {artifact_path}; "
            "choose a new campaign name (historical artifacts are never overwritten)",
            file=sys.stderr,
        )
        return 2
    # Initialize the isolated storage FIRST and write the artifact
    # only after initialization succeeded, so a failed run can never
    # leave behind usable-looking authorization evidence.
    store = open_acceptance_store(
        storage_path,
        authorization=OwnerAcceptanceAuthorization(
            decision_reference=str(artifact["decision_reference"]),
            storage_id=str(artifact["storage_id"]),
            expires_at=datetime.fromisoformat(str(artifact["expires_at"])),
            campaign_id=str(artifact["campaign_id"]),
        ),
        now=now,
    )
    store.close()
    # Create the dedicated synthetic workspace as a sibling of the
    # database directory (exclusive; never inside database storage).
    workspace_path = Path(str(artifact["workspace_path"]))
    if workspace_path.exists() or workspace_path.is_symlink():
        print(
            f"synthetic workspace already exists: {workspace_path}; choose a new campaign name",
            file=sys.stderr,
        )
        return 2
    workspace_path.mkdir(mode=0o700)
    # Bind the created workspace's filesystem identity into the
    # artifact: later substitution or identity drift is refused at
    # startup and at registration.
    workspace_metadata = workspace_path.stat()
    artifact["workspace_identity"] = [workspace_metadata.st_dev, workspace_metadata.st_ino]
    with artifact_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(artifact, indent=2, sort_keys=True))
    print(f"authorization artifact: {artifact_path}")
    print(f"acceptance storage initialized: {storage_path}")
    print(f"synthetic workspace created: {workspace_path}")
    print(f"fixture app id: {artifact['fixture_app_id']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
