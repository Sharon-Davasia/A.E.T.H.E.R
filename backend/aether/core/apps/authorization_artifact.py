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
) -> tuple[dict[str, object], Path]:
    """Compose the artifact dict + storage path from discovered apps."""
    from aether.core.apps.launch_authority import app_version_token

    if not (0 < expires_hours <= MAX_HOURS):
        raise ValueError("authorization lifetime must be within (0, 4] hours")
    if discovered_records is None or fixture_executable is None or integrity_verifier is None:
        raise ValueError("discovery, fixture executable and verifier are required")
    wanted = {name.casefold() for name in app_display_names}
    selected = [
        r for r in discovered_records if str(getattr(r, "display_name", "")).casefold() in wanted
    ]
    found = {str(getattr(r, "display_name", "")).casefold() for r in selected}
    missing = wanted - found
    if missing:
        raise ValueError(f"requested applications were not discovered: {sorted(missing)}")
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
    artifact: dict[str, object] = {
        "approved_commit": commit,
        "decision_reference": decision_reference,
        "campaign_id": campaign_id,
        "storage_id": str(uuid.uuid4()),
        "storage_path": str(storage_path),
        "authorized_app_ids": sorted(
            {str(getattr(r, "app_id")) for r in selected} | {fixture.app_id}
        ),
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
    )
    root.mkdir(parents=True, exist_ok=True)
    artifact_path = root / "authorization.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
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
    print(f"authorization artifact: {artifact_path}")
    print(f"acceptance storage initialized: {storage_path}")
    print(f"fixture app id: {artifact['fixture_app_id']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
