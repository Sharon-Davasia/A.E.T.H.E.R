"""Trusted backend-hosted authenticated channel service.

Run as ``python -P -I -B -u -m aether.channel.service`` with an interpreter that
has the ``aether`` package installed (the backend project venv in development,
a bundled build in the future). ``-I`` implies ``-E`` (ignore ``PYTHON*``
environment variables, including ``PYTHONPATH`` and ``PYTHONHOME``) and ``-s``
(suppress user site-packages); ``-P`` (Python >= 3.11) removes the current
directory/script directory from ``sys.path``. Imports therefore resolve only
through the selected interpreter's own installation metadata. ``-I`` does not
prove every module physically resides in site-packages: an editable
development installation legitimately imports the AETHER source checkout
through an installed ``.pth``/editable finder. Development expects a trusted,
selected interpreter with a controlled editable or installed AETHER package;
packaged releases (future) must use a non-editable, verified package
installation with independent import-provenance and integrity verification as
required by the Master Specification. No uncontrolled ``PYTHONPATH``,
user-site or cwd injection exists at run time. This process is the single
trusted backend peer for the Electron desktop's authenticated channel at this
build stage. It performs the Stage 1 bootstrap (MAGIC, session id, per-launch
HMAC key, challenge) and speaks the same canonical-JSON envelope protocol; on
top of the Stage 1 ``demo.ping`` it additionally serves three narrow, typed
review operations backed by the real persisted task/plan store:

* ``review.get_preview``    — present the exact preview for one reviewable
  persisted PREVIEW_READY/AWAITING_APPROVAL task;
* ``review.record_outcome`` — record one exact bounded, non-authorizing audit
  outcome through ``PreviewReviewService``;
* ``review.get_outcome``    — read-only audit reconciliation of a previously
  submitted exact request (added so a lost acknowledgement can be confirmed).
  It never writes, never transitions state and never re-verifies a preview;
  it only reports what the persisted audit records already prove.

There is no generic privileged operation: unknown kinds terminate the session.
Storage initialization (FI-02A): the supported application database named
by ``AETHER_APP_DB`` (passed by Electron main for every build) opens via
``aether.channel.app_storage`` with the store's owner lock, private
permissions and active-schema-only migrations. The development review
database named by ``AETHER_REVIEW_DB`` is a dev-only seed mechanism; when
it is explicitly configured it takes precedence for the shared store.
When neither is usable, live operations answer ``composition_unavailable``
and review operations ``review_unavailable``; the ping path keeps working.

No operation here issues, stores, consumes or implies an ExactApprovalGrant;
every acknowledgement carries ``NON_AUTHORIZING_AUDIT_RECORD`` semantics.
"""

from __future__ import annotations

import os
import platform
import secrets
import sys
import time
from pathlib import Path
from typing import Any

from aether.channel import protocol
from aether.channel.app_storage import (
    ACCEPTANCE_MODE_ENV,
    AcceptanceStorageError,
    fixture_layout,
    open_application_store,
    open_fixture_store,
)
from aether.channel.live_bridge import LiveBridge
from aether.channel.protocol import canonical
from aether.channel.review_bridge import ReviewBridge
from aether.core.composition import ActivationScope, CompositionUnavailable, TrustedComposition
from aether.core.persistence.sqlite_store import SQLiteTaskStore

_PING_KIND = "demo.ping"
_GET_PREVIEW_KIND = "review.get_preview"
_RECORD_OUTCOME_KIND = "review.record_outcome"
_GET_OUTCOME_KIND = "review.get_outcome"

# Live workflow kinds (Phase 2 final integration), served by the trusted
# composition when it could be built; otherwise each answers a bounded
# `live.error` with reason `composition_unavailable`. There is no generic
# privileged operation: unknown kinds still terminate the session.
_PHASE3_KINDS = {
    "phase3.get_state": ("get_state", "phase3.state"),
    "phase3.set_privacy": ("set_privacy", "phase3.state"),
    "phase3.search_apps": ("search_apps", "phase3.apps"),
    "phase3.inspect_window": ("inspect_window", "phase3.snapshot"),
    "phase3.preview_interaction": ("preview_fixture_interaction", "phase3.preview"),
    "phase3.approve_interaction": ("approve_fixture_interaction", "phase3.outcome"),
    "phase3.get_task": ("get_task_state", "phase3.task"),
    "phase3.pause_task": ("pause_task", "phase3.task"),
    "phase3.list_windows": ("list_windows", "phase3.windows"),
    "phase3.register_project": ("register_project", "phase3.project"),
    "phase3.check_project_context": ("check_project_context", "phase3.project"),
    "phase3.arm_project_context": ("arm_project_context", "phase3.project"),
    "phase3.cancel_project_context": ("cancel_project_context", "phase3.project"),
    "phase3.prepare_launch": ("prepare_launch", "phase3.prepared"),
    "phase3.prepare_activation": ("prepare_activation", "phase3.prepared"),
    "phase3.prepare_fixture": ("prepare_fixture_interaction", "phase3.prepared"),
    "phase3.preview_operation": ("preview_operation", "phase3.preview"),
    "phase3.approve_operation": ("approve_operation", "phase3.outcome"),
    "phase3.get_receipt": ("get_receipt", "phase3.receipt"),
    "phase3.cancel_task": ("cancel_task", "phase3.task"),
    "phase3.resume_task": ("resume_task", "phase3.task"),
}

_LIVE_KINDS = {
    "project.register": ("register_project", "project.registered"),
    "project.resolve": ("resolve_resource", "project.resolved"),
    "task.create": ("create_task", "task.created"),
    "task.plan": ("plan_task", "task.preview"),
    "task.planned_preview": ("get_planned_preview", "task.planned"),
    "fs.execute_read": ("execute_read", "fs.read_result"),
    "gesture.begin": ("begin_gesture", "gesture.challenge"),
    "gesture.submit": ("submit_gesture", "gesture.authorized"),
    "edit.execute": ("execute_edit", "edit.executed"),
    "edit.receipt": ("get_receipt", "edit.receipt"),
}


def _hello(session: str, challenge: str, key: bytes) -> dict[str, object]:
    envelope: dict[str, object] = {
        "v": protocol.PROTOCOL,
        "session": session,
        "direction": "child-to-parent",
        "seq": 0,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time() * 1000),
        "requestId": protocol.HELLO_REQUEST_ID,
        "kind": "channel.hello",
        "payload": {
            "challenge": challenge,
            "protocol": protocol.PROTOCOL,
            "pythonVersion": platform.python_version(),
        },
    }
    return protocol.signed(envelope, key)


def _response(
    kind: str,
    *,
    session: str,
    seq: int,
    request_id: str,
    payload: dict[str, object],
    key: bytes,
) -> dict[str, object]:
    envelope: dict[str, object] = {
        "v": protocol.PROTOCOL,
        "session": session,
        "direction": "child-to-parent",
        "seq": seq,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time() * 1000),
        "requestId": request_id,
        "kind": kind,
        "payload": payload,
    }
    return protocol.signed(envelope, key)


def _emit_bounded(envelope: dict[str, object]) -> None:
    """Write one frame, enforcing the channel bound on the serialized body."""

    body = canonical(envelope)
    if not 2 <= len(body) <= protocol.MAX_FRAME:
        raise ValueError("frame size outside bounds")
    sys.stdout.buffer.write(len(body).to_bytes(4, "big") + body)
    sys.stdout.buffer.flush()


def _error_payload(reason: str) -> dict[str, object]:
    return {"reason": reason}


_GIT_BASENAMES = {"git", "git.exe"}


def _trusted_git_executable(
    env: dict[str, str], *, candidates: list[str] | None = None
) -> str | None:
    """Resolve Git from an explicitly validated trusted path only.

    The controlled backend is launched by Electron with a sanitized
    PATH (runtime dir + System32 on Windows) that intentionally
    excludes the normal Git installation directory, so invoking
    ``git`` by name cannot work and must not be attempted: a PATH
    lookup would also let any directory on that PATH supply the
    executable. Resolution therefore uses, in order:

    1. ``AETHER_GIT_EXECUTABLE`` when the trusted main process
       forwarded an owner-set absolute path — it must be absolute,
       name ``git``/``git.exe`` and be an existing regular file;
       an explicitly configured but invalid path denies resolution
       outright (no silent fallback).
    2. Fixed well-known installation locations (Program Files /
       per-user Git for Windows; ``/usr/bin/git`` etc. elsewhere),
       each validated the same way.

    Returns the validated absolute path or None (unverifiable).
    """
    from pathlib import Path as _Path

    def _valid(value: str) -> str | None:
        try:
            path = _Path(value)
            if not path.is_absolute() or path.name.casefold() not in _GIT_BASENAMES:
                return None
            if not path.is_file():
                return None
            return str(path)
        except Exception:
            return None

    explicit = env.get("AETHER_GIT_EXECUTABLE")
    if explicit:
        return _valid(explicit)
    if candidates is None:
        import os as _os
        import sys as _sys

        if _sys.platform == "win32":
            # The backend child may run with a deliberately stripped
            # environment (no USERPROFILE/HOME): home resolution must
            # never raise here, and the service-level env mapping is
            # consulted before the process environment.
            local_app_data = env.get("LOCALAPPDATA") or _os.environ.get("LOCALAPPDATA") or ""
            user_profile = env.get("USERPROFILE") or _os.environ.get("USERPROFILE") or ""
            roots = [
                env.get("PROGRAMFILES") or _os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                env.get("PROGRAMFILES(X86)")
                or _os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            ]
            if user_profile:
                roots.append(str(_Path(user_profile) / "AppData" / "Local" / "Programs"))
            candidates = [str(_Path(root) / "Git" / "cmd" / "git.exe") for root in roots] + [
                str(_Path(root) / "Git" / "bin" / "git.exe") for root in roots
            ]
            if local_app_data:
                candidates.append(
                    str(_Path(local_app_data) / "Programs" / "Git" / "cmd" / "git.exe")
                )
        else:
            candidates = ["/usr/bin/git", "/usr/local/bin/git", "/bin/git"]
    for candidate in candidates:
        resolved = _valid(candidate)
        if resolved is not None:
            return resolved
    return None


def _controlled_phase3_composition(env: dict[str, str], gesture_key: bytes):  # type: ignore[no-untyped-def]
    """A01 trusted startup path: explicit controlled-entry marker +
    owner authorization artifact. Ordinary startup never takes this
    path (it has no marker and no artifact). Any failure raises and
    the process refuses to start; there is no fallback storage."""
    import subprocess
    from pathlib import Path as _Path

    if env.get("_CONTROLLED_ENTRY") != "acceptance":
        return None
    artifact = env.get("AETHER_PHASE3_AUTHORIZATION")
    if not artifact:
        from aether.core.apps.acceptance_startup import StartupDenied

        raise StartupDenied("controlled_startup_artifact_missing")
    git_executable = _trusted_git_executable(env)
    try:
        commit = (
            subprocess.run(
                [git_executable, "rev-parse", "HEAD"],
                cwd=_Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            ).stdout.strip()
            if git_executable is not None
            else ""
        )
    except Exception:
        commit = ""
    from aether.core.apps.acceptance_startup import ControlledAcceptanceAuthorization
    from aether.core.apps.composition import Phase3Composition

    authorization = ControlledAcceptanceAuthorization.load(_Path(artifact))
    if not commit:
        from aether.core.apps.acceptance_startup import StartupDenied

        raise StartupDenied("approved_commit_unverifiable")
    # The gesture secret is the actual independent per-launch secret
    # from the authenticated Electron bootstrap — never derived from
    # the authorization artifact, session id or environment.
    platform = None
    if env.get("AETHER_PHASE3_PLATFORM") == "fake-windows":
        # Test-harness platform boundary only: raw Windows-API fakes
        # feed the identical provider construction path. It enables
        # no native capability and is never set by the desktop app.
        from aether.adapters.windows.fake_windows import build_fake_seams
        from aether.core.apps.composition import build_native_platform

        platform = build_native_platform(authorization, seams=build_fake_seams())
    # Startup order matters: the authorization artifact's isolated
    # storage is selected here — before any real-user store exists
    # (ordinary storage is opened only after this returns).
    return Phase3Composition.native(
        authorization=authorization,
        current_commit=commit,
        storage_dir=authorization.storage_path,
        gesture_key=gesture_key,
        platform=platform,
    )


def _simulated_phase3_bridge(env: dict[str, str], gesture_key: bytes):  # type: ignore[no-untyped-def]
    """Build the simulated composition for integration tests, or None."""
    import uuid as _uuid
    from datetime import UTC, datetime, timedelta
    from pathlib import Path as _Path

    storage = env.get("AETHER_PHASE3_STORAGE")
    if not storage:
        return None
    try:
        from aether.core.apps.composition import Phase3Composition
        from aether.core.apps.fixture import FixtureApp
        from aether.core.contracts.app_window import (
            ApplicationRecord,
            DiscoverySource,
            LaunchMethod,
            location_identity_digest,
            registration_app_id,
        )
        from aether.core.persistence.acceptance_storage import (
            OwnerAcceptanceAuthorization,
            open_acceptance_store,
        )

        now = datetime.now(UTC)
        store = open_acceptance_store(
            _Path(storage),
            authorization=OwnerAcceptanceAuthorization(
                decision_reference="simulated-acceptance-test",
                storage_id=str(_uuid.uuid4()),
                expires_at=now + timedelta(hours=1),
            ),
            now=now,
        )
        exe = "C:\\Fake\\AETHERFixture.exe"
        record = ApplicationRecord(
            app_id=registration_app_id(
                display_name="AETHER Fixture",
                executable_identity=exe,
                launch_method=LaunchMethod.APPROVED_EXECUTABLE,
            ),
            display_name="AETHER Fixture",
            launch_method=LaunchMethod.APPROVED_EXECUTABLE,
            executable_identity=exe,
            location_digest=location_identity_digest(exe),
            discovery_source=DiscoverySource.FAKE_FIXTURE,
            discovered_at=now,
            fresh_until=now + timedelta(hours=2),
        )
        composition = Phase3Composition.simulated(
            store=store, fixture=FixtureApp(), fixture_record=record, gesture_key=gesture_key
        )
        return composition.bridge
    except Exception:
        return None


def main(env_override: dict[str, str] | None = None) -> int:
    # Bootstrap (private stdin pipe, written once by Electron main):
    # MAGIC | 16B session id | 32B channel HMAC key | 32B challenge |
    # 32B gesture key. The gesture key is an independent per-launch secret
    # (Decision A): cryptographically separated from the channel key, held
    # only by main and this child, never logged or persisted.
    bootstrap = protocol.read_exact(sys.stdin.buffer, len(protocol.MAGIC) + 16 + 32 + 32 + 32)
    if bootstrap[: len(protocol.MAGIC)] != protocol.MAGIC:
        raise ValueError("invalid startup bootstrap")
    offset = len(protocol.MAGIC)
    session = bootstrap[offset : offset + 16].hex()
    key = bootstrap[offset + 16 : offset + 48]
    challenge = bootstrap[offset + 48 : offset + 80].hex()
    gesture_key = bootstrap[offset + 80 : offset + 112]

    env = dict(env_override if env_override is not None else os.environ)
    # Controlled-activation acceptance launches (AETHER_ACCEPTANCE_MODE
    # =fixture) run ONLY against explicitly configured fixture storage:
    # an invalid or missing fixture configuration refuses startup here
    # (no hello is emitted, the backend never becomes ready) instead of
    # falling back to the real application database, and a development
    # review seed cannot redirect the launch.
    app_store: SQLiteTaskStore | None
    fixture_project_root: Path | None = None
    if env.get(ACCEPTANCE_MODE_ENV) == "fixture":
        try:
            # Canonical fixture layout is validated BEFORE storage is
            # opened or Activation B is enabled; an invalid layout
            # refuses startup outright.
            fixture_project_root = fixture_layout(env).project_dir
            app_store = open_fixture_store(env)
        except AcceptanceStorageError:
            return 3
        bridge = None
    elif env.get("_CONTROLLED_ENTRY") == "acceptance":
        # Controlled startup selects isolated acceptance storage
        # first: no review bridge and no real-user application store
        # is opened in this mode at all.
        bridge = None
        app_store = None
    else:
        bridge = ReviewBridge.from_env(env)
        # FI-02A: the supported application store (AETHER_APP_DB, passed by
        # Electron main for every build) initializes the trusted composition
        # independently of the development review seed. The review seed —
        # when explicitly configured — keeps precedence for the store the
        # composition shares, exactly as before; otherwise the application
        # store is used. Misconfiguration fails closed to no composition.
        app_store = None if bridge is not None else open_application_store(env)
    composition = None
    live_bridge = None
    # CP7: the Phase 3 surface is constructed disabled in ordinary
    # operation (no native providers are wired here); a reviewed
    # activation decision supplies a wired surface separately.
    from aether.channel.phase3_bridge import Phase3Bridge, Phase3Surface

    phase3_bridge = Phase3Bridge(Phase3Surface.disabled())
    phase3_composition = None
    if env.get("_CONTROLLED_ENTRY") == "acceptance":
        phase3_composition = _controlled_phase3_composition(env, gesture_key)
        phase3_bridge = phase3_composition.bridge
    # G01/G02 simulated acceptance (automated integration tests only):
    # an explicit test-harness launch may request the *simulated*
    # composition, which uses fake platform providers and isolated
    # acceptance storage. Ordinary launches never set this, native
    # providers are never constructed here, and this is not an
    # owner-side activation mechanism.
    if env.get("AETHER_PHASE3_SIMULATED") == "simulated-acceptance":
        phase3_bridge = _simulated_phase3_bridge(env, gesture_key) or phase3_bridge
    # Hello is emitted only after storage resolution: an acceptance
    # launch with invalid fixture storage exits above without ever
    # becoming ready.
    _emit_bounded(_hello(session, challenge, key))
    composition_store = bridge.store if bridge is not None else app_store
    if composition_store is not None:
        try:
            # Activation B: only a validated acceptance-fixture launch
            # carries a controlled-activation scope (production-trusted
            # issuance bounded to the fixture root). Ordinary launches
            # pass no scope and remain issuance-disabled.
            activation_scope = None
            if fixture_project_root is not None:
                activation_scope = ActivationScope(project_root=fixture_project_root)
            composition = TrustedComposition.build(
                store=composition_store,
                gesture_key=gesture_key,
                activation_scope=activation_scope,
            )
            live_bridge = LiveBridge(composition)
        except CompositionUnavailable:
            # Fail closed for the trusted-execution tier only; the audit-only
            # review surface is independent and keeps working.
            composition = None
            live_bridge = None
    try:
        inbound_seen: set[str] = set()
        inbound_seq = 1
        outbound_seq = 1
        seen_requests: set[str] = set()
        while True:
            raw = protocol.read_frame(sys.stdin.buffer)
            if raw is None:
                break
            request = protocol.validate(
                raw,
                key=key,
                session=session,
                seq=inbound_seq,
                direction="parent-to-child",
                seen_nonces=inbound_seen,
            )
            inbound_seq += 1
            request_id = str(request["requestId"])
            if request_id in seen_requests:
                raise ValueError("duplicate request identifier")
            seen_requests.add(request_id)
            if len(seen_requests) > 4096:
                raise ValueError("session request capacity exceeded")
            kind = str(request["kind"])
            payload: Any = request["payload"]

            if kind == _PING_KIND:
                if payload != {"text": "synthetic-only"}:
                    raise ValueError("unsupported synthetic channel message")
                response_kind = "demo.pong"
                response_payload: dict[str, object] = {"text": "synthetic-only"}
            elif kind == _GET_PREVIEW_KIND:
                if bridge is None:
                    response_payload = {"status": "unavailable", "reason": "review_unavailable"}
                else:
                    response_payload = bridge.get_preview_payload(payload)
                response_kind = "review.preview"
            elif kind == _RECORD_OUTCOME_KIND:
                if bridge is None:
                    response_kind = "review.error"
                    response_payload = _error_payload("review_unavailable")
                else:
                    acknowledgement, reason = bridge.record_outcome(payload)
                    if acknowledgement is not None:
                        response_kind = "review.outcome"
                        response_payload = acknowledgement
                    else:
                        response_kind = "review.error"
                        response_payload = _error_payload(reason or "review_unavailable")
            elif kind == _GET_OUTCOME_KIND:
                if bridge is None:
                    response_kind = "review.error"
                    response_payload = _error_payload("review_unavailable")
                else:
                    acknowledgement, reason = bridge.get_outcome(payload)
                    if acknowledgement is not None:
                        response_kind = "review.outcome"
                        response_payload = acknowledgement
                    else:
                        response_kind = "review.error"
                        response_payload = _error_payload(reason or "review_unavailable")
            elif kind in _PHASE3_KINDS:
                method_name, success_kind = _PHASE3_KINDS[kind]
                result = getattr(phase3_bridge, method_name)(payload)
                if result.get("status") == "unavailable":
                    response_kind = "phase3.error"
                    response_payload = _error_payload(str(result.get("reason")))
                else:
                    response_kind = success_kind
                    response_payload = result
            elif kind in _LIVE_KINDS:
                method_name, success_kind = _LIVE_KINDS[kind]
                if live_bridge is None:
                    response_kind = "live.error"
                    response_payload = _error_payload("composition_unavailable")
                else:
                    result = getattr(live_bridge, method_name)(payload)
                    if result.get("status") == "unavailable":
                        response_kind = "live.error"
                        response_payload = _error_payload(str(result.get("reason")))
                    else:
                        response_kind = success_kind
                        response_payload = result
            else:
                raise ValueError("unsupported channel message")

            envelope = _response(
                response_kind,
                session=session,
                seq=outbound_seq,
                request_id=request_id,
                payload=response_payload,
                key=key,
            )
            try:
                _emit_bounded(envelope)
            except ValueError:
                if response_kind != "review.preview":
                    raise
                # A preview larger than the channel bound fails closed with a
                # bounded, non-success payload instead of an undeliverable frame.
                envelope = _response(
                    "review.preview",
                    session=session,
                    seq=outbound_seq,
                    request_id=request_id,
                    payload={"status": "unavailable", "reason": "preview_too_large"},
                    key=key,
                )
                _emit_bounded(envelope)
            outbound_seq += 1
    finally:
        if phase3_composition is not None:
            phase3_composition.shutdown()
        if composition is not None:
            composition.close()
        if bridge is not None:
            bridge.close()
        if app_store is not None:
            app_store.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EOFError, OSError, ValueError, UnicodeError):
        raise SystemExit(2) from None
