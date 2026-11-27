"""Blocker closeout: genuine cross-process controlled acceptance.

Spawns the actual controlled channel service
(``aether.channel.controlled_service``) as a subprocess, performs the
authenticated Electron bootstrap with an independent per-launch
gesture secret, and drives the full workflow over framed, MAC-signed
channel messages: controlled startup -> privacy opt-in -> discovery
-> launch (forged gesture refused, genuine gesture exactly once,
replay refused) -> observer-published window registration ->
activation -> supervised worker-subprocess inspection -> exact
fixture approval -> verified effect -> durable receipt -> shutdown.

Only the Windows platform boundary is faked (raw Win32-API seams
feeding the real provider construction path). No window, success
evidence or receipt is inserted by the test. Not native evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aether.adapters.windows.discovery import discover_applications
from aether.adapters.windows.fake_windows import build_fake_seams, fixture_executable
from aether.core.apps.authorization_artifact import build_authorization
from aether.core.apps.discovery_normalize import normalize_discovery
from aether.core.persistence.acceptance_storage import (
    OwnerAcceptanceAuthorization,
    open_acceptance_store,
)

MAGIC = b"AETHR1\x00\x01"
BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _sign(value: dict, key: bytes) -> dict:  # type: ignore[type-arg]
    return {**value, "mac": hmac.new(key, _canonical(value), hashlib.sha256).hexdigest()}


def _encode(value: dict) -> bytes:  # type: ignore[type-arg]
    body = _canonical(value)
    return struct.pack(">I", len(body)) + body


def _read_frame(stream) -> dict:  # type: ignore[no-untyped-def,type-arg]
    header = stream.read(4)
    assert len(header) == 4, "child did not emit a complete frame"
    size = struct.unpack(">I", header)[0]
    body = stream.read(size)
    assert len(body) == size, "child emitted a truncated frame"
    return json.loads(body)


def test_controlled_service_cross_process_workflow(tmp_path: Path) -> None:
    # -- owner-side artifact + isolated storage (implemented tooling) --
    seams = build_fake_seams()
    now = datetime.now(UTC)
    records = normalize_discovery(discover_applications(seams.discovery_providers), now=now)  # type: ignore[arg-type]
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    artifact, storage_path = build_authorization(
        decision_reference="owner-decision-cross-process",
        campaign_id="campaign-xproc",
        app_display_names=["Notepad"],
        acceptance_root=tmp_path,
        now=now,
        expires_hours=2.0,
        discovered_records=list(records),
        fixture_executable=fixture_executable(),
        integrity_verifier=seams.integrity_verifier,
        commit=commit,
    )
    # Mirror the owner tool: create the sibling synthetic workspace
    # and bind its filesystem identity into the artifact.
    workspace_path = Path(str(artifact["workspace_path"]))
    workspace_path.mkdir(parents=True)
    _ws_stat = workspace_path.stat()
    artifact["workspace_identity"] = [_ws_stat.st_dev, _ws_stat.st_ino]
    artifact_path = tmp_path / "authorization.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
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

    session = secrets.token_bytes(16)
    key = secrets.token_bytes(32)
    challenge = secrets.token_bytes(32)
    gesture_key = secrets.token_bytes(32)
    env: dict[str, str] = {"PATH": os.environ.get("PATH", "")}
    if os.name == "nt":
        # Minimal Windows runtime environment the child Python and
        # its worker subprocess need (DLL search, home/profile and
        # program-files resolution); a fixed allowlist only, so the
        # child's environment stays isolated.
        for name in (
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "LOCALAPPDATA",
            "APPDATA",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "TEMP",
            "TMP",
        ):
            if name in os.environ:
                env[name] = os.environ[name]
    env.update(
        {
            "AETHER_PHASE3_AUTHORIZATION": str(artifact_path),
            "AETHER_PHASE3_PLATFORM": "fake-windows",
        }
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "aether.channel.controlled_service"],
        cwd=BACKEND_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    def _diagnostics(exit_code: int | None) -> str:
        """Bounded, redacted child diagnostics for a failed startup."""
        raw = b""
        if process.stderr is not None:
            try:
                raw = process.stderr.read() or b""
            except Exception:
                raw = b""
        text = raw.decode("utf-8", errors="replace")[-2000:]
        text = text.replace(str(tmp_path), "<tmp>").replace(str(REPO_ROOT), "<repo>")
        for secret in (session, key, challenge, gesture_key):
            text = text.replace(secret.hex(), "<redacted>")
        return f"child_exit={exit_code} child_stderr={text!r}"

    seq = 0

    def call(kind: str, payload: dict) -> dict:  # type: ignore[type-arg]
        nonlocal seq
        seq += 1
        assert process.stdin is not None and process.stdout is not None
        request = _sign(
            {
                "v": 1,
                "session": session.hex(),
                "direction": "parent-to-child",
                "seq": seq,
                "nonce": f"{seq:032x}",
                "timestamp": int(time.time() * 1000),
                "requestId": f"{seq:08d}-4444-4444-8444-444444444444",
                "kind": kind,
                "payload": payload,
            },
            key,
        )
        process.stdin.write(_encode(request))
        process.stdin.flush()
        return _read_frame(process.stdout)

    def sign_gesture(preview: dict, *, signing_key: bytes) -> dict:  # type: ignore[type-arg]
        from aether.core.planning.authorizing_gesture import (
            GestureBinding,
            GestureNonceRegister,
            TrustedGestureAuthority,
        )

        binding = preview["binding"]
        authority = TrustedGestureAuthority(
            key=signing_key, nonces=GestureNonceRegister(), clock=lambda: datetime.now(UTC)
        )
        gesture = authority.sign(
            nonce=preview["nonce"],
            binding=GestureBinding(
                task_id=UUID(binding["taskId"]),
                plan_revision=binding["planRevision"],
                plan_hash=binding["planHash"],
                preview_id=UUID(binding["previewId"]),
                preview_digest=binding["previewDigest"],
                scope_digest=binding["scopeDigest"],
            ),
            user_intent="APPROVE",
        )
        return {
            "nonce": preview["nonce"],
            "assertedAt": gesture.asserted_at.isoformat(),
            "userIntent": "APPROVE",
            "signature": gesture.signature,
            "binding": binding,
        }

    workflow_error: BaseException | None = None
    try:
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(MAGIC + session + key + challenge + gesture_key)
        process.stdin.flush()
        try:
            hello = _read_frame(process.stdout)
        except AssertionError as exc:
            raise AssertionError(f"controlled child emitted no hello frame: {exc}") from exc
        assert hello.get("kind") == "channel.hello"

        state = call("phase3.get_state", {})
        assert state["payload"]["nativeAvailable"] is True
        assert state["payload"]["privacy"]["mode"] == "off"  # sensors off
        optin = call(
            "phase3.set_privacy", {"optedIn": True, "mode": "metadata_only", "paused": False}
        )
        assert optin["payload"]["status"] == "ready" or optin["kind"] == "phase3.state"

        apps = call("phase3.search_apps", {"query": ""})
        names = {r["displayName"] for r in apps["payload"]["results"]}
        assert {"Notepad", "AETHER Fixture"} <= names

        fixture_id = artifact["fixture_app_id"]
        prepared = call("phase3.prepare_launch", {"appId": fixture_id})
        assert prepared["payload"]["status"] == "ready", prepared
        task_id = prepared["payload"]["taskId"]
        preview = call("phase3.preview_operation", {"taskId": task_id, "effect": "app.launch"})
        assert preview["payload"]["status"] == "ready", preview
        # Forged gesture (wrong key) is refused.
        forged = call(
            "phase3.approve_operation",
            {
                "taskId": task_id,
                "effect": "app.launch",
                **sign_gesture(preview["payload"], signing_key=b"x" * 32),
            },
        )
        assert forged["payload"].get("outcome") != "SUCCEEDED"
        # Genuine Electron-compatible gesture succeeds exactly once.
        gesture_payload = sign_gesture(preview["payload"], signing_key=gesture_key)
        outcome = call(
            "phase3.approve_operation",
            {"taskId": task_id, "effect": "app.launch", **gesture_payload},
        )
        assert outcome["payload"].get("outcome") == "SUCCEEDED", outcome
        # Replayed gesture is refused.
        replay = call(
            "phase3.approve_operation",
            {"taskId": task_id, "effect": "app.launch", **gesture_payload},
        )
        assert replay["payload"].get("outcome") != "SUCCEEDED"

        # Observer-published registration (poll the authenticated state).
        window_id = None
        for _ in range(100):
            state = call("phase3.get_state", {})
            for window in state["payload"]["windows"]:
                if window["appId"] == fixture_id:
                    window_id = window["windowId"]
            if window_id:
                break
            time.sleep(0.05)
        assert window_id, "observer did not register the launched window"

        activation = call("phase3.prepare_activation", {"windowId": window_id})
        assert activation["payload"]["status"] == "ready", activation
        apreview = call(
            "phase3.preview_operation",
            {"taskId": activation["payload"]["taskId"], "effect": "window.activate"},
        )
        aoutcome = call(
            "phase3.approve_operation",
            {
                "taskId": activation["payload"]["taskId"],
                "effect": "window.activate",
                **sign_gesture(apreview["payload"], signing_key=gesture_key),
            },
        )
        assert aoutcome["payload"]["status"] == "ready", aoutcome

        snapshot = call("phase3.inspect_window", {"windowId": window_id})
        assert snapshot["payload"].get("status") == "ready", snapshot

        interaction = call("phase3.prepare_fixture", {"windowId": window_id})
        assert interaction["payload"].get("status") == "ready", interaction
        assert interaction["payload"]["preview"]["verifiedPrecondition"] == "Count: 0"
        assert interaction["payload"]["preview"]["expectedPostcondition"] == "Count: 1"
        itask = interaction["payload"]["taskId"]
        ipreview = call("phase3.preview_interaction", {"taskId": itask})
        assert ipreview["payload"]["status"] == "ready", ipreview
        iresult = call(
            "phase3.approve_interaction",
            {"taskId": itask, **sign_gesture(ipreview["payload"], signing_key=gesture_key)},
        )
        assert iresult["payload"].get("outcome") == "SUCCEEDED", iresult
        receipt = call("phase3.get_receipt", {"taskId": itask})
        assert receipt["payload"]["taskState"] == "COMPLETED", receipt
        assert receipt["payload"]["uiAttempts"][0]["receipt_status"] == "SUCCEEDED"
        # Exactly one effect: a fresh preparation now sees Count: 1.
        again = call("phase3.prepare_fixture", {"windowId": window_id})
        assert again["payload"]["preview"]["verifiedPrecondition"] == "Count: 1", again
    except BaseException as exc:  # capture diagnostics before re-raising
        workflow_error = exc
        raise
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            exit_code = process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            exit_code = process.wait(timeout=15)
        if workflow_error is not None:
            raise AssertionError(
                f"controlled cross-process workflow failed: {_diagnostics(exit_code)}"
            ) from workflow_error
        if process.stdout is not None:
            process.stdout.close()
    assert exit_code == 0, _diagnostics(exit_code)
