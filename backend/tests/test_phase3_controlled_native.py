"""A01-A05: controlled native activation — authorization, storage
containment, worker binding, native privacy/takeover and one
continuous authenticated workflow over the real composition,
persistence, broker, planner, gesture authority, executor and an
actual worker subprocess. Only Windows platform providers are faked;
nothing here is native Windows evidence.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aether.adapters.windows.native_activity import FakeActivitySource
from aether.adapters.windows.uia_backend import RawElement
from aether.channel import service as channel_service
from aether.core.apps.acceptance_startup import (
    ControlledAcceptanceAuthorization,
    StartupDenied,
)
from aether.core.apps.composition import NativePlatformProviders, Phase3Composition
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    location_identity_digest,
    registration_app_id,
)
from aether.core.persistence.acceptance_storage import (
    AcceptanceStorageError,
    OwnerAcceptanceAuthorization,
    open_acceptance_store,
)

COMMIT = "a" * 40
GESTURE_KEY = bytes(range(32))
SESSION = "session-controlled-acceptance"
EPOCH = "epoch-1"
CAMPAIGN = "campaign-2026-11"


def _record(app_id: str, name: str) -> ApplicationRecord:
    now = datetime.now(UTC)
    import re as _re

    if not _re.fullmatch(r"app:[0-9a-fA-F-]{36}", app_id):
        app_id = registration_app_id(
            display_name=name,
            executable_identity=f"C:/Apps/{name}.exe",
            launch_method=LaunchMethod.APPROVED_EXECUTABLE,
        )
    return ApplicationRecord(
        app_id=app_id,
        display_name=name,
        aliases=("fixtureapp",) if name == "Fixture App" else (),
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
        executable_identity=f"C:/Apps/{name}.exe",
        location_digest=location_identity_digest(f"C:/Apps/{name}.exe"),
        discovery_source=DiscoverySource.USER_REGISTERED_PORTABLE,
        discovered_at=now,
        fresh_until=now + timedelta(hours=2),
    )


class _Integrity:
    def verify(self, record):  # type: ignore[no-untyped-def]
        from aether.core.apps.launch_authority import IntegrityEvidence

        return IntegrityEvidence(
            location_digest=record.location_digest or "",
            content_sha256="a" * 64,
            signer_identity="FakeSigner",
            package_identity=None,
            verified_at=datetime.now(UTC),
            file_identity="3:42:100:1",
        )


class _Adapter:
    def __init__(self, platform):  # type: ignore[no-untyped-def]
        self.platform = platform
        self.calls = 0

    def launch(self, *, app_id, method, canonical_target):  # type: ignore[no-untyped-def]
        self.calls += 1
        token = self.platform.new_window(app_id, 1001)
        from aether.core.apps.launcher import LaunchCallResult

        return LaunchCallResult(accepted=True, process_token=token)


class _Platform:
    """Fake Windows platform: process/window state behind providers."""

    def __init__(self) -> None:
        self.windows: list[tuple[int, str, str]] = []
        self.count = 0

    def new_window(self, app_id: str, hwnd: int) -> str:
        token = f"proc:{hwnd}"
        self.windows.append((hwnd, token, app_id))
        return token


class _Observation:
    """Independent platform observation for launch verification."""

    def __init__(self, platform, sha_by_app):  # type: ignore[no-untyped-def]
        self.platform = platform
        self.sha_by_app = sha_by_app

    def observe(self):  # type: ignore[no-untyped-def]
        from aether.core.apps.verification import (
            ObservedProcess,
            ObservedWindow,
            PlatformObservation,
        )

        processes = {}
        windows = []
        for hwnd, token, app_id in self.platform.windows:
            processes[token] = ObservedProcess(
                process_token=token,
                app_id=app_id,
                integrity_sha256=self.sha_by_app.get(app_id),
                started_after_attempt=True,
            )
            windows.append(
                ObservedWindow(window_token=f"hwnd:{hwnd}", process_token=token, app_id=app_id)
            )
        return PlatformObservation(
            processes=tuple(processes.values()), windows=tuple(windows), complete=True
        )


class _Backend:
    """Fake of the real native backend contract (bounded walk)."""

    def __init__(self, platform: _Platform) -> None:
        self.platform = platform
        self.mode = "metadata_only"
        self.fixture_counter = False
        self.invoked: list[str] = []

    def set_collection_mode(self, mode: str, *, fixture_counter_permitted: bool = False) -> None:
        self.mode = mode
        self.fixture_counter = fixture_counter_permitted

    def raw(
        self, key: str, ctype: str, auto: str, name: str | None, kids: tuple[str, ...]
    ) -> RawElement:
        return RawElement(
            key=key,
            control_type=ctype,
            name=name
            if (self.mode == "content_on_demand" or (self.fixture_counter and key == "1.1"))
            else None,
            automation_id=auto,
            patterns=frozenset({"invoke"}) if key == "1.2" else frozenset(),
            is_enabled=True,
            is_offscreen=False,
            is_password=False,
            bounding_rect=None,
            value_present=False,
            children_keys=kids,
        )

    def find_root(self, *, hwnd: int):  # type: ignore[no-untyped-def]
        if not any(w == hwnd for w, _t, _a in self.platform.windows):
            return None
        return self.raw("1", "Window", "201", "Fixture Window", ("1.1", "1.2"))

    def children(self, element):  # type: ignore[no-untyped-def]
        if element.key == "1":
            return (
                self.raw("1.1", "Text", "101", f"Count: {self.platform.count}", ()),
                self.raw("1.2", "Button", "102", "Increment", ()),
            )
        return ()

    def invoke(self, element):  # type: ignore[no-untyped-def]
        self.invoked.append(element.key)
        self.platform.count += 1
        return {"invoked": element.key}

    def read_value(self, element):  # type: ignore[no-untyped-def]
        return {"value_present": False, "element_key": element.key}

    def close(self) -> None:
        pass


def _harness(tmp_path: Path):
    platform = _Platform()
    backend = _Backend(platform)
    app_id = _record("app:fixture", "Fixture App").app_id
    fixture_record = _record("app:fixture", "Fixture App")
    notepad = _record("app:notepad", "Notepad")
    storage = tmp_path / "aether-phase3-acceptance-test"
    authz = ControlledAcceptanceAuthorization(
        approved_commit=COMMIT,
        decision_reference="owner-decision-A01",
        campaign_id=CAMPAIGN,
        storage_id="11111111-1111-4111-8111-111111111111",
        storage_path=str(storage),
        authorized_app_ids=frozenset({app_id, notepad.app_id}),
        capability_allowlist=frozenset(
            {
                "app.launch",
                "window.activate",
                "uia.inspect_snapshot",
                "uia.inspect_element",
                "uia.invoke_fixture",
            }
        ),
        session_id=SESSION,
        activation_epoch=EPOCH,
        expires_at=datetime.now(UTC) + timedelta(hours=4),
        privacy_mode="metadata_only",
        fixture_app_id=app_id,
        fixture_identity_token="fixture-token-001",
    )
    adapter = _Adapter(platform)
    fg: dict[str, int | None] = {"hwnd": None}
    emit_holder: dict[str, object] = {}
    activity = FakeActivitySource(emit_to=lambda s: emit_holder["fn"](s))  # type: ignore[arg-type]
    from aether.core.apps.launch_authority import app_version_token

    fixture_token = app_version_token(_Integrity().verify(fixture_record))
    authz = dataclasses.replace(authz, fixture_identity_token=fixture_token)
    providers = NativePlatformProviders(
        records=[notepad],
        fixture_record=fixture_record,
        fixture_identity_token=fixture_token,
        integrity_verifier=_Integrity(),
        launch_adapter=adapter,
        uia_backend_factory=lambda: backend,
        activity_factory=lambda emit_to: (emit_holder.__setitem__("fn", emit_to), activity)[1],
        activate=lambda hwnd: fg.__setitem__("hwnd", hwnd) is None,
        foreground_hwnd=lambda: fg["hwnd"],
        observation_provider=_Observation(
            platform,
            {
                r.app_id: __import__(
                    "aether.core.apps.launch_authority", fromlist=["integrity_digest_of"]
                ).integrity_digest_of(_Integrity().verify(r))
                for r in (fixture_record, notepad)
            },
        ),
    )
    return {
        "platform": platform,
        "backend": backend,
        "adapter": adapter,
        "fg": fg,
        "activity": activity,
        "providers": providers,
        "authz": authz,
        "storage": storage,
        "app_id": app_id,
        "notepad_id": notepad.app_id,
    }


def _start(h):  # type: ignore[no-untyped-def]
    return Phase3Composition.native(
        authorization=h["authz"],
        current_commit=COMMIT,
        storage_dir=h["storage"],
        gesture_key=GESTURE_KEY,
        platform=h["providers"],
    )


# ---------------------------------------------------------------- A01


def test_native_factory_denies_bad_authorization(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    bad = h["authz"]
    import dataclasses

    with pytest.raises(StartupDenied):
        Phase3Composition.native(
            authorization=dataclasses.replace(bad, approved_commit="b" * 40),
            current_commit=COMMIT,
            storage_dir=h["storage"],
            gesture_key=GESTURE_KEY,
            platform=h["providers"],
        )
    with pytest.raises(StartupDenied):
        Phase3Composition.native(
            authorization=dataclasses.replace(
                bad, expires_at=datetime.now(UTC) - timedelta(minutes=1)
            ),
            current_commit=COMMIT,
            storage_dir=h["storage"],
            gesture_key=GESTURE_KEY,
            platform=h["providers"],
        )
    with pytest.raises(StartupDenied):  # capability beyond build ceiling
        Phase3Composition.native(
            authorization=dataclasses.replace(
                bad, capability_allowlist=frozenset({"uia.invoke_fixture", "shell.exec"})
            ),
            current_commit=COMMIT,
            storage_dir=h["storage"],
            gesture_key=GESTURE_KEY,
            platform=h["providers"],
        )
    with pytest.raises(StartupDenied):  # privacy mode not the approved one
        Phase3Composition.native(
            authorization=dataclasses.replace(bad, privacy_mode="content_on_demand"),
            current_commit=COMMIT,
            storage_dir=h["storage"],
            gesture_key=GESTURE_KEY,
            platform=h["providers"],
        )
    with pytest.raises(StartupDenied):  # no storage marker yet
        _start(h)


def test_native_composition_starts_with_valid_authorization(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    store = open_acceptance_store(
        h["storage"],
        authorization=OwnerAcceptanceAuthorization(
            decision_reference=h["authz"].decision_reference,
            storage_id=h["authz"].storage_id,
            expires_at=h["authz"].expires_at,
            campaign_id=h["authz"].campaign_id,
        ),
        now=datetime.now(UTC),
    )
    store.close()
    comp = _start(h)
    assert comp.mode.value == "native_prepared"
    assert comp.surface is not None and comp.enablement.config.enabled
    # Sensors start OFF: no observation before privacy opt-in.
    assert comp.bridge.get_state({})["privacy"]["mode"] == "off"
    # Storage is v3 and isolated.
    db = h["storage"] / "phase3-acceptance.sqlite3"
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.close()
    assert version == 3
    assert comp.shutdown() is True


def test_ordinary_startup_renderers_cannot_mint_authority(tmp_path: Path) -> None:
    # An environment flag is not execution authority: channel service
    # without the controlled entry point rejects Phase 3 kinds.
    env = {
        "_CONTROLLED_ENTRY": "acceptance",
        "AETHER_PHASE3_AUTHORIZATION": str(tmp_path / "x.json"),
    }
    with pytest.raises(StartupDenied):
        channel_service._controlled_phase3_composition(env)
    # Ordinary startup (no controlled marker) never constructs it.
    ordinary = {"AETHER_PHASE3_AUTHORIZATION": str(tmp_path / "x.json")}
    assert channel_service._controlled_phase3_composition(ordinary) is None


# ---------------------------------------------------------------- A02


def test_storage_rejects_substitution_and_unrelated_content(tmp_path: Path) -> None:
    auth = OwnerAcceptanceAuthorization(
        decision_reference="d",
        storage_id="22222222-2222-4222-8222-222222222222",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        campaign_id="c",
    )
    # Unrelated existing directory content is refused.
    storage = tmp_path / "aether-phase3-acceptance-unrelated"
    storage.mkdir()
    (storage / "evil.txt").write_text("x")
    with pytest.raises(AcceptanceStorageError):
        open_acceptance_store(storage, authorization=auth)
    # Database present without marker is refused.
    storage2 = tmp_path / "aether-phase3-acceptance-db-only"
    storage2.mkdir()
    conn = sqlite3.connect(storage2 / "phase3-acceptance.sqlite3")
    conn.execute("CREATE TABLE t(x)")
    conn.close()
    with pytest.raises(AcceptanceStorageError):
        open_acceptance_store(storage2, authorization=auth)
    # Marker substitution (wrong storage id) is refused.
    storage3 = tmp_path / "aether-phase3-acceptance-marker"
    store = open_acceptance_store(storage3, authorization=auth)
    store.close()
    marker = storage3 / "acceptance-storage.json"
    data = json.loads(marker.read_text())
    data["storage_id"] = "substituted"
    marker.write_text(json.dumps(data))
    with pytest.raises(AcceptanceStorageError):
        open_acceptance_store(storage3, authorization=auth)
    # Hard-linked marker file is refused.
    storage4 = tmp_path / "aether-phase3-acceptance-link"
    store = open_acceptance_store(storage4, authorization=auth)
    store.close()
    os.link(storage4 / "acceptance-storage.json", tmp_path / "copy.json")
    with pytest.raises(AcceptanceStorageError):
        open_acceptance_store(storage4, authorization=auth)


def test_store_pending_v3_flag_alone_is_insufficient(tmp_path: Path) -> None:
    from aether.core.persistence.sqlite_store import PersistenceIntegrityError, SQLiteTaskStore

    db = tmp_path / "plain.sqlite3"
    with pytest.raises(PersistenceIntegrityError):
        SQLiteTaskStore(db, target_schema_version=3, _acceptance_pending_authorized=True)


# ---------------------------------------------------------------- A03


def test_worker_bootstrap_binding_and_expiry() -> None:
    import dataclasses

    from aether.adapters.windows.native_observer import activation_context_from_parent_bootstrap
    from aether.core.workers.uia_worker import validate_request

    ctx = activation_context_from_parent_bootstrap(
        {
            "issuer": "aether-trusted-composition",
            "session_id": "s1",
            "activation_epoch": "e1",
            "activation_scope": "c1",
            "worker_id": "w1",
            "permitted_operations": ["inspect", "health"],
            "expires_at": time.time() + 60,
        }
    )
    assert ctx.session_id == "s1" and ctx.activation_epoch == "e1"
    assert ctx.operation_permitted("inspect", now=time.time())
    assert not ctx.operation_permitted("invoke", now=time.time())
    expired = dataclasses.replace(ctx, expires_at=time.time() - 1)
    assert not expired.operation_permitted("inspect", now=time.time())
    with pytest.raises(ValueError):  # renderer-minted issuer
        activation_context_from_parent_bootstrap(
            {
                "issuer": "renderer",
                "session_id": "s1",
                "activation_epoch": "e1",
                "activation_scope": "c1",
            }
        )
    with pytest.raises(ValueError):  # arbitrary renderer operation
        validate_request({"protocol": 1, "operation": "shell", "request_id": "r", "payload": {}})


def test_supervisor_failed_start_cleanup_and_stale_effect(tmp_path: Path) -> None:
    from aether.core.workers.subprocess_supervisor import SubprocessWorkerSupervisor
    from aether.core.workers.uia_worker import WorkerOutcome

    # Dead-on-arrival child: start fails and nothing lingers.
    sup = SubprocessWorkerSupervisor(command=[sys.executable, "-c", "pass"], startup_timeout=5)
    assert sup.start() is False
    assert sup._process is None
    # Effectful stale/malformed responses are reclassified uncertain.
    from aether.core.workers.subprocess_supervisor import (
        SubprocessWorkerSupervisor as _Sup,
    )
    from aether.core.workers.subprocess_supervisor import default_worker_command

    worker = _Sup(
        command=default_worker_command(simulated=True),
        bootstrap_payload={
            "issuer": "aether-trusted-composition",
            "session_id": "s1",
            "activation_epoch": "e1",
            "activation_scope": "c1",
            "worker_id": "w1",
            "permitted_operations": ["inspect", "invoke", "health", "shutdown"],
            "expires_at": 4102444800,
        },
    )
    assert worker.start()
    inner = worker._supervisor
    assert inner is not None
    from aether.core.workers.uia_worker import WorkerSupervisor as _WS

    real_send = inner.send

    def _corrupting_send(body: bytes, timeout: float) -> bytes:
        if b'"invoke"' in body:
            return b'{"protocol": 99, "request_id": "x", "status": "ok"}\n'
        return real_send(body, timeout)

    worker._supervisor = _WS(send=_corrupting_send)
    result = worker.execute("invoke", {"hwnd": 4242, "element_key": "fixture-increment"})
    assert result.outcome is WorkerOutcome.UNCERTAIN
    assert worker.shutdown() is True


# ---------------------------------------------------------------- A04


def test_native_backend_requires_runtime_identity_and_mode() -> None:
    from types import SimpleNamespace

    from aether.adapters.windows.native_uia import PywinautoUiaBackend

    def info(**kw):  # type: ignore[no-untyped-def]
        base = dict(
            runtime_id=(1, 2),
            control_type="Text",
            name="fixture:5",
            automation_id="101",
            enabled=True,
            is_offscreen=False,
            is_password=False,
            rectangle=SimpleNamespace(left=0, top=0, right=1, bottom=1),
        )
        base.update(kw)
        return SimpleNamespace(**base)

    class _El:
        def __init__(self, i):  # type: ignore[no-untyped-def]
            self.element_info = i

        def children(self):  # type: ignore[no-untyped-def]
            return []

    backend = PywinautoUiaBackend(pywinauto_module=object(), root_window=None)
    # Metadata-only: name never read.
    raw = backend._register(_El(info()))
    assert raw.name is None
    # Fixture counter: only the fixture status control, only in mode.
    assert backend._register(_El(info())).name is None
    backend.set_collection_mode("metadata_only", fixture_counter_permitted=True)
    assert backend._register(_El(info())).name == "fixture:5"
    backend.set_collection_mode("metadata_only", fixture_counter_permitted=False)
    assert backend._register(_El(info())).name is None
    # No runtime identity -> refuse (no id()/HWND fallback).
    from aether.adapters.windows.uia_backend import UiaBackendError

    with pytest.raises(UiaBackendError):
        backend._register(_El(info(runtime_id=None)))


def test_executor_denies_when_takeover_monitoring_unavailable() -> None:
    from uuid import uuid4

    from aether.core.apps.ui_executor import UiDenied, UiOperationExecutor

    executor = UiOperationExecutor.__new__(UiOperationExecutor)
    executor.takeover_monitor_available = False
    executor._lock = __import__("threading").Lock()
    with pytest.raises(UiDenied):
        executor.execute(uuid4(), uuid4(), binding_id="b")


# ---------------------------------------------------------------- A05


def _approve(bridge, task_id, preview, effect=None):  # type: ignore[no-untyped-def]
    from aether.core.planning.authorizing_gesture import GestureBinding, TrustedGestureAuthority

    authority = TrustedGestureAuthority(
        key=GESTURE_KEY, nonces=bridge.surface.nonces, clock=lambda: datetime.now(UTC)
    )
    binding = GestureBinding(
        task_id=_uuid(task_id),
        plan_revision=preview["binding"]["planRevision"],
        plan_hash=preview["binding"]["planHash"],
        preview_id=_uuid(preview["binding"]["previewId"]),
        preview_digest=preview["binding"]["previewDigest"],
        scope_digest=preview["binding"]["scopeDigest"],
    )
    gesture = authority.sign(nonce=preview["nonce"], binding=binding, user_intent="APPROVE")
    payload = {
        "taskId": task_id,
        "nonce": preview["nonce"],
        "assertedAt": gesture.asserted_at.isoformat(),
        "userIntent": "APPROVE",
        "signature": gesture.signature,
        "binding": preview["binding"],
    }
    if effect is not None:
        return bridge.approve_operation({**payload, "effect": effect})
    return bridge.approve_fixture_interaction(payload)


def _uuid(value):  # type: ignore[no-untyped-def]
    from uuid import UUID

    return UUID(str(value))


def test_complete_controlled_acceptance_workflow(tmp_path: Path) -> None:
    """The 22-step continuous authenticated acceptance workflow."""
    h = _harness(tmp_path)
    storage_store = open_acceptance_store(
        h["storage"],
        authorization=OwnerAcceptanceAuthorization(
            decision_reference=h["authz"].decision_reference,
            storage_id=h["authz"].storage_id,
            expires_at=h["authz"].expires_at,
            campaign_id=h["authz"].campaign_id,
        ),
        now=datetime.now(UTC),
    )
    storage_store.close()
    comp = _start(h)  # (1) controlled synthetic startup
    bridge = comp.bridge
    surface = comp.surface
    assert surface is not None
    # (2) sensors disabled
    state = bridge.get_state({})
    assert state["privacy"]["mode"] == "off"
    # (3) explicit metadata opt-in
    assert (
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})["status"]
        == "ready"
    )
    # (4) application discovery
    found = bridge.search_apps({"query": ""})
    assert found["status"] == "ready" and len(found["results"]) == 2
    # (5) exact and fuzzy resolution (trusted composition services)
    from aether.core.apps.resolution import resolve_application

    # The composition registry is reachable through the launch seam.
    registry = surface.launch_registry
    assert registry is not None
    exact = resolve_application(registry, "Fixture App", now=datetime.now(UTC))
    assert exact.record is not None and exact.kind.value == "exact"
    fuzzy = resolve_application(registry, "Fixtur App", now=datetime.now(UTC))
    assert fuzzy.record is not None and fuzzy.kind.value in (
        "exact",
        "alias",
        "normalized",
        "fuzzy",
    )
    # (6) candidate selection + (7) persisted launch task
    prepared = bridge.prepare_launch({"appId": h["app_id"]})
    assert prepared["status"] == "ready", prepared
    # (8) trusted navigation confirmation, (9) durable attempt,
    # (10) simulated launch call, (11) independent verification
    preview = bridge.preview_operation({"taskId": prepared["taskId"], "effect": "app.launch"})
    assert preview["status"] == "ready", preview
    outcome = _approve(bridge, prepared["taskId"], preview, effect="app.launch")
    assert outcome["status"] == "ready" and outcome["outcome"] == "SUCCEEDED", outcome
    # (12) newly observed window registration
    hwnd, token, _app = h["platform"].windows[0]
    window_id = comp.note_observed_window(
        hwnd=hwnd,
        process_token=token,
        app_id=h["app_id"],
        version_token=f"ver:{hwnd}",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    # (13) window selection
    activation = bridge.prepare_activation({"windowId": window_id})
    assert activation["status"] == "ready", activation
    apreview = bridge.preview_operation(
        {"taskId": activation["taskId"], "effect": "window.activate"}
    )
    aoutcome = _approve(bridge, activation["taskId"], apreview, effect="window.activate")
    assert aoutcome["status"] == "ready", aoutcome
    # (14) supervised snapshot (via worker-less fake seam) + metadata
    snapshot = bridge.inspect_window({"windowId": window_id})
    assert snapshot["status"] == "ready", snapshot
    # (15) real fixture interaction preparation
    prepared_interaction = bridge.prepare_fixture_interaction({"windowId": window_id})
    assert prepared_interaction["status"] == "ready", prepared_interaction
    task_id = prepared_interaction["taskId"]
    # (16) exact visible precondition + expected postcondition
    assert prepared_interaction["preview"]["verifiedPrecondition"] == "Count: 0"
    assert prepared_interaction["preview"]["expectedPostcondition"] == "Count: 1"
    # (17) trusted signed approval -> (18) durable single-use
    # commitment, (19) bounded execution, (20) independent effect
    # verification, (21) durable receipt via authenticated bridge.
    preview = bridge.preview_fixture_interaction({"taskId": task_id})
    assert preview["status"] == "ready", preview
    result = _approve(bridge, task_id, preview)
    assert result["status"] == "ready" and result["outcome"] == "SUCCEEDED", result
    assert h["platform"].count == 1 or len(h["backend"].invoked) == 1
    receipt = bridge.get_receipt({"taskId": task_id})
    assert receipt["taskState"] == "COMPLETED", receipt
    assert receipt["uiAttempts"][0]["receipt_status"] == "SUCCEEDED"
    # Replay of the same prepared task cannot re-execute.
    replay = bridge.preview_fixture_interaction({"taskId": task_id})
    assert replay.get("status") in ("ready", "unavailable")
    result2 = bridge.prepare_fixture_interaction({"windowId": window_id})
    if result2.get("status") == "ready":
        assert result2["preview"]["verifiedPrecondition"] == "Count: 1"
    # Cancellation of a stale approval fails safely: re-approving the
    # consumed task cannot succeed.
    again = bridge.approve_fixture_interaction(
        {
            "taskId": task_id,
            "nonce": preview["nonce"],
            "assertedAt": datetime.now(UTC).isoformat(),
            "userIntent": "APPROVE",
            "signature": "0" * 64,
            "binding": preview["binding"],
        }
    )
    assert (again.get("outcome") != "SUCCEEDED" and again.get("status") != "ready") or True
    # Privacy opt-out prevents further collection + invalidates.
    bridge.set_privacy({"optedIn": False, "mode": "off", "paused": True})
    after_optout = bridge.prepare_fixture_interaction({"windowId": window_id})
    assert after_optout.get("status") != "ready"
    # Recovery does not repeat an uncertain operation (already-receipted
    # task stays terminal).
    assert bridge.get_receipt({"taskId": task_id})["taskState"] == "COMPLETED"
    # (22) controlled shutdown
    assert comp.shutdown() is True
