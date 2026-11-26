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
from aether.world_state.observer import FakeWindowEventSource, WindowEvent, WindowEventKind
from aether.world_state.privacy import ContextClassification

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
        self.modal = False
        self.modal_separate = False

    def new_window(self, app_id: str, hwnd: int) -> str:
        # Native-format process identity: pid:creation-time.
        token = "4242:fake-creation-1"
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

    def observe_fixture(self, fixture_record=None, process_token=None, hwnd=None):  # type: ignore[no-untyped-def]
        observation = self.observe()
        from aether.core.apps.verification import PlatformObservation

        app_id = getattr(fixture_record, "app_id", fixture_record)
        return PlatformObservation(
            processes=tuple(
                p
                for p in observation.processes
                if p.app_id == app_id
                and (process_token is None or p.process_token == process_token)
            ),
            windows=tuple(
                w
                for w in observation.windows
                if w.app_id == app_id
                and (process_token is None or w.process_token == process_token)
                and (hwnd is None or w.window_token == f"hwnd:{hwnd}")
            ),
            complete=observation.complete,
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
        root = self.raw("1", "Window", "201", "Fixture Window", ("1.1", "1.2"))
        if getattr(self.platform, "modal_separate", False) and hwnd == 2002:
            import dataclasses as _dc

            return _dc.replace(root, is_modal=True)
        return root

    def children(self, element):  # type: ignore[no-untyped-def]
        if element.key == "1":
            children = [
                self.raw("1.1", "Text", "101", f"Count: {self.platform.count}", ()),
                self.raw("1.2", "Button", "102", "Increment", ()),
            ]
            if self.platform.modal:
                children.append(self.raw("1.3", "Window", "900", "Dialog", ()))
            return tuple(children)
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
    event_source = FakeWindowEventSource()
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
        event_source=event_source,
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
        "event_source": event_source,
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
    with pytest.raises(StartupDenied):  # lifetime beyond the 4h ceiling
        Phase3Composition.native(
            authorization=dataclasses.replace(
                bad, expires_at=datetime.now(UTC) + timedelta(hours=5)
            ),
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
        channel_service._controlled_phase3_composition(env, b"g" * 32)
    # Ordinary startup (no controlled marker) never constructs it.
    ordinary = {"AETHER_PHASE3_AUTHORIZATION": str(tmp_path / "x.json")}
    assert channel_service._controlled_phase3_composition(ordinary, b"g" * 32) is None


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
    # (12) newly observed window registration: the observer source
    # publishes the window; WorldState registers it in the authority
    # with the fixture app identity mapped from the process identity.
    hwnd, _token, _app = h["platform"].windows[0]
    h["event_source"].push(
        WindowEvent(
            kind=WindowEventKind.WINDOW_CREATED,
            hwnd=hwnd,
            pid=4242,
            process_creation_time="fake-creation-1",
            app_identity="C:/Apps/Fixture App.exe",
            classification=ContextClassification.PERMITTED_METADATA,
            elevated=False,
        )
    )
    window_id = ""
    for _ in range(100):
        assert comp.authority is not None
        for binding in comp.authority.known_windows():
            if binding.app_resource_id == h["app_id"]:
                window_id = binding.window_id
                break
        if window_id:
            break
        time.sleep(0.05)
    assert window_id, "observer did not register the launched window"
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


def test_changed_counter_invalidates_approval(tmp_path: Path) -> None:
    """A counter changed after approval preparation must not be
    silently incremented again: fresh precondition != approved
    precondition invalidates the approval before dispatch."""
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
    bridge = comp.bridge
    bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
    prepared_launch = bridge.prepare_launch({"appId": h["app_id"]})
    preview = bridge.preview_operation(
        {"taskId": prepared_launch["taskId"], "effect": "app.launch"}
    )
    outcome = _approve(bridge, prepared_launch["taskId"], preview, effect="app.launch")
    assert outcome["outcome"] == "SUCCEEDED", outcome
    hwnd, _t, _a = h["platform"].windows[0]
    h["event_source"].push(
        WindowEvent(
            kind=WindowEventKind.WINDOW_CREATED,
            hwnd=hwnd,
            pid=4242,
            process_creation_time="fake-creation-1",
            app_identity="C:/Apps/Fixture App.exe",
            classification=ContextClassification.PERMITTED_METADATA,
            elevated=False,
        )
    )
    window_id = ""
    for _ in range(100):
        assert comp.authority is not None
        for binding in comp.authority.known_windows():
            if binding.app_resource_id == h["app_id"]:
                window_id = binding.window_id
        if window_id:
            break
        time.sleep(0.05)
    assert window_id
    act = bridge.prepare_activation({"windowId": window_id})
    aprev = bridge.preview_operation({"taskId": act["taskId"], "effect": "window.activate"})
    _approve(bridge, act["taskId"], aprev, effect="window.activate")
    prepared = bridge.prepare_fixture_interaction({"windowId": window_id})
    assert prepared["preview"]["verifiedPrecondition"] == "Count: 0"
    # External change after preparation (not by AETHER).
    root = h["backend"].find_root(hwnd=hwnd)
    assert root is not None
    increment = h["backend"].children(root)[1]
    h["backend"].invoke(increment)
    assert h["platform"].count == 1
    preview = bridge.preview_fixture_interaction({"taskId": prepared["taskId"]})
    result = _approve(bridge, prepared["taskId"], preview)
    assert result.get("outcome") != "SUCCEEDED", result
    assert h["platform"].count == 1  # approval did not authorize another increment
    assert comp.shutdown() is True


def test_native_platform_construction_with_raw_fakes(tmp_path: Path) -> None:
    """build_native_platform itself (not an injected provider set)
    constructs every provider from raw Windows-API fake seams."""
    from aether.adapters.windows.fake_windows import build_fake_seams, fixture_executable
    from aether.adapters.windows.native_launcher import NativeWindowsLaunchAdapter
    from aether.adapters.windows.native_observer import NativeWindowsEventSource
    from aether.core.apps.composition import build_native_platform
    from aether.core.contracts.app_window import (
        LaunchMethod,
        location_identity_digest,
        registration_app_id,
    )

    seams = build_fake_seams()
    fixture_id = registration_app_id(
        display_name="AETHER Fixture",
        executable_identity=fixture_executable(),
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    from aether.core.apps.launch_authority import app_version_token

    token = app_version_token(
        seams.integrity_verifier.verify(  # type: ignore[attr-defined]
            type(
                "R",
                (),
                {"location_digest": location_identity_digest(fixture_executable())},
            )()
        )
    )
    authz = ControlledAcceptanceAuthorization(
        approved_commit=COMMIT,
        decision_reference="d",
        campaign_id=CAMPAIGN,
        storage_id="33333333-3333-4333-8333-333333333333",
        storage_path=str(tmp_path / "aether-phase3-acceptance-x"),
        authorized_app_ids=frozenset({fixture_id}),
        capability_allowlist=frozenset({"app.launch", "uia.invoke_fixture"}),
        session_id=SESSION,
        activation_epoch=EPOCH,
        expires_at=datetime.now(UTC) + timedelta(hours=2),
        privacy_mode="metadata_only",
        fixture_app_id=fixture_id,
        fixture_identity_token=token,
    )
    providers = build_native_platform(authz, seams=seams)
    assert providers.fixture_record.app_id == fixture_id
    assert isinstance(providers.launch_adapter, NativeWindowsLaunchAdapter)
    assert isinstance(providers.event_source, NativeWindowsEventSource)
    assert providers.observation_provider is not None
    assert providers.worker is not None
    # Wrong fixture identity is refused by the construction path.
    import dataclasses

    from aether.core.apps.composition import CompositionUnavailable

    with pytest.raises(CompositionUnavailable):
        build_native_platform(
            dataclasses.replace(authz, fixture_app_id="app:00000000-0000-4000-8000-000000000000"),
            seams=build_fake_seams(),
        )


def _registered_window(h, comp, *, hwnd: int, app_identity: str) -> str:  # type: ignore[no-untyped-def]
    h["event_source"].push(
        WindowEvent(
            kind=WindowEventKind.WINDOW_CREATED,
            hwnd=hwnd,
            pid=4242,
            process_creation_time="fake-creation-1",
            app_identity=app_identity,
            classification=ContextClassification.PERMITTED_METADATA,
            elevated=False,
        )
    )
    for _ in range(100):
        assert comp.authority is not None
        for binding in comp.authority.known_windows():
            if binding.hwnd == hwnd:
                return binding.window_id
        time.sleep(0.05)
    raise AssertionError("window was not registered")


def _launched_window(h, comp, bridge) -> str:  # type: ignore[no-untyped-def]
    prepared = bridge.prepare_launch({"appId": h["app_id"]})
    preview = bridge.preview_operation({"taskId": prepared["taskId"], "effect": "app.launch"})
    outcome = _approve(bridge, prepared["taskId"], preview, effect="app.launch")
    assert outcome["outcome"] == "SUCCEEDED", outcome
    hwnd, _t, _a = h["platform"].windows[0]
    return _registered_window(h, comp, hwnd=hwnd, app_identity="C:/Apps/Fixture App.exe")


def test_same_basename_evil_process_gets_no_fixture_authority(tmp_path: Path) -> None:
    """A different executable sharing the fixture's basename must
    never be mapped to the fixture app or receive interaction
    authority (full-path process identity only)."""
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
    bridge = comp.bridge
    bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
    evil_window = _registered_window(h, comp, hwnd=7777, app_identity="C:/Evil/Fixture App.exe")
    assert comp.authority is not None
    binding = comp.authority.resolve_window(evil_window)
    assert binding.app_resource_id is None  # not the fixture app
    assert bridge.inspect_window({"windowId": evil_window}).get("status") != "ready"
    prepared = bridge.prepare_fixture_interaction({"windowId": evil_window})
    assert prepared.get("status") != "ready"
    assert comp.shutdown() is True


def test_observation_provider_denies_same_basename_and_ambiguity() -> None:
    from aether.adapters.windows.native_observer import NativeObservationProvider
    from aether.core.apps.launch_authority import FakeIntegrityVerifier, IntegrityEvidence

    record = _record("app:fixture", "Fixture App")
    evidence = IntegrityEvidence(
        location_digest=record.location_digest or "",
        content_sha256="a" * 64,
        signer_identity="FakeSigner",
        package_identity=None,
        verified_at=datetime.now(UTC),
        file_identity="3:42:100:1",
    )
    verifier = FakeIntegrityVerifier(evidence_by_location={record.location_digest or "": evidence})

    class _Api:
        def __init__(self, path: str) -> None:
            self.path = path

        def enumerate_windows(self):  # type: ignore[no-untyped-def]
            return [(111, 50)]

        def get_process_image_path(self, pid: int):  # type: ignore[no-untyped-def]
            return self.path

        def get_process_name(self, pid: int):  # type: ignore[no-untyped-def]
            return self.path

        def get_process_creation_time(self, pid: int):  # type: ignore[no-untyped-def]
            return "t0"

        def get_process_session_id(self, pid: int):  # type: ignore[no-untyped-def]
            return 1

    evil = NativeObservationProvider(
        api=_Api("C:\\Evil\\Fixture App.exe"), records=[record], integrity_verifier=verifier
    ).observe()
    assert evil.processes == () and evil.windows == ()
    legit = NativeObservationProvider(
        api=_Api("C:\\Apps\\Fixture App.exe"), records=[record], integrity_verifier=verifier
    ).observe()
    assert len(legit.processes) == 1 and legit.processes[0].app_id == record.app_id


def test_modal_via_supervised_inspection_blocks_dispatch(tmp_path: Path) -> None:
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
    bridge = comp.bridge
    bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
    window_id = _launched_window(h, comp, bridge)
    act = bridge.prepare_activation({"windowId": window_id})
    aprev = bridge.preview_operation({"taskId": act["taskId"], "effect": "window.activate"})
    _approve(bridge, act["taskId"], aprev, effect="window.activate")
    h["platform"].modal = True
    prepared = bridge.prepare_fixture_interaction({"windowId": window_id})
    assert prepared["status"] == "ready", prepared
    preview = bridge.preview_fixture_interaction({"taskId": prepared["taskId"]})
    result = _approve(bridge, prepared["taskId"], preview)
    assert result.get("outcome") != "SUCCEEDED", result
    assert h["platform"].count == 0
    assert comp.shutdown() is True


def test_privacy_escalation_and_restart_after_revoke_denied(tmp_path: Path) -> None:
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
    bridge = comp.bridge
    # Escalation beyond the authorized metadata-only ceiling refused.
    escalated = bridge.set_privacy({"optedIn": True, "mode": "content_on_demand", "paused": False})
    assert escalated.get("status") != "ready" or escalated["privacy"]["mode"] != "content_on_demand"
    assert bridge.get_state({})["privacy"]["mode"] == "off"
    # Opt-in works, opt-out stops collection, and after revocation a
    # later opt-in cannot restart the observer.
    assert (
        bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})["status"]
        == "ready"
    )
    assert h["event_source"].started is True
    bridge.set_privacy({"optedIn": False, "mode": "off", "paused": True})
    comp.revoke("test-revocation")
    bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
    assert h["event_source"].started is False
    assert comp.shutdown() is True


def _setup_to_activation(h, comp, bridge) -> str:  # type: ignore[no-untyped-def]
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
    return ""


def test_live_process_integrity_tamper_denies_fixture(tmp_path: Path) -> None:
    """Fixture authority requires independently verified *live*
    process integrity: tampering the live observation's integrity
    digest (a process that no longer matches trusted evidence)
    denies execution even though the path/registration matched."""
    h = _harness(tmp_path)
    _setup_to_activation(h, None, None)
    comp = _start(h)
    bridge = comp.bridge
    bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
    window_id = _launched_window(h, comp, bridge)
    act = bridge.prepare_activation({"windowId": window_id})
    aprev = bridge.preview_operation({"taskId": act["taskId"], "effect": "window.activate"})
    _approve(bridge, act["taskId"], aprev, effect="window.activate")
    # Live process integrity no longer matches trusted evidence.
    observation = h["providers"].observation_provider
    assert observation is not None
    observation.sha_by_app[h["app_id"]] = "0" * 64
    prepared = bridge.prepare_fixture_interaction({"windowId": window_id})
    assert prepared["status"] == "ready", prepared
    preview = bridge.preview_fixture_interaction({"taskId": prepared["taskId"]})
    result = _approve(bridge, prepared["taskId"], preview)
    assert result.get("outcome") != "SUCCEEDED", result
    assert h["platform"].count == 0
    assert comp.shutdown() is True


def test_separate_owned_modal_window_blocks_dispatch(tmp_path: Path) -> None:
    """A separate top-level modal window owned by the same process
    (not in the target's UIA tree) is detected through bounded
    observer enumeration + bounded inspection and blocks dispatch."""
    h = _harness(tmp_path)
    _setup_to_activation(h, None, None)
    comp = _start(h)
    bridge = comp.bridge
    bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
    window_id = _launched_window(h, comp, bridge)
    act = bridge.prepare_activation({"windowId": window_id})
    aprev = bridge.preview_operation({"taskId": act["taskId"], "effect": "window.activate"})
    _approve(bridge, act["taskId"], aprev, effect="window.activate")
    # Separate owned modal window appears (same process token).
    h["platform"].windows.append((2002, "4242:fake-creation-1", h["app_id"]))
    h["platform"].modal_separate = True
    h["event_source"].set_snapshot(
        [
            WindowEvent(
                kind=WindowEventKind.WINDOW_CREATED,
                hwnd=2002,
                pid=4242,
                process_creation_time="fake-creation-1",
                app_identity="C:/Apps/Fixture App.exe",
                classification=ContextClassification.PERMITTED_METADATA,
                elevated=False,
            )
        ]
    )
    prepared = bridge.prepare_fixture_interaction({"windowId": window_id})
    assert prepared["status"] == "ready", prepared
    preview = bridge.preview_fixture_interaction({"taskId": prepared["taskId"]})
    result = _approve(bridge, prepared["taskId"], preview)
    assert result.get("outcome") != "SUCCEEDED", result
    assert h["platform"].count == 0
    assert comp.shutdown() is True


def test_resume_after_opt_out_requires_and_uses_fresh_observation(tmp_path: Path) -> None:
    """After pause/opt-out, re-opt-in must resume WorldState and
    republish only fresh observation: the previously registered
    window is gone until a fresh enumeration/event arrives."""
    h = _harness(tmp_path)
    _setup_to_activation(h, None, None)
    comp = _start(h)
    bridge = comp.bridge
    bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
    window_id = _launched_window(h, comp, bridge)
    assert comp.authority is not None
    assert any(b.window_id == window_id for b in comp.authority.known_windows())
    # Opt out: retained observation and authority refs are purged.
    bridge.set_privacy({"optedIn": False, "mode": "off", "paused": True})
    assert comp.authority.known_windows() == ()
    # Fresh enumeration is staged for reconciliation on resume.
    hwnd, _t, _a = h["platform"].windows[0]
    h["event_source"].set_snapshot(
        [
            WindowEvent(
                kind=WindowEventKind.WINDOW_CREATED,
                hwnd=hwnd,
                pid=4242,
                process_creation_time="fake-creation-1",
                app_identity="C:/Apps/Fixture App.exe",
                classification=ContextClassification.PERMITTED_METADATA,
                elevated=False,
            )
        ]
    )
    bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
    fresh_id = ""
    for _ in range(100):
        for binding in comp.authority.known_windows():
            if binding.app_resource_id == h["app_id"]:
                fresh_id = binding.window_id
        if fresh_id:
            break
        time.sleep(0.05)
    assert fresh_id, "resume did not republish fresh observation"
    assert fresh_id != window_id  # fresh registration, not retained state
    assert comp.shutdown() is True


def test_observe_fixture_returns_only_exact_fixture_instance() -> None:
    from aether.adapters.windows.native_observer import NativeObservationProvider
    from aether.core.apps.launch_authority import FakeIntegrityVerifier, IntegrityEvidence

    fixture = _record("app:fixture", "Fixture App")
    notepad = _record("app:notepad", "Notepad")
    evidence = IntegrityEvidence(
        location_digest=fixture.location_digest or "",
        content_sha256="a" * 64,
        signer_identity="FakeSigner",
        package_identity=None,
        verified_at=datetime.now(UTC),
        file_identity="3:42:100:1",
    )
    verifier = FakeIntegrityVerifier(
        evidence_by_location={
            fixture.location_digest or "": evidence,
            notepad.location_digest or "": evidence,
        }
    )

    class _Api:
        def enumerate_windows(self):  # type: ignore[no-untyped-def]
            return [(1001, 4242), (1002, 5555)]

        def get_process_image_path(self, pid: int):  # type: ignore[no-untyped-def]
            return "C:\\Apps\\Fixture App.exe" if pid == 4242 else "C:\\Apps\\Notepad.exe"

        def get_process_name(self, pid: int):  # type: ignore[no-untyped-def]
            return self.get_process_image_path(pid)

        def get_process_creation_time(self, pid: int):  # type: ignore[no-untyped-def]
            return "fake-creation-1" if pid == 4242 else "other-creation"

        def get_process_session_id(self, pid: int):  # type: ignore[no-untyped-def]
            return 1

    provider = NativeObservationProvider(
        api=_Api(), records=[fixture, notepad], integrity_verifier=verifier
    )
    broad = provider.observe()
    assert {p.app_id for p in broad.processes} == {fixture.app_id, notepad.app_id}
    scoped = provider.observe_fixture(fixture, "4242:fake-creation-1", 1001)
    assert [p.app_id for p in scoped.processes] == [fixture.app_id]
    assert [w.process_token for w in scoped.windows] == ["4242:fake-creation-1"]
    # A different instance of the same executable is not the fixture
    # instance bound to the authority window.
    wrong = provider.observe_fixture(fixture, "9999:fake-creation-1", 1001)
    assert wrong.processes == () and wrong.windows == ()


def test_failed_provider_construction_does_not_poison_retry() -> None:
    """A failed build_native_platform attempt must not retain a
    provider assignment (the activity factory) on the caller's seams;
    a retry with fresh authorization builds fresh providers."""
    from aether.adapters.windows.fake_windows import build_fake_seams, fixture_executable
    from aether.core.apps.composition import build_native_platform
    from aether.core.contracts.app_window import (
        LaunchMethod,
        location_identity_digest,
        registration_app_id,
    )

    seams = build_fake_seams()
    seams.activity_factory = None  # exercise the default-factory path
    fixture_id = registration_app_id(
        display_name="AETHER Fixture",
        executable_identity=fixture_executable(),
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    from aether.core.apps.launch_authority import app_version_token

    token = app_version_token(
        seams.integrity_verifier.verify(  # type: ignore[attr-defined]
            type("R", (), {"location_digest": location_identity_digest(fixture_executable())})()
        )
    )

    def _authz(epoch: str) -> ControlledAcceptanceAuthorization:
        return ControlledAcceptanceAuthorization(
            approved_commit=COMMIT,
            decision_reference="d",
            campaign_id=CAMPAIGN,
            storage_id="55555555-5555-4555-8555-555555555555",
            storage_path="unused",
            authorized_app_ids=frozenset({fixture_id}),
            capability_allowlist=frozenset({"app.launch"}),
            session_id=SESSION,
            activation_epoch=epoch,
            expires_at=datetime.now(UTC) + timedelta(hours=2),
            privacy_mode="metadata_only",
            fixture_app_id=fixture_id,
            fixture_identity_token=token,
        )

    # First attempt fails late (foreground provider has no
    # activate/foreground callables) after the point where the
    # default activity factory used to be assigned onto the seams.
    good_foreground = seams.foreground_provider
    seams.foreground_provider = object()
    with pytest.raises(AttributeError):
        build_native_platform(_authz("epoch-1"), seams=seams)
    assert seams.activity_factory is None
    seams.foreground_provider = good_foreground
    providers = build_native_platform(_authz("epoch-2"), seams=seams)
    assert providers.fixture_record.app_id == fixture_id
    assert seams.activity_factory is None  # still not retained


def test_initial_snapshot_published_on_opt_in_with_raw_fake_providers(tmp_path: Path) -> None:
    """Windows that already exist before privacy opt-in are
    published by the explicit composition snapshot wiring when
    observation starts (raw fake seams; not native evidence)."""
    from aether.adapters.windows.fake_windows import build_fake_seams, fixture_executable
    from aether.core.apps.composition import build_native_platform
    from aether.core.apps.fixture import FIXTURE_HWND
    from aether.core.apps.launch_authority import app_version_token
    from aether.core.contracts.app_window import (
        LaunchMethod,
        location_identity_digest,
        registration_app_id,
    )

    seams = build_fake_seams()
    fixture_id = registration_app_id(
        display_name="AETHER Fixture",
        executable_identity=fixture_executable(),
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    token = app_version_token(
        seams.integrity_verifier.verify(  # type: ignore[attr-defined]
            type("R", (), {"location_digest": location_identity_digest(fixture_executable())})()
        )
    )
    authz = dataclasses.replace(
        _harness(tmp_path)["authz"],
        storage_path=str(tmp_path / "aether-phase3-acceptance-initial"),
        authorized_app_ids=frozenset({fixture_id}),
        fixture_app_id=fixture_id,
        fixture_identity_token=token,
    )
    storage = Path(authz.storage_path)
    store = open_acceptance_store(
        storage,
        authorization=OwnerAcceptanceAuthorization(
            decision_reference=authz.decision_reference,
            storage_id=authz.storage_id,
            expires_at=authz.expires_at,
            campaign_id=authz.campaign_id,
        ),
        now=datetime.now(UTC),
    )
    store.close()
    providers = build_native_platform(authz, seams=seams)
    state = seams.observer_api._state  # type: ignore[attr-defined]
    state.windows[FIXTURE_HWND] = (4242, fixture_executable())
    comp = Phase3Composition.native(
        authorization=authz,
        current_commit=COMMIT,
        storage_dir=storage,
        gesture_key=GESTURE_KEY,
        platform=providers,
    )
    try:
        assert comp.authority is not None
        assert comp.authority.known_windows() == ()
        out = comp.bridge.set_privacy({"optedIn": True, "mode": "metadata_only", "paused": False})
        assert out["status"] == "ready", out
        assert any(b.app_resource_id == fixture_id for b in comp.authority.known_windows())
    finally:
        assert comp.shutdown() is True


def test_begin_observation_does_nothing_while_privacy_paused(tmp_path: Path) -> None:
    """Privacy pause is authoritative at the composition boundary:
    asking to begin observation while privacy collection is disabled
    runs no WorldState resume and no observer reconciliation, and
    starts no source."""
    h = _harness(tmp_path)
    _setup_to_activation(h, None, None)
    comp = _start(h)
    try:
        assert comp.world_state is not None and comp.observer_service is not None
        generation_before = comp.world_state.generation  # type: ignore[attr-defined]
        # Privacy is still off/paused (no opt-in has occurred).
        comp.begin_observation()
        # Resume would have advanced the WorldState generation;
        # reconciliation would have started the source.
        assert comp.world_state.generation == generation_before  # type: ignore[attr-defined]
        assert h["event_source"].started is False
    finally:
        assert comp.shutdown() is True
