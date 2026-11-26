"""G01: controlled Phase 3 composition factory and trusted lifecycle.

One composition owns every Phase 3 component instance so that
observation, policy, planning, execution, worker, takeover/dialog
signals and the channel bridge all share the *same* authorities.
Modes:

* ``disabled`` — ordinary operation. No native providers, no worker,
  truthful ``phase3_native_disabled`` surface.
* ``simulated`` — explicit isolated simulated acceptance for automated
  integration tests. Platform providers are simulated fakes injected
  at the platform boundary only; all policy/planning/persistence
  components are the real ones.
* ``native_prepared`` — a prepared native composition descriptor. It
  cannot start: construction raises until trusted composition is
  given a separately approved owner activation (out of scope for this
  gate). This is deliberate — prepared is not enabled.

Lifecycle: ``start()`` wires activity/dialog routing; ``revoke()``
revokes enablement, purges snapshots and stops worker/activity;
``shutdown()`` additionally closes storage. Any initialization
failure shuts down whatever partially started, leaving no active
sensors, workers or executable capabilities.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from aether.core.apps.dialogs import DialogDetector, DialogGuard
from aether.core.apps.enablement import OwnerEnablementConfig, Phase3Enablement
from aether.core.apps.focus import ActivitySignal, FocusCoordinator
from aether.core.apps.recovery import RecoveryService
from aether.core.context.project_detection import ProjectDetector
from aether.world_state.privacy import ObservationPolicy, PrivacyMode

if TYPE_CHECKING:
    from aether.adapters.windows.native_activity import FakeActivitySource
    from aether.channel.phase3_bridge import Phase3Bridge, Phase3Surface
    from aether.core.apps.activation import WindowActivationService
    from aether.core.apps.fixture import FixtureApp
    from aether.core.apps.launcher import TrustedLaunchCoordinator
    from aether.core.apps.ui_executor import UiOperationExecutor
    from aether.core.apps.uia_snapshot import UiaSnapshotService
    from aether.core.persistence.sqlite_store import SQLiteTaskStore
    from aether.core.resources.app_window_authority import AppWindowResourceAuthority
    from aether.core.workers.subprocess_supervisor import SubprocessWorkerSupervisor


class CompositionUnavailable(RuntimeError):
    pass


class Phase3Mode(StrEnum):
    DISABLED = "disabled"
    SIMULATED = "simulated"
    NATIVE_PREPARED = "native_prepared"


@dataclass(slots=True)
class ObservationPrivacyAuthority:
    """The single authoritative observation/privacy state (G06).

    The bridge never owns privacy truth: updates go through here,
    bump the privacy generation, purge snapshots and notify listeners
    (e.g. approval invalidation) atomically from the caller's view.
    """

    policy: ObservationPolicy = field(default_factory=ObservationPolicy)
    paused: bool = False
    generation: int = 0
    _listeners: list[Callable[[], None]] = field(default_factory=list)

    def add_listener(self, listener: Callable[[], None]) -> None:
        self._listeners.append(listener)

    def snapshot_dict(self) -> dict[str, object]:
        return {
            "optedIn": self.policy.opted_in,
            "mode": self.policy.mode.value,
            "paused": self.paused,
            "generation": self.generation,
        }

    def update(self, *, opted_in: bool, mode: str, paused: bool) -> dict[str, object]:
        try:
            parsed = PrivacyMode(mode)
        except ValueError as exc:
            raise ValueError("privacy mode is not permitted") from exc
        self.policy = ObservationPolicy(mode=parsed, opted_in=opted_in)
        self.paused = paused
        self.generation += 1
        for listener in list(self._listeners):
            listener()
        return self.snapshot_dict()

    @property
    def collection_enabled(self) -> bool:
        return self.policy.collection_enabled and not self.paused


@dataclass(slots=True)
class Phase3Composition:
    mode: Phase3Mode
    surface: Phase3Surface
    bridge: Phase3Bridge
    enablement: Phase3Enablement
    privacy: ObservationPrivacyAuthority
    focus: FocusCoordinator | None = None
    snapshots: UiaSnapshotService | None = None
    executor: UiOperationExecutor | None = None
    activation_service: WindowActivationService | None = None
    launch_coordinator: TrustedLaunchCoordinator | None = None
    detector: ProjectDetector | None = None
    recovery: RecoveryService | None = None
    dialog_guard: DialogGuard | None = None
    activity_source: FakeActivitySource | None = None
    worker: SubprocessWorkerSupervisor | None = None
    store: SQLiteTaskStore | None = None
    authority: AppWindowResourceAuthority | None = None
    fixture_window_id: str | None = None
    _started: bool = False
    _revoked: bool = False

    # -- lifecycle ------------------------------------------------------

    def start(self) -> Phase3Composition:
        if self._revoked:
            raise CompositionUnavailable("composition has been revoked")
        self._started = True
        return self

    @property
    def active(self) -> bool:
        return self._started and not self._revoked and self.executor is not None

    def revoke(self, reason: str = "revoked") -> None:
        """Revoke capabilities and purge volatile observation state."""
        self._revoked = True
        self.enablement.revoke()
        if self.snapshots is not None:
            self.snapshots.note_privacy_change()
        if self.activity_source is not None:
            stop = getattr(self.activity_source, "stop", None)
            if stop is not None:
                stop()
        if self.worker is not None:
            self.worker.shutdown()

    def shutdown(self) -> None:
        self.revoke("shutdown")
        if self.store is not None:
            self.store.close()

    # -- factories --------------------------------------------------------

    @classmethod
    def disabled(cls) -> Phase3Composition:
        from aether.channel.phase3_bridge import Phase3Bridge, Phase3Surface

        privacy = ObservationPrivacyAuthority()
        surface = Phase3Surface.disabled()
        surface.privacy_authority = privacy  # type: ignore[attr-defined]
        return cls(
            mode=Phase3Mode.DISABLED,
            surface=surface,
            bridge=Phase3Bridge(surface),
            enablement=Phase3Enablement.disabled(),
            privacy=privacy,
        )

    @classmethod
    def native_prepared(cls, **_kwargs: object) -> Phase3Composition:
        """Prepared native composition: never startable in this gate."""
        raise CompositionUnavailable(
            "native composition requires a separately approved owner activation"
        )

    @classmethod
    def simulated(
        cls,
        *,
        store: SQLiteTaskStore,
        fixture: FixtureApp,
        fixture_record: object,
        fixture_identity_token: str = "fixture-identity-v1",
        clock: Callable[[], datetime] | None = None,
        session_id: str = "session-1",
        activation_scope: str = "test-scope",
        use_worker: bool = False,
        launch_coordinator: TrustedLaunchCoordinator | None = None,
        launch_authority: object | None = None,
        launch_registry: object | None = None,
        activation_service: WindowActivationService | None = None,
        gesture_key: bytes | None = None,
        planner: object | None = None,
    ) -> Phase3Composition:
        """Explicit isolated simulated acceptance composition.

        All real policy/planning/persistence components; only the
        platform providers (fixture backend, optional simulated worker
        child) are simulated, at the platform boundary.
        """
        from datetime import timedelta

        from aether.adapters.windows.native_activity import FakeActivitySource
        from aether.channel.phase3_bridge import Phase3Bridge, Phase3Surface
        from aether.core.apps.ui_executor import UiOperationExecutor
        from aether.core.apps.uia_snapshot import UiaSnapshotService
        from aether.core.persistence.sqlite_store import SQLiteTaskStore as _Store  # noqa: F401
        from aether.core.planning.authorizing_gesture import (
            GestureNonceRegister,
            TrustedGestureAuthority,
        )
        from aether.core.planning.planner import Planner
        from aether.core.policy.broker import PolicyBroker
        from aether.core.policy.capabilities import CapabilityRegistry
        from aether.core.resources.app_window_authority import AppWindowResourceAuthority
        from aether.core.resources.registry import ResourceRegistry

        now_fn = clock or (lambda: datetime.now(UTC))
        started: list[Callable[[], None]] = []
        try:
            privacy = ObservationPrivacyAuthority(
                policy=ObservationPolicy(mode=PrivacyMode.METADATA_ONLY, opted_in=True)
            )
            authority = AppWindowResourceAuthority(session_id=session_id)
            authority.register_app(fixture_record, version_token=fixture_identity_token)  # type: ignore[arg-type]
            from aether.core.apps.fixture import FIXTURE_HWND
            from aether.world_state.privacy import ContextClassification

            fixture_window_ref = authority.register_window(
                hwnd=FIXTURE_HWND,
                process_token="pid:7:ct",
                instance_generation=1,
                version_token="pid:7:ct#1",
                expires_at=now_fn() + timedelta(hours=1),
                app_resource_id=getattr(fixture_record, "app_id"),
                classification=ContextClassification.PERMITTED_METADATA,
            )
            capabilities = CapabilityRegistry.phase3_with_uia()
            focus = FocusCoordinator()
            worker = None
            if use_worker:
                from aether.core.workers.subprocess_supervisor import (
                    SubprocessWorkerSupervisor,
                    default_worker_command,
                )

                worker = SubprocessWorkerSupervisor(command=default_worker_command(simulated=True))
                if not worker.start():
                    raise CompositionUnavailable("simulated worker failed to start")
                started.append(worker.shutdown)
            snapshots = UiaSnapshotService(
                authority=authority,
                backend_factory=fixture.backend,
                session_id=session_id,
                clock=now_fn,
                content_inspection_permitted=lambda app_id: app_id
                == getattr(fixture_record, "app_id", None),
                worker=worker,
            )
            privacy.add_listener(snapshots.note_privacy_change)
            broker = PolicyBroker(
                capabilities=capabilities,
                resources=ResourceRegistry(windows_semantics=False),
                app_authority=authority,
                executors=frozenset({"uia.invoke_fixture"}),
            )
            enablement = Phase3Enablement.from_owner_config(
                OwnerEnablementConfig(
                    enabled=True,
                    capability_allowlist=frozenset(
                        {"uia.invoke_fixture", "window.activate", "app.launch"}
                    ),
                    app_allowlist=frozenset({getattr(fixture_record, "app_id")}),
                    session_lifetime=timedelta(hours=1),
                    scope_name=activation_scope,
                ),
                now=now_fn(),
            )

            def _dialog_present(window_id: str) -> str | None:
                # Simulated modal evidence from the fixture platform:
                # a relevant modal stops dispatch (never dismissed).
                backend = fixture.backend()
                try:
                    root = backend.find_root(hwnd=_fixture_hwnd())
                    if root is None:
                        return "dialog_state_unknown"
                    stack = [root]
                    while stack:
                        node = stack.pop()
                        if getattr(node, "key", "") == "fixture-modal-dialog":
                            return "unexpected_dialog:modal_application"
                        stack.extend(backend.children(node))
                    return None
                except Exception:
                    return "dialog_state_unknown"

            executor = UiOperationExecutor(
                store=store,
                snapshots=snapshots,
                backend_factory=fixture.backend,
                focus=focus,
                capabilities=capabilities,
                session_id=session_id,
                activation_scope=activation_scope,
                clock=now_fn,
                broker=broker,
                enablement=enablement,
                approved_fixture_app_id=getattr(fixture_record, "app_id"),
                approved_fixture_identity_token=fixture_identity_token,
                dialog_present=_dialog_present,
                worker=worker,
            )
            planner = planner or Planner(
                capabilities=capabilities,
                resources=ResourceRegistry(windows_semantics=False),
                app_authority=authority,
                clock=now_fn,
            )
            recovery = RecoveryService(store=store)
            detector = ProjectDetector(
                registry=ResourceRegistry(windows_semantics=False), clock=now_fn
            )
            dialog_guard = DialogGuard(
                detector=DialogDetector(
                    modal_evidence=lambda _wid: ()  # simulated: no modal unless fixture says so
                ),
                on_dialog=lambda wid, _a: snapshots.on_dialog(wid),
            )
            nonces = GestureNonceRegister(clock=now_fn)
            gesture_authority = (
                TrustedGestureAuthority(key=gesture_key, nonces=nonces, clock=now_fn)
                if gesture_key is not None
                else None
            )

            composition_holder: dict[str, Phase3Composition] = {}

            def _route_activity(signal: ActivitySignal) -> None:
                focus.note_activity(signal)
                comp = composition_holder.get("composition")
                if comp is not None and comp.authority is not None:
                    for binding in comp.authority.known_windows():
                        if focus.takeover_detected(binding.window_id):
                            snapshots.on_takeover(binding.window_id)

            activity = FakeActivitySource(emit_to=_route_activity)

            surface = Phase3Surface(
                store=store,
                snapshots=snapshots,
                executor=executor,
                authority=authority,
                app_records=lambda: [fixture_record],  # type: ignore[list-item]
                detector=detector,
                gesture_authority=gesture_authority,
                nonces=nonces,
                recovery=recovery,
            )
            surface.privacy_authority = privacy  # type: ignore[attr-defined]
            surface.planner = planner  # type: ignore[attr-defined]
            surface.launch_coordinator = launch_coordinator  # type: ignore[attr-defined]
            surface.launch_authority = launch_authority  # type: ignore[attr-defined]
            surface.launch_registry = launch_registry  # type: ignore[attr-defined]
            surface.activation_service = activation_service  # type: ignore[attr-defined]
            surface.dialog_guard = dialog_guard  # type: ignore[attr-defined]
            composition = cls(
                mode=Phase3Mode.SIMULATED,
                surface=surface,
                bridge=Phase3Bridge(surface),
                enablement=enablement,
                privacy=privacy,
                focus=focus,
                snapshots=snapshots,
                executor=executor,
                activation_service=activation_service,
                launch_coordinator=launch_coordinator,
                detector=detector,
                recovery=recovery,
                dialog_guard=dialog_guard,
                activity_source=activity,
                worker=worker,
                store=store,
                authority=authority,
            )
            composition.fixture_window_id = fixture_window_ref.resource_id  # type: ignore[attr-defined]
            composition_holder["composition"] = composition
            return composition.start()
        except Exception:
            # Initialization failure leaves nothing active behind.
            for cleanup in reversed(started):
                try:
                    cleanup()
                except Exception:
                    pass
            raise


def _fixture_hwnd() -> int:
    from aether.core.apps.fixture import FIXTURE_HWND

    return FIXTURE_HWND
