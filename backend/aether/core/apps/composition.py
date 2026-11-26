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

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from aether.core.apps.acceptance_startup import ControlledAcceptanceAuthorization
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
    from aether.core.apps.dialogs import ModalWindowEvidence
    from aether.core.apps.fixture import FixtureApp
    from aether.core.apps.launch_authority import IntegrityVerifier, LaunchAuthority
    from aether.core.apps.launcher import TrustedLaunchCoordinator
    from aether.core.apps.registry import InMemoryApplicationRegistry
    from aether.core.apps.ui_executor import UiOperationExecutor
    from aether.core.apps.uia_snapshot import UiaSnapshotService
    from aether.core.contracts.app_window import ApplicationRecord
    from aether.core.persistence.sqlite_store import SQLiteTaskStore
    from aether.core.planning.planner import Planner
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
    # Campaign ceiling: modes outside this set can never be selected
    # through any caller (e.g. metadata-only campaigns cannot be
    # escalated to content collection by a bridge request).
    permitted_modes: frozenset[str] | None = None
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
        if self.permitted_modes is not None and mode not in self.permitted_modes:
            raise ValueError("privacy mode exceeds the authorized campaign ceiling")
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
    fixture: FixtureApp | None = None
    world_state: object | None = None  # InMemoryWorldState
    observer_service: object | None = None  # ObserverService
    expiry_timer: object | None = None  # threading.Timer at expiry
    _started: bool = False
    _revoked: bool = False

    # -- lifecycle ------------------------------------------------------

    def start(self) -> Phase3Composition:
        if self._revoked:
            raise CompositionUnavailable("composition has been revoked")
        # Expiration is a lifecycle boundary, not a suggestion.
        if self.enablement.config.enabled and self.privacy is not None:
            pass  # enablement.is_active enforces expiry per operation
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

    def begin_observation(self) -> None:
        """Start observer + activity source (privacy opt-in only).

        A revoked composition (shutdown/expiry) can never restart
        collection through a later privacy update.
        """
        if self._revoked:
            return
        # Correct resume after pause/opt-out: WorldState is resumed
        # first (retained state stays cleared; only fresh observation
        # may repopulate it), then the observer restarts and a
        # bounded reconciliation republishes current windows.
        # Starting the observer without resuming WorldState would
        # silently drop every fresh event (paused store).
        if self.world_state is not None:
            self.world_state.resume()  # type: ignore[attr-defined]
        if self.observer_service is not None:
            self.observer_service.start()  # type: ignore[attr-defined]
            reconcile = getattr(self.observer_service, "reconcile", None)
            if reconcile is not None:
                reconcile()
        if self.activity_source is not None:
            start = getattr(self.activity_source, "start", None)
            if start is not None:
                start()

    def pause_observation(self) -> None:
        if self.observer_service is not None:
            self.observer_service.stop()  # type: ignore[attr-defined]
        if self.activity_source is not None:
            stop = getattr(self.activity_source, "stop", None)
            if stop is not None:
                stop()
        if self.world_state is not None:
            self.world_state.pause()  # type: ignore[attr-defined]
        if self.snapshots is not None:
            self.snapshots.note_privacy_change()

    def shutdown(self) -> bool:
        """Revoke, stop native collection/worker, purge, close storage.

        Returns True only when the worker's exit is confirmed and
        observers are stopped; never claims success over live threads.
        """
        if self.expiry_timer is not None:
            self.expiry_timer.cancel()  # type: ignore[attr-defined]
            self.expiry_timer = None
        self.pause_observation()
        self.revoke("shutdown")
        confirmed = True
        if self.worker is not None:
            confirmed = bool(self.worker.shutdown())
        if self.observer_service is not None and getattr(self.observer_service, "running", False):
            confirmed = False
        if self.store is not None:
            self.store.close()
        return confirmed

    # -- shared controlled construction (native + injected platforms) -----

    @classmethod
    def _build_controlled(
        cls,
        *,
        store: SQLiteTaskStore,
        providers: NativePlatformProviders,
        authorization: ControlledAcceptanceAuthorization,
        gesture_key: bytes,
        clock: Callable[[], datetime] | None,
        mode: Phase3Mode,
    ) -> Phase3Composition:
        """Wire the full controlled composition over shared authorities."""

        from aether.adapters.windows.native_activity import FakeActivitySource  # noqa: F401
        from aether.channel.phase3_bridge import Phase3Bridge, Phase3Surface
        from aether.core.apps.activation import WindowActivationService
        from aether.core.apps.confirmation import TrustedNavigationConfirmer
        from aether.core.apps.launch_authority import LaunchAuthority, app_version_token
        from aether.core.apps.launcher import TrustedLaunchCoordinator
        from aether.core.apps.registry import InMemoryApplicationRegistry
        from aether.core.apps.ui_executor import UiOperationExecutor
        from aether.core.apps.uia_snapshot import UiaSnapshotService
        from aether.core.apps.verification import LaunchVerifier
        from aether.core.planning.authorizing_gesture import (
            GestureNonceRegister,
            TrustedGestureAuthority,
        )
        from aether.core.planning.planner import Planner
        from aether.core.policy.broker import PolicyBroker
        from aether.core.policy.capabilities import CapabilityRegistry
        from aether.core.resources.app_window_authority import AppWindowResourceAuthority
        from aether.core.resources.registry import ResourceRegistry
        from aether.world_state.observer import ObserverService
        from aether.world_state.service import InMemoryWorldState

        now_fn = clock or (lambda: datetime.now(UTC))
        cleanups: list[Callable[[], None]] = []
        try:
            # Observation starts OFF (A01): opted out, mode off, and
            # capped at the authorization's approved privacy mode.
            privacy = ObservationPrivacyAuthority(
                permitted_modes=frozenset({"off", authorization.privacy_mode})
            )
            authority = AppWindowResourceAuthority(session_id=authorization.session_id)
            registry = InMemoryApplicationRegistry()
            records = [r for r in providers.records if r.app_id in authorization.authorized_app_ids]
            if providers.fixture_record.app_id not in {r.app_id for r in records}:
                records.append(providers.fixture_record)
            for record in records:
                registry.register(record)
                evidence = providers.integrity_verifier.verify(record)
                token = app_version_token(evidence) if evidence is not None else None
                if token is not None:
                    authority.register_app(record, version_token=token)
            capabilities = CapabilityRegistry.phase3_with_uia()
            focus = FocusCoordinator()
            worker = providers.worker
            if worker is not None:
                if not worker.start():
                    raise CompositionUnavailable("uia worker failed to start")
                cleanups.append(lambda: _shutdown_result(worker))
            snapshots = UiaSnapshotService(
                inspection_permitted=lambda app_id: (
                    privacy.collection_enabled
                    and enablement.is_active(
                        capability_id="uia.inspect_snapshot", app_id=app_id, now=now_fn()
                    )
                ),
                authority=authority,
                backend_factory=providers.uia_backend_factory,  # type: ignore[arg-type]
                session_id=authorization.session_id,
                clock=now_fn,
                content_inspection_permitted=lambda app_id: (
                    privacy.collection_enabled and app_id == providers.fixture_record.app_id
                ),
                worker=worker,
            )
            if worker is not None:
                worker.on_worker_restart = snapshots.note_privacy_change
            from pathlib import PureWindowsPath as _PWP

            from aether.world_state.observer import GenerationClock

            # One authoritative collection generation shared by the
            # observer (stamps at collection) and WorldState
            # (validates at the retained-state commit boundary), so
            # pause/resume/privacy invalidation advances the same
            # clock on both sides and stale stamps can never
            # repopulate retained state while fresh ones can.
            generation_clock = GenerationClock()
            world_state = InMemoryWorldState(
                generation_clock=generation_clock,
                policy=privacy.policy,
                authority=authority,
                app_id_by_identity={
                    _PWP(r.executable_identity or "").as_posix().casefold(): r.app_id
                    for r in records
                    if r.executable_identity
                },
            )
            observer_service = None
            if providers.event_source is not None:
                observer_service = ObserverService(
                    generation_clock=generation_clock,
                    source=providers.event_source,  # type: ignore[arg-type]
                    on_event=lambda event: world_state.handle_event(event, now=now_fn()),
                    snapshot_handler=lambda events: world_state.apply_snapshot(
                        events, now=now_fn()
                    ),
                )
            broker = PolicyBroker(
                capabilities=capabilities,
                resources=ResourceRegistry(windows_semantics=False),
                app_authority=authority,
                executors=frozenset({"app.launch", "window.activate", "uia.invoke_fixture"}),
            )
            enablement = Phase3Enablement.from_owner_config(
                OwnerEnablementConfig(
                    enabled=True,
                    capability_allowlist=authorization.capability_allowlist,
                    app_allowlist=authorization.authorized_app_ids,
                    session_lifetime=authorization.expires_at - now_fn(),
                    scope_name=authorization.campaign_id,
                ),
                now=now_fn(),
            )
            confirmer = TrustedNavigationConfirmer()
            launch_authority = LaunchAuthority(
                verifier=providers.integrity_verifier,
                clock=now_fn,
            )

            class _AuthorityObservationProvider:
                """Independent launch verification over authoritative
                window/process registrations (observer-published)."""

                def observe(self):  # type: ignore[no-untyped-def]
                    from aether.core.apps.verification import (
                        ObservedProcess,
                        ObservedWindow,
                        PlatformObservation,
                    )

                    windows = []
                    processes = []
                    seen: set[str] = set()
                    for binding in authority.known_windows():
                        windows.append(
                            ObservedWindow(
                                window_token=binding.version_token,
                                process_token=binding.process_token,
                                app_id=binding.app_resource_id or "",
                            )
                        )
                        if binding.process_token not in seen:
                            seen.add(binding.process_token)
                            processes.append(
                                ObservedProcess(
                                    process_token=binding.process_token,
                                    app_id=binding.app_resource_id or "",
                                    integrity_sha256=None,
                                    started_after_attempt=False,
                                )
                            )
                    return PlatformObservation(
                        processes=tuple(processes), windows=tuple(windows), complete=True
                    )

            observation_provider = providers.observation_provider or _AuthorityObservationProvider()
            coordinator = TrustedLaunchCoordinator(
                store=store,
                capabilities=capabilities,
                registry=registry,
                authority=launch_authority,
                confirmer=confirmer,
                broker=broker,
                adapter=providers.launch_adapter,  # type: ignore[arg-type]
                verifier=LaunchVerifier(observation_provider),  # type: ignore[arg-type]
                enablement=enablement,
                session_id=authorization.session_id,
                activation_scope=authorization.campaign_id,
                clock=now_fn,
            )
            activation_service = WindowActivationService(
                store=store,
                authority=authority,
                confirmer=confirmer,
                broker=broker,
                enablement=enablement,
                focus=focus,
                activate=providers.activate,
                foreground_hwnd=providers.foreground_hwnd,
                session_id=authorization.session_id,
                activation_scope=authorization.campaign_id,
                clock=now_fn,
            )

            def _native_modal_evidence(window_id: str):  # type: ignore[no-untyped-def]
                """Bounded modal evidence, including separate owned
                modal windows.

                Two bounded sources, both through supervised/bounded
                inspection: (a) the target window's supervised
                snapshot tree, and (b) separate top-level windows
                owned by the same process, enumerated through the
                observer's bounded reconciliation and inspected via
                the bounded UIA backend — a separate owned window
                whose root reports modal (or is a secondary Window)
                is modal evidence. Missing, truncated or failed
                evidence is *unknown* (None) and prevents dispatch.
                """
                from aether.core.apps.dialogs import ModalWindowEvidence

                result = snapshots.inspect(window_id, require_content=False)
                if result.snapshot is None or result.snapshot.truncated:
                    return None
                try:
                    binding = authority.resolve_window(window_id)
                except Exception:
                    return None
                evidence = [
                    ModalWindowEvidence(
                        window_resource_id=window_id,
                        owner_process_token=binding.process_token,
                        is_modal=True,
                        title_hint=None,
                        elevated=binding.elevated,
                        accessible=True,
                    )
                    for element in result.snapshot.elements
                    if element.depth >= 1 and element.control_type in ("Window", "Dialog")
                ]
                # Separate owned windows: bounded enumeration via
                # the observer event source's reconciliation.
                source = providers.event_source
                reconcile = getattr(source, "reconcile", None)
                if reconcile is not None:
                    try:
                        events = reconcile()
                    except Exception:
                        return None
                    candidates = [
                        event
                        for event in events
                        if event.hwnd
                        and event.hwnd != binding.hwnd
                        and f"{event.pid}:{event.process_creation_time or 'unknown'}"
                        == binding.process_token
                    ][:8]
                    for event in candidates:
                        try:
                            backend = providers.uia_backend_factory()
                            try:
                                root = backend.find_root(hwnd=event.hwnd)  # type: ignore[attr-defined]
                            finally:
                                backend.close()  # type: ignore[attr-defined]
                        except Exception:
                            return None
                        if root is not None and (
                            getattr(root, "is_modal", False) or root.control_type == "Window"
                        ):
                            evidence.append(
                                ModalWindowEvidence(
                                    window_resource_id=window_id,
                                    owner_process_token=binding.process_token,
                                    is_modal=True,
                                    title_hint=None,
                                    elevated=binding.elevated,
                                    accessible=True,
                                )
                            )
                return tuple(evidence)

            detector = DialogDetector(
                modal_evidence=providers.modal_evidence or _native_modal_evidence
            )

            def _live_fixture_process_verified(window_id: str) -> bool:
                """Fresh, independent live-process integrity check.

                Re-observes the platform now, finds the process
                owning this exact window instance, and compares its
                independently reported integrity digest against
                freshly computed trusted evidence for the registered
                fixture executable. Registration-time path equality
                alone is never sufficient.
                """
                from aether.core.apps.launch_authority import integrity_digest_of

                try:
                    binding = authority.resolve_window(window_id)
                    if binding.app_resource_id != providers.fixture_record.app_id:
                        return False
                    observation = observation_provider.observe()  # type: ignore[attr-defined]
                    process = next(
                        (
                            p
                            for p in observation.processes
                            if p.process_token == binding.process_token
                            and p.app_id == providers.fixture_record.app_id
                        ),
                        None,
                    )
                    if process is None or process.integrity_sha256 is None:
                        return False
                    evidence = providers.integrity_verifier.verify(providers.fixture_record)
                    if evidence is None:
                        return False
                    return bool(process.integrity_sha256 == integrity_digest_of(evidence))
                except Exception:
                    return False

            def _dialog_present(window_id: str) -> str | None:
                try:
                    binding = authority.resolve_window(window_id)
                except Exception:
                    return "dialog_state_unknown"
                assessment = detector.assess(window_id, process_token=binding.process_token)
                if assessment.present:
                    return assessment.redacted_reason
                if assessment.unknown:
                    return "dialog_state_unknown"
                return None

            def _route_activity_early(signal: ActivitySignal) -> None:
                if (
                    signal.kind == "manual_activity_in_window"
                    and focus._active_operation_window is None
                ):
                    return
                focus.note_activity(signal)
                for binding in authority.known_windows():
                    if focus.takeover_detected(binding.window_id):
                        snapshots.on_takeover(binding.window_id)

            activity = providers.activity_factory(_route_activity_early)
            executor = UiOperationExecutor(
                store=store,
                snapshots=snapshots,
                backend_factory=providers.uia_backend_factory,  # type: ignore[arg-type]
                focus=focus,
                capabilities=capabilities,
                session_id=authorization.session_id,
                activation_scope=authorization.campaign_id,
                clock=now_fn,
                broker=broker,
                enablement=enablement,
                approved_fixture_app_id=providers.fixture_record.app_id,
                approved_fixture_identity_token=providers.fixture_identity_token,
                dialog_present=_dialog_present,
                worker=worker,
                takeover_monitor_available=lambda: bool(
                    getattr(activity, "healthy", lambda: False)()
                ),
                privacy_check=lambda: privacy.collection_enabled,
                live_process_verifier=lambda window_id: _live_fixture_process_verified(window_id),
            )
            planner = Planner(
                capabilities=capabilities,
                resources=ResourceRegistry(windows_semantics=False),
                app_authority=authority,
                app_registry=registry,
                integrity_verifier=providers.integrity_verifier,
                clock=now_fn,
            )
            recovery = RecoveryService(store=store)
            project_detector = ProjectDetector(
                registry=ResourceRegistry(windows_semantics=False),
                explorer_folder=providers.explorer_folder,  # type: ignore[arg-type]
                clock=now_fn,
            )
            dialog_guard = DialogGuard(
                detector=detector, on_dialog=lambda wid, _a: snapshots.on_dialog(wid)
            )
            nonces = GestureNonceRegister(clock=now_fn)
            gesture_authority = TrustedGestureAuthority(
                key=gesture_key, nonces=nonces, clock=now_fn
            )
            holder: dict[str, Phase3Composition] = {}

            def _route_activity(signal: ActivitySignal) -> None:
                # Only signals relevant to an active operation are
                # forwarded; idle user activity is not retained.
                if (
                    signal.kind == "manual_activity_in_window"
                    and focus._active_operation_window is None
                ):
                    return
                focus.note_activity(signal)
                for binding in authority.known_windows():
                    if focus.takeover_detected(binding.window_id):
                        snapshots.on_takeover(binding.window_id)

            surface = Phase3Surface(
                store=store,
                snapshots=snapshots,
                executor=executor,
                authority=authority,
                app_records=lambda: list(registry.all()),
                detector=project_detector,
                gesture_authority=gesture_authority,
                nonces=nonces,
                recovery=recovery,
            )
            surface.session_id = authorization.session_id
            surface.activation_scope = authorization.campaign_id
            surface.privacy_authority = privacy
            surface.planner = planner
            surface.launch_coordinator = coordinator
            surface.launch_authority = launch_authority
            surface.launch_registry = registry
            surface.activation_service = activation_service
            surface.dialog_guard = dialog_guard
            composition = cls(
                mode=mode,
                surface=surface,
                bridge=Phase3Bridge(surface),
                enablement=enablement,
                privacy=privacy,
                focus=focus,
                snapshots=snapshots,
                executor=executor,
                activation_service=activation_service,
                launch_coordinator=coordinator,
                detector=project_detector,
                recovery=recovery,
                dialog_guard=dialog_guard,
                activity_source=activity,  # type: ignore[arg-type]
                worker=worker,
                store=store,
                authority=authority,
            )
            composition.world_state = world_state
            composition.observer_service = observer_service
            holder["composition"] = composition

            def _on_privacy_change() -> None:
                snapshots.note_privacy_change()
                world_state.set_policy(privacy.policy)
                if privacy.collection_enabled:
                    composition.begin_observation()
                else:
                    composition.pause_observation()

            privacy.add_listener(_on_privacy_change)
            # Reconcile before accepting any new execution (also done
            # by the storage factory; idempotent and truthful).
            recovery.reconcile_after_restart()
            # Expiry is enforced as a lifecycle boundary: when the
            # authorization expires, collection stops and execution
            # authority is revoked even if nobody interacts again.
            import threading as _threading

            delay = max(0.0, (authorization.expires_at - now_fn()).total_seconds())

            def _expire() -> None:
                composition.pause_observation()
                composition.revoke("authorization_expired")

            timer = _threading.Timer(delay, _expire)
            timer.daemon = True
            timer.start()
            composition.expiry_timer = timer
            return composition.start()
        except Exception:
            for cleanup in reversed(cleanups):
                with contextlib.suppress(Exception):
                    cleanup()
            raise

    # -- factories --------------------------------------------------------

    @classmethod
    def disabled(cls) -> Phase3Composition:
        from aether.channel.phase3_bridge import Phase3Bridge, Phase3Surface

        privacy = ObservationPrivacyAuthority()
        surface = Phase3Surface.disabled()
        surface.privacy_authority = privacy
        return cls(
            mode=Phase3Mode.DISABLED,
            surface=surface,
            bridge=Phase3Bridge(surface),
            enablement=Phase3Enablement.disabled(),
            privacy=privacy,
        )

    @classmethod
    def native_prepared(cls, **_kwargs: object) -> Phase3Composition:
        """Back-compatible alias: use ``native(...)`` with authorization."""
        raise CompositionUnavailable(
            "native composition requires a validated controlled acceptance authorization"
        )

    @classmethod
    def native(
        cls,
        *,
        authorization: ControlledAcceptanceAuthorization,
        current_commit: str,
        storage_dir: object,
        gesture_key: bytes,
        platform: NativePlatformProviders | None = None,
        clock: Callable[[], datetime] | None = None,
        now: datetime | None = None,
    ) -> Phase3Composition:
        """A01: operational controlled native acceptance composition.

        Validates the owner authorization against the candidate
        commit, the acceptance-storage marker and this build's hard
        ceilings *before* opening storage or constructing any native
        component; opens isolated v3 acceptance storage (never any
        real-user store); then wires the real native (or injected
        fake-platform) providers into the same shared authorities as
        the simulated composition. Observation starts OFF: no
        observer or activity source runs until privacy opt-in.
        """
        from pathlib import Path as _Path

        from aether.core.persistence.acceptance_storage import (
            OwnerAcceptanceAuthorization,
            open_acceptance_store,
            read_acceptance_marker,
        )

        moment = now or (clock() if clock else datetime.now(UTC))
        # Authorization is validated against reality first; unsafe or
        # unauthorized startup fails before any storage is opened.
        marker = read_acceptance_marker(_Path(str(storage_dir)))
        authorization.validate(current_commit=current_commit, now=moment, storage_marker=marker)
        if authorization.storage_path != str(storage_dir):
            raise CompositionUnavailable("storage_path_mismatch")
        providers = platform or build_native_platform(authorization)
        store = open_acceptance_store(
            _Path(str(storage_dir)),
            authorization=OwnerAcceptanceAuthorization(
                decision_reference=authorization.decision_reference,
                storage_id=authorization.storage_id,
                expires_at=authorization.expires_at,
                campaign_id=authorization.campaign_id,
            ),
            now=moment,
        )
        try:
            return cls._build_controlled(
                store=store,
                providers=providers,
                authorization=authorization,
                gesture_key=gesture_key,
                clock=clock,
                mode=Phase3Mode.NATIVE_PREPARED,
            )
        except Exception:
            store.close()
            raise

    @classmethod
    def simulated(
        cls,
        *,
        store: SQLiteTaskStore,
        fixture: FixtureApp,
        fixture_record: ApplicationRecord,
        fixture_identity_token: str = "fixture-identity-v1",
        clock: Callable[[], datetime] | None = None,
        session_id: str = "session-1",
        activation_scope: str = "test-scope",
        use_worker: bool = False,
        launch_coordinator: TrustedLaunchCoordinator | None = None,
        launch_authority: LaunchAuthority | None = None,
        launch_registry: InMemoryApplicationRegistry | None = None,
        activation_service: WindowActivationService | None = None,
        gesture_key: bytes | None = None,
        planner: Planner | None = None,
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
            authority.register_app(fixture_record, version_token=fixture_identity_token)
            from aether.core.apps.fixture import FIXTURE_HWND
            from aether.world_state.privacy import ContextClassification

            fixture_window_ref = authority.register_window(
                hwnd=FIXTURE_HWND,
                process_token="pid:7:ct",
                instance_generation=1,
                version_token="pid:7:ct#1",
                expires_at=now_fn() + timedelta(hours=1),
                app_resource_id=fixture_record.app_id,
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
                started.append(lambda: _shutdown_result(worker))
            snapshots = UiaSnapshotService(
                authority=authority,
                backend_factory=fixture.backend,
                session_id=session_id,
                clock=now_fn,
                content_inspection_permitted=lambda app_id: (
                    app_id == getattr(fixture_record, "app_id", None)
                ),
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
                    app_allowlist=frozenset({fixture_record.app_id}),
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
                approved_fixture_app_id=fixture_record.app_id,
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
                app_records=lambda: [fixture_record],
                detector=detector,
                gesture_authority=gesture_authority,
                nonces=nonces,
                recovery=recovery,
            )
            surface.privacy_authority = privacy
            surface.planner = planner
            surface.launch_coordinator = launch_coordinator
            surface.launch_authority = launch_authority
            surface.launch_registry = launch_registry
            surface.activation_service = activation_service
            surface.dialog_guard = dialog_guard
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
                fixture=fixture,
            )
            composition.fixture_window_id = fixture_window_ref.resource_id
            composition_holder["composition"] = composition
            return composition.start()
        except Exception:
            # Initialization failure leaves nothing active behind.
            for cleanup in reversed(started):
                with contextlib.suppress(Exception):
                    cleanup()
            raise


def _fixture_hwnd() -> int:
    from aether.core.apps.fixture import FIXTURE_HWND

    return FIXTURE_HWND


def _shutdown_result(worker: SubprocessWorkerSupervisor) -> None:
    worker.shutdown()


@dataclass(slots=True)
class NativePlatformProviders:
    """Injectable platform boundary for the native composition.

    Production builds these from the real Windows providers; Arena
    tests inject Windows-API fakes. Everything above this boundary —
    policy, planning, persistence, authorization — is identical.
    """

    records: list[ApplicationRecord]
    fixture_record: ApplicationRecord
    fixture_identity_token: str
    integrity_verifier: IntegrityVerifier
    launch_adapter: object  # LaunchAdapter
    uia_backend_factory: Callable[[], object]
    activity_factory: Callable[[Callable[[ActivitySignal], None]], object]
    activate: Callable[[int], bool]
    foreground_hwnd: Callable[[], int | None]
    observation_provider: object | None = None  # LaunchVerifier provider
    event_source: object | None = None  # WindowEventSource (observer)
    explorer_folder: Callable[[], object] | None = None
    modal_evidence: Callable[[str], tuple[ModalWindowEvidence, ...] | None] | None = None
    worker: SubprocessWorkerSupervisor | None = None


@dataclass(slots=True)
class NativePlatformSeams:
    """Raw Windows platform boundary for provider construction.

    Seams carry *unconstructed* platform surfaces (Win32 API objects,
    discovery providers, a pywinauto module object). Every provider
    is constructed by ``build_native_platform`` itself, so the test
    path exercises the identical construction logic as production;
    injecting an already-constructed replacement provider is not
    possible through this seam.
    """

    discovery_providers: object
    launch_api: object
    observer_api: object
    integrity_verifier: IntegrityVerifier
    activity_factory: Callable[[Callable[[ActivitySignal], None]], object] | None
    foreground_provider: object  # activate(hwnd)/foreground_hwnd()
    explorer_folder: Callable[[], object] | None = None
    worker_command: list[str] | None = None
    pywinauto_module: object | None = None


def _native_explorer_folder() -> object:  # pragma: no cover - Windows COM
    """Current Explorer folder via Shell.Application; None if unknown."""
    try:
        import win32com.client  # type: ignore[import-untyped]

        shell = win32com.client.Dispatch("Shell.Application")
        import ctypes

        foreground = ctypes.windll.user32.GetForegroundWindow()  # type: ignore[attr-defined]
        for window in shell.Windows():
            try:
                if int(window.HWND) == int(foreground):
                    return window.Document.Folder.Self.Path
            except Exception:
                continue
    except Exception:
        return None
    return None


def build_native_platform(
    authorization: ControlledAcceptanceAuthorization,
    *,
    seams: NativePlatformSeams | None = None,
) -> NativePlatformProviders:
    """One trusted platform-provider construction path.

    With no seams this constructs the real Windows providers and
    raises on any other platform or when a required provider cannot
    be constructed, so controlled startup fails closed instead of
    falling back. Tests pass raw Windows-API fakes as seams and
    exercise this exact construction logic; that is simulated
    evidence, never native evidence.
    """
    import sys
    from datetime import UTC as _UTC
    from datetime import datetime as _dt
    from datetime import timedelta as _td
    from pathlib import Path as _Path

    from aether.adapters.windows.discovery import (
        StdlibWindowsDiscoveryProviders,
        discover_applications,
    )
    from aether.adapters.windows.native_activity import NativeActivitySource
    from aether.adapters.windows.native_launcher import (
        NativeIntegrityProvider,
        NativeWindowsLaunchAdapter,
        _CtypesWin32LaunchApi,
    )
    from aether.adapters.windows.native_observer import (
        NativeForegroundProvider,
        NativeObservationProvider,
        NativeWindowsEventSource,
        _CtypesWin32Api,
        activation_context_from_parent_bootstrap,
    )
    from aether.adapters.windows.native_uia import build_native_uia_backend
    from aether.core.apps.discovery_normalize import normalize_discovery
    from aether.core.apps.fixture_contract import FIXTURE_EXECUTABLE_NAME
    from aether.core.contracts.app_window import (
        ApplicationRecord as _Record,
    )
    from aether.core.contracts.app_window import (
        DiscoverySource,
        LaunchMethod,
        location_identity_digest,
        registration_app_id,
    )
    from aether.core.workers.subprocess_supervisor import (
        SubprocessWorkerSupervisor,
        default_worker_command,
    )

    if seams is None:
        if sys.platform != "win32":  # pragma: no cover - exercised on Windows
            raise CompositionUnavailable("native_platform_requires_windows")
        foreground = NativeForegroundProvider()
        seams = NativePlatformSeams(
            discovery_providers=StdlibWindowsDiscoveryProviders(),
            launch_api=_CtypesWin32LaunchApi(),
            observer_api=_CtypesWin32Api(),
            integrity_verifier=NativeIntegrityProvider(),
            activity_factory=None,
            foreground_provider=foreground,
            explorer_folder=_native_explorer_folder,
        )
    now = _dt.now(_UTC)
    batch = discover_applications(seams.discovery_providers)  # type: ignore[arg-type]
    records = [
        r
        for r in normalize_discovery(batch, now=now)
        if r.app_id in authorization.authorized_app_ids
    ]
    # The fixture is an explicit portable registration (owner-built
    # executable), never auto-discovered as launchable software. Its
    # identity is derived from the executable, exactly as registered;
    # an authorization naming any other fixture identity is refused.
    fixture_exe = str(
        _Path(__file__).resolve().parents[4] / "tools" / "windows-fixture" / FIXTURE_EXECUTABLE_NAME
    )
    expected_fixture_id = registration_app_id(
        display_name="AETHER Fixture",
        executable_identity=fixture_exe,
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
    )
    if authorization.fixture_app_id != expected_fixture_id:
        raise CompositionUnavailable("fixture_identity_mismatch")
    fixture_record = _Record(
        app_id=expected_fixture_id,
        display_name="AETHER Fixture",
        launch_method=LaunchMethod.APPROVED_EXECUTABLE,
        executable_identity=fixture_exe,
        location_digest=location_identity_digest(fixture_exe),
        discovery_source=DiscoverySource.USER_REGISTERED_PORTABLE,
        discovered_at=now,
        fresh_until=now + _td(hours=2),
    )
    records = [r for r in records if r.app_id != fixture_record.app_id] + [fixture_record]
    activation = activation_context_from_parent_bootstrap(
        {
            "issuer": "aether-trusted-composition",
            "session_id": authorization.session_id,
            "activation_epoch": authorization.activation_epoch,
            "activation_scope": authorization.campaign_id,
            "permitted_operations": ["inspect", "invoke", "health", "shutdown"],
            "expires_at": authorization.expires_at.timestamp(),
        }
    )
    if seams.activity_factory is None:
        seams.activity_factory = lambda emit_to: NativeActivitySource(
            activation=activation, emit_to=emit_to
        )
    worker = SubprocessWorkerSupervisor(
        command=seams.worker_command or default_worker_command(),
        bootstrap_payload={
            "issuer": "aether-trusted-composition",
            "session_id": authorization.session_id,
            "activation_epoch": authorization.activation_epoch,
            "activation_scope": authorization.campaign_id,
            "worker_id": f"worker:{authorization.activation_epoch}",
            "permitted_operations": ["inspect", "invoke", "health", "shutdown"],
            "expires_at": authorization.expires_at.timestamp(),
        },
    )
    return NativePlatformProviders(
        records=records,
        fixture_record=fixture_record,
        fixture_identity_token=authorization.fixture_identity_token,
        integrity_verifier=seams.integrity_verifier,
        launch_adapter=NativeWindowsLaunchAdapter(api=seams.launch_api, activation=activation),  # type: ignore[arg-type]
        uia_backend_factory=(
            lambda: (
                build_native_uia_backend(
                    activation=activation, pywinauto_module=seams.pywinauto_module
                )
                if seams.pywinauto_module is not None
                else build_native_uia_backend(activation=activation)
            )
        ),
        activity_factory=seams.activity_factory,
        activate=seams.foreground_provider.activate,  # type: ignore[attr-defined]
        foreground_hwnd=seams.foreground_provider.foreground_hwnd,  # type: ignore[attr-defined]
        event_source=NativeWindowsEventSource(api=seams.observer_api, activation=activation),  # type: ignore[arg-type]
        observation_provider=NativeObservationProvider(
            api=seams.observer_api,  # type: ignore[arg-type]
            records=records,
            integrity_verifier=seams.integrity_verifier,
        ),
        explorer_folder=seams.explorer_folder,
        worker=worker,
    )
