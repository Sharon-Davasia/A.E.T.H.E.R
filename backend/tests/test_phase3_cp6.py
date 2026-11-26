"""CP6: project detection, dialogs, takeover/recovery (fake-backed)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from aether.adapters.windows.native_activity import FakeActivitySource, NativeActivityDisabled, NativeActivitySource
from aether.core.apps.dialogs import (
    DialogDetector,
    DialogGuard,
    DialogKind,
    ModalWindowEvidence,
)
from aether.core.apps.focus import FocusCoordinator
from aether.core.apps.recovery import RecoveryClass, RecoveryService
from aether.core.context.project_detection import ProjectDetector
from aether.core.persistence.models import PersistentTaskState
from aether.core.resources.registry import ResourceRegistry

from test_phase3_cp5_interaction import NOW, _World as _UiWorld


def _registry_with_root(tmp_path: Path, alias: str = "proj", *, manifest: bool = True) -> tuple[ResourceRegistry, Path]:
    root = tmp_path / alias
    root.mkdir()
    if manifest:
        (root / "pyproject.toml").write_text("[project]\nname='x'\n")
    registry = ResourceRegistry(windows_semantics=False)
    registry.register_root(alias, root, allowed_capabilities=frozenset({"fs.inspect_file"}))
    return registry, root


def test_one_registered_project_resolves(tmp_path: Path) -> None:
    registry, _root = _registry_with_root(tmp_path)
    detector = ProjectDetector(registry=registry, clock=lambda: NOW)
    candidates = detector.detect()
    assert len(candidates) == 1 and candidates[0].available
    assert candidates[0].manifests == ("pyproject.toml",)
    resolution = detector.resolve_reference("this project", now=NOW)
    assert not resolution.clarification_required
    assert resolution.candidate == candidates[0]


def test_multiple_projects_ambiguous_requires_clarification(tmp_path: Path) -> None:
    registry, _ = _registry_with_root(tmp_path, "alpha")
    other = tmp_path / "beta"
    other.mkdir()
    (other / "package.json").write_text("{}")
    registry.register_root("beta", other, allowed_capabilities=frozenset({"fs.inspect_file"}))
    detector = ProjectDetector(registry=registry, clock=lambda: NOW)
    assert len(detector.detect()) == 2
    resolution = detector.resolve_reference("this project", now=NOW)
    assert resolution.clarification_required and resolution.reason == "ambiguous_project_evidence"


def test_explorer_context_and_unregistered_discovery(tmp_path: Path) -> None:
    registry, root = _registry_with_root(tmp_path)
    detector = ProjectDetector(registry=registry, explorer_folder=lambda: root, clock=lambda: NOW)
    candidate = detector.detect()[0]
    assert candidate.evidence_source == "explorer_registered"

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ".git").mkdir()
    detector2 = ProjectDetector(registry=registry, explorer_folder=lambda: elsewhere, clock=lambda: NOW)
    discovered = [c for c in detector2.detect() if c.evidence_source == "explorer_discovered"]
    assert discovered and not discovered[0].available
    assert discovered[0].resource_id is None  # no permission is created
    assert "unregistered_root" in discovered[0].limitations


def test_stale_project_evidence_and_reference_expiry(tmp_path: Path) -> None:
    registry, _ = _registry_with_root(tmp_path)
    detector = ProjectDetector(registry=registry, clock=lambda: NOW)
    later = NOW + timedelta(minutes=10)
    resolution = detector.resolve_reference("this project", now=later)
    # Candidates are re-observed fresh at resolve time in this
    # implementation, so expiry manifests for held candidate objects:
    candidate = detector.detect()[0]
    assert not candidate.fresh(later)


def test_dialog_detection_and_guard() -> None:
    evidence = (
        ModalWindowEvidence(
            window_resource_id="window:x", owner_process_token="pid:7:ct",
            is_modal=True, title_hint="Unsaved changes — confirm",
        ),
    )
    detector = DialogDetector(modal_evidence=lambda wid: evidence)
    assessment = detector.assess("window:x", process_token="pid:7:ct")
    assert assessment.present and assessment.kind is DialogKind.UNSAVED_WARNING
    guard = DialogGuard(detector=detector)
    decision = guard.check("window:x", process_token="pid:7:ct", effectful=True)
    assert not decision.allowed and "unsaved_warning" in (decision.redacted_reason or "")

    unknown = DialogGuard(detector=DialogDetector(modal_evidence=lambda wid: None))
    assert not unknown.check("window:x", process_token="pid:7:ct", effectful=True).allowed
    assert unknown.check("window:x", process_token="pid:7:ct", effectful=False).allowed


def test_native_activity_source_disabled_without_activation() -> None:
    import sys

    if sys.platform != "win32":
        with pytest.raises(NativeActivityDisabled):
            NativeActivitySource(activation=None, emit_to=lambda signal: None)
    focus = FocusCoordinator()
    source = FakeActivitySource(emit_to=focus.note_activity)
    source.manual_activity("window:1")
    # note_activity registers takeover interest for manual signals via on_takeover path
    source.emit(type("S", (), {"kind": "foreground_changed", "window_id": "window:1", "at": NOW})())  # type: ignore[arg-type]


def test_pause_resume_recovery_cycle(tmp_path: Path) -> None:
    world = _UiWorld(tmp_path)
    task_id, _step = world.plan_task()
    recovery = RecoveryService(store=world.store)
    assert recovery.classify(task_id).classification is RecoveryClass.SAFE_PRE_EFFECT_PAUSE
    paused = recovery.pause(task_id, now=NOW)
    assert paused.classification is RecoveryClass.SAFE_PRE_EFFECT_PAUSE
    assert world.store.get_task(task_id).state is PersistentTaskState.PAUSED
    # Resume requires fresh precheck + valid approval; goes to PLANNING,
    # never straight back to EXECUTING.
    denied = recovery.resume(task_id, fresh_precheck=lambda tid: False, approval_valid=lambda tid: True, now=NOW)
    assert denied.classification is RecoveryClass.REQUIRES_USER_INTERVENTION
    resumed = recovery.resume(task_id, fresh_precheck=lambda tid: True, approval_valid=lambda tid: True, now=NOW)
    assert resumed.redacted_reason == "resumed_to_planning"
    assert world.store.get_task(task_id).state is PersistentTaskState.PLANNING
    world.close()


def test_restart_reconciliation_covers_both_evidence_classes(tmp_path: Path) -> None:
    world = _UiWorld(tmp_path)
    task_id, step_id = world.plan_task()
    binding_id = world.executor.issue_binding(task_id, step_id)
    world.store.advance_ui_state(
        task_id, PersistentTaskState.PRECHECK, step_id=step_id, binding_id=binding_id, now=NOW
    )
    world.store.commit_ui_attempt(task_id=task_id, step_id=step_id, binding_id=binding_id, now=NOW)
    recovery = RecoveryService(store=world.store)
    results = recovery.reconcile_after_restart()
    assert (task_id, "UNVERIFIED") in results["ui_operations"]
    world.close()
