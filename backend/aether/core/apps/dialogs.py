"""Unexpected-dialog detection and guarding (CP6).

Detection uses conservative *independent window/modal evidence* (the
observer's window-level facts about a target process), never the
absence of a dialog inside a possibly truncated UIA snapshot. On a
relevant dialog: automated dispatch stops, stale snapshot references
are invalidated, the worker settles, the last verified task state is
preserved, a redacted reason is surfaced and resumption requires fresh
observation and authorization. Nothing here dismisses a dialog or
selects Save/Discard/Delete/Send/Continue — no such operation exists.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum


class DialogKind(StrEnum):
    MODAL_APPLICATION = "modal_application"
    CREDENTIAL_PROMPT = "credential_prompt"
    UNSAVED_WARNING = "unsaved_warning"
    UNRECOGNIZED_CONFIRMATION = "unrecognized_confirmation"
    ELEVATED_INACCESSIBLE = "elevated_inaccessible"


# Supplemental classification markers only (never a trust decision on
# their own; the window-level modal evidence is primary).
_KIND_MARKERS: tuple[tuple[str, DialogKind], ...] = (
    ("credential", DialogKind.CREDENTIAL_PROMPT),
    ("password", DialogKind.CREDENTIAL_PROMPT),
    ("unsaved", DialogKind.UNSAVED_WARNING),
    ("save changes", DialogKind.UNSAVED_WARNING),
    ("confirm", DialogKind.UNRECOGNIZED_CONFIRMATION),
    ("delete", DialogKind.UNRECOGNIZED_CONFIRMATION),
)


@dataclass(frozen=True, slots=True)
class ModalWindowEvidence:
    """Independent window-level evidence about one possible dialog."""

    window_resource_id: str
    owner_process_token: str
    is_modal: bool
    title_hint: str | None  # classification hint only; never persisted
    elevated: bool | None = None
    accessible: bool = True


@dataclass(frozen=True, slots=True)
class DialogAssessment:
    present: bool
    kind: DialogKind | None = None
    redacted_reason: str | None = None
    unknown: bool = False


@dataclass(slots=True)
class DialogDetector:
    """Classifies independent modal evidence for one target window."""

    modal_evidence: Callable[[str], tuple[ModalWindowEvidence, ...] | None]

    def assess(self, window_resource_id: str, *, process_token: str) -> DialogAssessment:
        evidence = self.modal_evidence(window_resource_id)
        if evidence is None:
            # Provider unavailable: dialog presence is *unknown*. A
            # truncated/failed observation never proves absence.
            return DialogAssessment(present=False, unknown=True)
        for item in evidence:
            if item.owner_process_token != process_token:
                continue
            if not item.accessible or item.elevated is True:
                return DialogAssessment(
                    present=True,
                    kind=DialogKind.ELEVATED_INACCESSIBLE,
                    redacted_reason="dialog_elevated_or_inaccessible",
                )
            if not item.is_modal:
                continue
            kind = DialogKind.MODAL_APPLICATION
            hint = (item.title_hint or "").casefold()
            for marker, candidate in _KIND_MARKERS:
                if marker in hint:
                    kind = candidate
                    break
            else:
                kind = DialogKind.UNRECOGNIZED_CONFIRMATION
            return DialogAssessment(
                present=True, kind=kind, redacted_reason=f"unexpected_dialog:{kind.value}"
            )
        return DialogAssessment(present=False)


@dataclass(frozen=True, slots=True)
class DialogDecision:
    allowed: bool
    redacted_reason: str | None = None
    assessment: DialogAssessment | None = None


@dataclass(slots=True)
class DialogGuard:
    """Stops dispatch on relevant dialogs; never dismisses anything."""

    detector: DialogDetector
    on_dialog: Callable[[str, DialogAssessment], None] | None = None

    def check(
        self, window_resource_id: str, *, process_token: str, effectful: bool
    ) -> DialogDecision:
        assessment = self.detector.assess(window_resource_id, process_token=process_token)
        if assessment.present:
            if self.on_dialog is not None:
                self.on_dialog(window_resource_id, assessment)
            return DialogDecision(False, assessment.redacted_reason, assessment)
        if assessment.unknown and effectful:
            # Unknown dialog state cannot clear an effectful operation.
            return DialogDecision(False, "dialog_state_unknown", assessment)
        return DialogDecision(True, None, assessment)
