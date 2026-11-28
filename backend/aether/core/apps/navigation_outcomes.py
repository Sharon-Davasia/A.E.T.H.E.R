"""Closed navigation outcome vocabulary (CP3-B02).

One typed vocabulary shared by the launch adapter contract, the
independent verifier, the durable evidence model and the schema-v3
SQL constraints. Success is never decided by string-prefix matching:
only members of :data:`VERIFIED_OUTCOMES` may support a ``SUCCEEDED``
receipt, and each verified outcome names the exact evidence that was
independently observed.
"""

from __future__ import annotations

from enum import StrEnum


class NavigationOutcome(StrEnum):
    """Distinct, closed postcondition outcomes for a launch attempt."""

    VERIFIED_NEW_INSTANCE = "verified_new_instance"
    VERIFIED_EXISTING_INSTANCE = "verified_existing_instance"
    VERIFIED_BACKGROUND_NO_WINDOW = "verified_background_no_window"
    ACCEPTED_UNVERIFIED = "accepted_unverified"
    TIMEOUT_BEFORE_EFFECT = "timeout_before_effect"
    TIMEOUT_AFTER_EFFECT = "timeout_after_effect"
    UNVERIFIED = "unverified"
    FAILED = "failed"


VERIFIED_OUTCOMES: frozenset[NavigationOutcome] = frozenset(
    {
        NavigationOutcome.VERIFIED_NEW_INSTANCE,
        NavigationOutcome.VERIFIED_EXISTING_INSTANCE,
        NavigationOutcome.VERIFIED_BACKGROUND_NO_WINDOW,
    }
)


class PostconditionKind(StrEnum):
    """The postcondition the authoritative plan declares for a launch."""

    WINDOW_REQUIRED = "window_required"
    BACKGROUND_NO_WINDOW = "background_no_window"


def receipt_status_for(outcome: NavigationOutcome) -> str:
    """Map a verification outcome to its durable receipt status."""
    if outcome in VERIFIED_OUTCOMES:
        return "SUCCEEDED"
    if outcome in (NavigationOutcome.FAILED, NavigationOutcome.TIMEOUT_BEFORE_EFFECT):
        return "FAILED"
    return "UNVERIFIED"
