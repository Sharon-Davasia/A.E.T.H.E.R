"""Independent launch verification (CP3-B02).

The launch adapter reports only whether the platform accepted the
launch call. It can never grant itself a verified outcome. This
verifier independently observes process/window state through a
separate observation provider and compares it against the exact
approved application and the postcondition declared by the
authoritative plan:

- a *new* instance requires a process instance that did not exist
  before the attempt, matching the approved identity/integrity, plus
  a window owned by that process when a window is required;
- *existing-instance activation* requires the pre-existing process
  plus independently observed activation evidence after the attempt
  (an existing process alone is never verified activation);
- a *background* outcome requires a newly observed matching process
  and is permitted only when the plan explicitly declares a
  no-window postcondition;
- wrong process/window identity, missing identity evidence, PID
  reuse (creation-time mismatch) and integrity mismatch never verify;
- bounded polling tolerates delayed appearance; timeout after the
  platform accepted the call is ``TIMEOUT_AFTER_EFFECT`` (the effect
  may have occurred), never proof of no effect.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from aether.core.apps.navigation_outcomes import NavigationOutcome, PostconditionKind


@dataclass(frozen=True, slots=True)
class ObservedProcess:
    """One independently observed process instance."""

    process_token: str  # pid + creation-time identity; PID alone is not identity
    app_id: str
    integrity_sha256: str | None
    started_after_attempt: bool


@dataclass(frozen=True, slots=True)
class ObservedWindow:
    """One independently observed top-level window."""

    window_token: str
    process_token: str
    app_id: str
    activated_after_attempt: bool = False


@dataclass(frozen=True, slots=True)
class PlatformObservation:
    processes: tuple[ObservedProcess, ...]
    windows: tuple[ObservedWindow, ...]
    # An incomplete baseline cannot establish that a process is new:
    # absence from a partial enumeration proves nothing (CP3-R04).
    complete: bool = True
    generation: int = 0


class ObservationProvider(Protocol):
    """Independent observation source, separate from the adapter."""

    def observe(self) -> PlatformObservation: ...


@dataclass(frozen=True, slots=True)
class VerificationExpectation:
    app_id: str
    integrity_sha256: str
    postcondition: PostconditionKind
    pre_existing_process_tokens: frozenset[str]
    # Attempt correlation (CP3-R04): when the launch call returned a
    # process identity, only that exact instance can verify a new
    # launch; an unrelated process the user started must not satisfy
    # the task. Without a returned identity, a *complete* pre-attempt
    # baseline is required before any process counts as new.
    attempt_id: str = ""
    returned_process_token: str | None = None
    baseline_complete: bool = True


@dataclass(frozen=True, slots=True)
class VerificationResult:
    outcome: NavigationOutcome
    process_token: str | None = None
    window_token: str | None = None


class LaunchVerifier:
    """Bounded, independent postcondition verifier."""

    def __init__(
        self,
        provider: ObservationProvider,
        *,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if timeout_seconds <= 0 or poll_interval_seconds <= 0:
            raise ValueError("verification bounds must be positive")
        self._provider = provider
        self._timeout = timeout_seconds
        self._interval = poll_interval_seconds
        self._sleep = sleep

    def observe_snapshot(self) -> PlatformObservation:
        """One independent observation (pre-launch baseline, verifier input)."""
        return self._provider.observe()

    def verify(
        self, expectation: VerificationExpectation, *, call_accepted: bool
    ) -> VerificationResult:
        """Poll observations until a decisive outcome or the deadline."""
        deadline = time.monotonic() + self._timeout
        while True:
            result = self._decide(expectation, self._provider.observe())
            if result is not None:
                return result
            if time.monotonic() >= deadline:
                break
            self._sleep(self._interval)
        # Deadline reached without decisive evidence.
        if call_accepted:
            return VerificationResult(NavigationOutcome.TIMEOUT_AFTER_EFFECT)
        return VerificationResult(NavigationOutcome.UNVERIFIED)

    def _decide(
        self, expectation: VerificationExpectation, observation: PlatformObservation
    ) -> VerificationResult | None:
        matching = [
            process
            for process in observation.processes
            if process.app_id == expectation.app_id
            and process.integrity_sha256 is not None
            and process.integrity_sha256 == expectation.integrity_sha256
        ]
        if expectation.returned_process_token is not None:
            new_instances = [
                p
                for p in matching
                if p.process_token == expectation.returned_process_token
                and p.process_token not in expectation.pre_existing_process_tokens
            ]
        elif expectation.baseline_complete:
            new_instances = [
                p
                for p in matching
                if p.process_token not in expectation.pre_existing_process_tokens
                and p.started_after_attempt
            ]
        else:
            new_instances = []
        for process in new_instances:
            if expectation.postcondition is PostconditionKind.BACKGROUND_NO_WINDOW:
                return VerificationResult(
                    NavigationOutcome.VERIFIED_BACKGROUND_NO_WINDOW,
                    process_token=process.process_token,
                )
            window = self._window_for(observation, process)
            if window is not None:
                return VerificationResult(
                    NavigationOutcome.VERIFIED_NEW_INSTANCE,
                    process_token=process.process_token,
                    window_token=window.window_token,
                )
        # Existing-instance activation requires *activation* evidence:
        # a window of the pre-existing process activated after the attempt.
        for process in matching:
            if process.process_token not in expectation.pre_existing_process_tokens:
                continue
            for window in observation.windows:
                if (
                    window.process_token == process.process_token
                    and window.app_id == expectation.app_id
                    and window.activated_after_attempt
                ):
                    return VerificationResult(
                        NavigationOutcome.VERIFIED_EXISTING_INSTANCE,
                        process_token=process.process_token,
                        window_token=window.window_token,
                    )
        return None

    @staticmethod
    def _window_for(
        observation: PlatformObservation, process: ObservedProcess
    ) -> ObservedWindow | None:
        for window in observation.windows:
            if window.process_token == process.process_token and window.app_id == process.app_id:
                return window
        return None
