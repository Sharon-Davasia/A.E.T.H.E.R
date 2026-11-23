"""The authenticated authorizing gesture (Phase 2B trusted approval).

This is the one place where an *explicit user action* becomes trustworthy. The
Master Specification requires that approval come from an authenticated
Electron-main/backend boundary, not from a renderer string, not from audit-only
review evidence, and not from a model proposal.

How the gesture is authenticated, and what each layer actually proves:

1. **Electron main issues the challenge.** Before the UI shows an approval
   button, main generates a nonce and the exact binding it belongs to (task,
   plan revision, plan hash, preview digest, scope digest) and registers it in
   :class:`GestureNonceRegister` with a short expiry.
2. **The renderer only echoes a nonce.** The preload API exposes a single call
   that carries the nonce of the dialog the user actually clicked. The renderer
   cannot mint a nonce, choose the binding, or reach the backend directly.
3. **Main signs the gesture.** Main holds the HMAC key; the renderer never does.
   The signed payload includes the nonce, the binding and the assertion that a
   human clicked *this specific* control.
4. **The backend verifies.** The backend recomputes the signature with its copy
   of the key, requires the nonce to be registered, unexpired and unused, and
   requires the binding to match the persisted preview and the exact scope.

What this does **not** claim: it is not a defence against a compromised Electron
main process or a local attacker with the key — that is stated in
``docs/security/TRUST_BOUNDARIES.md`` rather than papered over. What it does
provide is that no *renderer* input, model output or audit record can forge an
approval, and every approval is single-use and bound to one exact action.

The register is process-local and single-use by design: a replayed nonce fails,
and a backend restart invalidates outstanding gestures rather than accepting
stale authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

MAX_GESTURE_LIFETIME = timedelta(minutes=5)
_MIN_KEY_BYTES = 32


class GestureRejected(Exception):
    """The authorizing gesture is not trustworthy; nothing may be issued."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True, slots=True)
class GestureBinding:
    """Exactly what the user was looking at when they clicked."""

    task_id: UUID
    plan_revision: int
    plan_hash: str
    preview_id: UUID
    preview_digest: str
    scope_digest: str

    def canonical(self) -> str:
        return json.dumps(
            {
                "task_id": str(self.task_id),
                "plan_revision": self.plan_revision,
                "plan_hash": self.plan_hash.casefold(),
                "preview_id": str(self.preview_id),
                "preview_digest": self.preview_digest,
                "scope_digest": self.scope_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True, slots=True)
class SignedGesture:
    """What Electron main sends after a real click."""

    nonce: str
    binding: GestureBinding
    asserted_at: datetime
    user_intent: str
    signature: str

    def canonical_payload(self) -> str:
        return json.dumps(
            {
                "nonce": self.nonce,
                "binding": json.loads(self.binding.canonical()),
                "asserted_at": self.asserted_at.isoformat(),
                "user_intent": self.user_intent,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


class GestureNonceRegister:
    """Issues and consumes single-use approval nonces.

    Nonces are bound to one exact action. Consuming is atomic, so two
    concurrent approvals of the same dialog cannot both succeed.
    """

    def __init__(
        self,
        *,
        lifetime: timedelta = MAX_GESTURE_LIFETIME,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if lifetime <= timedelta(0) or lifetime > MAX_GESTURE_LIFETIME:
            raise ValueError("gesture lifetime outside the permitted range")
        self._lifetime = lifetime
        self._clock = clock or (lambda: datetime.now(UTC))
        self._entries: dict[str, tuple[GestureBinding, datetime]] = {}
        self._lock = threading.Lock()

    def issue(self, binding: GestureBinding) -> str:
        nonce = secrets.token_hex(32)
        with self._lock:
            self._purge_expired()
            self._entries[nonce] = (binding, self._clock())
        return nonce

    def consume(self, nonce: str, binding: GestureBinding) -> None:
        """Atomically validate and burn a nonce for exactly this binding."""

        with self._lock:
            self._purge_expired()
            entry = self._entries.get(nonce)
            if entry is None:
                raise GestureRejected(
                    "GESTURE_NONCE_UNKNOWN", "the nonce was never issued, or it was already used"
                )
            registered_binding, issued_at = entry
            if registered_binding != binding:
                raise GestureRejected(
                    "GESTURE_BINDING_MISMATCH",
                    "the nonce was issued for a different action than the one being approved",
                )
            if self._clock() - issued_at > self._lifetime:
                raise GestureRejected("GESTURE_EXPIRED", "the approval prompt expired")
            # Burn before returning so a replay inside the same instant fails.
            del self._entries[nonce]

    def outstanding(self) -> int:
        with self._lock:
            self._purge_expired()
            return len(self._entries)

    def _purge_expired(self) -> None:
        now = self._clock()
        expired = [
            nonce
            for nonce, (_, issued_at) in self._entries.items()
            if now - issued_at > self._lifetime
        ]
        for nonce in expired:
            del self._entries[nonce]


class TrustedGestureAuthority:
    """Verifies signed gestures from Electron main (the trusted UI origin).

    The key is a per-launch secret held by main and the backend. It is never
    exposed to the renderer, never passed through environment variables, and
    never logged.
    """

    authority_id = "electron-main-gesture"

    def __init__(
        self,
        *,
        key: bytes,
        nonces: GestureNonceRegister,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if len(key) < _MIN_KEY_BYTES:
            raise ValueError("gesture key must be at least 32 bytes")
        self._key = key
        self._nonces = nonces
        self._clock = clock or (lambda: datetime.now(UTC))

    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(32)

    def sign(self, *, nonce: str, binding: GestureBinding, user_intent: str) -> SignedGesture:
        """Produce a gesture signature. Called by main, never by the renderer."""

        gesture = SignedGesture(
            nonce=nonce,
            binding=binding,
            asserted_at=self._clock(),
            user_intent=user_intent,
            signature="",
        )
        signature = hmac.new(
            self._key, gesture.canonical_payload().encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return SignedGesture(
            nonce=gesture.nonce,
            binding=gesture.binding,
            asserted_at=gesture.asserted_at,
            user_intent=gesture.user_intent,
            signature=signature,
        )

    def verify(self, gesture: SignedGesture, *, expected: GestureBinding) -> None:
        """Confirm the gesture is authentic, fresh, single-use and correct."""

        if gesture.user_intent != "APPROVE":
            raise GestureRejected(
                "GESTURE_NOT_APPROVAL", "only an explicit approving action may authorize"
            )
        if gesture.binding != expected:
            raise GestureRejected(
                "GESTURE_BINDING_MISMATCH", "the gesture approves a different action"
            )
        expected_signature = hmac.new(
            self._key, gesture.canonical_payload().encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(gesture.signature, expected_signature):
            raise GestureRejected(
                "GESTURE_SIGNATURE_INVALID", "the gesture was not signed by the trusted UI"
            )
        if gesture.asserted_at.tzinfo is None:
            raise GestureRejected("GESTURE_TIMESTAMP_INVALID", "timestamp lacks a timezone")
        if (
            abs((self._clock() - gesture.asserted_at).total_seconds())
            > MAX_GESTURE_LIFETIME.seconds
        ):
            raise GestureRejected("GESTURE_STALE", "the gesture is outside its validity window")
        self._nonces.consume(gesture.nonce, expected)


def binding_digest(binding: GestureBinding) -> str:
    return hashlib.sha256(binding.canonical().encode("utf-8")).hexdigest()


def random_launch_key() -> bytes:
    return os.urandom(32)


__all__ = [
    "MAX_GESTURE_LIFETIME",
    "GestureBinding",
    "GestureNonceRegister",
    "GestureRejected",
    "SignedGesture",
    "TrustedGestureAuthority",
    "binding_digest",
    "random_launch_key",
]
