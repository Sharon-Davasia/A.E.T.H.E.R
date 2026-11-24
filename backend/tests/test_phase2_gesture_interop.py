"""TS<->Python gesture-signature interoperability (Decision A).

The Electron main process signs authorizing gestures in TypeScript; the
trusted backend verifies them in Python. Both sides must produce byte-
identical canonical payloads or every genuine approval fails (and, worse,
any drift that *loosened* the format could be exploitable). These golden
vectors are pinned in both suites:

* Python: ``aether.core.planning.authorizing_gesture``
* TypeScript: ``apps/desktop/electron/gesture.ts`` (+ ``tests/gesture.test.ts``)

If a vector changes here, the TypeScript suite must change in the same
commit, and vice versa.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from aether.core.planning import authorizing_gesture as gesture_module
from aether.core.planning.authorizing_gesture import (
    GestureBinding,
    GestureNonceRegister,
    GestureRejected,
    SignedGesture,
    TrustedGestureAuthority,
)

# bytes(range(32)): a fixed, public test key — never a real session key.
GOLDEN_KEY = bytes(range(32))
GOLDEN_BINDING = GestureBinding(
    task_id=UUID("11111111-2222-3333-4444-555555555555"),
    plan_revision=3,
    plan_hash="A" * 64,
    preview_id=UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
    preview_digest="b" * 64,
    scope_digest="c" * 64,
)
GOLDEN_NONCE = "d" * 64

GOLDEN_PAYLOAD_WHOLE_SECOND = (
    '{"asserted_at":"2026-11-15T12:00:00+00:00","binding":{"plan_hash":"'
    + "a" * 64
    + '","plan_revision":3,"preview_digest":"'
    + "b" * 64
    + '","preview_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","scope_digest":"'
    + "c" * 64
    + '","task_id":"11111111-2222-3333-4444-555555555555"},"nonce":"'
    + "d" * 64
    + '","user_intent":"APPROVE"}'
)
GOLDEN_SIGNATURE_WHOLE_SECOND = "f35972cf61a6b548ce493d15caf62c8323b5822f188eb4c655085e351b181c73"
GOLDEN_SIGNATURE_FRACTIONAL = "a20500762dbd03d58d7a8bb72362b345c1dc6ef494e11f8232369ac358d1246b"

NOW = datetime(2026, 11, 15, 12, 0, 30, tzinfo=UTC)


def _register_with_golden_nonce(monkeypatch: pytest.MonkeyPatch, *, at: datetime) -> GestureNonceRegister:
    monkeypatch.setattr(gesture_module.secrets, "token_hex", lambda _n: GOLDEN_NONCE)
    nonces = GestureNonceRegister(clock=lambda: at)
    assert nonces.issue(GOLDEN_BINDING) == GOLDEN_NONCE
    return nonces


def test_golden_canonical_payload_matches_typescript_contract() -> None:
    gesture = SignedGesture(
        nonce=GOLDEN_NONCE,
        binding=GOLDEN_BINDING,
        asserted_at=datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC),
        user_intent="APPROVE",
        signature="",
    )
    assert gesture.canonical_payload() == GOLDEN_PAYLOAD_WHOLE_SECOND


def test_typescript_produced_signature_verifies_in_python(monkeypatch: pytest.MonkeyPatch) -> None:
    """A gesture carrying the TS-computed golden signature must verify."""
    nonces = _register_with_golden_nonce(monkeypatch, at=NOW)
    authority = TrustedGestureAuthority(key=GOLDEN_KEY, nonces=nonces, clock=lambda: NOW)
    gesture = SignedGesture(
        nonce=GOLDEN_NONCE,
        binding=GOLDEN_BINDING,
        asserted_at=datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC),
        user_intent="APPROVE",
        signature=GOLDEN_SIGNATURE_WHOLE_SECOND,
    )
    authority.verify(gesture, expected=GOLDEN_BINDING)  # must not raise
    # ...and the nonce is burned: replaying the same gesture fails.
    with pytest.raises(GestureRejected):
        authority.verify(gesture, expected=GOLDEN_BINDING)


def test_typescript_fractional_second_signature_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    nonces = _register_with_golden_nonce(monkeypatch, at=NOW)
    authority = TrustedGestureAuthority(key=GOLDEN_KEY, nonces=nonces, clock=lambda: NOW)
    gesture = SignedGesture(
        nonce=GOLDEN_NONCE,
        binding=GOLDEN_BINDING,
        asserted_at=datetime(2026, 11, 15, 12, 0, 0, 123000, tzinfo=UTC),
        user_intent="APPROVE",
        signature=GOLDEN_SIGNATURE_FRACTIONAL,
    )
    assert gesture.canonical_payload().startswith(
        '{"asserted_at":"2026-11-15T12:00:00.123000+00:00"'
    )
    authority.verify(gesture, expected=GOLDEN_BINDING)  # must not raise


def test_channel_key_cannot_verify_gestures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Domain separation: signatures under any other key are refused."""
    nonces = _register_with_golden_nonce(monkeypatch, at=NOW)
    wrong_key_authority = TrustedGestureAuthority(key=b"c" * 32, nonces=nonces, clock=lambda: NOW)
    gesture = SignedGesture(
        nonce=GOLDEN_NONCE,
        binding=GOLDEN_BINDING,
        asserted_at=datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC),
        user_intent="APPROVE",
        signature=GOLDEN_SIGNATURE_WHOLE_SECOND,
    )
    with pytest.raises(GestureRejected):
        wrong_key_authority.verify(gesture, expected=GOLDEN_BINDING)


def test_wrong_binding_and_wrong_intent_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    nonces = _register_with_golden_nonce(monkeypatch, at=NOW)
    authority = TrustedGestureAuthority(key=GOLDEN_KEY, nonces=nonces, clock=lambda: NOW)
    other_binding = GestureBinding(
        task_id=GOLDEN_BINDING.task_id,
        plan_revision=4,
        plan_hash=GOLDEN_BINDING.plan_hash,
        preview_id=GOLDEN_BINDING.preview_id,
        preview_digest=GOLDEN_BINDING.preview_digest,
        scope_digest=GOLDEN_BINDING.scope_digest,
    )
    gesture = SignedGesture(
        nonce=GOLDEN_NONCE,
        binding=GOLDEN_BINDING,
        asserted_at=datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC),
        user_intent="APPROVE",
        signature=GOLDEN_SIGNATURE_WHOLE_SECOND,
    )
    with pytest.raises(GestureRejected):
        authority.verify(gesture, expected=other_binding)
    reject = SignedGesture(
        nonce=GOLDEN_NONCE,
        binding=GOLDEN_BINDING,
        asserted_at=datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC),
        user_intent="REJECT",
        signature=GOLDEN_SIGNATURE_WHOLE_SECOND,
    )
    with pytest.raises(GestureRejected):
        authority.verify(reject, expected=GOLDEN_BINDING)


def test_expired_nonce_is_refused() -> None:
    cell = [datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)]
    nonces = GestureNonceRegister(clock=lambda: cell[0])
    nonce = nonces.issue(GOLDEN_BINDING)
    authority = TrustedGestureAuthority(key=GOLDEN_KEY, nonces=nonces, clock=lambda: cell[0])
    gesture = authority.sign(nonce=nonce, binding=GOLDEN_BINDING, user_intent="APPROVE")
    cell[0] = cell[0] + timedelta(minutes=30)  # nonce (and gesture) age out
    with pytest.raises(GestureRejected):
        authority.verify(gesture, expected=GOLDEN_BINDING)
