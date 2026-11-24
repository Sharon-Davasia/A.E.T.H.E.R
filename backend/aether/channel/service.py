"""Trusted backend-hosted authenticated channel service.

Run as ``python -P -I -B -u -m aether.channel.service`` with an interpreter that
has the ``aether`` package installed (the backend project venv in development,
a bundled build in the future). ``-I`` implies ``-E`` (ignore ``PYTHON*``
environment variables, including ``PYTHONPATH`` and ``PYTHONHOME``) and ``-s``
(suppress user site-packages); ``-P`` (Python >= 3.11) removes the current
directory/script directory from ``sys.path``. Imports therefore resolve only
through the selected interpreter's own installation metadata. ``-I`` does not
prove every module physically resides in site-packages: an editable
development installation legitimately imports the AETHER source checkout
through an installed ``.pth``/editable finder. Development expects a trusted,
selected interpreter with a controlled editable or installed AETHER package;
packaged releases (future) must use a non-editable, verified package
installation with independent import-provenance and integrity verification as
required by the Master Specification. No uncontrolled ``PYTHONPATH``,
user-site or cwd injection exists at run time. This process is the single
trusted backend peer for the Electron desktop's authenticated channel at this
build stage. It performs the Stage 1 bootstrap (MAGIC, session id, per-launch
HMAC key, challenge) and speaks the same canonical-JSON envelope protocol; on
top of the Stage 1 ``demo.ping`` it additionally serves three narrow, typed
review operations backed by the real persisted task/plan store:

* ``review.get_preview``    — present the exact preview for one reviewable
  persisted PREVIEW_READY/AWAITING_APPROVAL task;
* ``review.record_outcome`` — record one exact bounded, non-authorizing audit
  outcome through ``PreviewReviewService``;
* ``review.get_outcome``    — read-only audit reconciliation of a previously
  submitted exact request (added so a lost acknowledgement can be confirmed).
  It never writes, never transitions state and never re-verifies a preview;
  it only reports what the persisted audit records already prove.

There is no generic privileged operation: unknown kinds terminate the session.
Storage initialization (FI-02A): the supported application database named
by ``AETHER_APP_DB`` (passed by Electron main for every build) opens via
``aether.channel.app_storage`` with the store's owner lock, private
permissions and active-schema-only migrations. The development review
database named by ``AETHER_REVIEW_DB`` is a dev-only seed mechanism; when
it is explicitly configured it takes precedence for the shared store.
When neither is usable, live operations answer ``composition_unavailable``
and review operations ``review_unavailable``; the ping path keeps working.

No operation here issues, stores, consumes or implies an ExactApprovalGrant;
every acknowledgement carries ``NON_AUTHORIZING_AUDIT_RECORD`` semantics.
"""

from __future__ import annotations

import os
import platform
import secrets
import sys
import time
from typing import Any

from aether.channel import protocol
from aether.channel.app_storage import open_application_store
from aether.channel.live_bridge import LiveBridge
from aether.channel.protocol import canonical
from aether.channel.review_bridge import ReviewBridge
from aether.core.composition import CompositionUnavailable, TrustedComposition

_PING_KIND = "demo.ping"
_GET_PREVIEW_KIND = "review.get_preview"
_RECORD_OUTCOME_KIND = "review.record_outcome"
_GET_OUTCOME_KIND = "review.get_outcome"

# Live workflow kinds (Phase 2 final integration), served by the trusted
# composition when it could be built; otherwise each answers a bounded
# `live.error` with reason `composition_unavailable`. There is no generic
# privileged operation: unknown kinds still terminate the session.
_LIVE_KINDS = {
    "project.register": ("register_project", "project.registered"),
    "project.resolve": ("resolve_resource", "project.resolved"),
    "task.create": ("create_task", "task.created"),
    "task.plan": ("plan_task", "task.preview"),
    "task.planned_preview": ("get_planned_preview", "task.planned"),
    "fs.execute_read": ("execute_read", "fs.read_result"),
    "gesture.begin": ("begin_gesture", "gesture.challenge"),
    "gesture.submit": ("submit_gesture", "gesture.authorized"),
    "edit.execute": ("execute_edit", "edit.executed"),
    "edit.receipt": ("get_receipt", "edit.receipt"),
}


def _hello(session: str, challenge: str, key: bytes) -> dict[str, object]:
    envelope: dict[str, object] = {
        "v": protocol.PROTOCOL,
        "session": session,
        "direction": "child-to-parent",
        "seq": 0,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time() * 1000),
        "requestId": protocol.HELLO_REQUEST_ID,
        "kind": "channel.hello",
        "payload": {
            "challenge": challenge,
            "protocol": protocol.PROTOCOL,
            "pythonVersion": platform.python_version(),
        },
    }
    return protocol.signed(envelope, key)


def _response(
    kind: str,
    *,
    session: str,
    seq: int,
    request_id: str,
    payload: dict[str, object],
    key: bytes,
) -> dict[str, object]:
    envelope: dict[str, object] = {
        "v": protocol.PROTOCOL,
        "session": session,
        "direction": "child-to-parent",
        "seq": seq,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time() * 1000),
        "requestId": request_id,
        "kind": kind,
        "payload": payload,
    }
    return protocol.signed(envelope, key)


def _emit_bounded(envelope: dict[str, object]) -> None:
    """Write one frame, enforcing the channel bound on the serialized body."""

    body = canonical(envelope)
    if not 2 <= len(body) <= protocol.MAX_FRAME:
        raise ValueError("frame size outside bounds")
    sys.stdout.buffer.write(len(body).to_bytes(4, "big") + body)
    sys.stdout.buffer.flush()


def _error_payload(reason: str) -> dict[str, object]:
    return {"reason": reason}


def main() -> int:
    # Bootstrap (private stdin pipe, written once by Electron main):
    # MAGIC | 16B session id | 32B channel HMAC key | 32B challenge |
    # 32B gesture key. The gesture key is an independent per-launch secret
    # (Decision A): cryptographically separated from the channel key, held
    # only by main and this child, never logged or persisted.
    bootstrap = protocol.read_exact(sys.stdin.buffer, len(protocol.MAGIC) + 16 + 32 + 32 + 32)
    if bootstrap[: len(protocol.MAGIC)] != protocol.MAGIC:
        raise ValueError("invalid startup bootstrap")
    offset = len(protocol.MAGIC)
    session = bootstrap[offset : offset + 16].hex()
    key = bootstrap[offset + 16 : offset + 48]
    challenge = bootstrap[offset + 48 : offset + 80].hex()
    gesture_key = bootstrap[offset + 80 : offset + 112]
    _emit_bounded(_hello(session, challenge, key))

    env = dict(os.environ)
    bridge = ReviewBridge.from_env(env)
    # FI-02A: the supported application store (AETHER_APP_DB, passed by
    # Electron main for every build) initializes the trusted composition
    # independently of the development review seed. The review seed —
    # when explicitly configured — keeps precedence for the store the
    # composition shares, exactly as before; otherwise the application
    # store is used. Misconfiguration fails closed to no composition.
    app_store = None if bridge is not None else open_application_store(env)
    composition = None
    live_bridge = None
    composition_store = bridge.store if bridge is not None else app_store
    if composition_store is not None:
        try:
            composition = TrustedComposition.build(store=composition_store, gesture_key=gesture_key)
            live_bridge = LiveBridge(composition)
        except CompositionUnavailable:
            # Fail closed for the trusted-execution tier only; the audit-only
            # review surface is independent and keeps working.
            composition = None
            live_bridge = None
    try:
        inbound_seen: set[str] = set()
        inbound_seq = 1
        outbound_seq = 1
        seen_requests: set[str] = set()
        while True:
            raw = protocol.read_frame(sys.stdin.buffer)
            if raw is None:
                break
            request = protocol.validate(
                raw,
                key=key,
                session=session,
                seq=inbound_seq,
                direction="parent-to-child",
                seen_nonces=inbound_seen,
            )
            inbound_seq += 1
            request_id = str(request["requestId"])
            if request_id in seen_requests:
                raise ValueError("duplicate request identifier")
            seen_requests.add(request_id)
            if len(seen_requests) > 4096:
                raise ValueError("session request capacity exceeded")
            kind = str(request["kind"])
            payload: Any = request["payload"]

            if kind == _PING_KIND:
                if payload != {"text": "synthetic-only"}:
                    raise ValueError("unsupported synthetic channel message")
                response_kind = "demo.pong"
                response_payload: dict[str, object] = {"text": "synthetic-only"}
            elif kind == _GET_PREVIEW_KIND:
                if bridge is None:
                    response_payload = {"status": "unavailable", "reason": "review_unavailable"}
                else:
                    response_payload = bridge.get_preview_payload(payload)
                response_kind = "review.preview"
            elif kind == _RECORD_OUTCOME_KIND:
                if bridge is None:
                    response_kind = "review.error"
                    response_payload = _error_payload("review_unavailable")
                else:
                    acknowledgement, reason = bridge.record_outcome(payload)
                    if acknowledgement is not None:
                        response_kind = "review.outcome"
                        response_payload = acknowledgement
                    else:
                        response_kind = "review.error"
                        response_payload = _error_payload(reason or "review_unavailable")
            elif kind == _GET_OUTCOME_KIND:
                if bridge is None:
                    response_kind = "review.error"
                    response_payload = _error_payload("review_unavailable")
                else:
                    acknowledgement, reason = bridge.get_outcome(payload)
                    if acknowledgement is not None:
                        response_kind = "review.outcome"
                        response_payload = acknowledgement
                    else:
                        response_kind = "review.error"
                        response_payload = _error_payload(reason or "review_unavailable")
            elif kind in _LIVE_KINDS:
                method_name, success_kind = _LIVE_KINDS[kind]
                if live_bridge is None:
                    response_kind = "live.error"
                    response_payload = _error_payload("composition_unavailable")
                else:
                    result = getattr(live_bridge, method_name)(payload)
                    if result.get("status") == "unavailable":
                        response_kind = "live.error"
                        response_payload = _error_payload(str(result.get("reason")))
                    else:
                        response_kind = success_kind
                        response_payload = result
            else:
                raise ValueError("unsupported channel message")

            envelope = _response(
                response_kind,
                session=session,
                seq=outbound_seq,
                request_id=request_id,
                payload=response_payload,
                key=key,
            )
            try:
                _emit_bounded(envelope)
            except ValueError:
                if response_kind != "review.preview":
                    raise
                # A preview larger than the channel bound fails closed with a
                # bounded, non-success payload instead of an undeliverable frame.
                envelope = _response(
                    "review.preview",
                    session=session,
                    seq=outbound_seq,
                    request_id=request_id,
                    payload={"status": "unavailable", "reason": "preview_too_large"},
                    key=key,
                )
                _emit_bounded(envelope)
            outbound_seq += 1
    finally:
        if composition is not None:
            composition.close()
        if bridge is not None:
            bridge.close()
        if app_store is not None:
            app_store.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EOFError, OSError, ValueError, UnicodeError):
        raise SystemExit(2) from None
