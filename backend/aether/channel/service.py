"""Trusted backend-hosted authenticated channel service.

Run as ``python -m aether.channel.service``. This process is the single
trusted backend peer for the Electron desktop's authenticated channel at this
build stage. It performs the Stage 1 bootstrap (MAGIC, session id, per-launch
HMAC key, challenge) and speaks the same canonical-JSON envelope protocol; on
top of the Stage 1 ``demo.ping`` it additionally serves two narrow, typed
review operations backed by the real persisted task/plan store:

* ``review.get_preview``    — present the exact preview for one reviewable
  persisted PREVIEW_READY/AWAITING_APPROVAL task;
* ``review.record_outcome`` — record one exact bounded, non-authorizing audit
  outcome through ``PreviewReviewService``.

There is no generic privileged operation: unknown kinds terminate the session.
The service holds an exclusive owner lock on the development database named by
``AETHER_REVIEW_DB``; when the variable is absent or unusable, review
operations answer ``review_unavailable`` and the ping path keeps working.

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
from aether.channel.protocol import canonical
from aether.channel.review_bridge import ReviewBridge

_PING_KIND = "demo.ping"
_GET_PREVIEW_KIND = "review.get_preview"
_RECORD_OUTCOME_KIND = "review.record_outcome"


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
    bootstrap = protocol.read_exact(sys.stdin.buffer, len(protocol.MAGIC) + 16 + 32 + 32)
    if bootstrap[: len(protocol.MAGIC)] != protocol.MAGIC:
        raise ValueError("invalid startup bootstrap")
    offset = len(protocol.MAGIC)
    session = bootstrap[offset : offset + 16].hex()
    key = bootstrap[offset + 16 : offset + 48]
    challenge = bootstrap[offset + 48 : offset + 80].hex()
    _emit_bounded(_hello(session, challenge, key))

    bridge = ReviewBridge.from_env(dict(os.environ))
    try:
        inbound_seen: set[str] = set()
        inbound_seq = 1
        outbound_seq = 1
        seen_requests: set[str] = set()
        while True:
            raw = protocol.read_frame(sys.stdin.buffer)
            if raw is None:
                return 0
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
        if bridge is not None:
            bridge.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EOFError, OSError, ValueError, UnicodeError):
        raise SystemExit(2) from None
