"""Synthetic-only authenticated parent/child channel; no approval or filesystem capabilities."""

from __future__ import annotations

import hashlib
import hmac
import json
import platform
import re
import secrets
import struct
import sys
import time

MAGIC = b"AETHR1\x00\x01"
MAX_FRAME = 64 * 1024
PROTOCOL = 1
MAX_SKEW_MS = 30_000
HELLO_REQUEST_ID = "00000000-0000-4000-8000-000000000000"


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def read_exact(stream: object, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(size - len(chunks))  # type: ignore[attr-defined]
        if not chunk:
            raise EOFError("incomplete channel bootstrap")
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(stream: object) -> bytes | None:
    first = stream.read(1)  # type: ignore[attr-defined]
    if not first:
        return None
    header = first + read_exact(stream, 3)
    length = struct.unpack(">I", header)[0]
    if not 2 <= length <= MAX_FRAME:
        raise ValueError("frame size outside bounds")
    return read_exact(stream, length)


def write_frame(envelope: dict[str, object]) -> None:
    body = canonical(envelope)
    if not 2 <= len(body) <= MAX_FRAME:
        raise ValueError("frame size outside bounds")
    sys.stdout.buffer.write(struct.pack(">I", len(body)) + body)
    sys.stdout.buffer.flush()


def signed(unsigned: dict[str, object], key: bytes) -> dict[str, object]:
    mac = hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    return {**unsigned, "mac": mac}


def validate(
    raw: bytes,
    *,
    key: bytes,
    session: str,
    seq: int,
    direction: str,
    seen_nonces: set[str],
) -> dict[str, object]:
    source = raw.decode("utf-8")
    parsed = json.loads(source)
    if not isinstance(parsed, dict):
        raise ValueError("envelope must be an object")
    if canonical(parsed).decode("utf-8") != source:
        raise ValueError("envelope JSON is not canonical")
    expected = {
        "v",
        "session",
        "direction",
        "seq",
        "nonce",
        "timestamp",
        "requestId",
        "kind",
        "payload",
        "mac",
    }
    if set(parsed) != expected:
        raise ValueError("unexpected envelope fields")
    if (
        type(parsed["v"]) is not int
        or parsed["v"] != PROTOCOL
        or parsed["session"] != session
        or parsed["direction"] != direction
    ):
        raise ValueError("wrong protocol session or direction")
    if type(parsed["seq"]) is not int or parsed["seq"] != seq:
        raise ValueError("replayed or out-of-order sequence")
    nonce = parsed["nonce"]
    if (
        not isinstance(nonce, str)
        or len(nonce) != 32
        or any(c not in "0123456789abcdef" for c in nonce)
    ):
        raise ValueError("malformed nonce")
    if nonce in seen_nonces:
        raise ValueError("replayed nonce")
    timestamp = parsed["timestamp"]
    if (
        type(timestamp) is not int
        or abs(int(time.time() * 1000) - timestamp) > MAX_SKEW_MS
    ):
        raise ValueError("stale timestamp")
    request_id = parsed["requestId"]
    if not isinstance(request_id, str) or not re.fullmatch(
        r"[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}",
        request_id,
    ):
        raise ValueError("malformed request identifier")
    kind = parsed["kind"]
    if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", kind):
        raise ValueError("malformed message kind")
    mac = parsed["mac"]
    unsigned = {name: value for name, value in parsed.items() if name != "mac"}
    expected_mac = hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    if (
        not isinstance(mac, str)
        or not re.fullmatch(r"[a-f0-9]{64}", mac)
        or not hmac.compare_digest(mac, expected_mac)
    ):
        raise ValueError("bad message authentication code")
    seen_nonces.add(nonce)
    if len(seen_nonces) > 4096:
        raise ValueError("session nonce capacity exceeded")
    return parsed


def main() -> int:
    # Wire mirror of the real service bootstrap: MAGIC | 16B session |
    # 32B channel key | 32B challenge | 32B gesture key. This Stage 1 test
    # child is not a trusted backend: it consumes and discards the gesture
    # key bytes so the frame stream stays aligned, and never uses them.
    bootstrap = read_exact(sys.stdin.buffer, len(MAGIC) + 16 + 32 + 32 + 32)
    if bootstrap[: len(MAGIC)] != MAGIC:
        raise ValueError("invalid startup bootstrap")
    offset = len(MAGIC)
    session = bootstrap[offset : offset + 16].hex()
    key = bootstrap[offset + 16 : offset + 48]
    challenge = bootstrap[offset + 48 : offset + 80].hex()
    del bootstrap  # gesture key bytes intentionally unused by this mirror
    hello = {
        "v": PROTOCOL,
        "session": session,
        "direction": "child-to-parent",
        "seq": 0,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time() * 1000),
        "requestId": HELLO_REQUEST_ID,
        "kind": "channel.hello",
        "payload": {
            "challenge": challenge,
            "protocol": PROTOCOL,
            "pythonVersion": platform.python_version(),
        },
    }
    write_frame(signed(hello, key))

    inbound_seen: set[str] = set()
    inbound_seq = 1
    outbound_seq = 1
    seen_requests: set[str] = set()
    while True:
        raw = read_frame(sys.stdin.buffer)
        if raw is None:
            return 0
        request = validate(
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
        if request["kind"] != "demo.ping" or request["payload"] != {
            "text": "synthetic-only"
        }:
            raise ValueError("unsupported synthetic channel message")
        nonce = secrets.token_hex(16)
        response = {
            "v": PROTOCOL,
            "session": session,
            "direction": "child-to-parent",
            "seq": outbound_seq,
            "nonce": nonce,
            "timestamp": int(time.time() * 1000),
            "requestId": request_id,
            "kind": "demo.pong",
            "payload": {"text": "synthetic-only"},
        }
        outbound_seq += 1
        write_frame(signed(response, key))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EOFError, OSError, ValueError, UnicodeError, json.JSONDecodeError):
        raise SystemExit(2) from None
