from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import secrets
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "backend" / "channel_child.py"
MAGIC = b"AETHR1\x00\x01"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def sign(value: dict[str, object], key: bytes) -> dict[str, object]:
    return {**value, "mac": hmac.new(key, canonical(value), hashlib.sha256).hexdigest()}


def encode(value: dict[str, object]) -> bytes:
    body = canonical(value)
    return struct.pack(">I", len(body)) + body


def read_frame(stream: object) -> dict[str, object]:
    header = stream.read(4)  # type: ignore[attr-defined]
    if len(header) != 4:
        raise AssertionError("child did not emit a complete frame")
    size = struct.unpack(">I", header)[0]
    body = stream.read(size)  # type: ignore[attr-defined]
    if len(body) != size:
        raise AssertionError("child emitted a truncated frame")
    return json.loads(body)


def wait_and_close(process: subprocess.Popen[bytes]) -> int:
    result = process.wait(timeout=5)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            stream.close()
    return result


class ChannelChildTests(unittest.TestCase):
    def start_child(self) -> tuple[subprocess.Popen[bytes], str]:
        session = secrets.token_hex(16)
        challenge = secrets.token_bytes(32)
        key = secrets.token_bytes(32)
        self.key = key
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", "-u", str(SCRIPT)],
            cwd=SCRIPT.parent,
            env={"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(MAGIC + bytes.fromhex(session) + key + challenge)
        process.stdin.flush()
        hello = read_frame(process.stdout)
        self.assertEqual(hello["kind"], "channel.hello")
        self.assertEqual(hello["payload"]["challenge"], challenge.hex())
        self.assertEqual(hello["payload"]["protocol"], 1)
        self.assertEqual(hello["payload"]["pythonVersion"], platform.python_version())
        body = {name: value for name, value in hello.items() if name != "mac"}
        expected = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(hello["mac"], expected))
        return process, session

    def envelope(self, active_session: str, **overrides: object) -> dict[str, object]:
        base: dict[str, object] = {
            "v": 1,
            "session": active_session,
            "direction": "parent-to-child",
            "seq": 1,
            "nonce": secrets.token_hex(16),
            "timestamp": int(time.time() * 1000),
            "requestId": "123e4567-e89b-42d3-a456-426614174000",
            "kind": "demo.ping",
            "payload": {"text": "synthetic-only"},
        }
        base.update(overrides)
        return sign(base, self.key)

    def expect_rejected(self, **overrides: object) -> None:
        process, session = self.start_child()
        assert process.stdin is not None
        process.stdin.write(encode(self.envelope(session, **overrides)))
        process.stdin.close()
        self.assertNotEqual(wait_and_close(process), 0)

    def test_authenticated_ping_and_clean_pipe_close(self) -> None:
        process, session = self.start_child()
        assert process.stdin is not None and process.stdout is not None
        request = self.envelope(session)
        process.stdin.write(encode(request))
        process.stdin.flush()
        response = read_frame(process.stdout)
        self.assertEqual(response["kind"], "demo.pong")
        self.assertEqual(response["requestId"], request["requestId"])
        unsigned = {name: value for name, value in response.items() if name != "mac"}
        expected = hmac.new(self.key, canonical(unsigned), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(response["mac"], expected))
        process.stdin.close()
        self.assertEqual(wait_and_close(process), 0)

    def test_bad_mac_wrong_direction_stale_session_and_timestamp_rejected(self) -> None:
        process, session = self.start_child()
        request = self.envelope(session)
        request["mac"] = "0" * 64
        assert process.stdin is not None
        process.stdin.write(encode(request))
        process.stdin.close()
        self.assertNotEqual(wait_and_close(process), 0)
        self.expect_rejected(session=secrets.token_hex(16))
        self.expect_rejected(direction="child-to-parent")
        self.expect_rejected(timestamp=int(time.time() * 1000) - 31_000)

    def test_replayed_sequence_duplicate_nonce_and_request_id_rejected(self) -> None:
        process, session = self.start_child()
        assert process.stdin is not None and process.stdout is not None
        first = self.envelope(session)
        process.stdin.write(encode(first))
        process.stdin.flush()
        read_frame(process.stdout)
        replay = self.envelope(session)
        process.stdin.write(encode(replay))
        process.stdin.close()
        self.assertNotEqual(wait_and_close(process), 0)

        process, session = self.start_child()
        assert process.stdin is not None and process.stdout is not None
        first = self.envelope(session)
        process.stdin.write(encode(first))
        process.stdin.flush()
        read_frame(process.stdout)
        duplicate_nonce = self.envelope(
            session, seq=2, nonce=first["nonce"], requestId="123e4567-e89b-42d3-a456-426614174001"
        )
        process.stdin.write(encode(duplicate_nonce))
        process.stdin.close()
        self.assertNotEqual(wait_and_close(process), 0)

        process, session = self.start_child()
        assert process.stdin is not None and process.stdout is not None
        first = self.envelope(session)
        process.stdin.write(encode(first))
        process.stdin.flush()
        read_frame(process.stdout)
        duplicate_id = self.envelope(session, seq=2, requestId=first["requestId"])
        process.stdin.write(encode(duplicate_id))
        process.stdin.close()
        self.assertNotEqual(wait_and_close(process), 0)

    def test_malformed_and_oversized_frames_fail_closed(self) -> None:
        process, _session = self.start_child()
        assert process.stdin is not None
        process.stdin.write(struct.pack(">I", 2) + b"{")
        process.stdin.close()
        self.assertNotEqual(wait_and_close(process), 0)

        process, _session = self.start_child()
        assert process.stdin is not None
        process.stdin.write(struct.pack(">I", 65_537))
        process.stdin.close()
        self.assertNotEqual(wait_and_close(process), 0)

    def test_parent_pipe_close_reaps_child_without_action(self) -> None:
        process, _session = self.start_child()
        assert process.stdin is not None
        process.stdin.close()
        self.assertEqual(wait_and_close(process), 0)

    def test_invalid_bootstrap_exits_without_protocol_output(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", "-u", str(SCRIPT)],
            cwd=SCRIPT.parent,
            env={"PATH": os.defpath},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(b"x" * (len(MAGIC) + 16 + 32 + 32))
        process.stdin.close()
        self.assertNotEqual(process.wait(timeout=5), 0)
        self.assertEqual(process.stdout.read(), b"")
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


if __name__ == "__main__":
    unittest.main()
