"""CP7: phase3 kinds over the real authenticated channel service.

Spawns the production channel service module against isolated
synthetic storage and verifies the Phase 3 surface answers truthfully
in ordinary (disabled) mode. Requires AETHER_DEV_PYTHON to point at
an interpreter with the backend importable; skipped otherwise.
"""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

from test_channel_child import encode, read_frame, sign, wait_and_close

BACKEND_ROOT = Path(__file__).resolve().parents[3] / "backend"


def _interpreter() -> str | None:
    candidate = os.environ.get("AETHER_DEV_PYTHON")
    if not candidate:
        return None
    probe = subprocess.run(
        [candidate, "-c", "import aether.channel.service"],
        cwd=BACKEND_ROOT,
        capture_output=True,
        timeout=30,
    )
    return candidate if probe.returncode == 0 else None


@unittest.skipUnless(
    _interpreter(), "no Python interpreter with aether installed importable"
)
class Phase3ChannelTests(unittest.TestCase):
    def test_phase3_state_disabled_in_ordinary_mode(self) -> None:
        import secrets

        interpreter = _interpreter()
        assert interpreter is not None
        session = secrets.token_bytes(16)
        key = secrets.token_bytes(32)
        challenge = secrets.token_bytes(32)
        gesture_key = secrets.token_bytes(32)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "AETHER_APP_DB": str(Path(self._tmp()) / "tasks.sqlite3"),
        }
        process = subprocess.Popen(
            [interpreter, "-P", "-I", "-B", "-u", "-m", "aether.channel.service"],
            cwd=BACKEND_ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        try:
            assert process.stdin is not None and process.stdout is not None
            bootstrap = b"AETHR1\x00\x01" + session + key + challenge + gesture_key
            process.stdin.write(bootstrap)
            process.stdin.flush()
            hello = read_frame(process.stdout)
            self.assertEqual(hello.get("kind"), "channel.hello")
            request = sign(
                {
                    "v": 1,
                    "session": session.hex(),
                    "direction": "parent-to-child",
                    "seq": 1,
                    "nonce": "a" * 32,
                    "timestamp": _now_ms(),
                    "requestId": "44444444-4444-4444-8444-444444444444",
                    "kind": "phase3.get_state",
                    "payload": {},
                },
                key,
            )
            process.stdin.write(encode(request))
            process.stdin.flush()
            response = read_frame(process.stdout)
            self.assertEqual(response.get("kind"), "phase3.state")
            payload = response.get("payload") or {}
            self.assertEqual(payload.get("status"), "ready")
            self.assertEqual(payload.get("nativeAvailable"), False)
            self.assertEqual(payload.get("disabledReason"), "phase3_native_disabled")
            # Interaction kinds refuse truthfully without a wired surface.
            request2 = sign(
                {
                    "v": 1,
                    "session": session.hex(),
                    "direction": "parent-to-child",
                    "seq": 2,
                    "nonce": "b" * 32,
                    "timestamp": _now_ms(),
                    "requestId": "55555555-5555-4555-8555-555555555555",
                    "kind": "phase3.inspect_window",
                    "payload": {"windowId": "window:x"},
                },
                key,
            )
            process.stdin.write(encode(request2))
            process.stdin.flush()
            response2 = read_frame(process.stdout)
            self.assertEqual(response2.get("kind"), "phase3.error")
        finally:
            if process.stdin:
                process.stdin.close()
            wait_and_close(process)

    def _tmp(self) -> str:
        import tempfile

        self._tmpdir = tempfile.mkdtemp(prefix="aether-phase3-channel-")
        return self._tmpdir


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


if __name__ == "__main__":
    unittest.main()
