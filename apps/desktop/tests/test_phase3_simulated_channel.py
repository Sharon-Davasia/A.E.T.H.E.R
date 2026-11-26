"""G02/§11: genuine authenticated cross-process simulated workflow.

Spawns the production channel service with the explicit simulated-
acceptance test composition (fake platform providers only), then
drives: state -> app search -> window list -> fixture preparation ->
trusted gesture (signed as Electron main signs) -> single execution
-> independent verification -> durable receipt. Not native evidence.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "backend"))

from test_channel_child import encode, read_frame, sign, wait_and_close  # noqa: E402

BACKEND_ROOT = Path(__file__).resolve().parents[3] / "backend"


def _interpreter() -> str | None:
    candidate = os.environ.get("AETHER_DEV_PYTHON")
    if not candidate:
        return None
    probe = subprocess.run(
        [candidate, "-c", "import aether.channel.service"],
        cwd=BACKEND_ROOT, capture_output=True, timeout=30,
    )
    return candidate if probe.returncode == 0 else None


@unittest.skipUnless(_interpreter(), "no Python interpreter with aether installed importable")
class SimulatedPhase3ChannelTests(unittest.TestCase):
    def test_full_simulated_fixture_workflow(self) -> None:
        interpreter = _interpreter()
        assert interpreter is not None
        session = secrets.token_bytes(16)
        key = secrets.token_bytes(32)
        challenge = secrets.token_bytes(32)
        gesture_key = secrets.token_bytes(32)
        storage = Path(tempfile.mkdtemp(prefix="aether-sim-")) / "aether-phase3-acceptance-sim"
        env = {
            "PATH": os.environ.get("PATH", ""),
            "AETHER_PHASE3_SIMULATED": "simulated-acceptance",
            "AETHER_PHASE3_STORAGE": str(storage),
        }
        process = subprocess.Popen(
            [interpreter, "-P", "-I", "-B", "-u", "-m", "aether.channel.service"],
            cwd=BACKEND_ROOT, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        seq = 0

        def call(kind: str, payload: dict) -> dict:
            nonlocal seq
            seq += 1
            assert process.stdin is not None and process.stdout is not None
            request = sign(
                {
                    "v": 1, "session": session.hex(), "direction": "parent-to-child",
                    "seq": seq, "nonce": f"{seq:032x}", "timestamp": int(time.time() * 1000),
                    "requestId": f"{seq:08d}-4444-4444-8444-444444444444",
                    "kind": kind, "payload": payload,
                },
                key,
            )
            process.stdin.write(encode(request))
            process.stdin.flush()
            return read_frame(process.stdout)

        try:
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write(b"AETHR1\x00\x01" + session + key + challenge + gesture_key)
            process.stdin.flush()
            hello = read_frame(process.stdout)
            self.assertEqual(hello.get("kind"), "channel.hello")

            state = call("phase3.get_state", {})
            self.assertEqual(state["kind"], "phase3.state")
            self.assertTrue(state["payload"]["nativeAvailable"])
            windows = state["payload"]["windows"]
            self.assertTrue(windows)
            window_id = windows[0]["windowId"]
            self.assertEqual(windows[0]["appDisplayName"], "AETHER Fixture")

            apps = call("phase3.search_apps", {"query": "fixture"})
            self.assertTrue(apps["payload"]["results"])

            prepared = call("phase3.prepare_fixture", {"windowId": window_id})
            self.assertEqual(prepared["kind"], "phase3.prepared", prepared)
            self.assertEqual(prepared["payload"]["preview"]["verifiedPrecondition"], "Count: 0")
            self.assertEqual(prepared["payload"]["preview"]["expectedPostcondition"], "Count: 1")
            task_id = prepared["payload"]["taskId"]

            preview = call("phase3.preview_interaction", {"taskId": task_id})
            self.assertEqual(preview["kind"], "phase3.preview", preview)
            nonce = preview["payload"]["nonce"]
            binding = preview["payload"]["binding"]

            from aether.core.planning.authorizing_gesture import (
                GestureBinding,
                GestureNonceRegister,
                TrustedGestureAuthority,
            )

            authority = TrustedGestureAuthority(
                key=gesture_key, nonces=GestureNonceRegister(), clock=None
            )
            gesture = authority.sign(
                nonce=nonce,
                binding=GestureBinding(
                    task_id=UUID(binding["taskId"]),
                    plan_revision=binding["planRevision"],
                    plan_hash=binding["planHash"],
                    preview_id=UUID(binding["previewId"]),
                    preview_digest=binding["previewDigest"],
                    scope_digest=binding["scopeDigest"],
                ),
                user_intent="APPROVE",
            )
            outcome = call(
                "phase3.approve_interaction",
                {
                    "taskId": task_id,
                    "nonce": nonce,
                    "assertedAt": gesture.asserted_at.isoformat(),
                    "userIntent": "APPROVE",
                    "signature": gesture.signature,
                    "binding": binding,
                },
            )
            self.assertEqual(outcome["kind"], "phase3.outcome", outcome)
            self.assertEqual(outcome["payload"]["outcome"], "SUCCEEDED")

            receipt = call("phase3.get_receipt", {"taskId": task_id})
            self.assertEqual(receipt["payload"]["taskState"], "COMPLETED")
            self.assertEqual(receipt["payload"]["uiAttempts"][0]["receipt_status"], "SUCCEEDED")
        finally:
            if process.stdin:
                process.stdin.close()
            wait_and_close(process)


if __name__ == "__main__":
    unittest.main()
