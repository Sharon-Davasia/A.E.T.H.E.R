"""Adapter-worker entry point (CP4): bounded typed ops over stdio lines.

Not started by ordinary application startup. The trusted backend owns
policy and authorization; this process only executes already-validated
bounded operations against an injected UIA backend and returns
size-bounded typed results. It accepts no arbitrary code, pattern
names, key sequences or shell input (see ``validate_request``).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any, BinaryIO

from aether.adapters.windows.uia_backend import UiaBackend, UiaBackendError
from aether.core.contracts.uia import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, UiaLimits
from aether.core.workers.uia_worker import PROTOCOL_VERSION, decode_message, validate_request


def handle_request(request: dict[str, Any], *, backend: UiaBackend) -> dict[str, Any]:
    """Execute one validated request; never raises across the boundary."""
    base = {"protocol": PROTOCOL_VERSION, "request_id": request.get("request_id", "")}
    operation = request.get("operation")
    payload = request.get("payload") or {}
    try:
        if operation == "health":
            return {**base, "status": "ok", "result": {"healthy": True}}
        if operation == "shutdown":
            return {**base, "status": "ok", "result": {"shutdown": True}}
        hwnd = payload.get("hwnd")
        if not isinstance(hwnd, int):
            raise ValueError("a bounded integer hwnd is required")
        root = backend.find_root(hwnd=hwnd)
        if root is None:
            return {**base, "status": "error", "error": "no_uia_root"}
        if operation == "inspect":
            limits = UiaLimits(
                max_depth=int(payload.get("max_depth", UiaLimits().max_depth)),
                max_elements=int(payload.get("max_elements", UiaLimits().max_elements)),
                max_total_text_chars=int(
                    payload.get("max_total_text_chars", UiaLimits().max_total_text_chars)
                ),
            )
            mode = str(payload.get("collection_mode", "metadata_only"))
            elements, truncated = _bounded_walk(
                backend, root, limits, include_names=(mode == "content_on_demand")
            )
            return {
                **base,
                "status": "ok",
                "result": {
                    "elements": elements,
                    "completeness": "truncated" if truncated else "complete",
                    "truncated": truncated,
                },
            }
        element_key = payload.get("element_key")
        if not isinstance(element_key, str):
            raise ValueError("an element key is required")
        target = _find(backend, root, element_key)
        if target is None:
            return {**base, "status": "error", "error": "element_not_found"}
        if operation == "invoke":
            return {**base, "status": "ok", "result": backend.invoke(target)}
        return {**base, "status": "error", "error": "unsupported_operation"}
    except (ValueError, UiaBackendError) as exc:
        return {**base, "status": "error", "error": str(exc)[:160]}


def _find(backend: UiaBackend, root: Any, key: str) -> Any | None:
    stack = [root]
    seen = 0
    while stack and seen < 400:
        node = stack.pop()
        seen += 1
        if node.key == key:
            return node
        try:
            stack.extend(backend.children(node))
        except UiaBackendError:
            continue
    return None


def _bounded_walk(
    backend: UiaBackend, root: Any, limits: UiaLimits, *, include_names: bool = False
) -> tuple[list[dict[str, Any]], bool]:
    out: list[dict[str, Any]] = []
    stack = [(root, 0)]
    text = 0
    truncated = False
    while stack and len(out) < limits.max_elements:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            truncated = True
            continue
        # G06: in metadata-only mode accessible names are never read
        # from the provider at all (not read-then-filtered). Password
        # names are never read in any mode.
        name = node.name if (include_names and not node.is_password) else None
        if name and text + len(name) > limits.max_total_text_chars:
            name = None
        elif name:
            text += len(name)
        out.append(
            {
                "key": node.key,
                "control_type": node.control_type,
                "name": None if node.is_password else name,
                "automation_id": node.automation_id,
                "patterns": sorted(node.patterns),
                "is_enabled": node.is_enabled,
                "is_password": node.is_password,
                "depth": depth,
                "child_count": len(node.children_keys),
            }
        )
        try:
            children = backend.children(node)
        except UiaBackendError:
            children = ()
            truncated = True
        stack.extend((child, depth + 1) for child in reversed(children))
    if stack:
        truncated = True
    return out, truncated


def serve(
    backend_factory: Callable[[], UiaBackend],
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
) -> None:  # pragma: no cover - process entry, exercised via handle_request
    source = stdin or sys.stdin.buffer
    sink = stdout or sys.stdout.buffer
    backend = backend_factory()
    try:
        for line in source:
            if len(line) > MAX_REQUEST_BYTES:
                continue
            try:
                request = validate_request(decode_message(line, bound=MAX_REQUEST_BYTES))
            except ValueError:
                continue
            response = handle_request(request, backend=backend)
            body = json.dumps(response, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_RESPONSE_BYTES:
                body = json.dumps(
                    {
                        "protocol": PROTOCOL_VERSION,
                        "request_id": request.get("request_id", ""),
                        "status": "error",
                        "error": "response_too_large",
                    }
                ).encode("utf-8")
            sink.write(body + b"\n")
            sink.flush()
            if request.get("operation") == "shutdown":
                break
    finally:
        backend.close()


def _simulated_backend_factory() -> UiaBackend:
    """Deterministic simulated provider for platform-independent tests.

    This is the child-process provider used by the subprocess
    reliability tests; it is never native evidence and is selected
    only by the trusted parent's explicit ``--simulated`` flag.
    """
    from aether.core.apps.fixture import FixtureApp

    return FixtureApp().backend()


def main(argv: list[str] | None = None) -> int:
    """Worker entry point. Disabled unless the trusted parent starts it
    with a provider it owns; ordinary application startup never does.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if "--simulated" in args:
        serve(_simulated_backend_factory)
        return 0
    if sys.platform != "win32":
        print("uia worker: native provider unavailable on this platform", file=sys.stderr)
        return 2
    # Windows: explicit COM apartment initialization/cleanup around
    # the serving loop. The trusted parent owns initialization: the
    # first line on the private stdin pipe must be a bounded bootstrap
    # envelope from which the activation context is minted. Without
    # it (or with a malformed one) the worker refuses to start. No
    # environment variable, CLI flag or importable token enables it.
    bootstrap_line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
    try:
        bootstrap = decode_message(bootstrap_line, bound=MAX_REQUEST_BYTES)
        if bootstrap.get("operation") != "bootstrap":
            raise ValueError("first worker line is not a bootstrap")
        from aether.adapters.windows.native_observer import (
            activation_context_from_parent_bootstrap,
        )

        activation = activation_context_from_parent_bootstrap(bootstrap.get("payload"))
    except (ValueError, UnicodeDecodeError):
        print("uia worker: parent bootstrap is required", file=sys.stderr)
        return 2
    import comtypes  # type: ignore[import-not-found]

    comtypes.CoInitialize()
    try:
        from aether.adapters.windows.native_uia import NativeUiaDisabled, build_native_uia_backend

        try:
            backend = build_native_uia_backend(activation=activation)
        except NativeUiaDisabled:
            print("uia worker: native UIA activation is disabled", file=sys.stderr)
            return 2
        serve(lambda: backend, stdin=sys.stdin.buffer)
        return 0
    finally:
        comtypes.CoUninitialize()


if __name__ == "__main__":  # pragma: no cover - process entry
    raise SystemExit(main())
