"""CP4 UIA snapshot + worker reliability (fake-backed; not native evidence)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aether.adapters.windows.uia_backend import FakeUiaBackend, RawElement
from aether.core.apps.uia_snapshot import UiaOutcome, UiaSnapshotService
from aether.core.contracts.uia import MAX_ELEMENTS, UiaLimits
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.resources.app_window_authority import AppWindowResourceAuthority
from aether.core.workers.uia_worker import WorkerOutcome, WorkerSupervisor, validate_request
from aether.world_state.privacy import ContextClassification

NOW = datetime(2026, 11, 15, tzinfo=UTC)
HWND = 777


def _authority(classification=ContextClassification.PERMITTED_METADATA, elevated=None):
    authority = AppWindowResourceAuthority(session_id="s1")
    ref = authority.register_window(
        hwnd=HWND,
        process_token="pid:42:ct",
        instance_generation=1,
        version_token="pid:42:ct#1",
        expires_at=NOW + timedelta(minutes=5),
        app_resource_id="app:fixture",
        classification=classification,
        elevated=elevated,
    )
    return authority, ref.resource_id


def _backend(*, passwords: bool = True) -> FakeUiaBackend:
    backend = FakeUiaBackend()
    children = [
        RawElement(
            key="btn",
            control_type="Button",
            name="Increment",
            patterns=frozenset({"invoke"}),
            depth=1,
        ),
        RawElement(key="status", control_type="Text", name="Count: 0", depth=1),
    ]
    if passwords:
        children.append(
            RawElement(
                key="pw",
                control_type="Edit",
                name="Password",
                patterns=frozenset({"value"}),
                is_password=True,
                value_present=True,
                depth=1,
            )
        )
    root = RawElement(
        key="root",
        control_type="Window",
        name="Fixture",
        depth=0,
        children_keys=tuple(c.key for c in children),
    )
    backend.add_root(hwnd=HWND, root=root, descendants=children)
    return backend


def _service(authority=None, backend=None, **kw) -> UiaSnapshotService:
    authority = authority or _authority()[0]
    return UiaSnapshotService(
        authority=authority,
        backend_factory=lambda: backend or _backend(),
        session_id="s1",
        clock=lambda: NOW,
        **kw,
    )


def test_authorized_snapshot_binds_window_instance() -> None:
    authority, window_id = _authority()
    result = _service(authority).inspect(window_id)
    assert result.outcome is UiaOutcome.OK and result.snapshot is not None
    snap = result.snapshot
    assert snap.window_version_token == "pid:42:ct#1"
    assert snap.process_token == "pid:42:ct"
    assert snap.root_element_ref == "el:1"
    assert snap.find("el:2") is not None


def test_password_value_and_name_never_retained() -> None:
    authority, window_id = _authority()
    result = _service(authority).inspect(window_id)
    assert result.snapshot is not None
    pw = next(e for e in result.snapshot.elements if e.runtime_id == "pw")
    assert pw.is_password and pw.name is None and pw.value_present is False


def test_unknown_window_and_unknown_context_denied() -> None:
    authority, _window_id = _authority()
    assert (
        _service(authority).inspect("window:does-not-exist").outcome is UiaOutcome.WINDOW_NOT_FOUND
    )
    authority2, window2 = _authority(classification=ContextClassification.UNKNOWN)
    assert _service(authority2).inspect(window2).outcome is UiaOutcome.PRIVACY_DENIED
    authority3, window3 = _authority(elevated=True)
    assert _service(authority3).inspect(window3).outcome is UiaOutcome.PRIVACY_DENIED


def test_content_inspection_requires_permission() -> None:
    authority, window_id = _authority()
    service = _service(authority, content_inspection_permitted=lambda app: False)
    assert service.inspect(window_id, require_content=True).outcome is UiaOutcome.PRIVACY_DENIED
    assert service.inspect(window_id, require_content=False).outcome is UiaOutcome.OK


def test_truncation_is_explicit_at_limits() -> None:
    authority, window_id = _authority()
    backend = FakeUiaBackend()
    kids = [RawElement(key=f"k{i}", control_type="Text", name=f"n{i}", depth=1) for i in range(50)]
    root = RawElement(
        key="root", control_type="Window", depth=0, children_keys=tuple(k.key for k in kids)
    )
    backend.add_root(hwnd=HWND, root=root, descendants=kids)
    result = _service(authority, backend).inspect(window_id, limits=UiaLimits(max_elements=10))
    assert result.outcome is UiaOutcome.TRUNCATED
    assert result.snapshot is not None and result.snapshot.truncated
    assert result.snapshot.truncated_reason == "element_limit"
    assert len(result.snapshot.elements) == 10
    # Truncation never proves absence:
    assert result.snapshot.completeness == "truncated"


def test_forged_or_unknown_element_ref_rejected() -> None:
    authority, window_id = _authority()
    service = _service(authority)
    snap = service.inspect(window_id).snapshot
    assert snap is not None
    assert (
        service.validate_element(snap.snapshot_id, "el:999").outcome is UiaOutcome.ELEMENT_NOT_FOUND
    )
    assert service.validate_element("snap:forged", "el:1").outcome is UiaOutcome.SNAPSHOT_EXPIRED
    assert service.validate_element(snap.snapshot_id, "el:2").outcome is UiaOutcome.OK


def test_window_replacement_stales_snapshot() -> None:
    authority, window_id = _authority()
    service = _service(authority)
    snap = service.inspect(window_id).snapshot
    assert snap is not None
    authority.register_window(
        hwnd=HWND,
        process_token="pid:42:ct",
        instance_generation=2,
        version_token="pid:42:ct#2",
        expires_at=NOW + timedelta(minutes=5),
        app_resource_id="app:fixture",
        classification=ContextClassification.PERMITTED_METADATA,
    )
    assert service.get(snap.snapshot_id).outcome is UiaOutcome.WINDOW_STALE


def test_snapshot_contract_bounds_enforced() -> None:
    from aether.core.contracts.uia import UiaElement, UiaSnapshot

    with pytest.raises(ValueError):
        UiaSnapshot(
            snapshot_id="s",
            session_id="s1",
            app_resource_id="app:x",
            window_resource_id="window:x",
            window_version_token="v",
            process_token="p",
            observed_at=NOW,
            expires_at=NOW,
            generation=0,
            elements=tuple(
                UiaElement(element_ref=f"el:{i}", runtime_id=str(i), control_type="Text", depth=0)
                for i in range(MAX_ELEMENTS + 1)
            ),
        )


def test_no_generic_interaction_capability_exists() -> None:
    registry = CapabilityRegistry.phase3_with_uia()
    ids = {d.capability_id for d in registry.definitions()}
    assert "uia.invoke_fixture" in ids
    for forbidden in ("uia.invoke", "uia.set_value", "uia.keyboard", "uia.mouse", "uia.setvalue"):
        assert forbidden not in ids


# -- worker reliability ----------------------------------------------------------


def _supervisor(send) -> WorkerSupervisor:
    return WorkerSupervisor(send=send)


def test_worker_malformed_and_stale_responses_rejected() -> None:
    timed = _supervisor(lambda body, timeout: (_ for _ in ()).throw(TimeoutError()))
    assert timed.execute("inspect", {}).outcome is WorkerOutcome.TIMED_OUT
    assert timed.execute("invoke", {"hwnd": 1, "element_key": "x"}).outcome is WorkerOutcome.UNCERTAIN

    def wrong_id(body: bytes, timeout: float) -> bytes:
        import json

        req = json.loads(body)
        return json.dumps(
            {"protocol": req["protocol"], "request_id": "req:other", "status": "ok", "result": {}}
        ).encode()

    assert (
        _supervisor(wrong_id).execute("health", {}).outcome
        is WorkerOutcome.STALE_RESPONSE
    )

    def garbage(body: bytes, timeout: float) -> bytes:
        return b"not-json"

    assert (
        _supervisor(garbage).execute("health", {}).outcome
        is WorkerOutcome.MALFORMED
    )

    def crash(body: bytes, timeout: float) -> bytes:
        raise ConnectionError("worker died")

    assert (
        _supervisor(crash).execute("inspect", {}).outcome
        is WorkerOutcome.CRASHED
    )
    assert (
        _supervisor(crash).execute("invoke", {"hwnd": 1, "element_key": "x"}).outcome
        is WorkerOutcome.UNCERTAIN
    )


def test_worker_request_validation_rejects_code_and_patterns() -> None:
    for payload in ({"python": "x"}, {"shell": "x"}, {"pattern_name": "Invoke"}, {"keys": "abc"}):
        with pytest.raises(ValueError):
            validate_request(
                {
                    "protocol": "aether-uia-worker/1",
                    "request_id": "r1",
                    "operation": "inspect",
                    "payload": payload,
                }
            )
    with pytest.raises(ValueError):
        validate_request(
            {
                "protocol": "aether-uia-worker/1",
                "request_id": "r1",
                "operation": "eval",
                "payload": {},
            }
        )


def test_worker_roundtrip_through_handler() -> None:
    import json

    from aether.adapters.windows.uia_worker_main import handle_request

    backend = _backend()

    def send(body: bytes, timeout: float) -> bytes:
        request = json.loads(body)
        return json.dumps(handle_request(request, backend=backend)).encode()

    result = _supervisor(send).execute("inspect", {"hwnd": HWND})
    assert result.outcome is WorkerOutcome.OK
    assert result.response is not None and len(result.response["elements"]) == 4
    password = next(e for e in result.response["elements"] if e["key"] == "pw")
    assert password["name"] is None
