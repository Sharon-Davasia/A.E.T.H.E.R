"""Exact UI-operation binding (CP5 sec.8): trusted approval/grant reuse.

A binding is issued by trusted backend code for one exact operation:
one task/step, one immutable plan revision+hash, one capability,
canonical arguments, one app, one window instance version, one
snapshot (id + generation), one transient element (ref + UIA runtime
id), one approved pattern, one declared intended effect, one session
and controlled activation scope, with issuance/expiry and single-use
consumption. Approving one element/pattern never approves another;
inspection approval never authorizes interaction; a changed snapshot
or target needs fresh validation and approval. This reuses the
navigation confirmation principles — there is no second policy
broker, and filesystem ``ApprovedResourceVersion`` validation is
untouched.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import uuid4

BINDING_TTL = timedelta(minutes=5)


class UiBindingError(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class UiOperationBinding:
    binding_id: str
    task_id: str
    step_id: str
    plan_revision: int
    plan_hash: str
    capability_id: str
    arguments_sha256: str
    app_resource_id: str
    window_resource_id: str
    window_version_token: str
    snapshot_id: str
    snapshot_generation: int
    element_ref: str
    element_runtime_id: str
    pattern: str
    intended_effect: str
    session_id: str
    activation_scope: str
    issued_at: datetime
    expires_at: datetime
    expected_precondition: str = ""
    expected_postcondition: str = ""

    def digest(self) -> str:
        payload = {
            "task_id": self.task_id,
            "step_id": self.step_id,
            "plan_revision": self.plan_revision,
            "plan_hash": self.plan_hash,
            "capability_id": self.capability_id,
            "arguments_sha256": self.arguments_sha256,
            "app_resource_id": self.app_resource_id,
            "window_resource_id": self.window_resource_id,
            "window_version_token": self.window_version_token,
            "snapshot_id": self.snapshot_id,
            "snapshot_generation": self.snapshot_generation,
            "element_ref": self.element_ref,
            "element_runtime_id": self.element_runtime_id,
            "pattern": self.pattern,
            "intended_effect": self.intended_effect,
            "expected_precondition": self.expected_precondition,
            "expected_postcondition": self.expected_postcondition,
            "session_id": self.session_id,
            "activation_scope": self.activation_scope,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


def arguments_digest(arguments: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def issue_binding(
    *,
    task_id: str,
    step_id: str,
    plan_revision: int,
    plan_hash: str,
    capability_id: str,
    arguments: dict[str, object],
    app_resource_id: str,
    window_resource_id: str,
    window_version_token: str,
    snapshot_id: str,
    snapshot_generation: int,
    element_ref: str,
    element_runtime_id: str,
    pattern: str,
    intended_effect: str,
    session_id: str,
    activation_scope: str,
    now: datetime,
    expected_precondition: str = "",
    expected_postcondition: str = "",
) -> UiOperationBinding:
    return UiOperationBinding(
        binding_id=f"uibind:{uuid4()}",
        task_id=task_id,
        step_id=step_id,
        plan_revision=plan_revision,
        plan_hash=plan_hash,
        capability_id=capability_id,
        arguments_sha256=arguments_digest(arguments),
        app_resource_id=app_resource_id,
        window_resource_id=window_resource_id,
        window_version_token=window_version_token,
        snapshot_id=snapshot_id,
        snapshot_generation=snapshot_generation,
        element_ref=element_ref,
        element_runtime_id=element_runtime_id,
        pattern=pattern,
        intended_effect=intended_effect,
        session_id=session_id,
        activation_scope=activation_scope,
        issued_at=now,
        expires_at=now + BINDING_TTL,
    )
