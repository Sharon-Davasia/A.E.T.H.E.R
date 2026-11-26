"""G05: real native fixture contract.

The fake fixture's transient keys (``fixture-status`` /
``fixture-increment``) are *simulated-provider* identities only. A real
native fixture window is identified by the trusted chain:

    approved fixture executable identity
    -> verified fixture process instance (app/window authority tokens)
    -> verified window instance version
    -> known fixture control contract (below)
    -> actual transient UIA runtime identity taken from the current
       authorized snapshot

This module defines the known control contract and the narrow
fixture-counter reading rules. Reading the counter is a fixture-
specific authorization for the status control only; it is not
unrestricted content mode and it never applies to any other app.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aether.core.contracts.uia import UiaElement, UiaSnapshot

FIXTURE_EXECUTABLE_NAME = "AETHERFixture.exe"
FIXTURE_WINDOW_TITLE = "AETHER Fixture"
STATUS_AUTOMATION_ID = "101"
INCREMENT_AUTOMATION_ID = "102"
DISABLED_AUTOMATION_ID = "103"
PASSWORD_AUTOMATION_ID = "104"
MODAL_AUTOMATION_ID = "105"
REPLACE_AUTOMATION_ID = "106"
RESET_AUTOMATION_ID = "107"
DELAY_TOGGLE_AUTOMATION_ID = "108"

_COUNT = re.compile(r"^Count: (0|[1-9][0-9]{0,9})$")


@dataclass(frozen=True, slots=True)
class FixtureElements:
    status: UiaElement
    increment: UiaElement
    count: int

    @property
    def expected_after_increment(self) -> int:
        return self.count + 1


class FixtureContractError(ValueError):
    pass


def parse_fixture_count(name: str | None) -> int:
    if name is None:
        raise FixtureContractError("fixture counter is unavailable")
    match = _COUNT.match(name.strip())
    if match is None:
        raise FixtureContractError("fixture counter has an unexpected shape")
    return int(match.group(1))


def _unique(snapshot: UiaSnapshot, *, automation_id: str, control_type: str) -> UiaElement:
    matches = [
        e
        for e in snapshot.elements
        if e.automation_id == automation_id and e.control_type == control_type
    ]
    if len(matches) != 1:
        raise FixtureContractError("fixture control contract is not uniquely satisfied")
    return matches[0]


def resolve_fixture_elements(snapshot: UiaSnapshot) -> FixtureElements:
    """Resolve status+Increment from a current authorized snapshot.

    Rejects missing/duplicated/substituted controls, a disabled or
    offscreen Increment, any password control carrying a name/value,
    and an unparseable counter. The returned increment element keeps
    its actual transient runtime identity from this snapshot; callers
    must bind that exact identity and re-resolve before dispatch.
    """
    status = _unique(snapshot, automation_id=STATUS_AUTOMATION_ID, control_type="Text")
    increment = _unique(snapshot, automation_id=INCREMENT_AUTOMATION_ID, control_type="Button")
    if not increment.is_enabled or increment.is_offscreen:
        raise FixtureContractError("fixture increment control is not dispatchable")
    if "Invoke" not in increment.patterns:
        raise FixtureContractError("fixture increment control lacks the Invoke pattern")
    for element in snapshot.elements:
        if element.is_password and (element.name is not None or element.value_present):
            raise FixtureContractError("password control exposed content")
    return FixtureElements(
        status=status, increment=increment, count=parse_fixture_count(status.name)
    )


def validate_fixture_launch_identity(*, executable_identity: str, launch_method: str) -> None:
    """Only the reproducibly built fixture executable may be launched.

    The Python fixture source is never launched as a script and no
    arbitrary interpreter/argument mechanism is permitted.
    """
    normalized = executable_identity.replace("/", "\\").casefold()
    if normalized.endswith((".py", ".pyw", ".ps1", ".bat", ".cmd")):
        raise FixtureContractError("fixture scripts are not launchable")
    if (
        not normalized.endswith("\\" + FIXTURE_EXECUTABLE_NAME.casefold())
        and normalized != FIXTURE_EXECUTABLE_NAME.casefold()
    ):
        raise FixtureContractError("fixture executable identity is not the approved build")
    if launch_method != "approved_executable":
        raise FixtureContractError("fixture launch method is not approved")
