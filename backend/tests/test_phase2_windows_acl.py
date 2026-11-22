"""S14-10: exact Windows DACL verification.

The defect: ``_verify_windows`` accepted any descriptor that *contained* an owner
ACE, so ``D:P(A;;FA;;;OW)(A;;FA;;;WD)`` — owner plus Everyone — was reported as
owner-only. The check was a substring test, not an evaluation of the inventory.

The SDDL parser and its evaluator are pure logic and are tested here on Linux.
What is *not* tested here is that Windows produces the SDDL we expect, or that
``SetFileSecurityW`` succeeds: those require NTFS and remain NOT VERIFIED until
executed on the target machine. These tests prove the verifier is strict, not that
the platform behaves.
"""

from __future__ import annotations

import pytest

from aether.core.security.file_permissions import (
    PermissionEnforcementError,
    evaluate_windows_dacl,
    parse_sddl_dacl,
)

TARGET = "vault.key"

# Well-known SDDL principals used in the negative cases.
EVERYONE = "WD"
BUILTIN_USERS = "BU"
AUTHENTICATED_USERS = "AU"
SYSTEM = "SY"
ADMINISTRATORS = "BA"
OWNER = "OW"


def _evaluate(sddl: str):
    from pathlib import Path

    return evaluate_windows_dacl(Path(TARGET), sddl)


# ---------------------------------------------------------------------------
# A. The correct descriptor is accepted
# ---------------------------------------------------------------------------


def test_the_applied_descriptor_is_accepted() -> None:
    report = _evaluate("D:P(A;;FA;;;OW)")
    assert report.enforced
    assert report.platform == "windows"
    assert report.detail == "D:P(A;;FA;;;OW)"


def test_the_owner_rights_spelling_is_accepted() -> None:
    assert _evaluate("D:P(A;;FA;;;S-1-3-4)").enforced


def test_a_protected_owner_only_dacl_with_several_owner_aces_is_accepted() -> None:
    """Redundant owner ACEs are still owner-only, so they are not a finding."""

    assert _evaluate("D:P(A;;FA;;;OW)(A;;FR;;;OW)").enforced


# ---------------------------------------------------------------------------
# B. Extra grants are rejected -- the headline defect
# ---------------------------------------------------------------------------


def test_everyone_is_rejected() -> None:
    report = _evaluate("D:P(A;;FA;;;OW)(A;;FA;;;WD)")
    assert not report.enforced
    assert "unauthorized principal WD" in report.detail


def test_everyone_with_read_only_access_is_still_rejected() -> None:
    """Read access to a key is disclosure, which is the whole risk."""

    report = _evaluate("D:P(A;;FA;;;OW)(A;;FR;;;WD)")
    assert not report.enforced
    assert "unauthorized principal WD" in report.detail


def test_builtin_users_is_rejected() -> None:
    report = _evaluate(f"D:P(A;;FA;;;{OWNER})(A;;FA;;;{BUILTIN_USERS})")
    assert not report.enforced
    assert BUILTIN_USERS in report.detail


def test_authenticated_users_is_rejected() -> None:
    report = _evaluate(f"D:P(A;;FA;;;{OWNER})(A;;FA;;;{AUTHENTICATED_USERS})")
    assert not report.enforced


def test_an_unrelated_sid_is_rejected() -> None:
    """A named account or group the threat model does not include."""

    report = _evaluate("D:P(A;;FA;;;OW)(A;;FA;;;S-1-5-21-1111-2222-3333-1001)")
    assert not report.enforced
    assert "S-1-5-21-1111-2222-3333-1001" in report.detail


def test_system_alone_is_not_accepted() -> None:
    """SYSTEM is not in the threat model's allowance, so it is a finding.

    If SYSTEM access is ever wanted, it must be justified in the threat model and
    added deliberately, not accepted because it happens to be privileged.
    """

    report = _evaluate(f"D:P(A;;FA;;;{OWNER})(A;;FA;;;{SYSTEM})")
    assert not report.enforced
    assert SYSTEM in report.detail


def test_administrators_alone_is_not_accepted() -> None:
    report = _evaluate(f"D:P(A;;FA;;;{OWNER})(A;;FA;;;{ADMINISTRATORS})")
    assert not report.enforced
    assert ADMINISTRATORS in report.detail


def test_the_headline_regression_from_the_review() -> None:
    """The exact descriptor the substring check would have passed."""

    sddl = "D:P(A;;FA;;;OW)(A;;FA;;;WD)"
    # The old check: 'D:P' prefix plus a substring for the owner ACE.
    assert sddl.startswith("D:P")
    assert ";;FA;;;OW)" in sddl
    # The new check rejects it.
    assert not _evaluate(sddl).enforced


# ---------------------------------------------------------------------------
# C. Inheritance and DACL shape
# ---------------------------------------------------------------------------


def test_an_unprotected_dacl_is_rejected() -> None:
    """Without P, inherited ACEs from the parent can apply."""

    report = _evaluate("D:(A;;FA;;;OW)")
    assert not report.enforced
    assert "not protected" in report.detail


def test_an_inherited_owner_ace_is_rejected() -> None:
    """ID flags mark the ACE inherited; it is not ours to rely on."""

    report = _evaluate("D:P(A;ID;FA;;;OW)")
    protected, aces = parse_sddl_dacl("D:P(A;ID;FA;;;OW)")
    assert protected
    assert aces[0].inherited
    assert not report.enforced
    assert "inherited ACE" in report.detail


def test_a_deny_ace_is_not_accepted_even_with_an_owner_allow() -> None:
    report = _evaluate("D:P(A;;FA;;;OW)(D;;FR;;;WD)")
    assert not report.enforced
    # A deny is a different shape; the verifier refuses to reason about it.
    assert "non-allow ACE" in report.detail


def test_an_empty_dacl_is_rejected() -> None:
    report = _evaluate("D:P")
    assert not report.enforced
    assert "grants no access" in report.detail


def test_a_null_dacl_is_rejected() -> None:
    """A null DACL grants everyone full control; it must never read as safe."""

    report = _evaluate("D:NO_ACCESS_CONTROL")
    assert not report.enforced


def test_a_descriptor_with_no_dacl_section_is_rejected() -> None:
    with pytest.raises(PermissionEnforcementError) as refused:
        _evaluate("O:BAG:BAD:PAI(A;;FA;;;OW)")
    assert refused.value.reason_code == "permissions_windows_unparseable"


def test_a_truncated_ace_is_rejected() -> None:
    with pytest.raises(PermissionEnforcementError) as refused:
        parse_sddl_dacl("D:P(A;;FA;;;OW")
    assert refused.value.reason_code == "permissions_windows_unparseable"


def test_an_ace_with_missing_fields_is_rejected() -> None:
    with pytest.raises(PermissionEnforcementError):
        parse_sddl_dacl("D:P(A;;FA)")


def test_a_non_hex_mask_is_rejected() -> None:
    with pytest.raises(PermissionEnforcementError) as refused:
        parse_sddl_dacl("D:P(A;;ZZ;;OW)")
    assert refused.value.reason_code == "permissions_windows_unparseable"


def test_an_inherit_only_ace_with_no_access_bits_is_still_flagged() -> None:
    report = _evaluate("D:P(A;;FA;;;OW)(A;;0x0;;;WD)")
    assert not report.enforced


# ---------------------------------------------------------------------------
# D. The parser reports what it saw
# ---------------------------------------------------------------------------


def test_the_parser_returns_the_full_ace_inventory() -> None:
    protected, aces = parse_sddl_dacl("D:P(A;;FA;;;OW)(A;;FR;;;WD)")
    assert protected
    assert len(aces) == 2
    assert aces[0].principal == "OW"
    assert aces[0].mask == 0x1F01FF
    assert aces[1].principal == "WD"
    assert not aces[1].inherited


def test_ace_access_mask_is_interpreted_not_substring_matched() -> None:
    """0x0 must not be mistaken for access just because an ACE exists."""

    report = _evaluate("D:P(A;;FA;;;OW)(A;;0;;;WD)")
    assert not report.enforced


def test_the_evaluator_is_pure_and_does_not_touch_the_filesystem() -> None:
    """These checks must be usable on a descriptor with no file present."""

    assert _evaluate("D:P(A;;FA;;;OW)").enforced
    assert not _evaluate("D:P(A;;FA;;;OW)(A;;FA;;;WD)").enforced


# ---------------------------------------------------------------------------
# E. Platform honesty
# ---------------------------------------------------------------------------


def test_windows_acl_acceptance_is_not_claimed_from_linux() -> None:
    """Nothing in this suite asserts that Windows behaves this way.

    It asserts that IF Windows reports a descriptor, the verifier judges it
    strictly. The platform-level claim stays with the Windows verifier.
    """

    import os

    report = _evaluate("D:P(A;;FA;;;OW)")
    if os.name == "nt":  # pragma: no cover - not executed here
        assert report.platform == "windows"
    else:
        # On Linux the parser still runs; it is a pure function of the string.
        assert report.platform == "windows"
        assert _evaluate("D:P(A;;FA;;;OW)(A;;FA;;;WD)").enforced is False
