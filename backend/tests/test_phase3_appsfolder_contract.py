"""N2: AppsFolder Shell COM argument/result contract regressions.

The fake Shell objects ENFORCE the documented pywin32 contracts:
ParseDisplayName(hwnd, bindCtx, name) -> (pidl, eaten, attrs);
EnumObjects(hwnd, SHCONTF_NONFOLDERS | SHCONTF_FASTITEMS);
GetDisplayNameOf(pidl, SHGDN_NORMAL) = human name and
GetDisplayNameOf(pidl, SHGDN_FORPARSING) = canonical AUMID.
Any wrong arity, flag or name identity fails the contract here.
Fake seams only - never native Windows evidence.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from aether.adapters.windows.discovery import StdlibWindowsDiscoveryProviders

_IID = object()  # IID_IShellFolder sentinel


class _ShellCon:
    SHCONTF_NONFOLDERS = 0x40
    SHCONTF_FASTITEMS = 0x2000
    SHGDN_NORMAL = 0x0
    SHGDN_FORPARSING = 0x8000


class _Enum:
    def __init__(self, pidls: list[object]) -> None:
        self._pidls = list(pidls)

    def Next(self, count: int) -> list[object]:
        assert count == 1
        if not self._pidls:
            return []
        return [self._pidls.pop(0)]


class _Folder:
    """Items: pidl -> (display, parsing) or an Exception to raise."""

    def __init__(self, items: dict[object, object], enum_flags: list[int]) -> None:
        self._items = items
        self._enum_flags = enum_flags

    def EnumObjects(self, hwnd: int, flags: int) -> _Enum:
        assert hwnd == 0
        self._enum_flags.append(flags)
        return _Enum(list(self._items))

    def GetDisplayNameOf(self, pidl: object, flags: int) -> str:
        item = self._items[pidl]
        if isinstance(item, Exception):
            raise item
        display, parsing = item  # type: ignore[misc]
        if flags == _ShellCon.SHGDN_NORMAL:
            return display  # type: ignore[return-value]
        if flags == _ShellCon.SHGDN_FORPARSING:
            return parsing  # type: ignore[return-value]
        raise AssertionError(f"undocumented SHGDN flags: {flags:#x}")


class _Desktop:
    def __init__(self, folder: _Folder) -> None:
        self._folder = folder

    def ParseDisplayName(self, hwnd: int, bind_ctx: object, name: str):
        # pywin32 contract: exactly three arguments, 3-tuple result.
        assert (hwnd, bind_ctx, name) == (0, None, "shell:AppsFolder")
        return (b"appsfolder-pidl", 0, 0)

    def BindToObject(self, pidl: object, bind_ctx: object, iid: object) -> _Folder:
        assert pidl == b"appsfolder-pidl" and bind_ctx is None and iid is _IID
        return self._folder


def _install(monkeypatch: pytest.MonkeyPatch, desktop: _Desktop) -> list[int]:
    enum_flags: list[int] = desktop._folder._enum_flags
    shell_module = SimpleNamespace(
        SHGetDesktopFolder=lambda: desktop,
        IID_IShellFolder=_IID,
    )
    monkeypatch.setitem(
        sys.modules,
        "pythoncom",
        SimpleNamespace(CoInitialize=lambda: None, CoUninitialize=lambda: None),
    )
    monkeypatch.setitem(sys.modules, "win32com", SimpleNamespace())
    monkeypatch.setitem(
        sys.modules, "win32com.shell", SimpleNamespace(shell=shell_module, shellcon=_ShellCon)
    )
    monkeypatch.setattr(sys, "platform", "win32")
    return enum_flags


def _providers(
    monkeypatch: pytest.MonkeyPatch, items: dict[object, object]
) -> tuple[StdlibWindowsDiscoveryProviders, list[int]]:
    enum_flags: list[int] = []
    desktop = _Desktop(_Folder(items, enum_flags))
    _install(monkeypatch, desktop)
    return StdlibWindowsDiscoveryProviders(), enum_flags


NOTEPAD = "Microsoft.WindowsNotepad_8wekyb3d8bbwe!App"
CALCULATOR = "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"


def test_appsfolder_contract_names_and_aumids(monkeypatch: pytest.MonkeyPatch) -> None:
    providers, enum_flags = _providers(
        monkeypatch,
        {
            b"p1": ("Notepad", NOTEPAD),
            b"p2": ("Calculator", CALCULATOR),
        },
    )
    candidates, status = providers.apps_folder_entries()
    assert status.status == "ok"
    # Leaf applications only, fast enumeration: exactly these flags.
    assert enum_flags == [_ShellCon.SHCONTF_NONFOLDERS | _ShellCon.SHCONTF_FASTITEMS]
    by_name = {c.display_name: c for c in candidates}
    assert set(by_name) == {"Notepad", "Calculator"}
    # Human names and canonical identities are never conflated.
    assert by_name["Notepad"].executable_identity == NOTEPAD
    assert by_name["Calculator"].executable_identity == CALCULATOR
    assert all("!" not in c.display_name for c in candidates)


def test_non_aumid_parsing_name_confers_no_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    providers, _flags = _providers(
        monkeypatch,
        {b"p1": ("Legacy Shell Item", "C:\\Program Files\\Legacy\\legacy.exe")},
    )
    candidates, status = providers.apps_folder_entries()
    assert status.status == "ok"
    assert len(candidates) == 1
    assert candidates[0].display_name == "Legacy Shell Item"
    assert candidates[0].executable_identity is None


def test_item_failure_is_partial_not_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    providers, _flags = _providers(
        monkeypatch,
        {
            b"p1": ("Notepad", NOTEPAD),
            b"p2": RuntimeError("shell item vanished"),
        },
    )
    candidates, status = providers.apps_folder_entries()
    assert [c.display_name for c in candidates] == ["Notepad"]
    assert status.status == "partial"
    assert status.detail == "apps_folder_items_failed"


def test_open_and_enum_stage_failures_are_truthful(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BadDesktop(_Desktop):
        def ParseDisplayName(self, hwnd: int, bind_ctx: object, name: str):
            raise RuntimeError("no shell")

    enum_flags: list[int] = []
    _install(monkeypatch, _BadDesktop(_Folder({}, enum_flags)))
    _candidates, status = StdlibWindowsDiscoveryProviders().apps_folder_entries()
    assert status.status == "unavailable"
    assert status.detail == "apps_folder_open_failed"

    class _BadFolder(_Folder):
        def EnumObjects(self, hwnd: int, flags: int) -> _Enum:
            raise RuntimeError("enum failed")

    _install(monkeypatch, _Desktop(_BadFolder({}, enum_flags)))
    _candidates, status = StdlibWindowsDiscoveryProviders().apps_folder_entries()
    assert status.status == "unavailable"
    assert status.detail == "apps_folder_enum_failed"


def test_off_windows_provider_is_truthfully_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    candidates, status = StdlibWindowsDiscoveryProviders().apps_folder_entries()
    assert candidates == []
    assert status.status == "unavailable"
    assert status.detail == "requires_windows"
