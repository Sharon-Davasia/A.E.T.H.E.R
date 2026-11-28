"""N2: AppsFolder Shell COM argument/result contract regressions.

The fake Shell objects ENFORCE the documented pywin32 contracts:
ParseDisplayName(hwnd, bindCtx, name) -> (eaten, pidl, attrs)
(pinned b312 order, Py_BuildValue("lOl", eaten, pidl, attr));
EnumObjects(hwnd, SHCONTF_NONFOLDERS);
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
    """Constants mirroring pinned pywin32 b312 shellcon.py exactly.

    b312 defines SHCONTF_NONFOLDERS = 64, SHGDN_NORMAL = 0 and
    SHGDN_FORPARSING = 32768 - and NO SHCONTF_FASTITEMS. A fake
    providing constants the pinned dependency lacks would again
    conceal the defect behind apps_folder_enum_failed. Accessing a
    missing constant on this class raises AttributeError naturally,
    exactly like the real pinned module.
    """

    SHCONTF_NONFOLDERS = 0x40
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


# Distinct sentinel values per tuple position: consumed count,
# PIDL and attributes can never be silently interchanged.
EATEN = 17
APPS_PID = b"appsfolder-pidl"
ATTRS = 0x10


class _Desktop:
    def __init__(self, folder: _Folder) -> None:
        self._folder = folder
        self.bound_pidl: object = None

    def ParseDisplayName(self, hwnd: int, bind_ctx: object, name: str):  # type: ignore[no-untyped-def]
        # pywin32 b312 contract ("OOO|k"): up to four arguments,
        # 3-tuple result (eaten, pidl, attributes).
        assert (hwnd, bind_ctx, name) == (0, None, "shell:AppsFolder")
        return (EATEN, APPS_PID, ATTRS)

    def BindToObject(self, pidl: object, bind_ctx: object, iid: object) -> _Folder:
        # Must receive the SECOND tuple value (the PIDL) - not the
        # consumed count and not the attributes.
        assert pidl == APPS_PID and pidl != EATEN and pidl != ATTRS
        assert bind_ctx is None and iid is _IID
        self.bound_pidl = pidl
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
    # BindToObject received the PIDL (second tuple value), proven
    # against distinct eaten/attributes sentinels above.
    # Leaf applications only: exactly the sole supported b312 flag.
    assert enum_flags == [_ShellCon.SHCONTF_NONFOLDERS]
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
    # Bounded stage detail: type only, never the message content.
    assert status.detail == "apps_folder_items_failed:RuntimeError"


def test_open_and_enum_stage_failures_are_truthful(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BadDesktop(_Desktop):
        def ParseDisplayName(self, hwnd: int, bind_ctx: object, name: str):
            raise RuntimeError("no shell")

    enum_flags: list[int] = []
    _install(monkeypatch, _BadDesktop(_Folder({}, enum_flags)))
    _candidates, status = StdlibWindowsDiscoveryProviders().apps_folder_entries()
    assert status.status == "unavailable"
    assert status.detail == "apps_folder_open_failed:RuntimeError"

    class _BadFolder(_Folder):
        def EnumObjects(self, hwnd: int, flags: int) -> _Enum:
            raise RuntimeError("enum failed")

    _install(monkeypatch, _Desktop(_BadFolder({}, enum_flags)))
    _candidates, status = StdlibWindowsDiscoveryProviders().apps_folder_entries()
    assert status.status == "unavailable"
    assert status.detail == "apps_folder_enum_failed:RuntimeError"


def test_off_windows_provider_is_truthfully_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    candidates, status = StdlibWindowsDiscoveryProviders().apps_folder_entries()
    assert candidates == []
    assert status.status == "unavailable"
    assert status.detail == "requires_windows"


class _ComError(Exception):
    """Exception carrying an HRESULT, like pywintypes.com_error."""

    def __init__(self, hresult: int) -> None:
        super().__init__("com failure (message must never surface)")
        self.hresult = hresult


def test_failure_detail_carries_bounded_hresult(monkeypatch: pytest.MonkeyPatch) -> None:
    class _ComBadFolder(_Folder):
        def EnumObjects(self, hwnd: int, flags: int) -> _Enum:
            raise _ComError(-2147024891)  # E_ACCESSDENIED as signed long

    enum_flags: list[int] = []
    _install(monkeypatch, _Desktop(_ComBadFolder({}, enum_flags)))
    _candidates, status = StdlibWindowsDiscoveryProviders().apps_folder_entries()
    assert status.status == "unavailable"
    assert status.detail == "apps_folder_enum_failed:_ComError(0x80070005)"
    assert "must never surface" not in status.detail


def test_com_refs_released_before_couninitialize(monkeypatch: pytest.MonkeyPatch) -> None:
    """Desktop/folder/enumerator __del__ events precede CoUninitialize
    on both the success path and the open-failure path."""
    import weakref

    def run(mode: str) -> list[str]:
        events: list[str] = []

        class _Tracked:
            label = "?"

            def __del__(self) -> None:
                events.append(f"del:{self.label}")

        class _TrackedEnum(_Tracked):
            label = "enum"

            def Next(self, count: int) -> list[object]:
                return []

        class _TrackedFolder(_Tracked):
            label = "folder"

            def __init__(self) -> None:
                self._tracked_enum = _TrackedEnum()

            def EnumObjects(self, hwnd: int, flags: int) -> object:
                return self._tracked_enum

        class _TrackedDesktop(_Tracked):
            label = "desktop"

            def __init__(self) -> None:
                self._tracked_folder = _TrackedFolder()

            def ParseDisplayName(self, hwnd: int, bind_ctx: object, name: str):
                if mode == "open_fails":
                    raise RuntimeError("no shell")
                return (EATEN, APPS_PID, ATTRS)

            def BindToObject(self, pidl: object, bind_ctx: object, iid: object) -> object:
                return self._tracked_folder

        box: list[object] = [_TrackedDesktop()]
        folder_ref = weakref.ref(box[0]._tracked_folder)  # type: ignore[attr-defined]
        shell_module = SimpleNamespace(
            SHGetDesktopFolder=lambda: box.pop(),
            IID_IShellFolder=_IID,
        )

        def _co_init() -> None:
            events.append("co_init")

        def _co_uninit() -> None:
            events.append("co_uninit")

        monkeypatch.setitem(
            sys.modules,
            "pythoncom",
            SimpleNamespace(CoInitialize=_co_init, CoUninitialize=_co_uninit),
        )
        monkeypatch.setitem(sys.modules, "win32com", SimpleNamespace())
        monkeypatch.setitem(
            sys.modules,
            "win32com.shell",
            SimpleNamespace(shell=shell_module, shellcon=_ShellCon),
        )
        monkeypatch.setattr(sys, "platform", "win32")
        StdlibWindowsDiscoveryProviders().apps_folder_entries()
        assert folder_ref() is None
        return events

    for mode in ("ok", "open_fails"):
        events = run(mode)
        assert events[0] == "co_init"
        assert events[-1] == "co_uninit"
        assert "del:desktop" in events
        assert events.index("del:desktop") < events.index("co_uninit")
        if mode == "ok":
            assert "del:folder" in events
            assert "del:enum" in events
            assert events.index("del:folder") < events.index("co_uninit")
            assert events.index("del:enum") < events.index("co_uninit")
