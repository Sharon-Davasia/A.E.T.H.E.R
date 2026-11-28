"""AETHER native synthetic fixture (Windows only, stdlib ctypes).

The smallest standard-controls fixture for Phase 3 native acceptance:
an identifiable window with a status text (`Count: N`), an Increment
button with a deterministic effect, a disabled button, a synthetic
password edit, a modal-dialog trigger, controlled element replacement
(the Increment button is destroyed and recreated, producing a new UIA
runtime identity), a controlled delayed-response mode and a
deterministic reset. Synthetic data only: no files, no network, no
settings, no other applications, no elevation.

Run (owner's environment, Python 3.12.10):

    py -3.12 aether_fixture.py [--delayed]

Control contract (established by trusted fixture identity + observed
UIA metadata at acceptance time — runtime identifiers are *observed*,
never assumed): window class ``AetherFixtureWindow``, title
``AETHER Fixture``; control IDs: status=101, increment=102,
disabled=103, password=104, modal=105, replace=106, reset=107.
"""

from __future__ import annotations

import ctypes
import sys

if sys.platform != "win32":  # pragma: no cover - native-only program
    print("aether_fixture: Windows only", file=sys.stderr)
    raise SystemExit(2)

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WS_OVERLAPPEDWINDOW = 0x00CF0000
WS_VISIBLE = 0x10000000
WS_CHILD = 0x40000000
WS_TABSTOP = 0x00010000
BS_PUSHBUTTON = 0x00000000
ES_PASSWORD = 0x0020
SS_LEFT = 0x00000000
WM_DESTROY = 0x0002
WM_COMMAND = 0x0111
SW_SHOWNORMAL = 1

ID_STATUS = 101
ID_INCREMENT = 102
ID_DISABLED = 103
ID_PASSWORD = 104
ID_MODAL = 105
ID_REPLACE = 106
ID_RESET = 107

_state = {
    "count": 0,
    "delayed": "--delayed" in sys.argv,
    "hwnd": None,
    "increment": None,
}


def _text(hwnd: int, text: str) -> None:
    user32.SetWindowTextW(hwnd, text)


def _status_hwnd() -> int:
    return user32.GetDlgItem(_state["hwnd"], ID_STATUS)


def _refresh() -> None:
    _text(_status_hwnd(), f"Count: {_state['count']}")


def _create_increment(parent: int) -> int:
    return user32.CreateWindowExW(
        0,
        "BUTTON",
        "Increment",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        20,
        50,
        120,
        30,
        parent,
        ID_INCREMENT,
        kernel32.GetModuleHandleW(None),
        None,
    )


WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p
)


def _wndproc(hwnd, msg, wparam, lparam):  # type: ignore[no-untyped-def]
    if msg == WM_COMMAND:
        control = wparam & 0xFFFF
        if control == ID_INCREMENT:
            if _state["delayed"]:
                ctypes.windll.kernel32.Sleep(10000)  # controlled delayed response
            _state["count"] += 1
            _refresh()
            return 0
        if control == ID_MODAL:
            user32.MessageBoxW(
                hwnd, "AETHER fixture modal dialog", "AETHER Fixture", 0x40
            )
            return 0
        if control == ID_REPLACE:
            # Controlled element replacement: the old control (and its
            # UIA runtime identity) is destroyed; a new one appears.
            old = user32.GetDlgItem(hwnd, ID_INCREMENT)
            if old:
                user32.DestroyWindow(old)
            _state["increment"] = _create_increment(hwnd)
            return 0
        if control == ID_RESET:
            _state["count"] = 0
            _refresh()
            return 0
    if msg == WM_DESTROY:
        user32.PostQuitMessage(0)
        return 0
    return user32.DefWindowProcW(hwnd, msg, wparam, lparam)


class WNDCLASS(ctypes.Structure):
    _fields_ = [
        ("style", ctypes.c_uint),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", ctypes.c_void_p),
        ("hIcon", ctypes.c_void_p),
        ("hCursor", ctypes.c_void_p),
        ("hbrBackground", ctypes.c_void_p),
        ("lpszMenuName", ctypes.c_wchar_p),
        ("lpszClassName", ctypes.c_wchar_p),
    ]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", ctypes.c_void_p),
        ("message", ctypes.c_uint),
        ("wParam", ctypes.c_void_p),
        ("lParam", ctypes.c_void_p),
        ("time", ctypes.c_ulong),
        ("pt_x", ctypes.c_long),
        ("pt_y", ctypes.c_long),
    ]


def main() -> int:
    instance = kernel32.GetModuleHandleW(None)
    proc = WNDPROC(_wndproc)
    klass = WNDCLASS(
        style=0,
        lpfnWndProc=proc,
        cbClsExtra=0,
        cbWndExtra=0,
        hInstance=instance,
        hIcon=None,
        hCursor=user32.LoadCursorW(None, 32512),
        hbrBackground=ctypes.c_void_p(6),
        lpszMenuName=None,
        lpszClassName="AetherFixtureWindow",
    )
    user32.RegisterClassW(ctypes.byref(klass))
    hwnd = user32.CreateWindowExW(
        0,
        "AetherFixtureWindow",
        "AETHER Fixture",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        100,
        100,
        420,
        320,
        None,
        None,
        instance,
        None,
    )
    _state["hwnd"] = hwnd

    def control(
        class_name: str,
        text: str,
        style: int,
        x: int,
        y: int,
        w: int,
        h: int,
        cid: int,
        enabled: bool = True,
    ) -> int:
        handle = user32.CreateWindowExW(
            0,
            class_name,
            text,
            WS_CHILD | WS_VISIBLE | style,
            x,
            y,
            w,
            h,
            hwnd,
            cid,
            instance,
            None,
        )
        if not enabled:
            user32.EnableWindow(handle, False)
        return handle

    control("STATIC", "Count: 0", SS_LEFT, 20, 15, 360, 25, ID_STATUS)
    _state["increment"] = _create_increment(hwnd)
    control(
        "BUTTON",
        "Disabled action",
        BS_PUSHBUTTON | WS_TABSTOP,
        160,
        50,
        140,
        30,
        ID_DISABLED,
        enabled=False,
    )
    control("EDIT", "", ES_PASSWORD | WS_TABSTOP | 0x0080, 20, 95, 200, 25, ID_PASSWORD)
    control(
        "BUTTON", "Open dialog", BS_PUSHBUTTON | WS_TABSTOP, 20, 135, 120, 30, ID_MODAL
    )
    control(
        "BUTTON",
        "Replace control",
        BS_PUSHBUTTON | WS_TABSTOP,
        160,
        135,
        140,
        30,
        ID_REPLACE,
    )
    control("BUTTON", "Reset", BS_PUSHBUTTON | WS_TABSTOP, 20, 180, 120, 30, ID_RESET)

    user32.ShowWindow(hwnd, SW_SHOWNORMAL)
    user32.UpdateWindow(hwnd)
    message = MSG()
    while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(message))
        user32.DispatchMessageW(ctypes.byref(message))
    return 0


if __name__ == "__main__":  # pragma: no cover - native entry point
    raise SystemExit(main())
