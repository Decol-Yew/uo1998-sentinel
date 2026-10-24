"""UO クライアントのウィンドウを前面化し、文字列をキーボード入力として送る。

標準ライブラリ(ctypes)のみ。KEYEVENTF_UNICODE で送るのでキーボードレイアウトに
依存せず ASCII 英字をそのまま入力できる。Enter は任意(既定では送らない=ユーザーが
ゲーム内で内容を確認してから自分で Enter)。
"""
from __future__ import annotations

import ctypes
import time
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

ULONG_PTR = ctypes.c_size_t

KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
INPUT_KEYBOARD = 1
VK_RETURN = 0x0D
SW_RESTORE = 9


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class _INPUTunion(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTunion)]


def _send_inputs(inputs):
    n = len(inputs)
    arr = (INPUT * n)(*inputs)
    sent = user32.SendInput(n, arr, ctypes.sizeof(INPUT))
    if sent != n:
        raise ctypes.WinError(ctypes.get_last_error())


def _key_unicode(ch, keyup=False):
    flags = KEYEVENTF_UNICODE | (KEYEVENTF_KEYUP if keyup else 0)
    ki = KEYBDINPUT(wVk=0, wScan=ord(ch), dwFlags=flags, time=0, dwExtraInfo=0)
    return INPUT(type=INPUT_KEYBOARD, u=_INPUTunion(ki=ki))


def _key_vk(vk, keyup=False):
    flags = KEYEVENTF_KEYUP if keyup else 0
    ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=flags, time=0, dwExtraInfo=0)
    return INPUT(type=INPUT_KEYBOARD, u=_INPUTunion(ki=ki))


# キー名 → 仮想キーコード。F13〜F24 はゲームが無視しAHKで拾いやすいので推奨。
VK_MAP = {f"f{i}": 0x70 + (i - 1) for i in range(1, 25)}   # F1=0x70 .. F24=0x87
for _c in range(ord("a"), ord("z") + 1):
    VK_MAP[chr(_c)] = 0x41 + (_c - ord("a"))
for _d in range(0, 10):
    VK_MAP[str(_d)] = 0x30 + _d


def vk_from_name(name: str):
    """'F13' や 'a' 等のキー名を仮想キーコードへ。不明なら None。"""
    if not name:
        return None
    return VK_MAP.get(name.strip().lower())


def send_vk(vk: int):
    """仮想キーを1回押下→離す。フォーカスは奪わない(前面化しない)。
    AHKのグローバルホットキー(例 F13::)を起動する用途。"""
    _send_inputs([_key_vk(vk, False), _key_vk(vk, True)])


def find_window(title_contains: str):
    """タイトルに title_contains を含む可視トップレベルウィンドウの hwnd を返す。"""
    target = title_contains.lower()
    found = []

    EnumProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def cb(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        if target in buf.value.lower():
            found.append(hwnd)
            return False
        return True

    user32.EnumWindows(EnumProc(cb), 0)
    return found[0] if found else None


def focus_window(hwnd) -> bool:
    """対象ウィンドウを前面化してキーボードフォーカスを与える(ベストエフォート)。"""
    try:
        if user32.IsIconic(hwnd):
            user32.ShowWindow(hwnd, SW_RESTORE)
        cur_tid = kernel32.GetCurrentThreadId()
        target_tid = user32.GetWindowThreadProcessId(hwnd, None)
        user32.AttachThreadInput(cur_tid, target_tid, True)
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
        user32.AttachThreadInput(cur_tid, target_tid, False)
        return user32.GetForegroundWindow() == hwnd
    except Exception:
        return False


def send_text(text: str, title_contains: str = "Ultima Online",
              press_enter: bool = False, focus_delay: float = 0.12):
    """UO ウィンドウを前面化し text を入力する。press_enter=True なら最後に Enter。

    戻り値: (ok: bool, message: str)
    """
    hwnd = find_window(title_contains)
    if not hwnd:
        return False, f"ウィンドウが見つかりません(タイトルに『{title_contains}』を含むもの)"
    focus_window(hwnd)
    time.sleep(focus_delay)  # フォーカス確定待ち

    inputs = []
    for ch in text:
        if ch == "\n" or ch == "\r":
            continue
        inputs.append(_key_unicode(ch, keyup=False))
        inputs.append(_key_unicode(ch, keyup=True))
    # 一括送出(長文は分割しても良いが通常は問題なし)
    if inputs:
        _send_inputs(inputs)
    if press_enter:
        time.sleep(0.03)
        _send_inputs([_key_vk(VK_RETURN, False), _key_vk(VK_RETURN, True)])
    return True, "送信しました"
