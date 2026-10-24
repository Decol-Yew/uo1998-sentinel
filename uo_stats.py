"""UO 受信ストリームから自分のステータス(HP/マナ/スタミナ/所持重量)を抽出するスキャナ。

マナアラーム等の監視ツール(monitor.py)用。capture.UOCapture に scanner_factory として
渡して使う(翻訳ツールと同じ受信下層を流用)。

扱うパケット(いずれもサーバー→クライアント):
  0x11 StatusBarInfo (可変, type>0 で str・stam・mana・gold・weight を含む。名前付き)
  0x2D MobileAttributes (17B: hp/mana/stam の max&cur)
  0xA1 hp更新 / 0xA2 mana更新 / 0xA3 stam更新 (各9B: serial, max, cur)

厳格な逐次フレーミングは1つの可変長誤読で止まるため、可変長が不当なら1バイト進めて
再同期する寛容スキャンにしている。ただし再同期中はゴミ領域を走査するため、固定長
パケットが偶然マッチしうる。そこで各値を厳しく妥当性検査し、壊れたイベントは出さない
(cur<=max、最大値は現実的範囲、名前は印字可能、等)。各イベントは dict で yield。
"""
from __future__ import annotations

import struct

from uo_packets import PACKET_LEN

_U16 = lambda b, o: struct.unpack_from(">H", b, o)[0]
_U32 = lambda b, o: struct.unpack_from(">I", b, o)[0]

_MAX_VAR = 4096    # 可変長がこれを超えたら同期ずれ → 再同期
_STAT_CAP = 2000   # hp/mana/stam の最大値の上限(これを超える値は壊れ)


def _ok(cur, mx):
    return 0 < mx <= _STAT_CAP and 0 <= cur <= mx


def _ok_name(s):
    return 1 <= len(s) <= 20 and all(0x20 <= ord(c) <= 0x7E for c in s)


def _name(b, off, ln=30):
    return b[off:off + ln].split(b"\x00", 1)[0].decode("latin1", "replace")


def parse_status(b):
    """0x11 を dict へ。type>0 なら mana/stam/weight 等も含む。妥当でなければ None。"""
    if len(b) < 43:
        return None
    name = _name(b, 7)
    if not _ok_name(name):
        return None
    hp_cur, hp_max = _U16(b, 37), _U16(b, 39)
    if not _ok(hp_cur, hp_max):
        return None
    serial = _U32(b, 3)
    d = {"t": "full", "serial": serial, "name": name, "hp": hp_cur, "hp_max": hp_max}
    typ = b[42]
    if typ > 0 and len(b) >= 66:
        s = _U16(b, 44)
        stam_c, stam_m = _U16(b, 50), _U16(b, 52)
        mana_c, mana_m = _U16(b, 54), _U16(b, 56)
        weight = _U16(b, 64)
        if not (_ok(stam_c, stam_m) and _ok(mana_c, mana_m) and 0 < s <= _STAT_CAP
                and weight <= 60000):
            return None
        d["str"] = s
        d["stam"], d["stam_max"] = stam_c, stam_m
        d["mana"], d["mana_max"] = mana_c, mana_m
        d["weight"] = weight
        # 1998クライアントは maxWeight 未送(type=1)なので str から概算。
        d["weight_max"] = int(40 + 3.5 * s)
        if typ >= 3 and len(b) >= 68:
            wm = _U16(b, 66)
            if 0 < wm <= 60000:
                d["weight_max"] = wm
    return d


class StatScanner:
    """解凍後バイト列を feed し、妥当なステータスイベント(dict)だけ yield する。"""

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf += data
        buf = self._buf
        i, n = 0, len(buf)
        out = []
        while i < n:
            pid = buf[i]
            L = PACKET_LEN[pid]
            if L == -1:
                if i + 3 > n:
                    break
                L = (buf[i + 1] << 8) | buf[i + 2]
                if L < 3 or L > _MAX_VAR:
                    i += 1
                    continue
            if i + L > n:
                break
            ev = self._parse(pid, buf, i, L)
            if ev is not None:
                out.append(ev)
            i += L
        del self._buf[:i]
        return out

    def _parse(self, pid, buf, i, L):
        try:
            if pid == 0x11:
                return parse_status(bytes(buf[i:i + L]))
            if pid == 0x2D and L == 17:
                hp, hpm = _U16(buf, i + 7), _U16(buf, i + 5)
                mn, mnm = _U16(buf, i + 11), _U16(buf, i + 9)
                st, stm = _U16(buf, i + 15), _U16(buf, i + 13)
                if _ok(hp, hpm) and _ok(mn, mnm) and _ok(st, stm):
                    return {"t": "attrs", "serial": _U32(buf, i + 1),
                            "hp": hp, "hp_max": hpm, "mana": mn, "mana_max": mnm,
                            "stam": st, "stam_max": stm}
            elif pid in (0xA1, 0xA2, 0xA3) and L == 9:
                mx, cur = _U16(buf, i + 5), _U16(buf, i + 7)
                if _ok(cur, mx):
                    kind = {0xA1: "hp", 0xA2: "mana", 0xA3: "stam"}[pid]
                    return {"t": kind, "serial": _U32(buf, i + 1), "max": mx, "cur": cur}
        except Exception:  # noqa: BLE001
            return None
        return None
