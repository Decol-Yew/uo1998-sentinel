"""UO 受信パケットのストリーム解析と発言(0x1C/0xAE)抽出。
クライアント 1.25.32 (pre-T2A) 用。長さテーブルは ClassicUO PacketsTable.cs 由来。自動生成。
"""

# 256要素: 各パケットIDの固定長。-1 は可変長(先頭の次に2バイトのサイズ場を持つ)。
PACKET_LEN = [
    104, 5, 7, -1, 2, 5, 5, 7,  # 0x00
    14, 5, 11, 266, -1, 3, -1, 61,  # 0x08
    215, -1, -1, 10, 6, 9, 1, -1,  # 0x10
    -1, -1, -1, 37, -1, 5, 4, 8,  # 0x18
    19, 8, 3, 26, 7, 20, 5, 2,  # 0x20
    5, 1, 5, 2, 2, 17, 15, 10,  # 0x28
    5, 1, 2, 2, 10, 653, -1, 8,  # 0x30
    7, 9, -1, -1, -1, 2, 37, -1,  # 0x38
    201, -1, -1, 553, 713, 5, -1, 11,  # 0x40
    73, 93, 5, 9, -1, -1, 6, 2,  # 0x48
    -1, -1, -1, 2, 12, 1, 11, 110,  # 0x50
    106, -1, -1, 4, 2, 73, -1, 49,  # 0x58
    5, 9, 15, 13, 1, 4, -1, 21,  # 0x60
    -1, -1, 3, 9, 19, 3, 14, -1,  # 0x68
    28, -1, 5, 2, -1, 35, 16, 17,  # 0x70
    -1, 9, -1, 2, -1, 13, 2, -1,  # 0x78
    62, -1, 2, 39, 69, 2, -1, -1,  # 0x80
    66, -1, -1, -1, 11, -1, -1, -1,  # 0x88
    19, 65, -1, 99, -1, 9, -1, 2,  # 0x90
    -1, 26, -1, 258, 309, 51, -1, -1,  # 0x98
    3, 9, 9, 9, 149, -1, -1, 4,  # 0xA0
    -1, -1, 5, -1, -1, -1, -1, 13,  # 0xA8
    -1, -1, -1, -1, -1, 64, 9, -1,  # 0xB0
    -1, 3, 6, 9, 3, -1, -1, -1,  # 0xB8
    36, -1, -1, -1, 6, 203, 1, 49,  # 0xC0
    2, 6, 6, 7, -1, 1, -1, 78,  # 0xC8
    -1, 2, 25, -1, -1, -1, -1, -1,  # 0xD0
    -1, 268, -1, -1, 9, -1, -1, -1,  # 0xD8
    -1, 9, 10, 77, -1, -1, -1, -1,  # 0xE0
    -1, -1, -1, -1, -1, -1, -1, 21,  # 0xE8
    -1, -1, -1, 24, -1, 21, -1, -1,  # 0xF0
    106, -1, -1, -1, -1, -1, -1, -1,  # 0xF8
]


def packet_total_len(buf, off):
    """buf[off] のパケット全長を返す。可変長でサイズ場が未達なら None。"""
    pid = buf[off]
    L = PACKET_LEN[pid]
    if L == -1:
        if off + 3 > len(buf):
            return None
        return (buf[off + 1] << 8) | buf[off + 2]
    return L


class PacketWalker:
    """解凍済みの受信バイト列を順次 feed し、完全なパケットを (pid, bytes) で得る。"""

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf += data
        out = []
        buf = self._buf
        i = 0
        n = len(buf)
        while i < n:
            pid = buf[i]
            L = PACKET_LEN[pid]
            if L == -1:
                if i + 3 > n:
                    break  # サイズ場未達
                L = (buf[i + 1] << 8) | buf[i + 2]
                if L < 3:
                    # 異常: 同期ずれ。1バイト進めて復帰を試みる
                    i += 1
                    continue
            if i + L > n:
                break  # パケット未達
            out.append((pid, bytes(buf[i:i + L])))
            i += L
        del self._buf[:i]
        return out


def _cstr_latin1(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("latin1", "replace")


def _cstr_utf16be(b: bytes) -> str:
    # 2バイト区切りで 0x0000 終端まで
    end = len(b)
    for j in range(0, len(b) - 1, 2):
        if b[j] == 0 and b[j + 1] == 0:
            end = j
            break
    return b[:end].decode("utf-16-be", "replace")


# 発言タイプ名 (参考)
SPEECH_TYPES = {
    0: "regular", 1: "system", 2: "emote", 6: "label",
    7: "whisper", 8: "yell", 9: "spell", 10: "guild", 13: "encoded",
}


def parse_speech(pid, pkt):
    """0x1C(ASCII)/0xAE(Unicode) をパースして dict を返す。発言でなければ None。
       返り値: {proto, serial, body, type, hue, font, lang, name, text}
    """
    if pid == 0x1C:
        # cmd,size(2),serial(4),body(2),type(1),hue(2),font(2),name(30),text(ascii)
        if len(pkt) < 44:
            return None
        serial = int.from_bytes(pkt[3:7], "big")
        body = int.from_bytes(pkt[7:9], "big")
        mtype = pkt[9]
        hue = int.from_bytes(pkt[10:12], "big")
        font = int.from_bytes(pkt[12:14], "big")
        name = _cstr_latin1(pkt[14:44])
        text = _cstr_latin1(pkt[44:])
        return dict(proto="ascii", serial=serial, body=body, type=mtype,
                    hue=hue, font=font, lang="", name=name, text=text)
    if pid == 0xAE:
        # cmd,size(2),serial(4),body(2),type(1),hue(2),font(2),lang(4),name(30),text(utf16be)
        if len(pkt) < 48:
            return None
        serial = int.from_bytes(pkt[3:7], "big")
        body = int.from_bytes(pkt[7:9], "big")
        mtype = pkt[9]
        hue = int.from_bytes(pkt[10:12], "big")
        font = int.from_bytes(pkt[12:14], "big")
        lang = _cstr_latin1(pkt[14:18])
        name = _cstr_latin1(pkt[18:48])
        text = _cstr_utf16be(pkt[48:])
        return dict(proto="unicode", serial=serial, body=body, type=mtype,
                    hue=hue, font=font, lang=lang, name=name, text=text)
    return None


_VALID_SPEECH_TYPES = {0, 1, 2, 6, 7, 8, 9, 10, 13}


def looks_like_speech(ev) -> bool:
    """parse_speech の結果が「本物の発言」として妥当かを構造的に判定する。

    スキャナが誤検出(他パケット中のたまたま0x1Cに見えるバイト列)を弾くための検査。
    """
    if ev is None:
        return False
    if ev["type"] not in _VALID_SPEECH_TYPES:
        return False
    name = ev["name"]
    text = ev["text"]
    if not name:
        return False
    if "�" in name or "�" in text:  # 文字化け(デコード失敗)を除外
        return False
    if not name.isprintable() or not text.isprintable():
        return False
    return True


class SpeechScanner:
    """解凍済みバイト列を走査し、発言(0x1C/0xAE)パケットだけを直接抽出する。

    通常の逐次パケット分割(PacketWalker)は、パケット長テーブルが1バイトでも実クライアント
    と食い違うとフレームがずれ、可変長パケットの長さを誤読して停止する。本スキャナは
    「発言パケットの自己記述サイズ」と「構造的妥当性(looks_like_speech)」だけに依存するため、
    他パケットの長さに関係なく発言を拾え、desyncで止まらない。

    ストリーム対応: チャンク境界で途切れた発言は内部バッファに繰り越す。
    発言は19.5KBあたり数十件程度と疎なので、走査コストは軽い。
    """

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf += data
        buf = self._buf
        out = []
        i = 0
        n = len(buf)
        pending = None  # 末尾に繰り越す不完全発言の開始位置
        while i < n:
            pid = buf[i]
            if pid == 0x1C or pid == 0xAE:
                if i + 3 > n:                       # サイズ場が未達
                    pending = i
                    break
                size = (buf[i + 1] << 8) | buf[i + 2]
                lo, hi = (44, 512) if pid == 0x1C else (48, 1024)
                if lo <= size <= hi:
                    if i + size > n:                # パケット本体が未達
                        pending = i
                        break
                    ev = parse_speech(pid, bytes(buf[i:i + size]))
                    if looks_like_speech(ev):
                        out.append(ev)
                        i += size
                        continue
            i += 1
        # 消費済みは破棄。末尾の不完全発言候補だけ次回へ繰り越す。
        del buf[: (pending if pending is not None else n)]
        return out
