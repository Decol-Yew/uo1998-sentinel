"""UO:1998 パッシブ・キャプチャ受信。

Npcap + Scapy を使い、サーバー→クライアント方向のTCPを *観測* して
Huffman解凍 → 発言(0x1C/0xAE)抽出し、on_speech コールバックへ渡す。

重要(安全性・安定性):
  経路に割り込まない。パケットの改変も、サーバーへの送信も一切しない。
  したがってゲーム接続を止めたりコネロスを起こしたりする仕組みを持たない。
  (旧プロキシ方式=中間者の、放置時コネロス/再接続破綻を根本回避する。)

設計:
  - キャプチャのコールバック(_on_packet)は *キューに積むだけ* の軽量処理に徹する。
    (重い解凍をここで行うと取りこぼしが増え、TCP再構成が詰まって解読が止まるため。)
  - 解読は専用スレッド(_analyze)で実施: TCP再構成→Huffman解凍→発言抽出→on_speech。
  - TCPハンドシェイク(SYN-ACK)でサーバISNを掴み、*接続の先頭から* ストリームを
    再構成する(Huffmanは1バイト目から読まないと解読できないため)。

前提: Npcap 導入済み。キャプチャには管理者権限が必要(run.bat が自動昇格)。
      クライアントは実サーバへ直結する(LOGIN.CFG は実サーバを指したままにする)。
"""
from __future__ import annotations

import os
import queue
import struct
import sys
import threading
import time

import uo_huffman
import uo_packets

_SYN = 0x02
_ACK = 0x10
_FIN = 0x01
_RST = 0x04

# 単一exe化(sys.frozen)時は実行ファイルのあるフォルダ、通常はこのファイルの場所。
# デバッグログ/ダンプを exe の隣(書き込み可)に出すため。
if getattr(sys, "frozen", False):
    _HERE = os.path.dirname(os.path.abspath(sys.executable))
else:
    _HERE = os.path.dirname(os.path.abspath(__file__))
_DUMP_CAP = 512 * 1024  # デバッグ時に解凍後ストリームをダンプする上限バイト数
_RAW_CAP = 64 * 1024 * 1024  # 生TCPセグメント記録の上限(再同期検証/ズレ解析用サンプル採取)


class _S2CReassembler:
    """サーバー→クライアント 1方向のTCPペイロードを seq 順に並べ直す。

    - 基準 seq(next)から連続する分だけを確定して返す
    - 再送(古いseq)は破棄、前方オーバーラップは先頭を切り詰め
    - 順序が飛んだ分は gap が埋まるまでバッファ(欠落はHuffmanへ渡さない)
    (seqラップ(2^32)は1セッションでは実質起きないため未対応)

    排出(drain)はオーバーラップを正しく畳む: buf内の最小startを見て、next を
    跨ぐ/手前にあるセグメントは「next からの尾部だけ」を emit する。
    (旧実装は next に完全一致する key しか消費せず、TCP再分割で生じる
     オーバーラップしたセグメントの尾部を取りこぼし、next より手前の key を buf に
     残したまま恒久停止する不具合があった。実キャプチャの『頭出しロスト』の主因。)
    """

    def __init__(self, next_seq=None):
        self.next = next_seq
        self.buf: dict[int, bytes] = {}

    def add(self, seq: int, data: bytes) -> bytes:
        if not data:
            return b""
        if self.next is None:
            self.next = seq
        end = seq + len(data)
        if end <= self.next:          # 完全に古い再送
            return b""
        if seq < self.next:           # 前方が重複 → 先頭を切り詰め
            data = data[self.next - seq:]
            seq = self.next
        # 同じ start には長い方を残す(短い再送で長いバッファを縮めない)
        old = self.buf.get(seq)
        if old is None or len(data) > len(old):
            self.buf[seq] = data
        # 確定排出: 最小startから、next を跨ぐ/手前の分の尾部を順に emit
        out = bytearray()
        while self.buf:
            s = min(self.buf)
            if s > self.next:          # 真の前方ギャップ(本当の欠落) → 埋まるまで待つ
                break
            seg = self.buf.pop(s)
            e = s + len(seg)
            if e <= self.next:         # 既に出した範囲 → 捨てる
                continue
            out += seg[self.next - s:]  # next からの未出分だけ
            self.next = e
        return bytes(out)


class _RawDump:
    """デバッグ用: 再構成前の生TCPセグメント(seq/payload)をそのまま記録する。

    用途(受信ズレ=頭出しロストの Plan B):
      - 再同期アルゴリズムの検証用サンプル採取。
      - 受信ズレの発生源(TCP再構成のどこで1バイト狂うか)のオフライン解析。
    接続開始(SYN-ACK)でローテーションし、直前接続分を <name>.prev<ext> に退避するので、
    ズレ後に反射的に入り直しても、採取済みのサンプルは失われない。

    形式(リトルエンディアン):
      先頭 7バイト: b"UOCAP1\\n"
      各レコードは種別1バイト:
        'S' + I(next_seq)                        … SYN-ACK(サーバISN+1。以降の基準seq)
        'D' + d(time) + I(seq) + I(len) + payload … データセグメント(再構成前)
        'N'                                       … 新規接続(クライアントSYN)
        'C'                                       … 切断(FIN/RST)
    """

    MAGIC = b"UOCAP1\n"

    def __init__(self, path, cap=_RAW_CAP):
        self.path = path
        base, ext = os.path.splitext(path)
        self.prev_path = base + ".prev" + ext
        self.cap = int(cap)
        self.f = None
        self.written = 0

    def _open_fresh(self):
        try:
            self.f = open(self.path, "wb")
            self.f.write(self.MAGIC)
            self.written = len(self.MAGIC)
        except Exception:  # noqa: BLE001
            self.f = None

    def rotate(self):
        """現ファイルを .prev に退避して新規に開き直す(入り直しでも前接続分を保全)。"""
        self.close()
        try:
            if os.path.exists(self.path):
                if os.path.exists(self.prev_path):
                    os.remove(self.prev_path)
                os.replace(self.path, self.prev_path)
        except Exception:  # noqa: BLE001
            pass
        self._open_fresh()

    def _write(self, b):
        if self.f is None or self.written >= self.cap:
            return
        try:
            self.f.write(b)
            self.written += len(b)
        except Exception:  # noqa: BLE001
            pass

    def synack(self, next_seq):
        self.rotate()
        self._write(b"S" + struct.pack("<I", next_seq & 0xFFFFFFFF))

    def data(self, t, seq, payload):
        self._write(b"D" + struct.pack("<dII", t, seq & 0xFFFFFFFF, len(payload)) + payload)

    def mark(self, code):
        self._write(code)

    def flush(self):
        if self.f is not None:
            try:
                self.f.flush()
            except Exception:  # noqa: BLE001
                pass

    def close(self):
        if self.f is not None:
            try:
                self.f.close()
            except Exception:  # noqa: BLE001
                pass
        self.f = None


class UOCapture:
    """受信キャプチャ。proxy.UOProxy と同じ I/F (start/stop, on_speech, on_status)。

    app 側は UOProxy を UOCapture に差し替えるだけで動く。

    受信下層(キャプチャ→TCP再構成→Huffman解凍)は用途非依存で、解凍後ストリームに通す
    「スキャナ」だけを差し替えれば他ツールでも流用できる(翻訳=発話スキャナ, hue確認=
    アイテムスキャナ 等)。スキャナ契約:
        scanner = scanner_factory()        # 接続(SYN-ACK)ごとに新規生成
        for ev in scanner.feed(dec): ...   # dec=解凍後バイト列。ev(dict)の iterable を返す
    スキャナは解凍ストリームを自己記述的に走査し、途中に数バイトのゴミが混じっても
    落ちない前提(内部で不完全な尾部は次回 feed へ繰り越す)。各 ev は on_event へ渡す。

    既定は従来どおり発話スキャナ(SpeechScanner)＋on_speech。hue側は
        UOCapture(game_port=2593, scanner_factory=ItemScanner, on_event=on_item, debug=True)
    のように ItemScanner と on_event を渡すだけでよい。
    """

    def __init__(self, game_port, on_speech=None, on_status=None, iface=None, debug=False,
                 scanner_factory=None, on_event=None):
        self.game_port = int(game_port)
        self.on_speech = on_speech
        # 1イベントごとのコールバック。on_event 優先、無ければ従来の on_speech。
        self.on_event = on_event or on_speech or (lambda ev: None)
        # 解凍後ストリームに通すスキャナの生成関数(接続ごとに呼ぶ)。既定=発話スキャナ。
        self._scanner_factory = scanner_factory or uo_packets.SpeechScanner
        self.on_status = on_status or (lambda m: None)
        self.iface = iface or None
        self.debug = bool(debug)
        self._q: "queue.Queue" = queue.Queue()
        self._sniffer = None
        self._worker = None
        self._stop = threading.Event()

    def _status(self, msg):
        try:
            self.on_status(msg)
        except Exception:
            pass

    # -------- 起動/停止 --------
    def start(self):
        try:
            from scapy.all import AsyncSniffer, conf  # type: ignore
        except Exception as e:  # noqa: BLE001
            self._status(f"scapy を読み込めません。'pip install scapy' を実行してください: {e}")
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._analyze, daemon=True)
        self._worker.start()
        iface = self.iface or getattr(conf, "iface", None)
        try:
            self._sniffer = AsyncSniffer(
                filter=f"tcp port {self.game_port}",
                prn=self._on_packet,
                store=False,
                iface=iface,
            )
            self._sniffer.start()
        except Exception as e:  # noqa: BLE001
            self._status(f"キャプチャ開始に失敗(Npcap導入/管理者権限/iface を確認): {e}")
            self._sniffer = None
            return
        self._status(
            f"受信待機中(パッシブキャプチャ): iface={iface} port={self.game_port}。"
            "UO を起動してログインしてください（既にログイン済みなら入り直すと確実）。"
        )

    def stop(self):
        self._stop.set()
        try:
            self._q.put_nowait(("stop",))
        except Exception:
            pass
        s = self._sniffer
        self._sniffer = None
        if s is not None:
            try:
                s.stop()
            except Exception:
                pass

    # -------- キャプチャのコールバック(snifferスレッド / 軽量に徹する) --------
    def _on_packet(self, pkt):
        try:
            if not pkt.haslayer("TCP"):
                return
            tcp = pkt["TCP"]
            sport, dport = int(tcp.sport), int(tcp.dport)
            flags = int(tcp.flags)

            # クライアント→サーバ:port の SYN = 新しい接続の開始
            if dport == self.game_port and (flags & _SYN) and not (flags & _ACK):
                self._q.put(("newconn",))
                return
            # サーバ:port→クライアント の SYN-ACK = サーバISN。データは seq+1 から
            if sport == self.game_port and (flags & _SYN) and (flags & _ACK):
                try:
                    src = pkt["IP"].src
                except Exception:  # noqa: BLE001
                    src = "?"
                self._q.put(("synack", (int(tcp.seq) + 1) & 0xFFFFFFFF, src))
                return
            if sport == self.game_port and (flags & (_FIN | _RST)):
                self._q.put(("close",))

            if sport != self.game_port:
                return
            payload = bytes(tcp.payload)
            if payload:
                self._q.put(("data", int(tcp.seq), payload))
        except Exception:
            pass

    # -------- 解読スレッド(キューを順に処理) --------
    def _analyze(self):
        reasm = None
        decomp = None
        scanner = None
        synced = False
        n_pkt = n_dec = n_speech = 0
        last_stat = time.time()

        log = None
        dump = None
        raw = None
        dump_written = 0
        if self.debug:
            try:
                log = open(os.path.join(_HERE, "capture_debug.log"), "a", encoding="utf-8")
                log.write(f"\n==== capture start {time.strftime('%Y-%m-%d %H:%M:%S')} "
                          f"port={self.game_port} iface={self.iface} ====\n")
                log.flush()
            except Exception:  # noqa: BLE001
                log = None
            try:
                dump = open(os.path.join(_HERE, "capture_decompressed.bin"), "wb")
            except Exception:  # noqa: BLE001
                dump = None
            try:
                raw = _RawDump(os.path.join(_HERE, "capture_raw.bin"))
            except Exception:  # noqa: BLE001
                raw = None

        def logln(s):
            if log:
                try:
                    log.write(s + "\n")
                    log.flush()
                except Exception:  # noqa: BLE001
                    pass

        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.3)
            except queue.Empty:
                continue
            kind = item[0]
            if kind == "stop":
                break
            if kind == "newconn":
                synced = False
                if raw:
                    raw.mark(b"N")
                logln(f"[{time.strftime('%H:%M:%S')}] newconn(SYN)")
                continue
            if kind == "close":
                synced = False
                if raw:
                    raw.mark(b"C")
                logln(f"[{time.strftime('%H:%M:%S')}] close(FIN/RST)")
                continue
            if kind == "synack":
                _, next_seq, src = item
                if raw:
                    raw.synack(next_seq)
                reasm = _S2CReassembler(next_seq)
                decomp = uo_huffman.HuffmanDecompressor()
                scanner = self._scanner_factory()
                synced = True
                n_pkt = n_dec = n_speech = 0
                if dump is not None:
                    try:
                        dump.seek(0)
                        dump.truncate(0)
                    except Exception:  # noqa: BLE001
                        pass
                    dump_written = 0
                self._status(f"ゲーム接続を検出: {src}:{self.game_port} の受信を監視します。")
                logln(f"[{time.strftime('%H:%M:%S')}] SYNCED src={src} next_seq={next_seq}")
                continue
            if kind == "data":
                if not synced:
                    continue
                _, seq, payload = item
                if raw:
                    raw.data(time.time(), seq, payload)
                n_pkt += 1
                data = reasm.add(seq, payload)
                if not data:
                    continue
                try:
                    dec = decomp.feed(data)
                except Exception as e:  # noqa: BLE001
                    logln(f"[{time.strftime('%H:%M:%S')}] DESYNC: {e} (接続を入り直すと復帰します)")
                    synced = False
                    continue
                n_dec += len(dec)
                if dump is not None and dump_written < _DUMP_CAP:
                    try:
                        chunk = dec[:_DUMP_CAP - dump_written]
                        dump.write(chunk)
                        dump.flush()
                        dump_written += len(chunk)
                    except Exception:  # noqa: BLE001
                        pass
                for ev in scanner.feed(dec):
                    n_speech += 1
                    if log:
                        if isinstance(ev, dict) and {"type", "name", "text"} <= ev.keys():
                            logln(f"[{time.strftime('%H:%M:%S')}] SPEECH "
                                  f"type={ev['type']} name={ev['name']!r} text={ev['text']!r}")
                        else:
                            logln(f"[{time.strftime('%H:%M:%S')}] EVENT {ev!r}")
                    try:
                        self.on_event(ev)
                    except Exception as e:  # noqa: BLE001
                        # 握りつぶすと原因が見えないのでログに残す(診断用)
                        logln(f"[{time.strftime('%H:%M:%S')}] on_event ERROR: {e!r}")
                if (time.time() - last_stat) > 5:
                    last_stat = time.time()
                    if raw:
                        raw.flush()
                    logln(f"[{time.strftime('%H:%M:%S')}] stat pkts={n_pkt} "
                          f"dec_bytes={n_dec} speech={n_speech} qsize={self._q.qsize()}")
        if log:
            try:
                log.close()
            except Exception:  # noqa: BLE001
                pass
        if dump:
            try:
                dump.close()
            except Exception:  # noqa: BLE001
                pass
        if raw:
            raw.close()
