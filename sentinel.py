"""UO:1998 Sentinel — ステータス監視ツール(別ウィンドウ)。

HP / マナ / スタミナ / 所持重量 を受信パケットから監視し、閾値(絶対値 or ％)に達したら
WAV再生 と キー送信(AutoHotkey起動用)を行う。受信は翻訳ツールと同じパッシブキャプチャ
(capture.UOCapture)を流用し、scanner に uo_stats.StatScanner を差し込む。

起動: run.bat (管理者昇格)。設定は config.ini の [capture]/[filter] を共有し、
監視ルールは sentinel_state.json に保存する。
"""
from __future__ import annotations

import configparser
import json
import os
import queue
import sys
import tkinter as tk
from tkinter import filedialog

import keysend
import uo_stats
from capture import UOCapture

try:
    import winsound
except Exception:  # noqa: BLE001  (非Windows開発環境など)
    winsound = None


def _base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


HERE = _base_dir()
CONFIG_PATH = os.path.join(HERE, "config.ini")
STATE_PATH = os.path.join(HERE, "sentinel_state.json")

# 判定モードの表示名(画面に出る文字列)。内部は "絶対値"/"％" で統一。
MODE_ABS = "値"   # 値そのもので判定
MODE_PCT = "%"    # 最大に対する割合(%)で判定


def _norm_mode(v):
    """旧表記(abs/pct/絶対値/％)や表記ゆれを内部表記(MODE_ABS/MODE_PCT)へ正規化。"""
    return MODE_PCT if str(v).strip() in ("pct", "%", "％", MODE_PCT) else MODE_ABS


# 監視する4ステータス: (キー, ラベル, 既定の条件, 既定閾値, 既定モード)
STATS = [
    ("hp", "HP", "<=", "30", MODE_PCT),
    ("mana", "マナ", ">=", "90", MODE_PCT),
    ("stam", "スタミナ", ">=", "90", MODE_PCT),
    ("weight", "重量", ">=", "90", MODE_PCT),
]


def load_config():
    cfg = configparser.ConfigParser()
    try:
        cfg.read(CONFIG_PATH, encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    return cfg


class Sentinel:
    def __init__(self, cfg):
        self.cfg = cfg
        self.game_port = cfg.getint("capture", "game_port", fallback=2593)
        self.iface = cfg.get("capture", "iface", fallback="").strip() or None
        self.debug = cfg.getboolean("capture", "debug", fallback=False)
        self.self_names = {
            n.strip().lower() for n in cfg.get("filter", "self_names", fallback="").split(",")
            if n.strip()
        }
        # 最大所持重量(stones)の決め方。1998仕様の 0x11(type=1)はサーバーが最大重量を
        # 送らないので自前で算出する。このシャードの上限は「ベースSTR」で決まり、ブレスや
        # Potの一時STRでは増えない点に注意。
        #   max_weight>0 → その固定値を使う(ゲーム内で実測した上限が最も確実)
        #   base_str>0   → STR*4 + 30 で算出(無バフ時のベースSTRを入れる)
        #   どちらも0    → 受信STR(現在値)から STR*4+30 で算出(バフ中は実際と差が出る)
        self.cfg_max_weight = cfg.getint("filter", "max_weight", fallback=0)
        self.cfg_base_str = cfg.getint("filter", "base_str", fallback=0)

        self._q: "queue.Queue" = queue.Queue()
        self._my = None                      # 自分の serial
        # 現在値: {stat: [cur, max]}
        self.cur = {k: [0, 0] for k, *_ in STATS}
        self.rules = {}                      # stat -> dict(vars) + _armed

        self._saved = self._load_state()
        self._build_gui()

        self.capture = UOCapture(
            game_port=self.game_port, iface=self.iface, debug=self.debug,
            scanner_factory=uo_stats.StatScanner, on_event=self._on_stat,
            on_status=lambda m: self._q.put(("status", m)),
            on_connect=lambda src: self._q.put(("reconnect", src)),
        )

    # ---------- 受信(キャプチャスレッド → キュー) ----------
    def _on_stat(self, ev):
        self._q.put(("stat", ev))

    def _redetect(self, reason=""):
        """追跡中の自分(serial)と現在値をリセットし、次の本人ステータスで再検出する。
        キャラ変更後や再接続時に呼ぶ。メインスレッドから呼ぶこと。"""
        self._my = None
        for k in self.cur:
            self.cur[k] = [0, 0]
        msg = "自分を再検出します。UOにキャラクターでログインしてください。"
        if reason:
            msg = f"{reason} {msg}"
        self.status_var.set(msg)

    def _apply_event(self, ev):
        t = ev.get("t")
        serial = ev.get("serial")
        # 自分の serial を確定: 妥当性検査済みの 0x11(full)から。self_names 一致を優先、
        # 無ければ拡張ステータス(type>0 = mana を含む = 本人のステータス)で判定。
        if t == "full":
            name = (ev.get("name") or "").lower()
            if self._my is None and (name in self.self_names or "mana" in ev):
                self._my = serial
        if self._my is not None and serial != self._my:
            return
        if t == "full":
            self.cur["hp"] = [ev["hp"], ev["hp_max"]]
            if "mana" in ev:
                self.cur["mana"] = [ev["mana"], ev["mana_max"]]
                self.cur["stam"] = [ev["stam"], ev["stam_max"]]
                self.cur["weight"] = [ev["weight"], self._max_weight(ev)]
        elif t == "attrs":
            self.cur["hp"] = [ev["hp"], ev["hp_max"]]
            self.cur["mana"] = [ev["mana"], ev["mana_max"]]
            self.cur["stam"] = [ev["stam"], ev["stam_max"]]
        elif t in ("hp", "mana", "stam"):
            self.cur[t] = [ev["cur"], ev["max"]]

    def _max_weight(self, ev):
        """最大所持重量(stones)。設定優先。サーバーが送らない1998仕様では算出する。
        ブレス/Potの一時STRでは増えない(ベースSTR依存)ため、設定値での固定を推奨。"""
        if self.cfg_max_weight > 0:
            return self.cfg_max_weight
        if self.cfg_base_str > 0:
            return self.cfg_base_str * 4 + 30
        return ev.get("weight_max", 0)

    # ---------- ルール評価(ヒステリシス付き) ----------
    def _evaluate(self):
        for key, _lbl, *_ in STATS:
            r = self.rules[key]
            if not r["enabled"].get():
                r["_armed"] = True
                continue
            cur, mx = self.cur[key]
            try:
                thr = float(r["value"].get())
            except ValueError:
                continue
            if r["mode"].get() == MODE_PCT:
                val = (cur / mx * 100.0) if mx else 0.0
            else:
                val = cur
            trig = (val >= thr) if r["cond"].get() == ">=" else (val <= thr)
            if trig and r["_armed"]:
                r["_armed"] = False
                self._fire(r)
            elif not trig:
                r["_armed"] = True

    def _fire(self, r):
        wav = r["wav"].get().strip()
        if wav and winsound is not None and os.path.exists(wav):
            try:
                winsound.PlaySound(wav, winsound.SND_FILENAME | winsound.SND_ASYNC)
            except Exception:  # noqa: BLE001
                pass
        vk = keysend.vk_from_name(r["key"].get())
        if vk is not None:
            try:
                keysend.send_vk(vk)
            except Exception:  # noqa: BLE001
                pass

    # ---------- GUI ----------
    def _build_gui(self):
        self.root = tk.Tk()
        self.root.title("UO:1998 Sentinel")
        try:
            _ico = os.path.join(getattr(sys, "_MEIPASS", HERE), "app.ico")
            if os.path.exists(_ico):
                self.root.iconbitmap(_ico)
        except Exception:  # noqa: BLE001
            pass
        geo = (self._saved or {}).get("geometry", "560x300+200+120")
        try:
            self.root.geometry(geo)
        except tk.TclError:
            pass
        self.root.configure(bg="#1e1e1e")
        self.root.attributes("-topmost", True)

        head = tk.Frame(self.root, bg="#252526"); head.pack(fill="x")
        # キャラ変更時の再検出ボタン(接続を入り直せば自動でも再検出するが、保険として手動も)
        tk.Button(head, text="キャラ再検出", command=lambda: self._redetect("手動再検出:"),
                  bg="#3a3d41", fg="#fff", relief="flat", font=("Yu Gothic UI", 9),
                  padx=6).pack(side="right", padx=6, pady=4)
        self.status_var = tk.StringVar(value="受信待機中…UOにログイン(入り直すと確実)")
        tk.Label(head, textvariable=self.status_var, fg="#c5c5c5", bg="#252526",
                 anchor="w", font=("Yu Gothic UI", 9), wraplength=430,
                 justify="left").pack(side="left", fill="x", expand=True, padx=8, pady=4)

        # 見出し行
        grid = tk.Frame(self.root, bg="#1e1e1e"); grid.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ["監視", "現在値", "条件", "閾値", "値/%", "WAV", "キー"]
        for c, t in enumerate(cols):
            tk.Label(grid, text=t, fg="#9cdcfe", bg="#1e1e1e",
                     font=("Yu Gothic UI", 9, "bold")).grid(row=0, column=c, padx=3, pady=2, sticky="w")

        saved_rules = (self._saved or {}).get("rules", {})
        for i, (key, label, dcond, dval, dmode) in enumerate(STATS, start=1):
            s = saved_rules.get(key, {})
            en = tk.BooleanVar(value=s.get("enabled", False))
            cond = tk.StringVar(value=s.get("cond", dcond))
            val = tk.StringVar(value=s.get("value", dval))
            mode = tk.StringVar(value=_norm_mode(s.get("mode", dmode)))
            wav = tk.StringVar(value=s.get("wav", ""))
            keyv = tk.StringVar(value=s.get("key", ""))
            cv = tk.StringVar(value="-")
            self.rules[key] = {"enabled": en, "cond": cond, "value": val, "mode": mode,
                               "wav": wav, "key": keyv, "_armed": True, "_cv": cv}

            tk.Checkbutton(grid, text=label, variable=en, width=7, anchor="w",
                           bg="#1e1e1e", fg="#e0e0e0", selectcolor="#1e1e1e",
                           activebackground="#1e1e1e", activeforeground="#fff",
                           font=("Yu Gothic UI", 9)).grid(row=i, column=0, sticky="w")
            tk.Label(grid, textvariable=cv, fg="#d7ffd7", bg="#1e1e1e", width=14,
                     anchor="w", font=("Consolas", 10)).grid(row=i, column=1, sticky="w")
            tk.OptionMenu(grid, cond, ">=", "<=").grid(row=i, column=2, sticky="w")
            tk.Entry(grid, textvariable=val, width=5, bg="#2d2d30", fg="#fff",
                     insertbackground="#fff").grid(row=i, column=3, sticky="w", padx=2)
            tk.OptionMenu(grid, mode, MODE_ABS, MODE_PCT).grid(row=i, column=4, sticky="w")
            wf = tk.Frame(grid, bg="#1e1e1e"); wf.grid(row=i, column=5, sticky="w")
            tk.Entry(wf, textvariable=wav, width=16, bg="#2d2d30", fg="#fff",
                     insertbackground="#fff").pack(side="left")
            tk.Button(wf, text="…", command=lambda w=wav: self._pick_wav(w),
                      bg="#3a3d41", fg="#fff", relief="flat", padx=3).pack(side="left", padx=1)
            tk.Button(wf, text="▶", command=lambda w=wav: self._test_wav(w),
                      bg="#3a3d41", fg="#fff", relief="flat", padx=3).pack(side="left")
            tk.Entry(grid, textvariable=keyv, width=5, bg="#2d2d30", fg="#fff",
                     insertbackground="#fff").grid(row=i, column=6, sticky="w", padx=2)

        foot = tk.Frame(self.root, bg="#252526"); foot.pack(fill="x")
        tk.Label(foot, text="値=そのもの / %=最大に対する割合。キーはF13〜F24推奨"
                 "(AHKで F13:: 等を拾う)。", fg="#a0a0a0", bg="#252526",
                 font=("Yu Gothic UI", 8), anchor="w", wraplength=540,
                 justify="left").pack(fill="x", padx=8, pady=3)

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _pick_wav(self, var):
        p = filedialog.askopenfilename(title="WAVを選択",
                                       filetypes=[("WAV", "*.wav"), ("すべて", "*.*")])
        if p:
            var.set(p)

    def _test_wav(self, var):
        p = var.get().strip()
        if p and winsound is not None and os.path.exists(p):
            try:
                winsound.PlaySound(p, winsound.SND_FILENAME | winsound.SND_ASYNC)
            except Exception:  # noqa: BLE001
                pass

    # ---------- ポーリング(メインスレッド) ----------
    def _poll(self):
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "status":
                    self.status_var.set(payload)
                elif kind == "stat":
                    self._apply_event(payload)
                elif kind == "reconnect":
                    # 新規ゲーム接続(再ログイン/キャラ変更)→ 自分を取り直す
                    self._redetect("接続を検出:")
        except queue.Empty:
            pass
        # 現在値の表示更新(値/最大と割合を常に併記) + ルール評価
        for key, *_ in STATS:
            cur, mx = self.cur[key]
            if mx:
                self.rules[key]["_cv"].set(f"{cur}/{mx} ({int(cur / mx * 100)}%)")
            else:
                self.rules[key]["_cv"].set(str(cur))
        self._evaluate()
        self.root.after(200, self._poll)

    # ---------- 状態保存 ----------
    def _load_state(self):
        try:
            with open(STATE_PATH, encoding="utf-8") as f:
                d = json.load(f)
                return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self):
        rules = {}
        for key, r in self.rules.items():
            rules[key] = {"enabled": bool(r["enabled"].get()), "cond": r["cond"].get(),
                          "value": r["value"].get(), "mode": r["mode"].get(),
                          "wav": r["wav"].get(), "key": r["key"].get()}
        data = {"geometry": self.root.geometry(), "rules": rules}
        try:
            with open(STATE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ---------- ライフサイクル ----------
    def run(self):
        self.capture.start()
        self.root.after(200, self._poll)
        self.root.mainloop()

    def _on_close(self):
        self._save_state()
        try:
            self.capture.stop()
        finally:
            self.root.destroy()


def main():
    Sentinel(load_config()).run()


if __name__ == "__main__":
    main()
