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

# 監視する4ステータス: (キー, ラベル, 既定の条件, 既定閾値, 既定モード)
STATS = [
    ("hp", "HP", "<=", "30", "pct"),
    ("mana", "マナ", ">=", "90", "pct"),
    ("stam", "スタミナ", ">=", "90", "pct"),
    ("weight", "重量", ">=", "90", "pct"),
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
        )

    # ---------- 受信(キャプチャスレッド → キュー) ----------
    def _on_stat(self, ev):
        self._q.put(("stat", ev))

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
                self.cur["weight"] = [ev["weight"], ev.get("weight_max", 0)]
        elif t == "attrs":
            self.cur["hp"] = [ev["hp"], ev["hp_max"]]
            self.cur["mana"] = [ev["mana"], ev["mana_max"]]
            self.cur["stam"] = [ev["stam"], ev["stam_max"]]
        elif t in ("hp", "mana", "stam"):
            self.cur[t] = [ev["cur"], ev["max"]]

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
            if r["mode"].get() == "pct":
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
        self.status_var = tk.StringVar(value="受信待機中…UOにログイン(入り直すと確実)")
        tk.Label(head, textvariable=self.status_var, fg="#c5c5c5", bg="#252526",
                 anchor="w", font=("Yu Gothic UI", 9), wraplength=540,
                 justify="left").pack(fill="x", padx=8, pady=4)

        # 見出し行
        grid = tk.Frame(self.root, bg="#1e1e1e"); grid.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ["監視", "現在値", "条件", "閾値", "絶対/％", "WAV", "キー"]
        for c, t in enumerate(cols):
            tk.Label(grid, text=t, fg="#9cdcfe", bg="#1e1e1e",
                     font=("Yu Gothic UI", 9, "bold")).grid(row=0, column=c, padx=3, pady=2, sticky="w")

        saved_rules = (self._saved or {}).get("rules", {})
        for i, (key, label, dcond, dval, dmode) in enumerate(STATS, start=1):
            s = saved_rules.get(key, {})
            en = tk.BooleanVar(value=s.get("enabled", False))
            cond = tk.StringVar(value=s.get("cond", dcond))
            val = tk.StringVar(value=s.get("value", dval))
            mode = tk.StringVar(value=s.get("mode", dmode))
            wav = tk.StringVar(value=s.get("wav", ""))
            keyv = tk.StringVar(value=s.get("key", ""))
            cv = tk.StringVar(value="-")
            self.rules[key] = {"enabled": en, "cond": cond, "value": val, "mode": mode,
                               "wav": wav, "key": keyv, "_armed": True, "_cv": cv}

            tk.Checkbutton(grid, text=label, variable=en, width=7, anchor="w",
                           bg="#1e1e1e", fg="#e0e0e0", selectcolor="#1e1e1e",
                           activebackground="#1e1e1e", activeforeground="#fff",
                           font=("Yu Gothic UI", 9)).grid(row=i, column=0, sticky="w")
            tk.Label(grid, textvariable=cv, fg="#d7ffd7", bg="#1e1e1e", width=9,
                     anchor="w", font=("Consolas", 10)).grid(row=i, column=1, sticky="w")
            tk.OptionMenu(grid, cond, ">=", "<=").grid(row=i, column=2, sticky="w")
            tk.Entry(grid, textvariable=val, width=5, bg="#2d2d30", fg="#fff",
                     insertbackground="#fff").grid(row=i, column=3, sticky="w", padx=2)
            tk.OptionMenu(grid, mode, "abs", "pct").grid(row=i, column=4, sticky="w")
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
        tk.Label(foot, text="絶対=値そのもの / ％=最大に対する割合。キーはF13〜F24推奨"
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
        except queue.Empty:
            pass
        # 現在値の表示更新 + ルール評価
        for key, *_ in STATS:
            cur, mx = self.cur[key]
            self.rules[key]["_cv"].set(f"{cur}/{mx}" if mx else str(cur))
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
