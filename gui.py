"""
gui.py
------
Tkinter-based GUI for the Presidio-Based LLM Security Mini-Gateway.
Lets the user type any prompt, runs the full pipeline, and displays:
  - Action (ALLOW / MASK / BLOCK) with colour coding
  - Injection score with a live progress bar
  - PII entities detected
  - Processed output text
  - Per-stage latency breakdown
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, font as tkfont
import threading

from injection_detector import compute_injection_score
from presidio_analyzer_module import analyze_text, anonymize_text
from policy_engine import apply_policy, INJECTION_THRESHOLD
from latency_monitor import LatencyReport, StageTimer

# ── colour palette ────────────────────────────────────────────────────────────
BG       = "#0d1117"
SURFACE  = "#161b22"
BORDER   = "#30363d"
FG       = "#e6edf3"
FG_DIM   = "#8b949e"
GREEN    = "#3fb950"
YELLOW   = "#d29922"
RED      = "#f85149"
BLUE     = "#58a6ff"
CYAN     = "#79c0ff"
ACCENT   = "#1f6feb"


def run_pipeline(user_input: str) -> dict:
    latency = LatencyReport()
    with StageTimer(latency, "1. Injection Detection"):
        score = compute_injection_score(user_input)
    with StageTimer(latency, "2. Presidio Analysis"):
        results = analyze_text(user_input)
    with StageTimer(latency, "3. Presidio Anonymization"):
        anon = anonymize_text(user_input, results)
    with StageTimer(latency, "4. Policy Decision"):
        decision = apply_policy(user_input, score, results, anon)
    latency.compute_total()
    return {"decision": decision, "latency": latency}


class GatewayGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LLM Security Mini-Gateway  •  CEN-451")
        self.configure(bg=BG)
        self.geometry("960x780")
        self.minsize(760, 600)
        self._build_fonts()
        self._build_ui()

    # ── fonts ─────────────────────────────────────────────────────────────────
    def _build_fonts(self):
        self.f_title  = tkfont.Font(family="Consolas", size=15, weight="bold")
        self.f_label  = tkfont.Font(family="Consolas", size=10, weight="bold")
        self.f_mono   = tkfont.Font(family="Consolas", size=10)
        self.f_badge  = tkfont.Font(family="Consolas", size=18, weight="bold")
        self.f_small  = tkfont.Font(family="Consolas", size=9)

    # ── full UI layout ────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── header
        hdr = tk.Frame(self, bg=SURFACE, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⬡  LLM SECURITY GATEWAY",
                 font=self.f_title, bg=SURFACE, fg=BLUE).pack(side="left", padx=20)
        tk.Label(hdr, text="CEN-451  •  Presidio Pipeline",
                 font=self.f_small, bg=SURFACE, fg=FG_DIM).pack(side="right", padx=20)

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x")

        # ── main two-column body
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=14)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        # ── LEFT column
        left = tk.Frame(body, bg=BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.rowconfigure(1, weight=1)
        left.rowconfigure(3, weight=1)
        left.columnconfigure(0, weight=1)

        # input
        self._section(left, "▸ INPUT PROMPT", 0)
        self.txt_input = scrolledtext.ScrolledText(
            left, height=8, font=self.f_mono,
            bg=SURFACE, fg=FG, insertbackground=BLUE,
            relief="flat", bd=0, wrap="word",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT)
        self.txt_input.grid(row=1, column=0, sticky="nsew", pady=(0, 8))
        self.txt_input.bind("<Control-Return>", lambda e: self._analyse())

        # button row
        btn_row = tk.Frame(left, bg=BG)
        btn_row.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        self.btn_run = tk.Button(
            btn_row, text="  RUN PIPELINE  ▶",
            font=self.f_label, bg=ACCENT, fg=FG,
            activebackground="#388bfd", activeforeground=FG,
            relief="flat", bd=0, padx=16, pady=8,
            cursor="hand2", command=self._analyse)
        self.btn_run.pack(side="left")
        tk.Button(
            btn_row, text="CLEAR",
            font=self.f_label, bg=SURFACE, fg=FG_DIM,
            activebackground=BORDER, activeforeground=FG,
            relief="flat", bd=0, padx=14, pady=8,
            cursor="hand2", command=self._clear).pack(side="left", padx=(8, 0))

        # output
        self._section(left, "▸ GATEWAY OUTPUT", 3)
        self.txt_output = scrolledtext.ScrolledText(
            left, height=8, font=self.f_mono,
            bg=SURFACE, fg=FG, insertbackground=BLUE,
            relief="flat", bd=0, wrap="word",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT, state="disabled")
        self.txt_output.grid(row=4, column=0, sticky="nsew")

        # ── RIGHT column
        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)

        # verdict badge
        self._section(right, "▸ VERDICT", 0)
        badge_frame = tk.Frame(right, bg=SURFACE,
                                highlightthickness=1, highlightbackground=BORDER)
        badge_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        self.lbl_action = tk.Label(badge_frame, text="—",
                                   font=self.f_badge, bg=SURFACE, fg=FG_DIM,
                                   pady=14)
        self.lbl_action.pack()
        self.lbl_reason = tk.Label(badge_frame, text="Submit a prompt to analyse",
                                   font=self.f_small, bg=SURFACE, fg=FG_DIM,
                                   wraplength=280, justify="center", pady=6)
        self.lbl_reason.pack()

        # injection score
        self._section(right, "▸ INJECTION SCORE", 2)
        score_frame = tk.Frame(right, bg=SURFACE,
                                highlightthickness=1, highlightbackground=BORDER)
        score_frame.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        score_frame.columnconfigure(0, weight=1)

        top_row = tk.Frame(score_frame, bg=SURFACE)
        top_row.pack(fill="x", padx=12, pady=(10, 4))
        self.lbl_score_val = tk.Label(top_row, text="0.00",
                                      font=self.f_label, bg=SURFACE, fg=FG)
        self.lbl_score_val.pack(side="left")
        self.lbl_threshold = tk.Label(top_row,
                                      text=f"threshold: {INJECTION_THRESHOLD}",
                                      font=self.f_small, bg=SURFACE, fg=FG_DIM)
        self.lbl_threshold.pack(side="right")

        bar_bg = tk.Frame(score_frame, bg=BORDER, height=12)
        bar_bg.pack(fill="x", padx=12, pady=(0, 10))
        bar_bg.pack_propagate(False)
        self.bar_inner = tk.Frame(bar_bg, bg=FG_DIM, width=0)
        self.bar_inner.place(x=0, y=0, relheight=1.0, width=0)
        self._bar_bg_widget = bar_bg

        # PII entities
        self._section(right, "▸ PII DETECTED", 4)
        self.frame_pii = tk.Frame(right, bg=SURFACE,
                                   highlightthickness=1, highlightbackground=BORDER,
                                   padx=12, pady=10)
        self.frame_pii.grid(row=5, column=0, sticky="ew", pady=(0, 10))
        self.lbl_pii = tk.Label(self.frame_pii, text="None",
                                 font=self.f_mono, bg=SURFACE, fg=FG_DIM,
                                 justify="left", anchor="w")
        self.lbl_pii.pack(fill="x")

        # latency
        self._section(right, "▸ LATENCY BREAKDOWN", 6)
        self.frame_lat = tk.Frame(right, bg=SURFACE,
                                   highlightthickness=1, highlightbackground=BORDER,
                                   padx=12, pady=10)
        self.frame_lat.grid(row=7, column=0, sticky="ew", pady=(0, 10))
        self.lat_labels = {}
        stages = [
            "1. Injection Detection",
            "2. Presidio Analysis",
            "3. Presidio Anonymization",
            "4. Policy Decision",
            "TOTAL",
        ]
        for i, s in enumerate(stages):
            fg = CYAN if s == "TOTAL" else FG_DIM
            row_f = tk.Frame(self.frame_lat, bg=SURFACE)
            row_f.pack(fill="x", pady=1)
            tk.Label(row_f, text=s, font=self.f_small,
                     bg=SURFACE, fg=fg, anchor="w", width=28).pack(side="left")
            val = tk.Label(row_f, text="—", font=self.f_small,
                           bg=SURFACE, fg=fg, anchor="e")
            val.pack(side="right")
            self.lat_labels[s] = val

        # status bar
        sep2 = tk.Frame(self, bg=BORDER, height=1)
        sep2.pack(fill="x")
        self.lbl_status = tk.Label(self, text="Ready  •  Ctrl+Enter to run",
                                    font=self.f_small, bg=SURFACE, fg=FG_DIM,
                                    anchor="w", padx=14, pady=6)
        self.lbl_status.pack(fill="x")

    def _section(self, parent, text, row):
        tk.Label(parent, text=text, font=self.f_small,
                 bg=BG, fg=FG_DIM, anchor="w"
                 ).grid(row=row, column=0, sticky="w", pady=(6, 2))

    # ── pipeline execution ────────────────────────────────────────────────────
    def _analyse(self):
        text = self.txt_input.get("1.0", "end").strip()
        if not text:
            return
        self.btn_run.config(state="disabled", text="  PROCESSING…")
        self.lbl_status.config(text="Running pipeline…")
        threading.Thread(target=self._run_thread, args=(text,), daemon=True).start()

    def _run_thread(self, text):
        result = run_pipeline(text)
        self.after(0, self._display_result, result)

    def _display_result(self, result):
        d = result["decision"]
        lat = result["latency"]

        # action badge
        colours = {"ALLOW": GREEN, "MASK": YELLOW, "BLOCK": RED}
        c = colours.get(d.action, FG)
        self.lbl_action.config(text=d.action, fg=c)
        self.lbl_reason.config(text=d.reason, fg=FG_DIM)

        # output text
        self.txt_output.config(state="normal")
        self.txt_output.delete("1.0", "end")
        self.txt_output.insert("end", d.output_text)
        self.txt_output.config(state="disabled")

        # injection score bar
        score = d.injection_score
        self.lbl_score_val.config(
            text=f"{score:.2f}",
            fg=RED if score > INJECTION_THRESHOLD else (YELLOW if score > 0.3 else GREEN))
        self.after(50, self._animate_bar, score, 0)

        # PII
        if d.pii_entities:
            pii_text = "\n".join(f"  ● {e}" for e in d.pii_entities)
            self.lbl_pii.config(text=pii_text, fg=YELLOW)
        else:
            self.lbl_pii.config(text="  None detected", fg=FG_DIM)

        # latency
        for stage, ms in lat.stage_times_ms.items():
            if stage in self.lat_labels:
                self.lat_labels[stage].config(text=f"{ms:.2f} ms")
        total = lat.total_ms
        self.lat_labels["TOTAL"].config(text=f"{total:.2f} ms", fg=CYAN)

        # status bar
        self.lbl_status.config(
            text=f"Done  •  Action: {d.action}  •  Total latency: {total:.2f} ms")
        self.btn_run.config(state="normal", text="  RUN PIPELINE  ▶")

    def _animate_bar(self, target_score, step):
        """Smoothly animate the injection score progress bar."""
        try:
            total_w = self._bar_bg_widget.winfo_width()
        except Exception:
            total_w = 200
        if total_w < 4:
            total_w = 200
        target_w = int(total_w * min(target_score, 1.0))
        current_w = int(total_w * (step / 20))
        c = RED if target_score > INJECTION_THRESHOLD else (YELLOW if target_score > 0.3 else GREEN)
        if step <= 20:
            w = int(target_w * (step / 20))
            self.bar_inner.place(x=0, y=0, relheight=1.0, width=max(w, 0))
            self.bar_inner.config(bg=c)
            self.after(18, self._animate_bar, target_score, step + 1)
        else:
            self.bar_inner.place(x=0, y=0, relheight=1.0, width=target_w)

    def _clear(self):
        self.txt_input.delete("1.0", "end")
        self.txt_output.config(state="normal")
        self.txt_output.delete("1.0", "end")
        self.txt_output.config(state="disabled")
        self.lbl_action.config(text="—", fg=FG_DIM)
        self.lbl_reason.config(text="Submit a prompt to analyse", fg=FG_DIM)
        self.lbl_score_val.config(text="0.00", fg=FG_DIM)
        self.bar_inner.place(x=0, y=0, relheight=1.0, width=0)
        self.lbl_pii.config(text="None", fg=FG_DIM)
        for lbl in self.lat_labels.values():
            lbl.config(text="—")
        self.lbl_status.config(text="Ready  •  Ctrl+Enter to run")


if __name__ == "__main__":
    app = GatewayGUI()
    app.mainloop()
