"""Email Security Analyzer - Tkinter GUI.   Run:  python app.py"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from analyzer import (
    LANGUAGES,
    analyze_steps,
    human_finding_detail,
    human_finding_title,
    human_next_step,
    human_severity,
    human_verdict,
    ui_text,
)

BLUE, BLUE_DARK = "#4a79b0", "#2f5d94"
BG = "#dfe6ee"
RED, RED_BG = "#b3202a", "#fdf3f3"
GREEN, GREEN_BG = "#1e7f3c", "#f1faf3"
AMBER, AMBER_BG = "#b36b00", "#fff8ea"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.language = tk.StringVar(value="English")
        self.title(ui_text(self.language.get(), "window_title"))
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        width = min(1000, int(screen_width * 0.9))
        height = min(750, int(screen_height * 0.9))
        self.geometry(f"{width}x{height}")
        self.minsize(min(620, width), min(500, height))
        self.resizable(True, True)
        self.configure(bg=BG)
        self.report = None
        self._busy = False
        self._build_style()
        self._build_ui()

    # ------------------------------------------------------------------ style
    def _build_style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TFrame", background=BG)
        s.configure("TLabelframe", background=BG, bordercolor="#9fb0c4")
        s.configure("TLabelframe.Label", background=BG, font=("Segoe UI", 9, "bold"))
        s.configure("TLabel", background=BG, font=("Segoe UI", 10))
        s.configure("Analyze.TButton", font=("Segoe UI", 16, "bold"), foreground="white",
                    background=BLUE, padding=10)
        s.map("Analyze.TButton", background=[("active", BLUE_DARK), ("disabled", "#8fa6c2")])
        s.configure("Tool.TButton", font=("Segoe UI", 9, "bold"), padding=6)
        s.configure("Blue.Horizontal.TProgressbar", troughcolor="#c5d2e2", background=BLUE,
                    bordercolor="#9fb0c4", thickness=18)

    # --------------------------------------------------------------------- ui
    def _build_ui(self):
        self.banner = tk.Label(self, text=ui_text(self.language.get(), "banner"), bg=BLUE, fg="white",
                               font=("Segoe UI", 11, "bold"), pady=5)
        self.banner.pack(fill="x")

        body = ttk.Frame(self, padding=(10, 8))
        body.pack(fill="both", expand=True)

        language_bar = ttk.Frame(body)
        language_bar.pack(fill="x")
        self.language_label = ttk.Label(language_bar, text=ui_text(self.language.get(), "language"))
        self.language_label.pack(side="left", padx=(0, 8))
        self.language_selector = ttk.Combobox(
            language_bar, textvariable=self.language, values=LANGUAGES, state="readonly", width=12
        )
        self.language_selector.pack(side="left")
        self.language_selector.bind("<<ComboboxSelected>>", self.on_language_change)

        # headers ------------------------------------------------------------
        self.header_frame = ttk.LabelFrame(
            body, text=ui_text(self.language.get(), "email_details"), padding=8
        )
        self.header_frame.pack(fill="x")
        self.header_frame.columnconfigure(1, weight=1)
        self.field_labels = {}
        self.sender = self._row(
            self.header_frame, 0, "sender",
            ui_text(self.language.get(), "sender_placeholder")
        )
        self.recipient = self._row(self.header_frame, 1, "recipient")
        self.subject = self._row(self.header_frame, 2, "subject")
        self.attach = self._row(
            self.header_frame, 3, "attachments",
            ui_text(self.language.get(), "attachments_placeholder")
        )
        self.placeholder_fields = {
            self.sender: "sender_placeholder",
            self.attach: "attachments_placeholder",
        }

        # body ---------------------------------------------------------------
        self.message_frame = ttk.LabelFrame(
            body, text=ui_text(self.language.get(), "message"), padding=6
        )
        self.message_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.content = tk.Text(self.message_frame, height=9, wrap="word", font=("Consolas", 10),
                               relief="solid", bd=1, undo=True)
        sb = ttk.Scrollbar(self.message_frame, command=self.content.yview)
        self.content.configure(yscrollcommand=sb.set)
        self.content.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # analyze + progress -------------------------------------------------
        self.btn = ttk.Button(body, text=ui_text(self.language.get(), "check"), style="Analyze.TButton",
                              command=self.on_analyze)
        self.btn.pack(fill="x", pady=(8, 4))
        self.pvar = tk.DoubleVar(value=0)
        self.pbar = ttk.Progressbar(body, variable=self.pvar, maximum=100,
                                    style="Blue.Horizontal.TProgressbar")
        self.pbar.pack(fill="x")
        self.plabel = tk.Label(
            self.pbar, text=ui_text(self.language.get(), "ready"), bg=BLUE, fg="white",
            font=("Segoe UI", 8)
        )
        self.plabel.place(relx=0.5, rely=0.5, anchor="center")

        # result -------------------------------------------------------------
        self.result_frame = ttk.LabelFrame(
            body, text=ui_text(self.language.get(), "results"), padding=6
        )
        self.result_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.rbox = tk.Frame(self.result_frame, bg="white", highlightthickness=2, highlightbackground="#b8c4d3")
        self.rbox.pack(fill="both", expand=True)
        self.rtext = tk.Text(self.rbox, height=9, wrap="word", bd=0, bg="white",
                             font=("Segoe UI", 10), state="disabled", padx=12, pady=8,
                             cursor="arrow")
        self.rtext.pack(fill="both", expand=True)
        for name, fg in (("title", "#222"), ("red", RED), ("green", GREEN), ("amber", AMBER)):
            self.rtext.tag_configure(name, foreground=fg)
        self.rtext.tag_configure("title", font=("Segoe UI", 15))
        self.rtext.tag_configure("verdict", font=("Segoe UI", 15, "bold"))
        self.rtext.tag_configure("b", font=("Segoe UI", 10, "bold"))
        self._show_placeholder()

        # footer buttons -----------------------------------------------------
        foot = ttk.Frame(body)
        foot.pack(fill="x", pady=(8, 0))
        self.clear_button = ttk.Button(
            foot, text=ui_text(self.language.get(), "clear"), style="Tool.TButton",
            command=self.on_clear
        )
        self.clear_button.pack(side="left")
        self.about_button = ttk.Button(
            foot, text=ui_text(self.language.get(), "about_button"), style="Tool.TButton",
            command=self.on_about
        )
        self.about_button.pack(side="right")
        self.save_button = ttk.Button(
            foot, text=ui_text(self.language.get(), "save"), style="Tool.TButton",
            command=self.on_save
        )
        self.save_button.pack(expand=True)

    def _row(self, parent, r, label_key, placeholder=""):
        label = ttk.Label(parent, text=ui_text(self.language.get(), label_key))
        label.grid(row=r, column=0, sticky="w", padx=(0, 8), pady=3)
        self.field_labels[label_key] = label
        e = tk.Entry(parent, font=("Segoe UI", 10), relief="solid", bd=1)
        e.grid(row=r, column=1, sticky="ew", pady=3, ipady=3)
        if placeholder:
            self._placeholder(e, placeholder)
        return e

    def on_language_change(self, _event=None):
        language = self.language.get()
        self.title(ui_text(language, "window_title"))
        self.banner.config(text=ui_text(language, "banner"))
        self.language_label.config(text=ui_text(language, "language"))
        self.header_frame.config(text=ui_text(language, "email_details"))
        self.message_frame.config(text=ui_text(language, "message"))
        self.result_frame.config(text=ui_text(language, "results"))
        for key, label in self.field_labels.items():
            label.config(text=ui_text(language, key))
        for entry, key in self.placeholder_fields.items():
            entry._ph = ui_text(language, key)
            if entry._has_ph:
                entry.delete(0, "end")
                entry.insert(0, entry._ph)
        self.btn.config(text=ui_text(language, "check"))
        self.clear_button.config(text=ui_text(language, "clear"))
        self.about_button.config(text=ui_text(language, "about_button"))
        self.save_button.config(text=ui_text(language, "save"))
        self._set_text_direction()
        if self.report is not None:
            self.report = None
            self._show_placeholder()
            self.pvar.set(0)
            self.plabel.config(text=ui_text(language, "language_changed"))
        else:
            self._show_placeholder()

    def _set_text_direction(self):
        direction = "right" if self.language.get() == "Arabic" else "left"
        self.content.tag_configure("language_direction", justify=direction)
        self.content.tag_add("language_direction", "1.0", "end")
        self.rtext.tag_configure("language_direction", justify=direction)

    def _placeholder(self, entry, text):
        entry._ph, entry._has_ph = text, False

        def show(_=None):
            if not entry.get():
                entry.insert(0, entry._ph)
                entry.config(fg="#9aa3ad")
                entry._has_ph = True

        def hide(_=None):
            if entry._has_ph:
                entry.delete(0, "end")
                entry.config(fg="black")
                entry._has_ph = False

        entry.bind("<FocusIn>", hide)
        entry.bind("<FocusOut>", show)
        show()

    @staticmethod
    def _val(entry):
        return "" if getattr(entry, "_has_ph", False) else entry.get().strip()

    # -------------------------------------------------------------- results ui
    def _set_result(self, border, bg):
        self.rbox.config(highlightbackground=border)
        self.rtext.config(bg=bg)
        self.rbox.config(bg=bg)

    def _write(self, parts):
        self.rtext.config(state="normal")
        self.rtext.delete("1.0", "end")
        direction = "right" if self.language.get() == "Arabic" else "left"
        self.rtext.tag_configure("language_direction", justify=direction)
        for text, *tags in parts:
            self.rtext.insert("end", text, [*tags, "language_direction"])
        self.rtext.config(state="disabled")

    def _show_placeholder(self):
        self._set_result("#b8c4d3", "white")
        self._write([(ui_text(self.language.get(), "placeholder_result"), "title")])

    # ---------------------------------------------------------------- actions
    def on_analyze(self):
        if self._busy:
            return
        sender, rcpt, subj = self._val(self.sender), self._val(self.recipient), self._val(self.subject)
        body = self.content.get("1.0", "end").strip()
        attachments = self._val(self.attach)
        if not sender:
            messagebox.showwarning(
                ui_text(self.language.get(), "missing_input"),
                ui_text(self.language.get(), "missing_sender"),
            )
            return
        if not subj and not body:
            messagebox.showwarning(
                ui_text(self.language.get(), "missing_input"),
                ui_text(self.language.get(), "missing_content"),
            )
            return
        self._busy = True
        self.btn.state(["disabled"])
        self.language_selector.state(["disabled"])
        self.pvar.set(0)
        language = self.language.get()
        self.plabel.config(text=ui_text(language, "starting"))
        self._steps = analyze_steps(
            sender, rcpt, subj, body, attachments=attachments, language=language
        )
        self._tick()

    def _tick(self):
        try:
            label, pct, report = next(self._steps)
        except StopIteration:
            return
        self.pvar.set(pct)
        friendly_label = {
            "Checking sender...": "status_sender",
            "Scanning subject...": "status_subject",
            "Reading reply thread...": "status_thread",
            "Inspecting links...": "status_links",
            "Testing IP addresses...": "status_ips",
            "Analyzing content...": "status_body",
            "Cross-checking identity...": "status_identity",
            "Analysis Complete": "status_complete",
        }.get(label, label)
        if label in {
            "Checking sender...", "Scanning subject...", "Reading reply thread...",
            "Inspecting links...", "Testing IP addresses...", "Analyzing content...",
            "Cross-checking identity...", "Analysis Complete",
        }:
            friendly_label = ui_text(self.language.get(), friendly_label)
        self.plabel.config(text=f"{friendly_label} ({pct}%)" if pct == 100 else friendly_label)
        if report is None:
            self.after(180, self._tick)
        else:
            self.report = report
            self._busy = False
            self.btn.state(["!disabled"])
            self.language_selector.state(["!disabled"])
            self._render(report)

    def _render(self, r):
        language = self.language.get()
        if r.verdict.startswith("HIGH"):
            border, bg, tag, icon = RED, RED_BG, "red", "\u26d4"
        elif r.verdict == "SUSPICIOUS":
            border, bg, tag, icon = AMBER, AMBER_BG, "amber", "\u26a0"
        else:
            border, bg, tag, icon = GREEN, GREEN_BG, "green", "\u2714"
        self._set_result(border, bg)
        sev_tag = {"Urgent": "red", "High": "red", "Moderate": "amber"}
        parts = [(f"{icon}  ", "title"),
                 (human_verdict(r.verdict, language), "verdict", tag),
                 (f"\n{ui_text(language, 'risk_score')}: {r.score}/100\n\n", "title"),
                 (ui_text(language, "noticed") + "\n", "b")]
        if r.findings:
            for f in r.findings:
                detail = human_finding_detail(f.detail, language)
                detail_parts = [(f"{detail} ",)] if detail else []
                parts += [("  \u2022 ", ),
                          (f"{human_finding_title(f.title, language)}", "b")]
                if detail_parts:
                    parts += [(": ",), *detail_parts]
                parts.append((f" [{human_severity(f.severity, language)}]\n",
                              "b", sev_tag.get(f.severity, "green")))
        else:
            parts.append((ui_text(language, "no_findings"), "green"))
        parts += [("\n" + ui_text(language, "next_step") + "\n", "b"),
                  (human_next_step(r.verdict, language),)]
        self._write(parts)

    def on_clear(self):
        for e in (self.sender, self.recipient, self.subject, self.attach):
            e.delete(0, "end")
            e.event_generate("<FocusOut>")
        self.content.delete("1.0", "end")
        self.pvar.set(0)
        self.plabel.config(text=ui_text(self.language.get(), "ready"))
        self.report = None
        self._show_placeholder()

    def on_save(self):
        language = self.language.get()
        if not self.report:
            messagebox.showinfo(
                ui_text(language, "nothing_to_save"),
                ui_text(language, "check_first"),
            )
            return
        path = filedialog.asksaveasfilename(
            title=ui_text(language, "save_dialog_title"),
            defaultextension=".txt",
            initialfile="email_report.txt",
            filetypes=[(ui_text(language, "report_filetype"), "*.txt")],
        )
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.report.as_text(self._val(self.sender), self._val(self.recipient),
                                             self._val(self.subject),
                                             attachments=self._val(self.attach),
                                             language=language))
            messagebox.showinfo(
                ui_text(language, "saved"),
                f"{ui_text(language, 'saved_to')}{path}",
            )

    def on_about(self):
        language = self.language.get()
        messagebox.showinfo(
            ui_text(language, "about_title"), ui_text(language, "about_text")
        )


if __name__ == "__main__":
    App().mainloop()
