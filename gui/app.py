import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
from pubsub import pub


class MalwareAnalysisGUI(ctk.CTk):
    """Modern dark-mode dashboard for the MARS analysis platform."""

    COLORS = {
        "bg": "#181820",
        "panel": "#242430",
        "panel_header": "#2A2A38",
        "sidebar": "#1E1E28",
        "sidebar_active": "#2A2A38",
        "accent": "#1785A6",
        "accent_hover": "#1A9BC0",
        "text": "#E8E8F0",
        "text_dim": "#888899",
        "input": "#1A1A24",
        "status_bar": "#14141C",
        "log_bg": "#000000",
    }

    NAV_ITEMS = [
        ("Overview", "🏠"),
        ("Execution Logs", "📋"),
        ("PE File Structure", "📄"),
        ("Mitigations & Security", "🛡"),
        ("Strings & Artifacts", "🔤"),
        ("YARA & Detections", "🐛"),
        ("Reports", "📑"),
    ]

    def __init__(self):
        super().__init__()

        self.results_store = {}
        self.nav_buttons = {}
        self.active_nav = "Overview"
        self.report_paths = {"json": None, "pdf": None}

        self._configure_window()
        self._configure_root_grid()
        self._build_header_bar()
        self._build_sidebar()
        self._build_content_area()
        self._build_status_bar()
        self._setup_pubsub()
        self._show_page("Overview")

    # ------------------------------------------------------------------
    # Window & layout
    # ------------------------------------------------------------------

    def _configure_window(self):
        self.title("MARS - Malware Analysis & Reverse-engineering System")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")
        self.geometry("1200x700")
        self.minsize(1000, 600)
        self.configure(fg_color=self.COLORS["bg"])

    def _configure_root_grid(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

    # ------------------------------------------------------------------
    # Header bar
    # ------------------------------------------------------------------

    def _build_header_bar(self):
        self.header = ctk.CTkFrame(self, fg_color=self.COLORS["panel"], corner_radius=0, height=64)
        self.header.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            self.header, text="File Path:", font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self.COLORS["text"],
        ).grid(row=0, column=0, padx=(16, 8), pady=14, sticky="w")

        self.path_var = tk.StringVar()
        self.path_entry = ctk.CTkEntry(
            self.header, textvariable=self.path_var, height=36,
            placeholder_text="C:/path/to/sample.exe",
            fg_color=self.COLORS["input"], border_color=self.COLORS["panel_header"],
        )
        self.path_entry.grid(row=0, column=1, padx=8, pady=14, sticky="ew")

        self.btn_browse = ctk.CTkButton(
            self.header, text="📁  Browse...", width=120, height=36,
            fg_color=self.COLORS["panel_header"], hover_color="#353545",
            command=self._browse_file,
        )
        self.btn_browse.grid(row=0, column=2, padx=(8, 4), pady=14)

        self.btn_analyze = ctk.CTkButton(
            self.header, text="▶  Start Analysis", width=150, height=36,
            fg_color=self.COLORS["accent"], hover_color=self.COLORS["accent_hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._start_analysis,
        )
        self.btn_analyze.grid(row=0, column=3, padx=(4, 16), pady=14)

    # ------------------------------------------------------------------
    # Sidebar
    # ------------------------------------------------------------------

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, fg_color=self.COLORS["sidebar"], corner_radius=0, width=220)
        self.sidebar.grid(row=1, column=0, rowspan=2, sticky="ns")
        self.sidebar.grid_propagate(False)

        ctk.CTkLabel(
            self.sidebar, text="NAVIGATION", font=ctk.CTkFont(size=11, weight="bold"),
            text_color=self.COLORS["text_dim"],
        ).pack(anchor="w", padx=20, pady=(20, 10))

        for label, icon in self.NAV_ITEMS:
            self._create_nav_item(label, icon)

    def _create_nav_item(self, label, icon):
        container = ctk.CTkFrame(self.sidebar, fg_color="transparent", height=42)
        container.pack(fill="x", padx=8, pady=2)
        container.pack_propagate(False)

        accent = ctk.CTkFrame(
            container, width=4, fg_color="transparent", corner_radius=2,
        )
        accent.pack(side="left", fill="y", padx=(4, 0))

        btn = ctk.CTkButton(
            container, text=f"{icon}   {label}", anchor="w", height=38,
            fg_color="transparent", hover_color=self.COLORS["panel_header"],
            text_color=self.COLORS["text"], font=ctk.CTkFont(size=13),
            command=lambda l=label: self._show_page(l),
        )
        btn.pack(side="left", fill="both", expand=True, padx=(4, 8))

        self.nav_buttons[label] = {"container": container, "accent": accent, "button": btn}

    def _set_active_nav(self, label):
        self.active_nav = label
        for name, widgets in self.nav_buttons.items():
            is_active = name == label
            widgets["accent"].configure(fg_color=self.COLORS["accent"] if is_active else "transparent")
            widgets["button"].configure(
                fg_color=self.COLORS["sidebar_active"] if is_active else "transparent",
            )

    # ------------------------------------------------------------------
    # Main content pages
    # ------------------------------------------------------------------

    def _build_content_area(self):
        self.content = ctk.CTkFrame(self, fg_color=self.COLORS["bg"], corner_radius=0)
        self.content.grid(row=1, column=1, sticky="nsew", padx=(0, 0), pady=0)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.pages = {}
        self.pages["Overview"] = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["Execution Logs"] = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["PE File Structure"] = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["Mitigations & Security"] = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["Strings & Artifacts"] = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["YARA & Detections"] = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["Reports"] = ctk.CTkFrame(self.content, fg_color="transparent")

        self._build_overview_page()
        self._build_logs_page()
        self._build_pe_page()
        self._build_mitigations_page()
        self._build_strings_page()
        self._build_yara_page()
        self._build_reports_page()

    def _build_overview_page(self):
        page = self.pages["Overview"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_columnconfigure(1, weight=1)
        page.grid_rowconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)

        self.card_summary, self.summary_body = self._create_card(page, "File Summary", 0, 0)
        self.card_security, self.security_tree = self._create_security_card(page, 0, 1)
        self.card_findings, self.findings_body = self._create_card(page, "Key Findings", 1, 0)
        self.card_log, self.overview_log = self._create_log_card(page, 1, 1)

        self._populate_summary_placeholder()
        self._populate_findings_placeholder()

    def _create_card(self, parent, title, row, col):
        card = ctk.CTkFrame(parent, fg_color=self.COLORS["panel"], corner_radius=10)
        card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(card, fg_color="transparent", height=36)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header, text=title, font=ctk.CTkFont(size=14, weight="bold"),
            text_color=self.COLORS["text"], anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header, text="⋯", font=ctk.CTkFont(size=16),
            text_color=self.COLORS["text_dim"],
        ).grid(row=0, column=1, sticky="e")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        body.grid_columnconfigure(1, weight=1)

        return card, body

    def _create_security_card(self, parent, row, col):
        card, _ = self._create_card(parent, "Security Posture", row, col)
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._configure_treeview_style()
        columns = ("mitigation", "status", "value")
        tree = ttk.Treeview(body, columns=columns, show="headings", style="MARS.Treeview", height=8)
        tree.heading("mitigation", text="Mitigations")
        tree.heading("status", text="Status")
        tree.heading("value", text="Exact Value")
        tree.column("mitigation", width=160, anchor="w")
        tree.column("status", width=90, anchor="center")
        tree.column("value", width=180, anchor="w")

        scroll = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        return card, tree

    def _create_log_card(self, parent, row, col):
        card, _ = self._create_card(parent, "Log", row, col)
        log = self._create_log_textbox(card)
        log.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        card.grid_rowconfigure(1, weight=1)
        return card, log

    def _create_log_textbox(self, parent):
        box = ctk.CTkTextbox(
            parent, fg_color=self.COLORS["log_bg"], text_color="#00FF00",
            font=ctk.CTkFont(family="Consolas", size=11), wrap="word",
            activate_scrollbars=True,
        )
        text = box._textbox
        text.configure(state="disabled")
        text.tag_configure("plus", foreground="#00FF00")
        text.tag_configure("info", foreground="#5B9BD5")
        text.tag_configure("warn", foreground="#FFD966")
        text.tag_configure("critical", foreground="#FF4444")
        text.tag_configure("default", foreground="#CCCCCC")
        return box

    def _configure_treeview_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "MARS.Treeview",
            background="#1A1A24", foreground=self.COLORS["text"],
            fieldbackground="#1A1A24", borderwidth=0, rowheight=26,
            font=("Segoe UI", 10),
        )
        style.configure(
            "MARS.Treeview.Heading",
            background=self.COLORS["panel_header"], foreground=self.COLORS["text"],
            font=("Segoe UI", 10, "bold"), borderwidth=0,
        )
        style.map("MARS.Treeview", background=[("selected", "#353545")])

    def _build_logs_page(self):
        page = self.pages["Execution Logs"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(0, weight=1)
        self.full_log = self._create_log_textbox(page)
        self.full_log.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

    def _build_detail_tree_page(self, page_key, title):
        page = self.pages[page_key]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            page, text=title, font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"], anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))

        frame = ctk.CTkFrame(page, fg_color=self.COLORS["panel"], corner_radius=10)
        frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        columns = ("category", "property", "value")
        tree = ttk.Treeview(frame, columns=columns, show="headings", style="MARS.Treeview")
        tree.heading("category", text="Category")
        tree.heading("property", text="Property")
        tree.heading("value", text="Value / Finding")
        tree.column("category", width=180)
        tree.column("property", width=220)
        tree.column("value", width=500)

        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        scroll.grid(row=0, column=1, sticky="ns", pady=8)

        return tree

    def _build_pe_page(self):
        self.pe_tree = self._build_detail_tree_page("PE File Structure", "PE File Structure")

    def _build_mitigations_page(self):
        page = self.pages["Mitigations & Security"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            page, text="Mitigations & Security", font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"], anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))

        frame = ctk.CTkFrame(page, fg_color=self.COLORS["panel"], corner_radius=10)
        frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        columns = ("mitigation", "status", "value")
        self.mitigations_tree = ttk.Treeview(frame, columns=columns, show="headings", style="MARS.Treeview")
        self.mitigations_tree.heading("mitigation", text="Mitigation")
        self.mitigations_tree.heading("status", text="Status")
        self.mitigations_tree.heading("value", text="Exact Value")
        self.mitigations_tree.column("mitigation", width=240)
        self.mitigations_tree.column("status", width=100)
        self.mitigations_tree.column("value", width=300)

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.mitigations_tree.yview)
        self.mitigations_tree.configure(yscrollcommand=scroll.set)
        self.mitigations_tree.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        scroll.grid(row=0, column=1, sticky="ns", pady=8)

    def _build_strings_page(self):
        page = self.pages["Strings & Artifacts"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            page, text="Strings & Artifacts", font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"], anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))

        self.strings_scroll = ctk.CTkScrollableFrame(page, fg_color=self.COLORS["panel"], corner_radius=10)
        self.strings_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.strings_scroll.grid_columnconfigure(0, weight=1)

    def _build_yara_page(self):
        page = self.pages["YARA & Detections"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            page, text="YARA & Detections", font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"], anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))

        self.yara_frame = ctk.CTkFrame(page, fg_color=self.COLORS["panel"], corner_radius=10)
        self.yara_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.yara_frame.grid_columnconfigure(0, weight=1)

    def _build_reports_page(self):
        page = self.pages["Reports"]
        page.grid_columnconfigure(0, weight=1)

        card = ctk.CTkFrame(page, fg_color=self.COLORS["panel"], corner_radius=10)
        card.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            card, text="Generated Reports", font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"],
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=20, pady=(20, 16))

        self.report_json_label = ctk.CTkLabel(
            card, text="📄 JSON: —", anchor="w", text_color=self.COLORS["text_dim"],
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.report_json_label.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=4)

        self.report_pdf_label = ctk.CTkLabel(
            card, text="📕 PDF: —", anchor="w", text_color=self.COLORS["text_dim"],
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.report_pdf_label.grid(row=2, column=0, columnspan=2, sticky="ew", padx=20, pady=4)

        ctk.CTkButton(
            card, text="📂  Open Reports Folder", width=180,
            fg_color=self.COLORS["accent"], hover_color=self.COLORS["accent_hover"],
            command=self._open_reports_folder,
        ).grid(row=3, column=0, sticky="w", padx=20, pady=(16, 20))

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _build_status_bar(self):
        self.status_bar = ctk.CTkFrame(self, fg_color=self.COLORS["status_bar"], corner_radius=0, height=32)
        self.status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.status_bar.grid_propagate(False)

        self.status_label = ctk.CTkLabel(
            self.status_bar,
            text="Ready. Select a file and click Start Analysis.",
            font=ctk.CTkFont(size=12), text_color=self.COLORS["text_dim"], anchor="w",
        )
        self.status_label.pack(side="left", padx=16, pady=6)

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _show_page(self, label):
        for page in self.pages.values():
            page.grid_forget()
        self.pages[label].grid(row=0, column=0, sticky="nsew")
        self._set_active_nav(label)

    # ------------------------------------------------------------------
    # PubSub & backend integration
    # ------------------------------------------------------------------

    def _setup_pubsub(self):
        pub.subscribe(self.append_log, "gui.log")
        pub.subscribe(self._on_table_update, "gui.update_table")
        pub.subscribe(self._on_analysis_start, "analysis.start")
        pub.subscribe(self._on_analysis_complete, "analysis.complete")

    def append_log(self, msg):
        self.after(0, lambda: self._write_log(msg))

    def _write_log(self, msg):
        tag = self._log_tag_for_message(msg)
        for box in (self.overview_log, self.full_log):
            text = box._textbox
            text.configure(state="normal")
            text.insert("end", msg + "\n", tag)
            text.see("end")
            text.configure(state="disabled")

    @staticmethod
    def _log_tag_for_message(msg):
        if msg.strip().startswith("[+]"):
            return "plus"
        if msg.strip().startswith("[!!!]"):
            return "critical"
        if msg.strip().startswith("[!]") or "WARNING" in msg.upper():
            return "warn"
        if msg.strip().startswith("[*]"):
            return "info"
        return "default"

    def _on_table_update(self, module, data):
        self.after(0, lambda: self._apply_table_update(module, data))

    def _apply_table_update(self, module, data):
        self.results_store[module] = data
        self._refresh_all_views()

    def _on_analysis_start(self, filepath):
        self.after(0, lambda: self._reset_for_analysis(filepath))

    def _on_analysis_complete(self, status):
        self.after(0, lambda: self._finish_analysis(status))

    # ------------------------------------------------------------------
    # User actions
    # ------------------------------------------------------------------

    def _browse_file(self):
        filepath = filedialog.askopenfilename(
            title="Select Malware/File for Analysis",
            filetypes=(
                ("Executables & Archives", "*.exe *.dll *.sys *.zip *.msi"),
                ("All Files", "*.*"),
            ),
        )
        if filepath:
            self.path_var.set(filepath)

    def _start_analysis(self):
        filepath = self.path_var.get().strip()
        if not filepath or not os.path.exists(filepath):
            messagebox.showwarning("Invalid Input", "Please select a valid file to analyze.")
            return

        self.btn_analyze.configure(state="disabled")
        self.btn_browse.configure(state="disabled")
        pub.sendMessage("analysis.start", filepath=filepath)

    def _open_reports_folder(self):
        folder = os.path.abspath("./workspace/reports")
        os.makedirs(folder, exist_ok=True)
        os.startfile(folder)

    # ------------------------------------------------------------------
    # Dashboard refresh
    # ------------------------------------------------------------------

    def _reset_for_analysis(self, filepath):
        self.results_store.clear()
        self.report_paths = {"json": None, "pdf": None}
        self.path_var.set(filepath)

        for box in (self.overview_log, self.full_log):
            text = box._textbox
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.configure(state="disabled")

        for tree in (self.pe_tree,):
            for item in tree.get_children():
                tree.delete(item)
        for item in self.mitigations_tree.get_children():
            self.mitigations_tree.delete(item)
        for item in self.security_tree.get_children():
            self.security_tree.delete(item)

        for widget in self.strings_scroll.winfo_children():
            widget.destroy()
        for widget in self.yara_frame.winfo_children():
            widget.destroy()

        self._populate_summary_placeholder()
        self._populate_findings_placeholder()
        self.status_label.configure(text="Analysis in progress…")
        self._show_page("Overview")

    def _finish_analysis(self, status):
        self.btn_analyze.configure(state="normal")
        self.btn_browse.configure(state="normal")

        intake = self.results_store.get("Intake", {})
        analysis_id = intake.get("Analysis ID")
        if analysis_id and status == "Success":
            json_path = os.path.abspath(f"./workspace/reports/{analysis_id}_Report.json")
            pdf_path = os.path.abspath(f"./workspace/reports/{analysis_id}_Report.pdf")
            self.report_paths = {"json": json_path, "pdf": pdf_path}
            self.report_json_label.configure(text=f"📄 JSON: {json_path}")
            self.report_pdf_label.configure(text=f"📕 PDF: {pdf_path}")
            self.status_label.configure(
                text="Analysis Complete. Reports Saved: 📄 JSON, 📕 PDF",
                text_color="#5BC0BE",
            )
        elif status == "Failed":
            self.status_label.configure(text="Analysis failed. Check logs for details.", text_color="#FF6666")
        else:
            self.status_label.configure(text=f"Analysis finished with status: {status}", text_color=self.COLORS["text_dim"])

    def _refresh_all_views(self):
        self._refresh_summary_card()
        self._refresh_security_card()
        self._refresh_findings_card()
        self._refresh_pe_tree()
        self._refresh_mitigations_tree()
        self._refresh_strings_page()
        self._refresh_yara_page()

    def _populate_summary_placeholder(self):
        for widget in self.summary_body.winfo_children():
            widget.destroy()
        fields = [
            ("Analysis ID", "—"),
            ("Original File Name", "—"),
            ("File Size", "—"),
            ("Hash (MD5)", "—"),
            ("Hash (SHA256)", "—"),
        ]
        self.summary_labels = {}
        for i, (key, val) in enumerate(fields):
            ctk.CTkLabel(
                self.summary_body, text=key, text_color=self.COLORS["text_dim"],
                font=ctk.CTkFont(size=12), anchor="w",
            ).grid(row=i, column=0, sticky="w", pady=4, padx=(0, 12))
            lbl = ctk.CTkLabel(
                self.summary_body, text=val, text_color=self.COLORS["text"],
                font=ctk.CTkFont(size=12), anchor="w", wraplength=320,
            )
            lbl.grid(row=i, column=1, sticky="w", pady=4)
            self.summary_labels[key] = lbl

    def _populate_findings_placeholder(self):
        for widget in self.findings_body.winfo_children():
            widget.destroy()
        placeholders = [
            "Suspicious APIs: —",
            "URLs: —",
            "Emails: —",
            "YARA Hits: —",
        ]
        self.finding_labels = []
        for i, text in enumerate(placeholders):
            lbl = ctk.CTkLabel(
                self.findings_body, text=text, text_color=self.COLORS["text"],
                font=ctk.CTkFont(size=12), anchor="w", wraplength=380, justify="left",
            )
            lbl.grid(row=i, column=0, sticky="w", pady=6)
            self.finding_labels.append(lbl)

    def _refresh_summary_card(self):
        intake = self.results_store.get("Intake", {})
        if not intake:
            return

        size_bytes = intake.get("File Size (Bytes)", 0)
        size_str = self._format_size(size_bytes)

        self.summary_labels["Analysis ID"].configure(text=self._truncate(intake.get("Analysis ID", "—"), 28))
        self.summary_labels["Original File Name"].configure(
            text=self._truncate(intake.get("Original File Name", "—"), 32),
        )
        self.summary_labels["File Size"].configure(text=size_str)
        self.summary_labels["Hash (MD5)"].configure(text=self._truncate(intake.get("MD5", "—"), 40))
        self.summary_labels["Hash (SHA256)"].configure(text=self._truncate(intake.get("SHA256", "—"), 40))

    def _refresh_security_card(self):
        mitigations = self.results_store.get("Static: Mitigations", {})
        if not mitigations:
            return

        for item in self.security_tree.get_children():
            self.security_tree.delete(item)

        for name, value in mitigations.items():
            status_icon, status_text = self._status_for_value(value)
            self.security_tree.insert("", "end", values=(name, f"{status_icon} {status_text}", value))

        for item in self.mitigations_tree.get_children():
            self.mitigations_tree.delete(item)
        for name, value in mitigations.items():
            status_icon, status_text = self._status_for_value(value)
            self.mitigations_tree.insert("", "end", values=(name, f"{status_icon} {status_text}", value))

    def _refresh_findings_card(self):
        imports = self.results_store.get("Static: Suspicious Imports", {})
        artifacts = self.results_store.get("Static: Extracted Artifacts", {})
        yara = self.results_store.get("Static: YARA Signatures", {})

        api_count = imports.get("Tracked APIs Found", 0)
        apis = imports.get("APIs", "None detected")
        api_text = f"Suspicious APIs: {api_count} ({apis})" if api_count else "Suspicious APIs: 0"

        urls = self._artifact_list(artifacts, "URL")
        emails = self._artifact_list(artifacts, "Email")
        url_text = f"URLs: {len(urls)} ({self._truncate_list(urls)})" if urls else "URLs: 0"
        email_text = f"Emails: {len(emails)} ({self._truncate_list(emails)})" if emails else "Emails: 0"

        hits = yara.get("Hits", 0)
        rules = yara.get("Matched Rules", "Clean")
        yara_text = f"YARA Hits: {hits} ({rules})" if hits else "YARA Hits: 0 (Clean)"

        texts = [api_text, url_text, email_text, yara_text]
        for lbl, text in zip(self.finding_labels, texts):
            lbl.configure(text=text)

    def _refresh_pe_tree(self):
        pe_modules = {
            "Static: PE Headers": "PE Headers",
            "Static: Sections": "Sections",
            "Static: Manifest Data": "Manifest",
        }
        for item in self.pe_tree.get_children():
            self.pe_tree.delete(item)

        for module_key, category in pe_modules.items():
            data = self.results_store.get(module_key, {})
            for prop, val in data.items():
                self.pe_tree.insert("", "end", values=(category, prop, val))

    def _refresh_mitigations_tree(self):
        self._refresh_security_card()

    def _refresh_strings_page(self):
        counts = self.results_store.get("Static: Strings Analytics", {})
        artifacts = self.results_store.get("Static: Extracted Artifacts", {})

        for widget in self.strings_scroll.winfo_children():
            widget.destroy()

        if not counts and not artifacts:
            ctk.CTkLabel(
                self.strings_scroll, text="No string data yet. Run an analysis first.",
                text_color=self.COLORS["text_dim"],
            ).grid(row=0, column=0, sticky="w", padx=12, pady=12)
            return

        row = 0
        for category in ("IPv4", "IPv6", "URL", "Registry", "Email", "Password-Like"):
            count = counts.get(category, 0)
            values = self._artifact_list(artifacts, category)
            ctk.CTkLabel(
                self.strings_scroll,
                text=f"{category}  ({count})",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=self.COLORS["accent"], anchor="w",
            ).grid(row=row, column=0, sticky="w", padx=16, pady=(12, 4))
            row += 1

            if values:
                display = "\n".join(f"  • {v}" for v in values)
            else:
                display = "  (none found)"
            ctk.CTkLabel(
                self.strings_scroll, text=display, anchor="w", justify="left",
                text_color=self.COLORS["text"], font=ctk.CTkFont(family="Consolas", size=11),
                wraplength=700,
            ).grid(row=row, column=0, sticky="w", padx=16, pady=(0, 8))
            row += 1

    def _refresh_yara_page(self):
        yara = self.results_store.get("Static: YARA Signatures", {})
        for widget in self.yara_frame.winfo_children():
            widget.destroy()

        if not yara:
            ctk.CTkLabel(
                self.yara_frame, text="No YARA results yet.",
                text_color=self.COLORS["text_dim"],
            ).grid(row=0, column=0, sticky="w", padx=20, pady=20)
            return

        hits = yara.get("Hits", 0)
        rules = yara.get("Matched Rules", "Clean")
        color = "#FF6666" if hits else "#5BC0BE"

        ctk.CTkLabel(
            self.yara_frame, text=f"Total Hits: {hits}",
            font=ctk.CTkFont(size=14, weight="bold"), text_color=color,
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(20, 8))

        ctk.CTkLabel(
            self.yara_frame, text=f"Matched Rules: {rules}",
            font=ctk.CTkFont(size=12), text_color=self.COLORS["text"], wraplength=700, justify="left",
        ).grid(row=1, column=0, sticky="w", padx=20, pady=(0, 20))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_size(size_bytes):
        if size_bytes >= 1024 ** 2:
            return f"{size_bytes / (1024 ** 2):.1f} MB"
        if size_bytes >= 1024:
            return f"{size_bytes / 1024:.1f} KB"
        return f"{size_bytes} bytes"

    @staticmethod
    def _truncate(text, length):
        text = str(text)
        return text if len(text) <= length else text[: length - 3] + "..."

    @staticmethod
    def _truncate_list(items, max_items=3):
        if not items:
            return ""
        shown = ", ".join(items[:max_items])
        if len(items) > max_items:
            shown += f", +{len(items) - max_items} more"
        return shown

    @staticmethod
    def _artifact_list(artifacts, key):
        if not artifacts:
            return []
        raw = artifacts.get(key, [])
        if isinstance(raw, list):
            return raw
        if isinstance(raw, str) and raw not in ("", "None"):
            return [v.strip() for v in raw.split(",")]
        return []

    @staticmethod
    def _status_for_value(value):
        val = str(value).lower()
        if "enabled" in val and "disabled" not in val:
            return "🟢", "Enabled"
        if "disabled" in val:
            return "🔴", "Disabled"
        return "⚪", str(value)
