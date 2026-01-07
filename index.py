import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import re
from collections import OrderedDict, defaultdict
from urllib.parse import unquote
import html
import smtplib
from email.message import EmailMessage
from tkinter.simpledialog import askstring
import datetime
import os
from sklearn.ensemble import IsolationForest
import numpy as np







class LogBasedDetectionSystem(tb.Window):

    def __init__(self):
        super().__init__(themename="darkly")
        self.title("Log Based Detection System")
        self.geometry("1550x880")

        self.logs = []
        
        self.rules = self.load_rules()
        self.rules.update(self.load_custom_rules())

        self.detected_alerts = []
        self.attack_stats = defaultdict(int)
        self.ioc_ips = self.load_ioc_ips()
        self.blocked_ips = set()
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.admin_email = "admin@example.com"       
        self.sender_email = "yourmail@gmail.com"     
        self.sender_password = "APP_PASSWORD_HERE"   



        self.build_ui()

    # ================= UI ================= #

    def build_ui(self):
        self.build_top_panel()
        self.build_dashboard()
        self.build_filter_panel()
        self.build_tables()
        self.build_status_bar()

    def build_top_panel(self):
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill=X)

        ttk.Button(frame, text="Upload Log",
                   command=self.load_log,
                   bootstyle=PRIMARY).pack(side=LEFT, padx=6)

        ttk.Button(frame, text="Analyze",
                   command=self.analyze_logs,
                   bootstyle=SUCCESS).pack(side=LEFT, padx=6)

        ttk.Button(frame, text="Add Rule",
                   command=self.add_rule_dialog,
                   bootstyle=INFO).pack(side=LEFT, padx=6)

        ttk.Button(frame, text="Show Rules",
                   command=self.show_rules,
                   bootstyle=SECONDARY).pack(side=LEFT, padx=6)

        ttk.Button(frame, text="Clear",
                   command=self.clear_all,
                   bootstyle=DANGER).pack(side=LEFT, padx=6)
        ttk.Button(frame, text="Send Alert Email",
           command=self.send_alert_email,
           bootstyle=WARNING).pack(side=LEFT, padx=6)
        ttk.Button(frame, text="Generate Report",
           command=self.generate_report,
           bootstyle=SECONDARY).pack(side=LEFT, padx=6)
        ttk.Button(frame, text="ML Anomaly Detection",
           command=self.run_ml_detection,
           bootstyle=WARNING).pack(side=LEFT, padx=6)




    # -------- DASHBOARD -------- #

    def build_dashboard(self):
        self.dashboard = ttk.Labelframe(self, text="Dashboard", padding=10)
        self.dashboard.pack(fill=X, padx=10, pady=5)

        self.lbl_logs = ttk.Label(self.dashboard, text="Logs Loaded: 0")
        self.lbl_logs.pack(side=LEFT, padx=15)

        self.lbl_threats = ttk.Label(self.dashboard, text="Threats Detected: 0",
                                     bootstyle=DANGER)
        self.lbl_threats.pack(side=LEFT, padx=15)

        self.attack_frame = ttk.Frame(self.dashboard)
        self.attack_frame.pack(side=LEFT, padx=30)

    def update_dashboard(self):
        self.lbl_logs.config(text=f"Logs Loaded: {len(self.logs)}")
        self.lbl_threats.config(
            text=f"Threats Detected: {len(self.detected_alerts)}"
        )

        for widget in self.attack_frame.winfo_children():
            widget.destroy()

        for attack, count in sorted(self.attack_stats.items(),
                                     key=lambda x: x[1],
                                     reverse=True):
            ttk.Label(
                self.attack_frame,
                text=f"{attack}: {count}",
                bootstyle=WARNING
            ).pack(side=LEFT, padx=10)

    # -------- FILTER PANEL -------- #

    def build_filter_panel(self):
        frame = ttk.Frame(self, padding=8)
        frame.pack(fill=X)

        ttk.Label(frame, text="Search Logs:").pack(side=LEFT, padx=5)
        self.search_var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=self.search_var, width=30)
        entry.pack(side=LEFT, padx=5)
        entry.bind("<KeyRelease>", self.search_logs)

        ttk.Label(frame, text="Filter Rule:").pack(side=LEFT, padx=15)
        self.rule_filter = tk.StringVar(value="All")
        self.rule_combo = ttk.Combobox(frame, textvariable=self.rule_filter,
                                       width=30)
        self.rule_combo.pack(side=LEFT)
        self.rule_combo.bind("<<ComboboxSelected>>", self.filter_alerts)

    # -------- TABLES -------- #

    def build_tables(self):
        pane = ttk.PanedWindow(self, orient=HORIZONTAL)
        pane.pack(fill=BOTH, expand=True, padx=10, pady=5)

        left = ttk.Labelframe(pane, text="Parsed Logs")
        pane.add(left, weight=3)

        self.log_table = ttk.Treeview(
            left, columns=("time", "ip", "status", "request"),
            show="headings"
        )

        for col, w in zip(("time", "ip", "status", "request"),
                          (200, 160, 90, 760)):
            self.log_table.heading(col, text=col.upper())
            self.log_table.column(col, width=w)

        self.log_table.pack(fill=BOTH, expand=True)

        right = ttk.Labelframe(pane, text="Alerts Panel")
        pane.add(right, weight=2)

        self.alert_table = ttk.Treeview(
            right, columns=("rule", "time", "ip", "payload"),
            show="headings"
        )

        for col, w in zip(("rule", "time", "ip", "payload"),
                          (240, 200, 160, 480)):
            self.alert_table.heading(col, text=col.upper())
            self.alert_table.column(col, width=w)

        self.alert_table.pack(fill=BOTH, expand=True)

    def build_status_bar(self):
        self.status = ttk.Label(self,
                                text="Ready",
                                bootstyle=INVERSE,
                                anchor=W,
                                padding=5)
        self.status.pack(fill=X, side=BOTTOM)
    def load_ioc_ips(self):
        iocs = set()
        try:
            with open("ioc_ips.txt", "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        iocs.add(ip)
        except FileNotFoundError:
            pass
        return iocs
    def decode_payload(self, text):
        """
        Decode encoded attack payloads to prevent evasion.
        """
        try:
            decoded = unquote(text)          # URL decoding
            decoded = html.unescape(decoded) # HTML entity decoding

        # If decoding wipes content, fall back to original
            return decoded if decoded.strip() else text
        except Exception:
            return text
    def extract_features(self):
        features = []

        for log in self.logs:
            raw = log["raw"]

            ip_len = len(log["ip"]) if log["ip"] != "N/A" else 0
            req_len = len(log["request"])
            status_num = int(log["status"]) if log["status"].isdigit() else 0

            features.append([ip_len, req_len, status_num])

        return np.array(features)
    def run_ml_detection(self):

        if not self.logs:
            messagebox.showinfo("Info", "Load logs first.")
            return

        X = self.extract_features()

        model = IsolationForest(contamination=0.05, random_state=42)
        preds = model.fit_predict(X)

        for log, p in zip(self.logs, preds):
            if p == -1:   # anomaly
                alert = (
                    "ML Anomaly Detected",
                    log["time"],
                    log["ip"],
                    log["request"]
                )
                self.detected_alerts.append(alert)
                self.attack_stats["ML Anomaly"] += 1
                self.alert_table.insert("", "end", values=alert)

        self.update_dashboard()

        messagebox.showinfo("ML Detection", "Machine learning anomaly detection completed.")

    

    

    # ================= LOG PROCESSING ================= #

    def load_log(self):
        path = filedialog.askopenfilename(
            filetypes=[("Log Files", "*.log *.txt"), ("All Files", "*.*")]
        )
        if not path:
            return

        self.logs.clear()
        self.clear_tables()

        apache = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<time>.*?)\].*?"(?P<req>.*?)".*?(?P<status>\d{3})'
        )

        with open(path, "r", errors="ignore") as f:
            for line in f:
                m = apache.search(line)
                if m:
                    entry = {
                        "time": m.group("time"),
                        "ip": m.group("ip"),
                        "status": m.group("status"),
                        "request": m.group("req"),
                        "raw": line.strip()
                    }
                else:
                    entry = {
                        "time": "-",
                        "ip": "N/A",
                        "status": "-",
                        "request": line.strip()[:120],
                        "raw": line.strip()
                    }

                self.logs.append(entry)
                self.log_table.insert("", END, values=(
                    entry["time"], entry["ip"],
                    entry["status"], entry["request"]
                ))

        self.update_dashboard()
        self.status.config(text="Logs loaded successfully")

    def analyze_logs(self):
        self.detected_alerts.clear()
        self.attack_stats.clear()
        self.alert_table.delete(*self.alert_table.get_children())

        for entry in self.logs:
            raw = entry["raw"]

        # 🔥 IOC CHECK (HIGHEST PRIORITY)
            if entry["ip"] in self.ioc_ips:
                alert = (
                    "IOC Match (Known Malicious IP)",
                    entry["time"],
                    entry["ip"],
                    entry["request"]
            )
                self.detected_alerts.append(alert)
                self.attack_stats["IOC Match"] += 1
                self.blocked_ips.add(entry["ip"])
                self.alert_table.insert("", END, values=alert)
                continue  # skip rule checks

        # 🔹 RULE-BASED DETECTION
            for rule, pattern in self.rules.items():
                if re.search(pattern, raw, re.IGNORECASE):
                    alert = (rule, entry["time"], entry["ip"], entry["request"])
                    self.detected_alerts.append(alert)
                    self.attack_stats[rule] += 1
                    self.alert_table.insert("", END, values=alert)
                    break

        self.rule_combo["values"] = ["All"] + list(self.rules.keys()) + ["IOC Match"]
        self.update_dashboard()
        self.status.config(text="Analysis completed")

        if self.detected_alerts:
            messagebox.showwarning(
                "Threats Detected",
                f"{len(self.detected_alerts)} threats identified!"
        )

    # ================= SEARCH & FILTER ================= #

    def search_logs(self, event=None):
        query = self.search_var.get().lower()
        self.log_table.delete(*self.log_table.get_children())

        for e in self.logs:
            if query in e["raw"].lower():
                self.log_table.insert("", END, values=(
                    e["time"], e["ip"], e["status"], e["request"]
                ))

    def filter_alerts(self, event=None):
        selected = self.rule_filter.get()
        self.alert_table.delete(*self.alert_table.get_children())

        for a in self.detected_alerts:
            if selected == "All" or a[0] == selected:
                self.alert_table.insert("", END, values=a)

    # ================= RULE ENGINE ================= #

    def load_rules(self):
        return OrderedDict([

            ("Failed Login",
             r"\b(failed|unauthorized|invalid password|authentication failure|login failed)\b"),

            ("SQL Injection",
             r"(union\s+select|select\s+\*|drop\s+table|--|;--|\bOR\b.+?=.+?)"),

            ("XSS",
             r"(<script\b|javascript:|onerror=|onload=)"),

            
            ("Directory Traversal",
            r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ)"),

            ("Encoded Directory Traversal",
            r"(%2e%2e%2f|%2e%2e/|%252e%252e%252f)"),

            ("Error / Denied",
             r"\b(error|denied|forbidden|403|401|500|502)\b"),

            ("Multiple Failed Login Indicators",
             r"\b(failed login|authentication failure|invalid user|invalid password|incorrect password)\b"),

            ("Credential Stuffing Probe",
             r"(\busername=|\blogin=|\buser=).{1,80}(\bpassword=|\bpass=|\bpwd=)"),

            ("SQLi – Tautology / OR 1=1",
             r"(\bOR\b\s+1=1|'?\s+or\s+'1'='1'|\"?\s+or\s+\"1\"=\"1\")"),

            ("Command Injection / Shell",
             r"(;|\|\||&&|\$\(|\bwget\b|\bcurl\b|\bexec\b|\bsystem\b|\bbase64\s+-d\b)"),

            ("Local File Inclusion (LFI) / RFI",
             r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/proc/self/environ|http://|https://)"),

            ("SSRF / Internal URL Fetch",
             r"(http://(?:127\.0\.0\.1|localhost)|169\.254|0\.0\.0\.0)"),

            ("XSS – Script / Event Handlers",
             r"(<script\b|<img\b[^>]*onerror=|onload=|javascript:alert)"),

            ("Encoded Path Traversal",
             r"(%2e%2e%2f|%252e%252e%252f|(\.\./)+)"),

            ("File Upload to Admin / Upload Endpoint",
             r"(POST\s+/.{0,60}(upload|file|attach|import|admin).*HTTP|multipart/form-data)"),

            ("Sensitive File Access",
             r"(/etc/passwd|/etc/shadow|wp-config\.php|/id_rsa|\.git/config|/proc/self/environ)"),

            ("Discovery / Recon Probes",
             r"(/robots\.txt|/sitemap\.xml|/\.git/|/\.env|/phpinfo\.php|/admin|/wp-admin)"),

            ("Long Query / Possible Exfil",
             r".{200,}"),

            ("Scanner / Automation UA",
             r"(\bnikto\b|\bwget\b|\bcurl\b|\bsqlmap\b|\bacunetix\b|\bmasscan\b|\bpython-requests\b)"),

            ("Repeated 4xx / 5xx Status",
             r"\b(401|403|404|500|502|503|504)\b"),

            ("Base64 / Hex Payload",
             r"([A-Za-z0-9+/]{40,}={0,2}|\\x[0-9A-Fa-f]{2,})"),

            ("Open Redirect Parameter",
             r"(\bredirect=|\breturn=|\bnext=)\s*(https?://)"),

            ("Default Admin Login Probe",
             r"(/admin/login|/administrator/index|/manager/html)"),

            ("Path Traversal Encoded Variants",
             r"(%2e%2e%2f|%2e%2e/|%252e%252e%252f)")
        ])
    def load_custom_rules(self):
        """
        Load user-added rules from file
        """
        rules = {}
        try:
            with open("custom_rules.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":::" not in line:
                        continue
                    name, pattern = line.split(":::", 1)
                    rules[name] = pattern
        except FileNotFoundError:
            pass
        return rules


    def save_custom_rule(self, name, pattern):
        """
        Save a new rule permanently
        """
        with open("custom_rules.txt", "a") as f:
            f.write(f"{name}:::{pattern}\n")




    def add_rule_dialog(self):
        win = tb.Toplevel(self)
        win.title("Add Rule")
        win.geometry("400x260")

        ttk.Label(win, text="Rule Name").pack(pady=5)
        name = ttk.Entry(win, width=35)
        name.pack()

        ttk.Label(win, text="Regex Pattern").pack(pady=5)
        pattern = ttk.Entry(win, width=35)
        pattern.pack()

        def save():
            rule_name = name.get().strip()
            rule_pattern = pattern.get().strip()

            if not rule_name or not rule_pattern:
                messagebox.showerror("Error", "Rule name and pattern required")
                return

            try:
                re.compile(rule_pattern)
                self.rules[rule_name] = rule_pattern
                self.save_custom_rule(rule_name, rule_pattern)
                messagebox.showinfo("Added", "Rule added and saved successfully")
                win.destroy()
            except re.error:
                messagebox.showerror("Error", "Invalid regex")


        ttk.Button(win, text="Add Rule",
                   command=save,
                   bootstyle=SUCCESS).pack(pady=15)

    def show_rules(self):
        win = tb.Toplevel(self)
        win.title("Rules")
        win.geometry("800x600")

        text = tk.Text(win, bg="#1e1e1e", fg="white")
        text.pack(fill=BOTH, expand=True)

        for r, p in self.rules.items():
            text.insert(END, f"{r}\n{p}\n\n")

        text.config(state=DISABLED)

    # ================= UTIL ================= #

    def clear_tables(self):
        self.log_table.delete(*self.log_table.get_children())
        self.alert_table.delete(*self.alert_table.get_children())

    def clear_all(self):
        self.logs.clear()
        self.detected_alerts.clear()
        self.attack_stats.clear()
        self.clear_tables()
        self.update_dashboard()
        self.status.config(text="Cleared")
    def generate_report(self):

        if not self.logs:
            messagebox.showinfo("No Data", "Upload and analyze logs first.")
            return

        if not self.detected_alerts:
            messagebox.showinfo("No Threats", "No threats detected to report.")
            return

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"threat_report_{timestamp}.txt"

        with open(filename, "w", encoding="utf-8") as f:

            f.write("===== LOG BASED THREAT DETECTION REPORT =====\n\n")
            f.write(f"Generated On   : {datetime.datetime.now()}\n")
            f.write(f"Total Logs     : {len(self.logs)}\n")
            f.write(f"Threats Found  : {len(self.detected_alerts)}\n\n")

            f.write("----- THREAT STATISTICS -----\n")
            for rule, count in self.attack_stats.items():
                f.write(f"{rule} : {count}\n")

            f.write("\n----- DETAILED ALERTS -----\n\n")
            for alert in self.detected_alerts:
                rule, time, ip, payload = alert
                f.write(f"Rule    : {rule}\n")
                f.write(f"Time    : {time}\n")
                f.write(f"IP      : {ip}\n")
                f.write(f"Payload : {payload}\n")
                f.write("----------------------------------------\n")

        messagebox.showinfo("Report Generated",
                        f"Report saved as:\n{os.path.abspath(filename)}")
    
    def send_alert_email(self):
        if not self.detected_alerts:
            messagebox.showinfo("Info", "No threats detected yet. Run analysis first.")
            return

        threat_name = askstring("Send Alert", "Enter threat/rule name (exact match):")

        if not threat_name:
            return

    # Count occurrences
        count = sum(1 for a in self.detected_alerts if a[0].lower() == threat_name.lower())

        if count == 0:
            messagebox.showinfo("Not Found", f"No alerts found for: {threat_name}")
            return

        try:
            msg = EmailMessage()
            msg["From"] = self.sender_email
            msg["To"] = self.admin_email
            msg["Subject"] = f"Security Alert: {threat_name}"

            body = (
                f"Alert Type: {threat_name}\n"
                f"Occurrences Detected: {count}\n\n"
                f"This alert was generated by the Log-Based Threat Detection System."
            )

            msg.set_content(body)

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            messagebox.showinfo("Sent", f"Email sent for threat '{threat_name}' ({count} times detected).")

        except Exception as e:
            messagebox.showerror("Email Error", f"Failed to send email:\n{e}")
    

# ================= RUN ================= #

if __name__ == "__main__":
    app = LogBasedDetectionSystem()
    app.mainloop()   