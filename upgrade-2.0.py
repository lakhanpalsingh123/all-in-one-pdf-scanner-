import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import re
from datetime import datetime
import binascii
import hashlib
import zlib
import requests  # for VirusTotal
# Optional: pip install vt-py
try:
    from vt import Client as VTClient
    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False
    print("vt-py not installed → VirusTotal full integration disabled")

class SecurityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PDF Malware Analyzer - Advanced")
        self.geometry("1000x800")
        self.configure(bg="#f0f2f5")

        self.selected_file = tk.StringVar(value="No file selected")
        self.vt_api_key = tk.StringVar(value="")  # will be asked or loaded
        self.result_text = tk.StringVar(value="")

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = ttk.Label(main_frame, text="Advanced PDF Malware & Steganography Analyzer", font=("Helvetica", 22, "bold"), foreground="#1e40af")
        title_label.pack(pady=(0, 20))

        # ── API Key (VirusTotal) ──
        api_frame = ttk.LabelFrame(main_frame, text="VirusTotal API Key (required for VT check)", padding=10)
        api_frame.pack(fill=tk.X, pady=5)
        ttk.Entry(api_frame, textvariable=self.vt_api_key, width=60, show="*").pack(side=tk.LEFT, padx=5)
        ttk.Button(api_frame, text="Set / Save", command=self.save_vt_key).pack(side=tk.LEFT)

        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="PDF File", padding=15)
        file_frame.pack(fill=tk.X, pady=10)

        ttk.Label(file_frame, text="File:").pack(side=tk.LEFT, padx=5)
        ttk.Entry(file_frame, textvariable=self.selected_file, width=70, state="readonly").pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)

        # Scan Options
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=10)

        self.var_triage = tk.BooleanVar(value=True)
        self.var_deep = tk.BooleanVar(value=True)
        self.var_stego = tk.BooleanVar(value=True)
        self.var_vt = tk.BooleanVar(value=True)
        self.var_hex = tk.BooleanVar(value=False)
        self.var_decompress = tk.BooleanVar(value=True)

        ttk.Checkbutton(options_frame, text="Quick Triage", variable=self.var_triage).pack(side=tk.LEFT, padx=8)
        ttk.Checkbutton(options_frame, text="Deep Scan (JS/URLs/Actions)", variable=self.var_deep).pack(side=tk.LEFT, padx=8)
        ttk.Checkbutton(options_frame, text="Steganography Check", variable=self.var_stego).pack(side=tk.LEFT, padx=8)
        ttk.Checkbutton(options_frame, text="VirusTotal Check", variable=self.var_vt).pack(side=tk.LEFT, padx=8)
        ttk.Checkbutton(options_frame, text="Decompress & Scan Streams", variable=self.var_decompress).pack(side=tk.LEFT, padx=8)
        ttk.Checkbutton(options_frame, text="Hex Preview (512 bytes)", variable=self.var_hex).pack(side=tk.LEFT, padx=8)

        analyze_btn = ttk.Button(main_frame, text="Analyze PDF", command=self.analyze_file, style="Accent.TButton")
        analyze_btn.pack(pady=20)

        result_frame = ttk.LabelFrame(main_frame, text="Analysis Report", padding=15)
        result_frame.pack(fill=tk.BOTH, expand=True)

        self.result_display = tk.Text(result_frame, wrap=tk.WORD, height=25, font=("Consolas", 10), bg="#ffffff")
        self.result_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_display.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_display.config(yscrollcommand=scrollbar.set)

        save_btn = ttk.Button(main_frame, text="Save Report", command=self.save_report)
        save_btn.pack(pady=15)

        style = ttk.Style()
        style.configure("Accent.TButton", font=("Helvetica", 12, "bold"))

    def save_vt_key(self):
        key = self.vt_api_key.get().strip()
        if key:
            messagebox.showinfo("API Key", "VirusTotal API key updated (stored in memory only).")
        else:
            messagebox.showwarning("API Key", "No key entered.")

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")])
        if path:
            self.selected_file.set(path)
            self.result_display.delete(1.0, tk.END)

    def analyze_file(self):
        file_path = self.selected_file.get()
        if not file_path or not os.path.exists(file_path) or not file_path.lower().endswith('.pdf'):
            messagebox.showwarning("Error", "Please select a valid PDF file.")
            return

        self.result_display.delete(1.0, tk.END)
        self.result_display.insert(tk.END, f"Analyzing: {os.path.basename(file_path)}\n{'-'*80}\n\n")
        self.update()

        report = [f"File: {os.path.basename(file_path)}", f"Size: {os.path.getsize(file_path)/1024:.2f} KB", f"Time: {datetime.now():%Y-%m-%d %H:%M:%S}\n"]

        try:
            with open(file_path, "rb") as f:
                raw = f.read()

            # 1. Basic Triage
            if self.var_triage.get():
                report.append("=== Triage Scan ===")
                report.append("✓ Valid PDF" if raw.startswith(b"%PDF-") else "⚠ Not standard PDF header")
                suspicious = [kw.decode(errors='ignore') for kw in [b"/JavaScript", b"/JS", b"/URI", b"/Action", b"/GoToR", b"/SubmitForm", b"/Launch", b"/OpenAction", b"/AA"] if kw in raw]
                if suspicious:
                    report.append(f"⚠ Suspicious keywords: {', '.join(suspicious)}")

            # 2. Hex Preview
            if self.var_hex.get():
                report.append("\n=== Hex Preview (first 512 bytes) ===")
                hex_str = binascii.hexlify(raw[:512]).decode()
                report.append(' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))[:300] + "...")

            # 3. VirusTotal Check
            if self.var_vt.get() and self.vt_api_key.get():
                report.append("\n=== VirusTotal Check ===")
                try:
                    file_hash = hashlib.sha256(raw).hexdigest()
                    report.append(f"SHA256: {file_hash}")

                    if VT_AVAILABLE:
                        with VTClient(self.vt_api_key.get()) as client:
                            file_obj = client.get_object(f"/files/{file_hash}")
                            stats = file_obj.last_analysis_stats
                            report.append(f"Detection: {stats['malicious']} / {sum(stats.values())} engines")
                            if stats['malicious'] > 0:
                                report.append("⚠ MALICIOUS according to VirusTotal!")
                            elif stats['suspicious'] > 0:
                                report.append("⚠ Suspicious according to VirusTotal")
                            else:
                                report.append("Clean / undetected")
                    else:
                        # Fallback simple HTTP request (basic info)
                        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                        headers = {"x-apikey": self.vt_api_key.get()}
                        resp = requests.get(url, headers=headers, timeout=10)
                        if resp.status_code == 200:
                            data = resp.json()
                            stats = data["data"]["attributes"]["last_analysis_stats"]
                            report.append(f"VT Detection: {stats['malicious']} malicious / {sum(stats.values())} total")
                        else:
                            report.append(f"VT API error: {resp.status_code}")
                except Exception as e:
                    report.append(f"VT error: {str(e)} (check API key / rate limit)")

            # 4. Deep Scan + Object Parsing
            if self.var_deep.get() or self.var_decompress.get():
                report.append("\n=== Deep Scan + Object Parsing ===")
                text = raw.decode('latin-1', errors='replace')

                # URLs
                urls = re.findall(r'(https?://[^\s"<>)]+|www\.[^\s"<>)]+)', text, re.I)
                if urls:
                    report.append(f"Found {len(urls)} URLs/links (first 8):")
                    for u in urls[:8]: report.append(f"  • {u}")

                # JS / Actions
                js_patterns = [r'/JavaScript\b', r'app\.alert', r'eval\s*\(', r'unescape', r'String\.fromCharCode']
                actions = [r'/URI', r'/GoToR', r'/SubmitForm', r'/Launch', r'/OpenAction']
                for pat in js_patterns + actions:
                    if re.search(pat, text, re.I):
                        report.append(f"Found indicator: {pat}")

                # Deeper objects
                objstm = len(re.findall(r'/ObjStm', text, re.I))
                embedded = len(re.findall(r'/EmbeddedFile|/EF\b', text, re.I))
                if objstm: report.append(f"• {objstm} object stream(s) found (potential hiding place)")
                if embedded: report.append(f"⚠ {embedded} embedded file(s) indicator(s)")

            # 5. Basic Steganography / Hidden Data Checks
            if self.var_stego.get():
                report.append("\n=== Steganography & Hidden Data Heuristics ===")
                alerts = []

                # Suspicious large /Length in streams (possible hidden payload)
                lengths = [int(m.group(1)) for m in re.finditer(r'/Length\s+(\d+)', text) if int(m.group(1)) > 50000]
                if lengths:
                    alerts.append(f"Large stream lengths: {lengths[:3]}... (possible hidden data)")

                # Whitespace anomalies (very basic)
                ws_count = len(re.findall(r'\s{5,}', text))
                if ws_count > 30:
                    alerts.append(f"Excessive whitespace sequences ({ws_count}) → possible whitespace stego")

                # Known stego tool signatures (very limited)
                if b"/Producer (OpenPuff" in raw or b"pdf_hide" in raw.lower():
                    alerts.append("Known steganography tool signature found")

                # Hidden text / invisible layers (very rough)
                if re.search(r'/Text\b.*?(?:/RenderMode\s*[23]|/Invisible)', text, re.I | re.DOTALL):
                    alerts.append("Possible invisible/hidden text layer")

                if alerts:
                    report.extend([f"⚠ {a}" for a in alerts])
                else:
                    report.append("No obvious steganography indicators")

            # 6. Basic Stream Decompression + Scan
            if self.var_decompress.get():
                report.append("\n=== Stream Decompression Scan (basic) ===")
                try:
                    streams = re.finditer(rb'stream(.*?)endstream', raw, re.DOTALL)
                    decompressed_alerts = 0
                    for i, m in enumerate(streams):
                        if i > 10: break  # limit
                        data = m.group(1).strip()
                        if data.startswith(b"\r\n"): data = data[2:]
                        try:
                            dec = zlib.decompress(data)
                            dec_text = dec.decode('latin-1', errors='ignore')
                            if any(kw in dec for kw in [b"eval(", b"unescape", b"fromCharCode", b"http"]):
                                decompressed_alerts += 1
                                report.append(f"  Decompressed stream {i+1}: suspicious JS/URL patterns found")
                        except:
                            pass
                    if decompressed_alerts == 0:
                        report.append("No suspicious content found in decompressed streams")
                except Exception as e:
                    report.append(f"Decompression error: {str(e)}")

            report.append("\nScan finished. This is triage — use sandbox / professional tools for confirmation.")
            full_report = "\n".join(report)
            self.result_display.insert(tk.END, full_report)
            self.result_text.set(full_report)

        except Exception as e:
            msg = f"Critical error: {str(e)}"
            self.result_display.insert(tk.END, msg)
            messagebox.showerror("Error", msg)

    def save_report(self):
        if not self.result_text.get():
            messagebox.showinfo("Info", "No report available.")
            return
        default = f"PDF_Analysis_{datetime.now():%Y%m%d_%H%M}.txt"
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.result_text.get())
            messagebox.showinfo("Success", f"Saved to:\n{path}")

if __name__ == "__main__":
    app = SecurityApp()
    app.mainloop()