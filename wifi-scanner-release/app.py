import sys
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import socket
import json
import datetime
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor
import logging
import random

from scapy.all import ARP, Ether, srp, conf
from mac_vendor_lookup import MacLookup
import requests

# Enable UAC elevation logic for packet capturing
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # If not admin, re-run with admin privileges
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

# Filter warnings from Scapy to keep console clean
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Setup MacLookup (we may need to update vendors on first run, we'll try/except to handle caching)
mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()  # Will download and cache OUI.list
except Exception:
    pass

class WiFiScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Security Scanner 🛡️")
        self.root.geometry("900x650")
        
        # Applies a dark theme manually using color configurations
        self.bg_color = "#1E1E1E"
        self.fg_color = "#E0E0E0"
        self.accent_color = "#007ACC"
        self.root.configure(bg=self.bg_color)
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure common styles
        self.style.configure(".", background=self.bg_color, foreground=self.fg_color)
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"))
        self.style.configure("Disclaimer.TLabel", font=("Segoe UI", 9, "italic"), foreground="#A0A0A0")
        
        # Configure buttons
        self.style.configure("TButton", background="#333333", foreground=self.fg_color, 
                             focuscolor=self.accent_color, font=("Segoe UI", 10, "bold"), padding=8)
        self.style.map("TButton", background=[("active", "#444444"), ("disabled", "#2a2a2a")],
                                  foreground=[("disabled", "#808080")])
        
        # Configure Treeview
        self.style.configure("Treeview", background="#2D2D2D", foreground=self.fg_color, fieldbackground="#2D2D2D", rowheight=30)
        self.style.map('Treeview', background=[('selected', self.accent_color)])
        self.style.configure("Treeview.Heading", background="#333333", foreground=self.fg_color, font=("Segoe UI", 10, "bold"), padding=5)
        self.style.map("Treeview.Heading", background=[('active', "#444444")])
        
        # Configure Progressbar
        self.style.configure("Horizontal.TProgressbar", background=self.accent_color, troughcolor="#333333", bordercolor=self.bg_color, lightcolor=self.accent_color, darkcolor=self.accent_color)

        self.create_widgets()
        
        self.devices = []
        self.scanning = False
        self.queue = Queue()
        
        # Heartbeat check for GUI updates
        self.root.after(100, self.process_queue)

    def create_widgets(self):
        # Top Frame
        top_frame = tk.Frame(self.root, bg=self.bg_color)
        top_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        lbl_title = ttk.Label(top_frame, text="WiFi Security Scanner 🛡️", style="Header.TLabel")
        lbl_title.pack(side=tk.LEFT)
        
        self.btn_scan = ttk.Button(top_frame, text="Scan Network", command=self.start_scan)
        self.btn_scan.pack(side=tk.RIGHT)
        
        self.stealth_mode = tk.BooleanVar()
        self.chk_stealth = ttk.Checkbutton(top_frame, text="Stealth Mode (Slow)", variable=self.stealth_mode)
        self.chk_stealth.pack(side=tk.RIGHT, padx=10)
        
        # Disclaimer
        lbl_disclaimer = ttk.Label(self.root, text="For use on networks you own or have permission to scan.", style="Disclaimer.TLabel")
        lbl_disclaimer.pack(fill=tk.X, padx=20)
        
        # Progress Bar Frame
        pb_frame = tk.Frame(self.root, bg=self.bg_color)
        pb_frame.pack(fill=tk.X, padx=20, pady=15)
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(pb_frame, variable=self.progress_var, maximum=100, style="Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, side=tk.LEFT, expand=True)
        self.lbl_status = ttk.Label(pb_frame, text="Ready")
        self.lbl_status.pack(side=tk.RIGHT, padx=(15, 0))
        
        # Table
        table_frame = tk.Frame(self.root, bg=self.bg_color)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ("IP", "MAC", "Vendor", "Open Ports", "Risk Level")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)
        
        col_widths = {"IP": 110, "MAC": 140, "Vendor": 220, "Open Ports": 180, "Risk Level": 170}
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=col_widths[col], anchor=tk.W)
            
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)
        
        # Setup tags for colors
        self.tree.tag_configure("high_risk", foreground="#FFA500") # Orange for High Risk Ports
        self.tree.tag_configure("suspicious", foreground="#FF0000", background="#331111") # Red for Suspicious Flag

        # Bottom Frame
        bottom_frame = tk.Frame(self.root, bg=self.bg_color)
        bottom_frame.pack(fill=tk.X, padx=20, pady=15)
        
        self.lbl_router_status = ttk.Label(bottom_frame, text="Router Scan: N/A", font=("Segoe UI", 11, "bold"))
        self.lbl_router_status.pack(side=tk.LEFT)
        
        self.btn_export = ttk.Button(bottom_frame, text="Export Report", command=self.export_report, state=tk.DISABLED)
        self.btn_export.pack(side=tk.RIGHT)

    def process_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                msg_type = msg.get("type")
                if msg_type == "status":
                    self.lbl_status.config(text=msg["text"])
                elif msg_type == "progress":
                    self.progress_var.set(msg["value"])
                elif msg_type == "device_add":
                    self.add_device_to_tree(msg["device"])
                elif msg_type == "device_update":
                    self.update_device_in_tree(msg["device"])
                elif msg_type == "router_status":
                    self.lbl_router_status.config(text=msg["text"])
                    if msg["vulnerable"]:
                        self.lbl_router_status.config(foreground="#FF0000")
                    else:
                        self.lbl_router_status.config(foreground="#00FF00")
                elif msg_type == "scan_complete":
                    self.scanning = False
                    self.btn_scan.config(state=tk.NORMAL)
                    self.btn_export.config(state=tk.NORMAL)
        except Empty:
            pass
        self.root.after(100, self.process_queue)

    def determine_tags(self, risk):
        tags = ()
        if "⚠️" in risk:
            tags = ("suspicious",)
        elif "High" in risk:
            tags = ("high_risk",)
        return tags

    def add_device_to_tree(self, dev):
        tags = self.determine_tags(dev.get("Risk", "Unknown"))
        item_id = self.tree.insert("", tk.END, values=(dev["IP"], dev["MAC"], dev["Vendor"], dev.get("Ports", "Scanning..."), dev.get("Risk", "Unknown")), tags=tags)
        dev["tree_id"] = item_id

    def update_device_in_tree(self, dev):
        item_id = dev.get("tree_id")
        if item_id:
            risk = dev.get("Risk", "Unknown")
            tags = self.determine_tags(risk)
            self.tree.item(item_id, values=(dev["IP"], dev["MAC"], dev["Vendor"], dev.get("Ports", ""), risk), tags=tags)

    def start_scan(self):
        if self.scanning:
            return
        
        self.scanning = True
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_export.config(state=tk.DISABLED)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.devices = []
        self.lbl_router_status.config(text="Router Scan: Running...", foreground=self.fg_color)
        self.progress_var.set(0)
        
        threading.Thread(target=self.scan_worker, daemon=True).start()

    def get_default_gateway(self):
        try:
            import netifaces
            gws = netifaces.gateways()
            return gws['default'][netifaces.AF_INET][0]
        except ImportError:
            # Fallback to Scapy's routing table if netifaces is not installed (e.g. C++ build tools missing)
            import scapy.config as scconf
            return scconf.conf.route.route("0.0.0.0")[2]
        except Exception:
            return None

    def scan_worker(self):
        try:
            self.queue.put({"type": "status", "text": "Detecting network..."})
            self.queue.put({"type": "progress", "value": 5})
            
            default_gateway = self.get_default_gateway()
            if not default_gateway:
                self.queue.put({"type": "status", "text": "Error: Could not find default gateway."})
                self.queue.put({"type": "scan_complete"})
                return
                
            # Assume /24 subnet based on default gateway
            ip_parts = default_gateway.split('.')
            if len(ip_parts) == 4:
                target_ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            else:
                target_ip_range = f"{default_gateway}/24"
            
            self.queue.put({"type": "status", "text": f"ARP Scan on {target_ip_range}..."})
            self.queue.put({"type": "progress", "value": 10})
            
            # 1. ARP Scan Feature
            conf.verb = 0
            arp_request = ARP(pdst=target_ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp_request
            result = srp(packet, timeout=3, verbose=False)[0]
            
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                
                vendor = "Unknown"
                try:
                    vendor = mac_lookup.lookup(mac)
                except Exception:
                    pass
                
                dev = {"IP": ip, "MAC": mac, "Vendor": vendor, "Ports": "", "Risk": "Low"}
                self.devices.append(dev)
                
            # Suspicious device flagging rule 1: > 15 devices
            many_devices = len(self.devices) > 15
            
            self.queue.put({"type": "progress", "value": 30})
            self.queue.put({"type": "status", "text": f"Found {len(self.devices)} devices. Checking rules..."})
            
            for d in self.devices:
                # Rule 2: Hostname lookup
                hostname_failed = False
                try:
                    hostname = socket.gethostbyaddr(d["IP"])[0]
                except socket.herror:
                    hostname_failed = True
                except Exception:
                    hostname_failed = True
                
                # Rule 3: Vendor is unknown
                unknown_vendor = d["Vendor"] == "Unknown"
                
                risk_factors = []
                if unknown_vendor:
                    risk_factors.append("Unknown Vendor")
                if hostname_failed:
                    risk_factors.append("No Hostname")
                if many_devices:
                    risk_factors.append(">15 Devices")

                if risk_factors:
                    d["Risk"] = "⚠️ " + ", ".join(risk_factors)

                self.queue.put({"type": "device_add", "device": d})
            
            # 2. Router Credential Check Feature
            threading.Thread(target=self.router_check, args=(default_gateway,), daemon=True).start()
            
            # 3. Open Port Scanner Feature
            self.queue.put({"type": "status", "text": "Scanning ports..."})
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8443, 1080, 3306, 5900, 6881, 8888, 9090, 1433]
            
            total_tasks = len(self.devices) * len(ports_to_scan)
            completed_tasks = 0
            
            is_stealth = self.stealth_mode.get()
            
            def scan_port_t(ip, port):
                port_result = None
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    result = s.connect_ex((ip, port))
                    s.close()
                    if result == 0:
                        port_result = port
                except Exception:
                    pass
                finally:
                    if is_stealth:
                        time.sleep(random.uniform(0.5, 2.0))
                return port_result

            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {}
                for d in self.devices:
                    d["open_ports_list"] = []
                    for p in ports_to_scan:
                        futures[executor.submit(scan_port_t, d["IP"], p)] = d
                
                for f in futures:
                    dev_ref = futures[f]
                    port = f.result()
                    if port:
                        dev_ref["open_ports_list"].append(port)
                        if port in (23, 3389): # Telnet or RDP high risk
                            # Overwrite Risk Level to include high risk if it doesn't exist
                            if "High Risk" not in dev_ref["Risk"]:
                                prefix = ""
                                if "⚠️" in dev_ref["Risk"]:
                                    prefix = dev_ref["Risk"] + " | "
                                dev_ref["Risk"] = prefix + f"High Risk (Port {port})"
                    
                    completed_tasks += 1
                    prog = 30 + (completed_tasks / max(1, total_tasks) * 65)
                    self.queue.put({"type": "progress", "value": prog})
            
            # Update GUI fields with exact port lists
            for d in self.devices:
                d["open_ports_list"].sort()
                d["Ports"] = ", ".join(map(str, d["open_ports_list"])) if d["open_ports_list"] else "None"
                self.queue.put({"type": "device_update", "device": d})
            
            self.queue.put({"type": "progress", "value": 100})
            self.queue.put({"type": "status", "text": "Scan Complete"})
            self.queue.put({"type": "scan_complete"})

        except Exception as e:
            self.queue.put({"type": "status", "text": f"Error: {str(e)}"})
            self.queue.put({"type": "progress", "value": 100})
            self.queue.put({"type": "scan_complete"})

    def router_check(self, gateway_ip):
        combos = [
            ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
            ("user", "user"), ("root", "root"), ("admin", ""),
            ("cusadmin", "highspeed"), ("admin", "admin1234"),
            ("admin", "12345"), ("user", "1234")
        ]
        
        vulnerable = False
        success_msg = ""
        
        # 1. Baseline request using a guaranteed-to-fail dummy credential
        dummy_user, dummy_pass = "admin", "THIS_WILL_NEVER_WORK_999"
        baselines = {}
        
        for port in [80, 8080]:
            try:
                # 5. Short timeout to prevent hanging
                r = requests.get(f"http://{gateway_ip}:{port}", auth=(dummy_user, dummy_pass), timeout=1.5)
                # 2. Store both status code and response length
                baselines[port] = {"status": r.status_code, "length": len(r.text)}
            except requests.RequestException:
                baselines[port] = None
        
        for u, p in combos:
            if not self.scanning: break
            
            for port in [80, 8080]:
                b = baselines[port]
                if b is None:
                    continue
                    
                try:
                    # 5. Short timeout
                    r = requests.get(f"http://{gateway_ip}:{port}", auth=(u, p), timeout=1.5)
                    
                    # 4. Only flag as VULNERABLE if the response is significantly different AND status code is 200
                    if r.status_code == 200:
                        # 3. Compare response length/content to the baseline
                        # Using > 50 length difference to account for minor dynamic tokens or timestamps in HTML forms
                        is_diff = (b["status"] != 200) or (abs(len(r.text) - b["length"]) > 50)
                        
                        if is_diff:
                            vulnerable = True
                            success_msg = f"Vulnerable! ({u}/{p})" + (f" on {port}" if port != 80 else "")
                            break
                            
                except requests.RequestException:
                    pass
            
            if vulnerable:
                break
                
        if vulnerable:
            self.queue.put({"type": "router_status", "text": f"Router Scan: {success_msg}", "vulnerable": True})
        else:
            self.queue.put({"type": "router_status", "text": "Router Scan: Login protected", "vulnerable": False})
            
    def export_report(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            initialfile=f"WiFi_Security_Report_{int(time.time())}.html",
            title="Save HTML Report",
            filetypes=(("HTML files", "*.html"), ("All files", "*.*"))
        )
        if not filepath:
            return
            
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>WiFi Security Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #f0f0f0; margin: 0; padding: 20px; }}
        .container {{ max-width: 1000px; margin: auto; background-color: #1e1e1e; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        h1 {{ color: #007ACC; border-bottom: 2px solid #333; padding-bottom: 10px; margin-top: 0; }}
        .meta {{ color: #aaa; font-size: 0.9em; }}
        .disclaimer {{ background-color: #2c2c2c; padding: 10px; border-left: 4px solid #007ACC; font-style: italic; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; border: 1px solid #333; text-align: left; }}
        th {{ background-color: #2d2d2d; color: #fff; font-weight: bold; }}
        tr:nth-child(even) {{ background-color: #252525; }}
        tr:hover {{ background-color: #2a2a2a; }}
        .suspicious {{ background-color: #331111; color: #ff5555; }}
        .high-risk {{ background-color: #3d2200; color: #ffa500; font-weight: bold; }}
        .status-box {{ padding: 15px; margin-top: 20px; background-color: #252525; border-radius: 5px; }}
        .success {{ color: #55ff55; }}
        .danger {{ color: #ff5555; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ WiFi Security Scan Report</h1>
        <p class="meta"><strong>Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <div class="disclaimer">Disclaimer: Only for use on networks you own or have permission to scan. No credentials have been permanently stored.</div>
        
        <div class="status-box">
            <strong>Router Assessment:</strong> <span class="{'danger' if 'Vulnerable' in self.lbl_router_status.cget('text') else 'success'}">{self.lbl_router_status.cget('text')}</span>
        </div>
        
        <table>
            <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Vendor</th>
                <th>Open Ports</th>
                <th>Risk Level</th>
            </tr>
'''
        for d in self.devices:
            risk = d.get("Risk", "")
            row_class = ""
            if "⚠️" in risk:
                row_class = "suspicious"
            if "High" in risk:
                row_class = "high-risk"
                
            html += f'''
            <tr class="{row_class}">
                <td>{d.get("IP", "")}</td>
                <td>{d.get("MAC", "")}</td>
                <td>{d.get("Vendor", "")}</td>
                <td>{d.get("Ports", "")}</td>
                <td>{risk}</td>
            </tr>'''
        
        html += '''
        </table>
    </div>
</body>
</html>
'''
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)
            messagebox.showinfo("Export Successful", f"Report saved securely to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not save file:\n{str(e)}")

if __name__ == "__main__":
    # Workaround for blurry text in Windows due to high DPI scaling
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
        
    root = tk.Tk()
    app = WiFiScannerApp(root)
    root.mainloop()
