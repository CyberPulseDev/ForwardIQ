import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, Menu
import threading
import socket
from router_engine import NetworkScanner

# Import Help Content
try:
    from help_content import HELP_TEXT
except ImportError:
    HELP_TEXT = "Help file missing. Please ensure help_content.py is in the same folder."

try:
    from pro_tools.security_engine import SecurityEngine
    HAS_PRO = True
except ImportError:
    HAS_PRO = False

class AuthDialog(tk.Toplevel):
    def __init__(self, parent, callback):
        super().__init__(parent)
        self.callback = callback
        self.title("Router Login Required")
        self.geometry("350x200")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        ttk.Label(self, text="Router Authentication Required", font=('Helvetica', 10, 'bold')).pack(pady=10)
        ttk.Label(self, text="Enter admin credentials to identify router model.").pack(pady=2)
        
        form = ttk.Frame(self)
        form.pack(pady=10, padx=20, fill='x')
        
        ttk.Label(form, text="Username:").grid(row=0, column=0, sticky='w', pady=5)
        self.ent_user = ttk.Entry(form)
        self.ent_user.grid(row=0, column=1, sticky='ew', padx=5)
        self.ent_user.insert(0, "admin") 
        
        ttk.Label(form, text="Password:").grid(row=1, column=0, sticky='w', pady=5)
        self.ent_pass = ttk.Entry(form, show="*")
        self.ent_pass.grid(row=1, column=1, sticky='ew', padx=5)
        
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Login & Scan", command=self.on_submit).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side='left', padx=5)
        
        form.columnconfigure(1, weight=1)

    def on_submit(self):
        user = self.ent_user.get()
        pwd = self.ent_pass.get()
        if user and pwd:
            self.callback(user, pwd)
            self.destroy()
        else:
            messagebox.showwarning("Input Required", "Please enter both username and password.")

class HelpWindow(tk.Toplevel):
    """
    Dedicated Help / User Guide Window.
    Scrollable, read-only, formatted text.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.title("ForwardIQ User Guide")
        self.geometry("700x600")
        
        # Header
        lbl_head = ttk.Label(self, text="ForwardIQ Documentation", font=('Helvetica', 16, 'bold'))
        lbl_head.pack(pady=10)
        
        # Scrollable Text Area
        self.text_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 10))
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)
        
        # Configure Tags for Formatting
        self.text_area.tag_config("header", font=("Helvetica", 12, "bold"), foreground="#0055aa")
        self.text_area.tag_config("alert", foreground="red")
        
        # Insert Content
        self.insert_content()
        
        # Make Read-Only
        self.text_area.config(state='disabled')
        
        # Close Button
        ttk.Button(self, text="Close Guide", command=self.destroy).pack(pady=10)

    def insert_content(self):
        # We process the raw text to apply simple formatting
        lines = HELP_TEXT.split('\n')
        for line in lines:
            if line.startswith("===") or line.startswith("---"):
                self.text_area.insert(tk.END, line + "\n")
            elif line.isupper() and len(line) > 5:
                # Treat uppercase lines as Headers
                self.text_area.insert(tk.END, line + "\n", "header")
            elif "CRITICAL" in line or "WARNING" in line:
                self.text_area.insert(tk.END, line + "\n", "alert")
            else:
                self.text_area.insert(tk.END, line + "\n")

class ForwardIQApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ForwardIQ - Universal Port Manager")
        self.root.geometry("900x750")
        
        self.scanner = NetworkScanner()
        self.auto_refresh_active = False
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Green.TLabel", foreground="green", font=('Helvetica', 9, 'bold'))
        style.configure("Red.TLabel", foreground="red", font=('Helvetica', 9, 'bold'))
        style.configure("Orange.TLabel", foreground="#FF8C00", font=('Helvetica', 9, 'bold'))
        style.configure("Header.TLabel", font=('Helvetica', 12, 'bold'))
        
        # Build Menus BEFORE widgets
        self.build_menus()
        self.create_widgets()
        
        self.log("Initializing ForwardIQ...")
        self.log("Starting Router Discovery in background...")
        threading.Thread(target=self.perform_discovery, daemon=True).start()

    def build_menus(self):
        menubar = Menu(self.root)
        self.root.config(menu=menubar)
        
        # File Menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help Menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide / Manual", command=self.open_help_window)
        help_menu.add_separator()
        help_menu.add_command(label="About ForwardIQ", command=self.show_about)

    def open_help_window(self):
        HelpWindow(self.root)

    def show_about(self):
        messagebox.showinfo("About", "ForwardIQ v2.0\nUniversal Port Forwarding Tool\n\nSupports: UPnP, NAT-PMP, PCP\nRouter Detection & Security Audit")

    def create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.tab_dash = ttk.Frame(notebook)
        self.tab_map = ttk.Frame(notebook)
        self.tab_devices = ttk.Frame(notebook)
        self.tab_security = ttk.Frame(notebook)
        
        notebook.add(self.tab_dash, text="  Dashboard  ")
        notebook.add(self.tab_map, text="  Port Mappings  ")
        notebook.add(self.tab_devices, text="  Network Devices  ")
        notebook.add(self.tab_security, text="  🛡️ Security Audit (PRO)  ")
        
        self.build_dashboard(self.tab_dash)
        self.build_mapping_table(self.tab_map)
        self.build_device_scanner(self.tab_devices)
        self.build_security_tab(self.tab_security)
        
        log_frame = ttk.LabelFrame(self.root, text="System Log")
        log_frame.pack(fill='x', padx=10, pady=5, side='bottom')
        self.log_area = scrolledtext.ScrolledText(log_frame, height=8, state='disabled', font=("Consolas", 9))
        self.log_area.pack(fill='both', expand=True, padx=5, pady=5)

    def build_dashboard(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        
        disc_frame = ttk.LabelFrame(parent, text="Router Protocols")
        disc_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        self.lbl_upnp = ttk.Label(disc_frame, text="UPnP: Scanning...", style="Red.TLabel")
        self.lbl_upnp.pack(side="left", padx=20, pady=10)
        self.lbl_natpmp = ttk.Label(disc_frame, text="NAT-PMP: Scanning...", style="Red.TLabel")
        self.lbl_natpmp.pack(side="left", padx=20, pady=10)
        self.lbl_pcp = ttk.Label(disc_frame, text="PCP: Scanning...", style="Red.TLabel")
        self.lbl_pcp.pack(side="left", padx=20, pady=10)
        
        ident_frame = ttk.LabelFrame(parent, text="Router Identity")
        ident_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        ttk.Label(ident_frame, text="Router Model:").pack(side="left", padx=10)
        self.router_models = ["Unknown / Manual", "ASUS", "TP-Link", "Netgear", "D-Link", "Linksys", "Huawei", "ZTE", "MikroTik", "UniFi", "Tenda", "Cisco"]
        self.cb_router_model = ttk.Combobox(ident_frame, values=self.router_models, state="readonly", width=25)
        self.cb_router_model.current(0)
        self.cb_router_model.pack(side="left", padx=5)
        
        ttk.Button(ident_frame, text="✨ Auto Detect Router", command=self.on_auto_detect_router).pack(side="left", padx=10)
        self.lbl_router_det = ttk.Label(ident_frame, text="", foreground="gray")
        self.lbl_router_det.pack(side="left", padx=5)

        net_frame = ttk.LabelFrame(parent, text="Network Details")
        net_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        self.lbl_local_ip = ttk.Label(net_frame, text="Local IP: ...")
        self.lbl_local_ip.pack(anchor="w", padx=10, pady=2)
        self.lbl_gateway = ttk.Label(net_frame, text="Gateway: ...")
        self.lbl_gateway.pack(anchor="w", padx=10, pady=2)
        self.lbl_ext_ip = ttk.Label(net_frame, text="Public IP: ...")
        self.lbl_ext_ip.pack(anchor="w", padx=10, pady=2)
        self.lbl_doublenat = ttk.Label(net_frame, text="Double NAT: Checking...", foreground="blue")
        self.lbl_doublenat.pack(anchor="w", padx=10, pady=2)
        
        fwd_frame = ttk.LabelFrame(parent, text="Quick Add Rule")
        fwd_frame.grid(row=2, column=1, sticky="nsew", padx=5, pady=5)
        ttk.Label(fwd_frame, text="Ext. Port:").grid(row=0, column=0, padx=5, pady=5)
        self.ent_ext_port = ttk.Entry(fwd_frame, width=10)
        self.ent_ext_port.grid(row=0, column=1)
        ttk.Label(fwd_frame, text="Int. Port:").grid(row=1, column=0, padx=5, pady=5)
        self.ent_int_port = ttk.Entry(fwd_frame, width=10)
        self.ent_int_port.grid(row=1, column=1)
        ttk.Label(fwd_frame, text="Protocol:").grid(row=2, column=0, padx=5, pady=5)
        self.var_proto = tk.StringVar(value="TCP")
        ttk.Combobox(fwd_frame, textvariable=self.var_proto, values=["TCP", "UDP"], width=8).grid(row=2, column=1)
        ttk.Label(fwd_frame, text="App Name:").grid(row=3, column=0, padx=5, pady=5)
        self.ent_desc = ttk.Entry(fwd_frame, width=15)
        self.ent_desc.grid(row=3, column=1)
        btn_add = ttk.Button(fwd_frame, text="Forward Port", command=self.on_add_mapping)
        btn_add.grid(row=4, column=0, columnspan=2, pady=10, sticky="ew")

        check_frame = ttk.LabelFrame(parent, text="Local Port Listener Check")
        check_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Label(check_frame, text="Port:").pack(side="left", padx=5)
        self.ent_check_port = ttk.Entry(check_frame, width=8)
        self.ent_check_port.pack(side="left", padx=5)
        ttk.Button(check_frame, text="Check", command=self.on_check_port).pack(side="left", padx=5)
        self.lbl_check_status = ttk.Label(check_frame, text="Status: Ready")
        self.lbl_check_status.pack(side="left", padx=10)

    def build_mapping_table(self, parent):
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(top_frame, text="Manual Refresh", command=self.refresh_mappings).pack(side="left")
        self.var_autorefresh = tk.BooleanVar(value=False)
        ttk.Checkbutton(top_frame, text="Auto-Refresh (10s)", variable=self.var_autorefresh, command=self.toggle_autorefresh).pack(side="left", padx=10)
        ttk.Label(top_frame, text="Note: Manual Router Rules (Virtual Server) will NOT appear here.", foreground="gray").pack(side="right")
        cols = ("External", "Internal", "Protocol", "IP", "Description")
        self.tree = ttk.Treeview(parent, columns=cols, show='headings')
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)
        self.tree.pack(fill='both', expand=True, padx=5, pady=5)
        ttk.Button(parent, text="Delete Selected Rule", command=self.on_delete_mapping).pack(pady=5)

    def build_device_scanner(self, parent):
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(top_frame, text="Scan Network Devices", command=self.scan_devices).pack(side="left")
        ttk.Label(top_frame, text="(Uses ARP table)", foreground="gray").pack(side="left", padx=10)
        cols = ("IP Address", "MAC Address / Info")
        self.dev_tree = ttk.Treeview(parent, columns=cols, show='headings')
        self.dev_tree.heading("IP Address", text="IP Address")
        self.dev_tree.heading("MAC Address / Info", text="MAC Address / Info")
        self.dev_tree.column("IP Address", width=200)
        self.dev_tree.pack(fill='both', expand=True, padx=5, pady=5)

    def build_security_tab(self, parent):
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill='x', padx=20, pady=20)
        self.lbl_score = ttk.Label(header_frame, text="Threat Score: ???/100", font=('Helvetica', 24, 'bold'))
        self.lbl_score.pack()
        ttk.Label(header_frame, text="Checks: Botnet IPs, Tor Exit Nodes, Router Vulnerabilities, UPnP Exposure").pack(pady=5)
        ttk.Button(header_frame, text="RUN FULL SECURITY AUDIT", command=self.run_security_scan).pack(pady=10)
        ttk.Label(parent, text="Audit Results:", style="Header.TLabel").pack(anchor="w", padx=10)
        self.audit_list = tk.Listbox(parent, height=12, font=("Consolas", 10))
        self.audit_list.pack(fill='both', expand=True, padx=10, pady=5)

    def log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert('end', f">> {message}\n")
        self.log_area.see('end')
        self.log_area.config(state='disabled')

    def perform_discovery(self):
        vpn_active, vpn_name = self.scanner.check_vpn_status()
        
        def update_network_info():
            if vpn_active:
                self.lbl_local_ip.config(text=f"Local IP: {self.scanner.local_ip} (VPN Detected)", style="Orange.TLabel")
                self.log(f"WARNING: VPN Interface Detected ({vpn_name}). Router features may fail.")
            else:
                self.lbl_local_ip.config(text=f"Local IP: {self.scanner.local_ip}", style="TLabel")
            self.lbl_gateway.config(text=f"Gateway: {self.scanner.gateway_ip}")

        self.root.after(0, update_network_info)
        
        self.log("Scanning UPnP...")
        upnp_found, upnp_msg = self.scanner.scan_upnp()
        color = "Green.TLabel" if upnp_found else "Red.TLabel"
        text = f"UPnP: {'Active' if upnp_found else 'Not Found'}"
        self.root.after(0, lambda: self.lbl_upnp.config(text=text, style=color))
        self.log(f"UPnP: {upnp_msg}")
        
        self.log("Scanning NAT-PMP...")
        nat_found, nat_msg = self.scanner.scan_natpmp()
        color = "Green.TLabel" if nat_found else "Red.TLabel"
        text = f"NAT-PMP: {'Active' if nat_found else 'Not Supported'}"
        self.root.after(0, lambda: self.lbl_natpmp.config(text=text, style=color))
        self.log(f"NAT-PMP: {nat_msg}")
        
        self.log("Scanning PCP...")
        pcp_found, pcp_msg = self.scanner.scan_pcp()
        color = "Green.TLabel" if pcp_found else "Red.TLabel"
        self.root.after(0, lambda: self.lbl_pcp.config(text=f"PCP: {pcp_msg}", style=color))
        
        ext_ip = self.scanner.get_external_ip_api()
        self.root.after(0, lambda: self.lbl_ext_ip.config(text=f"Public IP: {ext_ip}"))
        
        dnat = self.scanner.detect_double_nat()
        self.root.after(0, lambda: self.lbl_doublenat.config(text=f"Double NAT: {dnat}"))
        
        self.on_auto_detect_router()
        self.refresh_mappings()

    def on_auto_detect_router(self):
        def task():
            self.log("Identifying router model (HTTP/HTTPS)...")
            brand, details = self.scanner.detect_router_identity()
            if brand == "AUTH_REQUIRED":
                auth_details = details 
                self.root.after(0, lambda: self.handle_auth_requirement(auth_details))
                return
            def update_ui():
                self.lbl_router_det.config(text=f"Detected: {details}")
                self.log(f"Router Detected: {details}")
                if brand:
                    for i, model in enumerate(self.router_models):
                        if brand.lower() in model.lower():
                            self.cb_router_model.current(i)
                            break
            self.root.after(0, update_ui)
        threading.Thread(target=task).start()

    def handle_auth_requirement(self, details):
        self.log(f"Authentication required for router: {details['url']}")
        self.lbl_router_det.config(text="Login Required", foreground="red")
        def retry_with_creds(user, pwd):
            self.log("Retrying router detection with credentials...")
            def auth_task():
                success, msg = self.scanner.attempt_login_and_identify(details['url'], user, pwd, details['type'])
                def update_auth_ui():
                    if success:
                        self.lbl_router_det.config(text=f"Detected: {msg}", foreground="black")
                        self.log(f"Login Successful: {msg}")
                    else:
                        self.lbl_router_det.config(text="Login Failed", foreground="red")
                        self.log(f"Login Failed: {msg}")
                        messagebox.showerror("Authentication Failed", f"Could not login to router: {msg}")
                self.root.after(0, update_auth_ui)
            threading.Thread(target=auth_task).start()
        AuthDialog(self.root, retry_with_creds)

    def on_add_mapping(self):
        try:
            ext = int(self.ent_ext_port.get())
            int_ = int(self.ent_int_port.get())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be numbers.")
            return
        proto = self.var_proto.get()
        desc = self.ent_desc.get()
        def task():
            self.log(f"Mapping {ext} -> {int_} ({proto})...")
            success, msg = self.scanner.add_mapping(ext, int_, proto, desc)
            self.log(msg)
            if success: self.refresh_mappings()
            else: self.root.after(0, lambda: messagebox.showerror("Failed", msg))
        threading.Thread(target=task).start()

    def on_delete_mapping(self):
        selected = self.tree.selection()
        if not selected: return
        item = self.tree.item(selected[0])
        ext_port = item['values'][0]
        proto = item['values'][2]
        def task():
            self.log(f"Deleting rule for port {ext_port}...")
            self.scanner.delete_mapping(ext_port, proto)
            self.refresh_mappings()
        threading.Thread(target=task).start()

    def refresh_mappings(self):
        def task():
            mappings = self.scanner.get_mappings()
            def update_ui():
                for row in self.tree.get_children(): self.tree.delete(row)
                for m in mappings: self.tree.insert("", "end", values=(m['ext'], m['int_port'], m['proto'], m['int_ip'], m['desc']))
                if self.auto_refresh_active: self.root.after(10000, self.refresh_mappings)
            self.root.after(0, update_ui)
        threading.Thread(target=task).start()

    def toggle_autorefresh(self):
        self.auto_refresh_active = self.var_autorefresh.get()
        if self.auto_refresh_active:
            self.log("Auto-refresh enabled (10s).")
            self.refresh_mappings()
        else: self.log("Auto-refresh disabled.")

    def scan_devices(self):
        def task():
            self.log("Scanning local devices (ARP)...")
            devices = self.scanner.scan_network_devices()
            def update_ui():
                for row in self.dev_tree.get_children(): self.dev_tree.delete(row)
                for d in devices: self.dev_tree.insert("", "end", values=(d['ip'], d['mac']))
                self.log(f"Found {len(devices)} devices.")
            self.root.after(0, update_ui)
        threading.Thread(target=task).start()

    def on_check_port(self):
        try: port = int(self.ent_check_port.get())
        except ValueError: return
        listening = self.scanner.port_check_local(port)
        status = "LISTENING (Open)" if listening else "CLOSED (Not Listening)"
        color = "green" if listening else "red"
        self.lbl_check_status.config(text=f"Status: {status}", foreground=color)
        self.log(f"Port {port} check: {status}")

    def run_security_scan(self):
        if not HAS_PRO:
            messagebox.showerror("Error", "Security module not found.")
            return
        self.log("Starting Security Audit...")
        engine = SecurityEngine()
        def task():
            pub_ip = self.scanner.get_external_ip_api()
            
            # --- FIX: Verify UPnP Functionality, don't just rely on object existence ---
            upnp_status = False
            if self.scanner.upnp:
                try:
                    # Check if UPnP is actually responding by asking for External IP
                    # If this fails, it means UPnP is restricted or disabled
                    if self.scanner.upnp.externalipaddress():
                        upnp_status = True
                except:
                    pass
            
            router_model = "Unknown"
            router_manuf = "Unknown"
            if self.scanner.upnp:
                try:
                    router_model = self.scanner.upnp.modelname
                    router_manuf = self.scanner.upnp.manufacturer
                except: pass
            
            self.root.after(0, lambda: self.log("Checking Dark Web Blocklists..."))
            risk, details = engine.check_ip_reputation(pub_ip)
            
            self.root.after(0, lambda: self.log(f"Checking Router Vulnerabilities for {router_manuf} {router_model}..."))
            vuln = engine.check_router_vulnerability(router_manuf, router_model)
            
            score, log_items = engine.calculate_threat_score(risk, upnp_status, vuln)
            
            def update():
                self.lbl_score.config(text=f"Threat Score: {score}/100")
                if score > 80: self.lbl_score.config(foreground="green")
                elif score > 50: self.lbl_score.config(foreground="orange")
                else: self.lbl_score.config(foreground="red")
                self.audit_list.delete(0, 'end')
                for item in log_items: self.audit_list.insert('end', item)
                for detail in details:
                    self.audit_list.insert('end', f"ALERT: {detail}")
                    self.audit_list.itemconfig('end', {'bg':'#ffe6e6'})
                self.log("Security Scan Complete.")
            self.root.after(0, update)
        threading.Thread(target=task).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = ForwardIQApp(root)
    root.mainloop()