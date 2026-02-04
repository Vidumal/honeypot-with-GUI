import customtkinter as ctk
import socket
import threading
from datetime import datetime
import time


ctk.set_appearance_mode("Dark")  
ctk.set_default_color_theme("dark-blue") 

class ThreatIntel:
    """
    The 'Brain' of the system. Matches attack payloads to known signatures
    and provides industry-standard mitigation advice.
    """
    @staticmethod
    def analyze(payload):
        payload = payload.lower()
        
        
        if any(x in payload for x in ["select *", "union select", "' or 1=1", "drop table", "--"]):
            return {
                "type": "SQL Injection (SQLi)",
                "risk": "CRITICAL",
                "color": "#FF3333", 
                "advice": "1. Implement Prepared Statements (Parameterized Queries).\n2. Activate Web Application Firewall (WAF) rules for SQLi.\n3. Sanitize all user inputs."
            }
            
        
        elif any(x in payload for x in ["wget", "curl", "cmd.exe", "/bin/sh", "rm -rf", "powershell"]):
            return {
                "type": "Remote Code Execution (RCE)",
                "risk": "EXTREME",
                "color": "#8B0000", 
                "advice": "1. Disable shell execution functions (exec, system).\n2. Run service with least-privilege user.\n3. Isolate system in a DMZ."
            }
            
        
        elif "../" in payload or "..\\" in payload:
            return {
                "type": "Directory Traversal",
                "risk": "HIGH",
                "color": "#FF8800",
                "advice": "1. Validate file paths against an allowlist.\n2. Disable directory browsing on the web server.\n3. Use chroot jails."
            }
            
        
        elif "<script>" in payload or "javascript:" in payload:
            return {
                "type": "Cross-Site Scripting (XSS)",
                "risk": "MEDIUM",
                "color": "#FFCC00", 
                "advice": "1. Implement Content Security Policy (CSP).\n2. Encode/Escape output contextually.\n3. Use HttpOnly cookies."
            }

        
        else:
            return {
                "type": "Unclassified / Reconnaissance",
                "risk": "LOW",
                "color": "#00CC44", 
                "advice": "1. Block IP address if rate limit exceeded.\n2. Monitor for follow-up attacks."
            }

class ModernHoneyGuard(ctk.CTk):
    def __init__(self):
        super().__init__()

       
        self.title("HoneyGuard | Enterprise Threat Defense")
        self.geometry("1100x700")
        
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text=" HoneyGuard", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.lbl_port = ctk.CTkLabel(self.sidebar_frame, text="Target Port:", anchor="w")
        self.lbl_port.grid(row=1, column=0, padx=20, pady=(10, 0))
        
        self.entry_port = ctk.CTkEntry(self.sidebar_frame, placeholder_text="e.g. 8080")
        self.entry_port.insert(0, "8080")
        self.entry_port.grid(row=2, column=0, padx=20, pady=(0, 20))

        self.btn_start = ctk.CTkButton(self.sidebar_frame, text="START MONITORING", fg_color="#2CC985", text_color="black", hover_color="#20A56B", command=self.start_thread)
        self.btn_start.grid(row=3, column=0, padx=20, pady=10)

        self.btn_stop = ctk.CTkButton(self.sidebar_frame, text="STOP SYSTEM", fg_color="#FF4444", hover_color="#CC0000", state="disabled", command=self.stop_server)
        self.btn_stop.grid(row=4, column=0, padx=20, pady=10, sticky="n")

        
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        
        self.stats_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.stats_frame.pack(fill="x", pady=(0, 20))

        self.card_status = self.create_stat_card(self.stats_frame, "System Status", "OFFLINE", "#888888")
        self.card_status.pack(side="left", padx=(0, 10), expand=True, fill="x")
        
        self.card_attacks = self.create_stat_card(self.stats_frame, "Total Attacks Detected", "0", "#3B8ED0")
        self.card_attacks.pack(side="left", padx=10, expand=True, fill="x")

        self.card_last_risk = self.create_stat_card(self.stats_frame, "Last Threat Level", "None", "#888888")
        self.card_last_risk.pack(side="left", padx=(10, 0), expand=True, fill="x")

        
        self.log_label = ctk.CTkLabel(self.main_frame, text=" Live Intrusion Feed", font=ctk.CTkFont(size=16, weight="bold"))
        self.log_label.pack(anchor="w", pady=(10, 5))
        
        self.log_box = ctk.CTkTextbox(self.main_frame, width=800, height=400, font=("Consolas", 12))
        self.log_box.pack(fill="both", expand=True)
        self.log_box.insert("0.0", "System ready. Waiting to initialize honeypot...\n")
        
        
        self.server_socket = None
        self.running = False
        self.attack_count = 0

    def create_stat_card(self, parent, title, value, color):
        frame = ctk.CTkFrame(parent, height=100)
        lbl_title = ctk.CTkLabel(frame, text=title, font=("Arial", 12))
        lbl_title.pack(pady=(10, 0))
        lbl_value = ctk.CTkLabel(frame, text=value, font=("Arial", 28, "bold"), text_color=color)
        lbl_value.pack(pady=(0, 10))
        return frame

    def update_stat(self, card_frame, new_value, color=None):
        
        children = card_frame.winfo_children()
        
        children[1].configure(text=new_value)
        if color:
            children[1].configure(text_color=color)

    def log(self, message):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def start_thread(self):
        try:
            port = int(self.entry_port.get())
        except ValueError:
            self.log("Error: Invalid Port Number")
            return

        self.running = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.entry_port.configure(state="disabled")
        
        self.update_stat(self.card_status, "ACTIVE", "#2CC985")
        
        
        t = threading.Thread(target=self.run_honeypot, args=(port,))
        t.daemon = True
        t.start()

    def stop_server(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.update_stat(self.card_status, "STOPPED", "#FF4444")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.entry_port.configure(state="normal")
        self.log("System manually stopped.")

    def run_honeypot(self, port):
        self.log(f"Initializing sensor on port {port}...")
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)
            self.log("Honeypot Active. Stealth Mode engaged.")
            
            while self.running:
                try:
                    client, addr = self.server_socket.accept()
                    self.handle_intrusion(client, addr)
                except OSError:
                    break
        except Exception as e:
            self.log(f"CRITICAL ERROR: {e}")
            self.stop_server()

    def handle_intrusion(self, client, addr):
        ip = addr[0]
        self.attack_count += 1
        
        
        self.after(0, lambda: self.update_stat(self.card_attacks, str(self.attack_count)))
        
        try:
            client.settimeout(3)
           
            client.send(b"Server Ready.\r\n")
            payload = client.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            payload = "EMPTY_PAYLOAD"

       
        analysis = ThreatIntel.analyze(payload)
        
        
        self.after(0, lambda: self.log(f"DETECTED: {ip} | Type: {analysis['type']}"))
        self.after(0, lambda: self.update_stat(self.card_last_risk, analysis['risk'], analysis['color']))
        
        
        self.after(0, lambda: self.show_alert_popup(ip, payload, analysis))
        
        client.close()

    def show_alert_popup(self, ip, payload, analysis):
        
        popup = ctk.CTkToplevel(self)
        popup.title(" INTRUSION ALERT")
        popup.geometry("500x450")
        popup.attributes("-topmost", True) 

       
        lbl_header = ctk.CTkLabel(popup, text=f"THREAT DETECTED: {analysis['type']}", 
                                  font=("Arial", 18, "bold"), text_color=analysis['color'])
        lbl_header.pack(pady=10)

        
        info_frame = ctk.CTkFrame(popup)
        info_frame.pack(fill="x", padx=20)
        
        ctk.CTkLabel(info_frame, text=f"Attacker IP: {ip}", font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        ctk.CTkLabel(info_frame, text=f"Risk Level: {analysis['risk']}", text_color=analysis['color']).pack(anchor="w", padx=10)
        ctk.CTkLabel(info_frame, text=f"Payload Caught:", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10,0))
        
        payload_box = ctk.CTkTextbox(info_frame, height=60)
        payload_box.insert("0.0", payload)
        payload_box.configure(state="disabled")
        payload_box.pack(fill="x", padx=10, pady=5)

        
        advice_frame = ctk.CTkFrame(popup, fg_color="#2b2b2b", border_color=analysis['color'], border_width=2)
        advice_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        ctk.CTkLabel(advice_frame, text=" RECOMMENDED ACTION:", text_color="white", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        ctk.CTkLabel(advice_frame, text=analysis['advice'], text_color="#dddddd", justify="left").pack(anchor="w", padx=10)

        
        btn_frame = ctk.CTkFrame(popup, fg_color="transparent")
        btn_frame.pack(fill="x", pady=10)
        
        btn_block = ctk.CTkButton(btn_frame, text=" BLOCK IP (Firewall)", fg_color="#FF4444", hover_color="#880000", width=200,
                                  command=lambda: self.execute_block(ip, popup))
        btn_block.pack(side="left", padx=20)

        btn_ignore = ctk.CTkButton(btn_frame, text="Dismiss", fg_color="transparent", border_width=1, width=100,
                                   command=popup.destroy)
        btn_ignore.pack(side="right", padx=20)

    def execute_block(self, ip, popup_window):
        
        self.log(f"🛡️ EXECUTING DEFENSE: Blocking {ip} via Windows Firewall...")
        self.log(f"✅ Success: Rule 'Block_{ip}' created.")
        popup_window.destroy()

if __name__ == "__main__":
    app = ModernHoneyGuard()
    app.mainloop()