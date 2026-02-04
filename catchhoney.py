import customtkinter as ctk
import socket
import threading
from datetime import datetime
import time
import requests
import random
import os
from tkintermapview import TkinterMapView

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")


if os.name == 'nt': 
    DESKTOP_PATH = os.path.join(os.environ['USERPROFILE'], 'Desktop')
else:  
    
    DESKTOP_PATH = "."

LOG_FILE_PATH = os.path.join(DESKTOP_PATH, "honeyguard_logs.txt")

class ThreatIntel:
    """The 'Brain' of the system."""
    @staticmethod
    def get_location_data(ip_address):
        if ip_address in ["127.0.0.1", "localhost"]:
            return {"country": "Localhost", "city": "Test Lab", "lat": 0, "lon": 0, "status": "fail"}
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=3).json()
            if response['status'] == 'success':
                return {"country": response['country'], "city": response['city'], "lat": response['lat'], "lon": response['lon'], "status": "success"}
            else: return {"status": "fail"}
        except: return {"status": "fail"}
    
    @staticmethod
    def analyze(payload):
        payload = payload.lower()
        if any(x in payload for x in ["select *", "union select", "' or 1=1", "drop table", "--"]):
            return {"type": "SQL Injection (SQLi)", "risk": "CRITICAL", "color": "#FF3333", "advice": "1. Implement Prepared Statements.\n2. Activate WAF rules."}
        elif any(x in payload for x in ["wget", "curl", "cmd.exe", "/bin/sh", "rm -rf", "powershell"]):
            return {"type": "Remote Code Execution", "risk": "EXTREME", "color": "#8B0000", "advice": "1. Disable shell execution.\n2. Isolate system in DMZ."}
        elif "<script>" in payload or "javascript:" in payload:
            return {"type": "Cross-Site Scripting", "risk": "MEDIUM", "color": "#FFCC00", "advice": "1. Implement CSP.\n2. Encode output contextually."}
        else:
            return {"type": "Reconnaissance / Scan", "risk": "LOW", "color": "#00CC44", "advice": "1. Block IP if rate limit exceeded."}

class ModernHoneyGuard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("HoneyGuard Pro | Global Threat Map & Logger")
        self.geometry("1200x800")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)


        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1) 

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ HoneyGuard", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.lbl_port = ctk.CTkLabel(self.sidebar_frame, text="Target Port:", anchor="w")
        self.lbl_port.grid(row=1, column=0, padx=20, pady=(10, 0))
        
        self.entry_port = ctk.CTkEntry(self.sidebar_frame, placeholder_text="8080")
        self.entry_port.insert(0, "8080")
        self.entry_port.grid(row=2, column=0, padx=20, pady=(0, 20))

        self.btn_start = ctk.CTkButton(self.sidebar_frame, text="START MONITORING", fg_color="#2CC985", text_color="black", hover_color="#20A56B", command=self.start_thread)
        self.btn_start.grid(row=3, column=0, padx=20, pady=10)

        self.btn_stop = ctk.CTkButton(self.sidebar_frame, text="STOP SYSTEM", fg_color="#FF4444", hover_color="#CC0000", state="disabled", command=self.stop_server)
        self.btn_stop.grid(row=4, column=0, padx=20, pady=10)
        
        self.btn_folder = ctk.CTkButton(self.sidebar_frame, text=" OPEN LOG FILE", fg_color="#555555", hover_color="#333333", command=self.open_log_file)
        self.btn_folder.grid(row=5, column=0, padx=20, pady=10)

        self.btn_sim = ctk.CTkButton(self.sidebar_frame, text=" SIMULATE ATTACK", fg_color="#3B8ED0", hover_color="#1F6AA5", command=self.simulate_attack)
        self.btn_sim.grid(row=6, column=0, padx=20, pady=10, sticky="s")


        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="#242424") 
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        self.stats_frame = ctk.CTkFrame(self.main_frame, fg_color="#242424") 
        self.stats_frame.pack(fill="x", pady=(0, 10))
        self.card_status = self.create_stat_card(self.stats_frame, "Status", "OFFLINE", "#888888")
        self.card_status.pack(side="left", padx=(0, 10), expand=True, fill="x")
        self.card_attacks = self.create_stat_card(self.stats_frame, "Attacks", "0", "#3B8ED0")
        self.card_attacks.pack(side="left", padx=10, expand=True, fill="x")
        self.card_last_risk = self.create_stat_card(self.stats_frame, "Threat Level", "None", "#888888")
        self.card_last_risk.pack(side="left", padx=(10, 0), expand=True, fill="x")

        self.map_label = ctk.CTkLabel(self.main_frame, text="🌍 Live Global Threat Map", font=ctk.CTkFont(size=16, weight="bold"))
        self.map_label.pack(anchor="w", pady=(10, 5))
        self.map_widget = TkinterMapView(self.main_frame, width=800, height=300, corner_radius=10)
        self.map_widget.pack(fill="x", pady=(0, 10))
        self.map_widget.set_tile_server("https://mt0.google.com/vt/lyrs=m&hl=en&x={x}&y={y}&z={z}&s=Ga", max_zoom=22)
        self.map_widget.set_position(20, 0)
        self.map_widget.set_zoom(2)

        self.log_label = ctk.CTkLabel(self.main_frame, text=f" Intrusion Logs ({LOG_FILE_PATH})", font=ctk.CTkFont(size=12, weight="bold"))
        self.log_label.pack(anchor="w", pady=(5, 5))
        self.log_box = ctk.CTkTextbox(self.main_frame, width=800, height=200, font=("Consolas", 12))
        self.log_box.pack(fill="both", expand=True)
        
        self.server_socket = None
        self.running = False
        self.attack_count = 0
        

        print(f"DEBUG: Trying to create file at: {LOG_FILE_PATH}")
        try:
            with open(LOG_FILE_PATH, "a") as f:
                f.write(f"--- SYSTEM STARTUP: {datetime.now()} ---\n")
            print("SUCCESS: Log file created successfully.")
            self.log_box.insert("0.0", f"SYSTEM READY. LOGGING TO: {LOG_FILE_PATH}\n")
        except Exception as e:
            print(f"CRITICAL ERROR: Could not create file! Reason: {e}")
            self.log_box.insert("0.0", f"ERROR: Could not create log file. Check permissions!\nError: {e}\n")

    def create_stat_card(self, parent, title, value, color):
        frame = ctk.CTkFrame(parent, height=80)
        lbl_title = ctk.CTkLabel(frame, text=title, font=("Arial", 12))
        lbl_title.pack(pady=(5, 0))
        lbl_value = ctk.CTkLabel(frame, text=value, font=("Arial", 24, "bold"), text_color=color)
        lbl_value.pack(pady=(0, 5))
        return frame

    def update_stat(self, card_frame, new_value, color=None):
        children = card_frame.winfo_children()
        children[1].configure(text=new_value)
        if color: children[1].configure(text_color=color)

    def log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        
        self.log_box.configure(state="normal")
        self.log_box.insert("end", log_entry + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
        
        try:
            with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")
        except Exception as e: 
            print(f"File Write Error: {e}")

    def open_log_file(self):
        try:
            os.startfile(LOG_FILE_PATH)
        except:
            if os.name == 'nt':
                os.startfile(DESKTOP_PATH)

    def start_thread(self):
        try: port = int(self.entry_port.get())
        except ValueError:
            self.log("Error: Invalid Port")
            return
        self.running = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.update_stat(self.card_status, "ACTIVE", "#2CC985")
        t = threading.Thread(target=self.run_honeypot, args=(port,))
        t.daemon = True
        t.start()

    def stop_server(self):
        self.running = False
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
        self.update_stat(self.card_status, "STOPPED", "#FF4444")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def run_honeypot(self, port):
        self.log(f"Sensor initialized on port {port}...")
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)
            self.log("Waiting for global connections...")
            while self.running:
                try:
                    client, addr = self.server_socket.accept()
                    self.process_attack(client, addr[0])
                except OSError: break
        except Exception as e:
            self.log(f"Error: {e}")
            self.stop_server()

    def simulate_attack(self):
        fake_ips = ["1.1.1.1", "8.8.8.8", "223.5.5.5", "95.163.212.192", "194.71.107.25"]
        fake_ip = random.choice(fake_ips)
        self.log(f"--- SIMULATING ATTACK FROM {fake_ip} ---")
        t = threading.Thread(target=self.process_attack, args=(None, fake_ip, True))
        t.start()

    def process_attack(self, client, ip, is_simulation=False):
        self.attack_count += 1
        self.after(0, lambda: self.update_stat(self.card_attacks, str(self.attack_count)))
        geo_data = ThreatIntel.get_location_data(ip)
        payload = "SIMULATED_SQL_INJECTION"
        if not is_simulation and client:
            try:
                client.settimeout(3)
                client.send(b"Server Ready.\r\n")
                payload = client.recv(1024).decode('utf-8', errors='ignore').strip()
                client.close()
            except: payload = "EMPTY"
        analysis = ThreatIntel.analyze(payload)
        self.after(0, lambda: self.update_map_and_ui(ip, geo_data, analysis, payload))

    def update_map_and_ui(self, ip, geo, analysis, payload):
        loc_str = f"{geo.get('country', 'Unknown')} ({geo.get('city', '?')})"
        self.log(f"DETECTED: {ip} | {loc_str} | {analysis['type']}")
        self.update_stat(self.card_last_risk, analysis['risk'], analysis['color'])
        if geo['status'] == 'success':
            self.map_widget.set_position(geo['lat'], geo['lon'])
            self.map_widget.set_zoom(5)
            self.map_widget.set_marker(geo['lat'], geo['lon'], text=f"Attacker: {ip}")
        self.show_alert_popup(ip, loc_str, payload, analysis)

    def show_alert_popup(self, ip, location, payload, analysis):
        popup = ctk.CTkToplevel(self)
        popup.title(" INTRUSION ALERT")
        popup.geometry("500x400")
        popup.attributes("-topmost", True) 
        ctk.CTkLabel(popup, text=f"THREAT DETECTED: {analysis['type']}", font=("Arial", 16, "bold"), text_color=analysis['color']).pack(pady=10)
        info = ctk.CTkFrame(popup)
        info.pack(fill="x", padx=20)
        ctk.CTkLabel(info, text=f"IP: {ip} | {location}", font=("Arial", 12)).pack(anchor="w", padx=10, pady=5)
        ctk.CTkTextbox(info, height=50).pack(fill="x", padx=10)
        btn_frame = ctk.CTkFrame(popup, fg_color="#242424") 
        btn_frame.pack(fill="x", pady=10)
        btn = ctk.CTkButton(popup, text="CLOSE", command=popup.destroy, fg_color="#444444")
        btn.pack(pady=10)


def run_headless(port=8080):
    print(f"--- HEADLESS MODE ACTIVE ---")
    print(f"HoneyGuard running in Docker/CLI on port {port}")
    print(f"Logs will be saved to: {LOG_FILE_PATH}")
    
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        
        while True:
            try:
                client, addr = server_socket.accept()
                ip = addr[0]
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"[{timestamp}] DOINK! Connection from {ip}")
                
         
                with open(LOG_FILE_PATH, "a") as f:
                    f.write(f"[{timestamp}] Connection from {ip}\n")
                    
                client.close()
            except Exception as inner_e:
                print(f"Connection Error: {inner_e}")
                
    except Exception as e:
        print(f"Server Error: {e}")


if __name__ == "__main__":
    
    try:
        app = ModernHoneyGuard()
        app.mainloop()
    except Exception as e:
       
        if "no display name" in str(e) or "TclError" in str(e):
            run_headless(port=8080)
        else:
            print(f"Critical Error: {e}")