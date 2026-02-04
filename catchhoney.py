import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading
from datetime import datetime

class HoneyGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HoneyGuard - Windows Intrusion Monitor")
        self.root.geometry("500x400")
        
       
        
       
        self.config_frame = tk.Frame(root, pady=10)
        self.config_frame.pack()

        tk.Label(self.config_frame, text="Port to Monitor:").pack(side=tk.LEFT, padx=5)
        self.port_entry = tk.Entry(self.config_frame, width=10)
        self.port_entry.insert(0, "8080") 
        self.port_entry.pack(side=tk.LEFT, padx=5)

        self.btn_start = tk.Button(self.config_frame, text="Start Honeypot", bg="green", fg="white", command=self.start_server_thread)
        self.btn_start.pack(side=tk.LEFT, padx=10)
        
        self.btn_stop = tk.Button(self.config_frame, text="Stop", bg="red", fg="white", command=self.stop_server, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT)

        
        tk.Label(root, text="Live Attack Logs:").pack(anchor="w", padx=10)
        self.log_area = scrolledtext.ScrolledText(root, height=15, state='disabled', bg="#f0f0f0")
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        
        self.server_socket = None
        self.is_running = False

    def log(self, message):
        """Updates the text box safely from any thread"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_msg = f"[{timestamp}] {message}\n"
        
        
        
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, full_msg)
        self.log_area.see(tk.END) 
        self.log_area.config(state='disabled')

    def start_server_thread(self):
        """Starts the honeypot in a background thread"""
        port = int(self.port_entry.get())
        self.is_running = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        
        
        t = threading.Thread(target=self.run_honeypot, args=(port,))
        t.daemon = True
        t.start()

    def stop_server(self):
        """Stops the server"""
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.log("Server stopped manually.")
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

    def run_honeypot(self, port):
        self.log(f"Starting surveillance on Port {port}...")
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)
            self.log("Waiting for attackers...")
            
            while self.is_running:
                try:
                    
                    client, addr = self.server_socket.accept()
                    
                   
                    self.handle_attack(client, addr)
                    
                except OSError:
                    break 
                    
        except Exception as e:
            self.log(f"Error: {e}")
        finally:
            self.btn_start.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)

    def handle_attack(self, client, addr):
        """Handles the intrusion and asks user for decision"""
        ip = addr[0]
        self.log(f"!!! ALERT: Connection from {ip} !!!")
        
       
        try:
            client.settimeout(2) 
            data = client.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            data = "<No Data>"

        self.log(f"Payload: {data}")

      
        self.root.after(0, lambda: self.show_decision_popup(ip, data))

      
        client.close()

    def show_decision_popup(self, ip, payload):
        """The 'Decision' Maker"""
        response = messagebox.askyesno(
            title="INTRUSION DETECTED", 
            message=f"Hacker detected from IP: {ip}\nPayload: {payload}\n\nDo you want to flag this IP as malicious?"
        )
        
        if response: 
            self.log(f"Running defensive measures against {ip}...")
          
            self.log(f"--> IP {ip} added to blacklist.")
        else:
            self.log(f"Action ignored for {ip}.")


if __name__ == "__main__":
    root = tk.Tk()
    app = HoneyGuardApp(root)
    root.mainloop()