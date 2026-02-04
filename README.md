# 🛡️ HoneyGuard Pro | Advanced Threat Intelligence Honeypot

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=for-the-badge&logo=docker)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-orange?style=for-the-badge)
![Security](https://img.shields.io/badge/Focus-Cybersecurity-red?style=for-the-badge)

**HoneyGuard Pro** is a multi-threaded network honeypot designed to detect, log, and visualize unauthorized access attempts in real-time. It features a unique **Dual-Mode Architecture** that automatically adapts its interface based on the environment:
1.  **GUI Mode:** A full dashboard with a live interactive world map for local Windows monitoring.
2.  **Headless Mode:** A text-only CLI optimized for high-performance Docker/Cloud deployment.

---

## 🌟 Key Features

### 🖥️ 1. Interactive GUI Dashboard (Local Mode)
* **Live Attack Map:** Integrated `TkinterMapView` to visualize attacker locations instantly on a zoomable world map.
* **Real-Time Stats:** dynamic counters for total attacks, threat levels, and system status.
* **Simulation Mode:** Built-in tool to simulate SQL Injection and XSS attacks for testing purposes.

### 🐳 2. Cloud-Ready Docker Support (Headless Mode)
* **Auto-Detection:** The application detects when it is running in a headless environment (Docker) and automatically switches to CLI mode.
* **Cross-Platform Paths:** Logic to handle file saving differences between Windows (`C:\Users\...`) and Linux (`/app`).
* **Instant Logging:** Forces unbuffered output to Docker logs for immediate threat verification.

### 🧠 3. Threat Intelligence
* **Geolocation Tracking:** Uses `ip-api.com` to fetch Country, City, and GPS coordinates of attackers.
* **Heuristic Analysis:** Analyzes payloads to classify threats (SQLi, RCE, XSS, Recon) and assigns risk scores.

### 📝 4. Forensic Logging
* **Persistent Storage:** Automatically appends all attack data to `honeyguard_logs.txt`.
* **Timestamped Evidence:** Precision logging for post-incident auditing.

---

## 🚀 Installation & Usage

### Option A: Run Locally (Windows with GUI)
*Prerequisites: Python 3.9+*

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/Vidumal/honeypot-with-GUI.git](https://github.com/Vidumal/honeypot-with-GUI.git)
    cd HoneyGuard
    ```

2.  **Install Dependencies**
    ```bash
    pip install customtkinter tkintermapview requests
    ```

3.  **Run the Application**
    ```bash
    python catchhoney.py
    ```
    *Enter a port (e.g., 8080) and click **START MONITORING**.*

---

### Option B: Run with Docker (Headless Mode)
*Perfect for cloud servers or isolated testing.*

1.  **Build the Image**
    ```bash
    docker build -t honeyguard-pro .
    ```

2.  **Run the Container**
    We use `-p` to map ports and `-e PYTHONUNBUFFERED=1` to see logs instantly.
    ```bash
    docker run -p 8080:8080 -e PYTHONUNBUFFERED=1 honeyguard-pro
    ```

3.  **Verify It Works**
    * Open your browser and visit `http://localhost:8080`.
    * Check your terminal. You will see the signature detection log:
        ```text
        [2026-02-05 12:00:00] DOINK! Connection from 172.17.0.1
        ```

---

## 📂 Project Structure

```text
/HoneyGuard-Project
│
├── catchhoney.py          # Main Application (Hybrid GUI/CLI Logic)
├── Dockerfile             # Container configuration for Linux/Python
├── requirements.txt       # Dependency list
├── honeyguard_logs.txt    # (Auto-Generated) Attack history log
└── README.md              # Documentation