# 🧭 ForwardIQ – Universal Port Manager

**ForwardIQ** is a powerful, all-in-one network utility that simplifies port forwarding, router management, and network security auditing.
It supports multiple port-control protocols (UPnP, NAT-PMP, PCP) and includes advanced diagnostic and security capabilities suitable for home users, gamers, and network professionals.

---

## 🌟 Key Features

### 🔌 Universal Port Forwarding

* Supports **UPnP (IGD v1/v2)**, **NAT-PMP**, and **PCP**
* Create, delete, and list port mappings
* Automatic protocol selection based on router capability

### 🧠 Smart Router Detection

* Router identification via:

  * UPnP device information
  * HTTP fingerprinting
  * MAC OUI vendor lookup
* Helps detect mesh routers, ISP gateways, and multi-router setups

### 🛡️ Security Audit (**PRO Features**)

* Public IP security checks against:

  * Dark Web exposure databases
  * Botnet and malware blocklists
* Router model CVE vulnerability scanning
* Generates an overall **Network Threat Score**

### 🌐 Network Diagnostics

* Detects **Double NAT**, **CGNAT**, and VPN interference (e.g., ProtonVPN)
* Identifies when the router forces **HTTPS-only** access
* Highlights connectivity or routing anomalies

### 🖥️ Local Device Scanner

* Scans local network (LAN)
* Displays connected device **IP**, **MAC**, **Vendor**

### 🔍 Port Checker

* Validates whether a local port:

  * Is listening
  * Is reachable externally
  * Is correctly forwarded through the router

---

## 📥 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ForwardIQ.git
cd ForwardIQ
```

### 2. Install Dependencies

Requires **Python 3.12 (64-bit)**.

```bash
py -3.12-64 -m pip install -r requirements.txt
```

---

## ▶️ Usage

Run the application using a **64-bit Python interpreter**:

```bash
py -3.12-64 ForwardIQ.py
```

---

## 📦 Building a Windows Executable

You can bundle ForwardIQ into a standalone `.exe` that runs on any Windows system (no Python required).

### 1. Install PyInstaller

```bash
py -3.12-64 -m pip install pyinstaller
```

### 2. Build the Executable

```bash
pyinstaller --noconsole --onefile --name ForwardIQ ForwardIQ.py
```

Your executable will be available in:

```
dist/ForwardIQ.exe
```

---

## ⚠️ Disclaimer

ForwardIQ includes features that modify **router and network security settings**, such as port forwarding.
Misconfigured ports can expose internal services to the internet.

You are responsible for how you use this tool.
The developers assume **no liability** for security incidents caused by misuse or misconfiguration.

---

## 📄 License

This project is released under the **MIT License**.
You are free to use, modify, and distribute the software.
