# **ForwardIQ – Universal Port Manager**

ForwardIQ is a professional-grade network utility designed to simplify port forwarding, automate router management, and perform comprehensive security audits.
With universal protocol support (UPnP, NAT-PMP, PCP) and advanced diagnostic capabilities, ForwardIQ helps users identify router vulnerabilities, detect network threats, and optimize network configurations with ease.

---

## 📌 **Table of Contents**

* [Features](#-features)
* [Project Structure](#-project-structure)
* [Installation](#-installation)
* [How to Run](#-how-to-run)
* [Usage Guide](#-usage-guide)
* [Troubleshooting](#-troubleshooting)
* [Disclaimer](#%EF%B8%8F-disclaimer)
* [License](#-license)

---

## 🚀 **Features**

### **🛡️ Security Audit (PRO Module)**

* **Dark Web Exposure Check**
  Compares your public IP against botnet feeds, Tor exit nodes, and malware blocklists.
* **Router Vulnerability Scanner**
  Fingerprints router models and checks them against a curated CVE database.
* **Threat Score Calculator**
  Generates a 0–100 score based on router configuration, exposed ports, and potential vulnerabilities.

---

### **🌐 Universal Port Forwarding**

* UPnP IGD v1/v2, NAT-PMP, and PCP support
* Auto-renewal of port mappings
* Port conflict detection to prevent duplicates or blocked ports

---

### **🔍 Advanced Router Detection**

* Router identification through:

  * HTTP/HTTPS probing
  * UPnP metadata extraction
  * MAC address OUI lookups
* Auth-aware detection with secure credential prompts
* Full HTTPS support, including self-signed certificates and router redirects

---

### **🛠️ Network Diagnostics**

* VPN tunnel detection
* Double NAT / CGNAT detection
* Local ARP device scanning with vendor lookup
* Port listener verification to confirm application availability before mapping

---

## 📂 **Project Structure**

```
ForwardIQ/
│
├── ForwardIQ.py             # Main GUI Application
├── router_engine.py         # Core logic: UPnP, NAT-PMP, PCP, scanning
├── help_content.py          # Internal user guide content
├── requirements.txt         # Dependency list
│
└── pro_tools/
    ├── __init__.py
    └── security_engine.py   # PRO security module (IP reputation + CVE scanning)
```

> ⚠️ **Important:** The `pro_tools` directory must exist and contain `security_engine.py` or the application will fail to start.

---

## ⚙️ **Installation**

### **Prerequisites**

* **Python 3.12+ (64-bit)**
  Required due to compatibility with libraries such as `psutil`.
* Compatible with:

  * Windows (recommended)
  * macOS
  * Linux (Admin privileges may be required for ARP scanning)

---

### **Step 1 — Download the Source Code**

```bash
git clone https://github.com/CyberPulseDev/ForwardIQ.git
cd ForwardIQ
```

### **Step 2 — Install Dependencies**

#### **Windows**

```bash
py -3.12-64 -m pip install -r requirements.txt
```

#### **macOS / Linux**

```bash
pip3 install -r requirements.txt
```

> If you encounter issues installing `miniupnpc` or `natpmp`, ensure appropriate C/C++ build tools are installed.

---

## ▶️ **How to Run**

Launch the application using a 64-bit Python interpreter:

```bash
py -3.12-64 ForwardIQ.py
```

---

## 💡 **Usage Guide**

### Dashboard Indicators

* **Green** → Protocol available
* **Red** → Router feature disabled or blocked
* **Orange** → VPN detected (may block router access)

### VPN Users

If VPN is detected, temporarily disable it to allow ForwardIQ to communicate with your physical router.

### Running a Security Audit (PRO)

1. Navigate to **Security Audit (PRO)**
2. Click **Run Full Security Audit**
3. Review your Threat Score and recommended actions

---

## ❓ **Troubleshooting**

| Issue                            | Cause                               | Solution                                                            |
| -------------------------------- | ----------------------------------- | ------------------------------------------------------------------- |
| **Unknown Router**               | Router requires login / unsupported | Click **Auto Detect Router**, enter admin credentials when prompted |
| **Public IP: Unreachable**       | VPN / firewall blocking             | Disable VPN, ensure `api.ipify.org` is accessible                   |
| **0 Mappings Found**             | No dynamic UPnP rules               | Normal; manually configured rules do not appear in UPnP lists       |
| **Application Crash on Startup** | Missing files                       | Ensure `pro_tools/security_engine.py` is present                    |

---

## ⚠️ **Disclaimer**

ForwardIQ modifies network configuration settings.
While safety mechanisms are implemented, users are fully responsible for:

* Ports they open
* Exposure of local services
* Risks arising from vulnerable router hardware or misconfigurations

Use the **Security Audit** module to evaluate risk levels before exposing network services publicly.

---

## 📄 **License**

Distributed under the **MIT License**.
See the `LICENSE` file for full legal details.

---
