📘 ForwardIQ – Universal Port Manager

ForwardIQ is a powerful, all-in-one network utility designed to simplify port forwarding, router detection, and network security auditing. It supports modern port-control protocols (UPnP, NAT-PMP, PCP) and includes advanced diagnostic and security features. Perfect for gamers, home-lab enthusiasts, and network professionals.

🚀 Features
🔌 Universal Port Forwarding

Full support for UPnP (IGD v1/v2), NAT-PMP, and PCP

Add, delete, or list existing port mappings

Auto-detect supported protocol per router

🧠 Smart Router Detection

Identifies router models via:

UPnP fingerprinting

HTTP header analysis

MAC OUI lookup

Helps detect ISP routers, mesh systems, and repeaters

🛡️ Security Audit (PRO Features)

Check Public IP against:

Dark Web exposure databases

Botnet & malware blocklists

Scan router firmware/model for known CVE vulnerabilities

Generate an overall Network Threat Score

🌐 Network Diagnostics

Detect Double NAT and ISP-level CGNAT

Identify VPN interference (e.g., ProtonVPN)

Validate router HTTPS-only access behavior

🖥️ Local Device Scanner

Discover devices on LAN

Shows IP address, MAC, and vendor name

🔍 Port Checker

Test if any local port is:

Listening

Reachable externally

Correctly forwarded

🛠️ Installation
git clone https://github.com/YOUR_USERNAME/ForwardIQ.git
cd ForwardIQ
py -3.12-64 -m pip install -r requirements.txt

▶️ Usage

Run the main application (requires 64-bit Python):

py -3.12-64 ForwardIQ.py

📦 Build a Windows Executable

Create a standalone .exe that runs without Python installed:

Install PyInstaller:

py -3.12-64 -m pip install pyinstaller


Build the application:

pyinstaller --noconsole --onefile --name ForwardIQ ForwardIQ.py


The final executable will be located in:

dist/ForwardIQ.exe

⚠️ Disclaimer

ForwardIQ allows modification of network and router settings (including Port Forwarding).
Improper configuration may expose internal services to the public internet.
Use responsibly. The developers are not liable for any security breaches or misuse.

📄 License

MIT License — free to use, modify, and distribute.
