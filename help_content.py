# Content for ForwardIQ User Guide

HELP_TEXT = """
================================================================
FORWARD IQ - OFFICIAL USER GUIDE
================================================================

1. WHAT IS FORWARD IQ?
----------------------------------------------------------------
ForwardIQ is a universal network tool designed to make "Port Forwarding" easy. 
It talks to your router automatically to open specific pathways (ports) so that 
friends can connect to your games, servers, or applications from the internet.

It also includes advanced features like:
- Network Device Scanning (Who is on my wifi?)
- Router Security Audits (Is my router vulnerable?)
- VPN & Double NAT Detection (Why isn't it working?)

================================================================
2. HOW PORT FORWARDING WORKS
================================================================
Imagine your home network is an Apartment Building.
- The Building Address is your "Public IP" (Visible to the internet).
- Your Computer is a specific "Apartment" (Local IP, e.g., 192.168.1.10).
- A "Port" is the specific door number (e.g., 25565 for Minecraft).

Normally, the building security (Router NAT) stops anyone from entering. 
Port Forwarding tells security: 
"If someone asks for Door 25565, send them straight to Apartment 10."

Without this, incoming connections from the internet hit the router and get blocked 
because the router doesn't know which computer inside needs the data.

================================================================
3. USING THE APP: DASHBOARD & ROUTER IDENTITY
================================================================
[Router Protocols]
These are the languages we use to talk to your router:
- UPnP: The most common standard. If GREEN, you are good to go.
- NAT-PMP: Used by Apple & some specialized routers.
- PCP: A newer standard, less common.

[Router Identity]
We attempt to detect your router brand (ASUS, TP-Link, etc.) to apply the best settings.
- Auto Detect: Tries to read the router's digital fingerprint.
- Manual Selection: If auto-detect fails, pick your brand from the list.
- Credentials: Some routers (ASUS/Ubiquiti) require a login to identify them. 
  Your password is used ONCE for detection and never saved.

[Network Details]
- Local IP: Your computer's address inside the house.
- Public IP: Your house's address on the internet.
- Double NAT: A critical error where you have TWO routers fighting each other. 
  (See Troubleshooting below).

================================================================
4. HOW TO FORWARD A PORT
================================================================
1. Go to the "Dashboard" or "Port Mappings" tab.
2. Enter the External Port (e.g., 25565).
3. Enter the Internal Port (usually the same, 25565).
4. Choose Protocol (TCP is most common; games often need UDP).
5. Add a Description (e.g., "Minecraft Server").
6. Click "Forward Port".

If successful, the status log will say "Success". 
Check the "Port Mappings" tab to see your active rule.

================================================================
5. TROUBLESHOOTING COMMON ISSUES
================================================================

[Issue: "Router Not Found" or "UPnP Failed"]
- Cause: UPnP is disabled in your router settings.
- Fix: Login to your physical router admin page (usually 192.168.1.1) via a browser 
  and enable "UPnP" in the WAN/Internet settings.

[Issue: "Double NAT Detected"]
- Cause: You have two routers connected (e.g., ISP Modem -> Your ASUS Router).
- Result: Port forwarding will FAIL because the first router blocks it.
- Fix: Set your ISP Modem to "Bridge Mode" so your main router gets the Public IP directly.

[Issue: "Public IP: Unreachable" or VPN Warning]
- Cause: You are using a VPN (Proton, Nord, etc.).
- Effect: The VPN hides your real router. The app cannot talk to your physical router 
  through the VPN tunnel.
- Fix: Turn off your VPN while setting up port forwarding.

[Issue: Port is mapped, but friends still can't connect]
- Cause 1: Windows Firewall is blocking the program.
- Cause 2: The server isn't running. (A port is only "Open" if a program is listening!).
- Fix: Use the "Local Port Listener Check" in the Dashboard to see if your 
  game/server is actually running.

[Issue: "ISP CGNAT"]
- Explanation: Some ISPs (like Starlink or mobile networks) do not give you a 
  real Public IP. They put you behind a giant shared router.
- Fix: You cannot port forward on CGNAT. You must ask your ISP for a "Static IP" 
  or use a tunneling service (like ngrok or Tailscale).

================================================================
6. PRO FEATURES: SECURITY AUDIT
================================================================
The "Security Audit" tab checks if your network is safe.

- Dark Web Exposure: Checks if your IP is listed in hacker databases/botnets.
- Router Vulnerabilities: Checks your router model against a database of known 
  security flaws (CVEs).
- UPnP Risk: While useful, UPnP adds risk. We calculate a "Threat Score" 
  to help you balance convenience vs security.

================================================================
7. BEST PRACTICES
================================================================
- Don't open ports you don't need.
- Use "Delete Selected Rule" to close ports when you stop gaming.
- If your router requires a login, don't worry—ForwardIQ runs locally on your PC. 
  Your password never leaves your computer.
- Always check the "System Log" at the bottom for detailed error messages.

For further support, check your router manufacturer's manual.
"""