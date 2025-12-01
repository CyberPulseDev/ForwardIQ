import socket
import struct
import threading
import time
import requests
import psutil
import subprocess
import platform
import re
import miniupnpc
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress "Unverified HTTPS request" warnings for self-signed router certs
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Try importing py-natpmp
try:
    import natpmp
    HAS_NAT_PMP = True
except ImportError:
    HAS_NAT_PMP = False

class NetworkScanner:
    def __init__(self):
        self.upnp = None
        self.natpmp_client = None
        self.local_ip = self.get_local_ip()
        self.interface_name = self.get_interface_name(self.local_ip)
        self.vpn_active, self.vpn_name = self.check_vpn_status()
        self.gateway_ip = self.get_physical_gateway()
        self.lock = threading.Lock() 
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def get_interface_name(self, ip_address):
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == ip_address:
                        return iface
        except:
            pass
        return "Unknown"

    def check_vpn_status(self):
        if_name = self.interface_name.lower()
        vpn_keywords = ["tun", "tap", "vpn", "wireguard", "proton", "nord", "tailscale", "zerotier", "wg"]
        for kw in vpn_keywords:
            if kw in if_name:
                return True, self.interface_name
        return False, None

    def get_default_gateway(self):
        try:
            os_type = platform.system()
            if os_type == "Windows":
                cmd = "route print 0.0.0.0"
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                output = subprocess.check_output(cmd, startupinfo=startupinfo, shell=True).decode()
                for line in output.splitlines():
                    parts = line.strip().split()
                    if len(parts) > 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        return parts[2]
            elif os_type in ["Linux", "Darwin"]:
                try:
                    output = subprocess.check_output("ip route show default", shell=True).decode()
                    match = re.search(r'via\s+([0-9.]+)', output)
                    if match: return match.group(1)
                except:
                    output = subprocess.check_output("netstat -rn", shell=True).decode()
                    for line in output.splitlines():
                        parts = line.strip().split()
                        if parts and parts[0] in ["default", "0.0.0.0"]:
                            return parts[1]
        except: pass
        return None

    def get_physical_gateway(self):
        default_gw = self.get_default_gateway()
        if not self.vpn_active: return default_gw
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                if any(k in iface.lower() for k in ["tun", "tap", "vpn", "wireguard"]): continue
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if ip.startswith("192.168."):
                            parts = ip.split('.')
                            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
                        if ip.startswith("10.") and not self.vpn_active:
                             parts = ip.split('.')
                             return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except: pass
        return default_gw 

    def get_external_ip_api(self):
        providers = ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com']
        for url in providers:
            try:
                r = requests.get(url, timeout=3)
                if r.status_code == 200: return r.text.strip()
            except: continue
        if self.natpmp_client: return "From NAT-PMP (APIs Blocked)"
        if self.upnp:
            try: return self.upnp.externalipaddress()
            except: pass
        return "Unreachable"

    # === Discovery Methods (BUG FIXED HERE) ===

    def scan_upnp(self):
        with self.lock:
            try:
                u = miniupnpc.UPnP()
                u.discoverdelay = 200
                ndevices = u.discover()
                
                # BUG FIX: Explicitly check if devices were found
                if ndevices == 0:
                    self.upnp = None
                    return False, "No devices found"

                # BUG FIX: Ensure a valid IGD (Internet Gateway Device) is selected
                if u.selectigd() is None:
                    self.upnp = None
                    return False, "No valid IGD selected"
                
                self.upnp = u
                return True, u.lanaddr
            except Exception as e:
                self.upnp = None
                return False, str(e)

    def scan_natpmp(self):
        if not HAS_NAT_PMP: return False, "Library missing"
        if not self.gateway_ip: return False, "No Gateway"
        with self.lock:
            try:
                resp = natpmp.get_public_address(self.gateway_ip)
                public_ip = str(resp.public_address) if hasattr(resp, 'public_address') else str(resp)
                self.natpmp_client = True 
                return True, public_ip
            except Exception as e: return False, str(e)

    def scan_pcp(self):
        if not self.gateway_ip: return False, "No Gateway"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            test_packet = struct.pack('!BBHI', 2, 0, 0, 0)
            sock.sendto(test_packet, (self.gateway_ip, 5351))
            data, _ = sock.recvfrom(1024)
            if len(data) > 0: return True, f"v{data[0]} Detected"
        except: pass
        finally: sock.close()
        return False, "No Response"

    # === Router Identification ===

    def detect_router_identity(self):
        if self.upnp:
            try:
                manuf = self.upnp.manufacturer
                model = self.upnp.modelname
                if manuf and model:
                    return manuf, f"{manuf} {model} (UPnP)"
            except: pass

        if not self.gateway_ip: return None, "Unknown (No Gateway)"

        targets = [
            (f"https://{self.gateway_ip}", "HTTPS"),
            (f"http://{self.gateway_ip}", "HTTP"),
            (f"https://{self.gateway_ip}/Main_Login.asp", "HTTPS (ASUS)"),
            (f"http://{self.gateway_ip}/Main_Login.asp", "HTTP (ASUS)"),
            (f"https://{self.gateway_ip}:8443", "HTTPS:8443"),
            (f"http://{self.gateway_ip}:8080", "HTTP:8080")
        ]

        for url, proto_name in targets:
            try:
                r = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                content = r.text.upper()
                headers = str(r.headers).upper()

                if r.status_code == 401:
                    return "AUTH_REQUIRED", {"url": url, "type": "basic", "proto": proto_name}
                
                if '<INPUT TYPE="PASSWORD"' in content or "PASSWORD" in content:
                    if "LOGIN" in content or "SIGN IN" in content or "AUTH" in content:
                        return "AUTH_REQUIRED", {"url": url, "type": "form", "proto": proto_name}

                fingerprint = ""
                if 'ASUS' in headers or 'RT-' in headers: fingerprint = "ASUS Router"
                elif 'TP-LINK' in headers: fingerprint = "TP-Link Router"
                elif 'MIKROTIK' in headers: fingerprint = "MikroTik"

                if not fingerprint:
                    title_match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).upper()
                        if "ASUS" in title: fingerprint = "ASUS Router"
                        elif "TP-LINK" in title: fingerprint = "TP-Link Router"
                        elif "NETGEAR" in title: fingerprint = "Netgear Router"
                        elif "D-LINK" in title: fingerprint = "D-Link Router"
                        elif "OPENWRT" in title: fingerprint = "OpenWrt"
                        elif "SYNOLOGY" in title: fingerprint = "Synology Router"
                        elif "UBIQUITI" in title or "UNIFI" in title: fingerprint = "UniFi Gateway"

                if fingerprint:
                    details = f"{fingerprint} ({proto_name})"
                    if self.vpn_active: details += " [VPN Active]"
                    return fingerprint.split()[0], details

            except requests.exceptions.SSLError: continue 
            except Exception: pass

        mac = self.get_gateway_mac(self.gateway_ip)
        if mac:
            mac_clean = re.sub(r'[:-]', '', mac).upper()[:6]
            oui_db = {'F832E4': 'ASUS', '049226': 'ASUS', '2C4D54': 'ASUS', '50C7BF': 'TP-Link', '14CC20': 'TP-Link', '9C3DCF': 'Netgear', 'A00460': 'Netgear', 'B0C554': 'D-Link', 'E48D8C': 'Linksys', '18FD74': 'MikroTik', '7483C2': 'UniFi'}
            vendor = oui_db.get(mac_clean)
            if vendor: return vendor, f"{vendor} Device (MAC OUI)"

        return None, "Unknown Router"

    def attempt_login_and_identify(self, url, username, password, auth_type):
        try:
            session = requests.Session()
            session.verify = False 
            if auth_type == "basic":
                r = session.get(url, auth=HTTPBasicAuth(username, password), timeout=5)
            else:
                payloads = [{'username': username, 'password': password}, {'user': username, 'pws': password}, {'admin_name': username, 'password': password}, {'login_name': username, 'login_pwd': password}]
                r = None
                for payload in payloads:
                    try:
                        r = session.post(url, data=payload, timeout=5)
                        if r.status_code == 200 and "password" not in r.text.lower(): break
                    except: pass
            
            if not r or r.status_code != 200: return False, "Login Failed"
            content = r.text.upper()
            if "INVALID PASSWORD" in content or "LOGIN FAILED" in content: return False, "Invalid Credentials"
            match = re.search(r'(RT-[A-Z0-9]+|GT-[A-Z0-9]+|ARCHER [A-Z0-9]+|R[0-9]{4}|DIR-[0-9]+)', content)
            if match: return True, f"{match.group(1)} (Authenticated)"
            title_match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
            if title_match: return True, f"{title_match.group(1)} (Authenticated)"
            return True, "Authenticated (Model Unknown)"
        except Exception as e: return False, str(e)

    def get_gateway_mac(self, gateway_ip):
        try:
            cmd = ['arp', '-a']
            startupinfo = None
            if platform.system() == 'Windows':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            output = subprocess.check_output(cmd, startupinfo=startupinfo).decode()
            for line in output.split('\n'):
                if gateway_ip in line:
                    mac_match = re.search(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line)
                    if mac_match: return mac_match.group(1)
        except: pass
        return None

    def detect_double_nat(self):
        if self.vpn_active: return "VPN Active (NAT Skipped)"
        wan_ip = None
        if self.upnp:
            try: wan_ip = self.upnp.externalipaddress()
            except: pass
        ext_ip = self.get_external_ip_api()
        if not wan_ip: return "Unknown (Router didn't report WAN IP)"
        if ext_ip == "Unreachable": return "Cannot Verify (Ext IP Unreachable)"
        is_private = False
        if wan_ip.startswith("10."): is_private = True
        elif wan_ip.startswith("192.168."): is_private = True
        elif wan_ip.startswith("172.") and 16 <= int(wan_ip.split('.')[1]) <= 31: is_private = True
        elif wan_ip.startswith("100.") and 64 <= int(wan_ip.split('.')[1]) <= 127: is_private = True 
        if is_private and wan_ip != ext_ip: return f"DETECTED! Router WAN ({wan_ip}) != Public"
        return "Not Detected"

    def port_check_local(self, port, protocol='TCP'):
        is_listening = False
        sock_type = socket.SOCK_STREAM if protocol == 'TCP' else socket.SOCK_DGRAM
        try:
            sock = socket.socket(socket.AF_INET, sock_type)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', int(port)))
            if result == 0: is_listening = True
            sock.close()
        except: pass
        return is_listening

    def scan_network_devices(self):
        devices = []
        try:
            cmd = ['arp', '-a']
            startupinfo = None
            if platform.system() == 'Windows':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            output = subprocess.check_output(cmd, startupinfo=startupinfo).decode()
            for line in output.split('\n'):
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if not ip.startswith("224.") and not ip.endswith(".255"):
                        mac_match = re.search(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line)
                        mac = mac_match.group(1) if mac_match else "Unknown"
                        devices.append({'ip': ip, 'mac': mac})
        except: pass
        return devices

    def add_mapping(self, ext_port, int_port, protocol, desc):
        with self.lock:
            if self.upnp:
                try:
                    self.upnp.addportmapping(int(ext_port), protocol, self.upnp.lanaddr, int(int_port), desc, '')
                    return True, "Success via UPnP"
                except Exception as e1:
                    try:
                        self.upnp.addportmapping(int(ext_port), protocol, self.upnp.lanaddr, int(int_port), desc, '', 0)
                        return True, "Success via UPnP (v2)"
                    except Exception as e2: print(f"UPnP Failed: {e1} | {e2}")
            if self.natpmp_client and HAS_NAT_PMP:
                try:
                    proto_code = 2 if protocol == 'TCP' else 1
                    natpmp.map_port(proto_code, int(ext_port), int(int_port), 3600, gateway_ip=self.gateway_ip)
                    return True, "Success via NAT-PMP"
                except Exception as e: print(f"NAT-PMP Failed: {e}")
            return False, "All automated methods failed."

    def delete_mapping(self, ext_port, protocol):
        with self.lock:
            if self.upnp:
                try: self.upnp.deleteportmapping(int(ext_port), protocol)
                except: pass
            if self.natpmp_client and HAS_NAT_PMP:
                try:
                    proto_code = 2 if protocol == 'TCP' else 1
                    natpmp.map_port(proto_code, int(ext_port), int(ext_port), 0, gateway_ip=self.gateway_ip)
                except: pass
            return False, "Could not delete"

    def get_mappings(self):
        with self.lock:
            if self.upnp is None: return [] 
            mappings = []
            i = 0
            while True:
                try:
                    res = self.upnp.getgenericportmapping(i)
                    if res is None: break 
                    mappings.append({'ext': res[0], 'proto': res[1], 'int_ip': res[2][0], 'int_port': res[2][1], 'desc': res[3]})
                    i += 1
                except: break
            return mappings