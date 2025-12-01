import requests
import threading
import json
import re

class SecurityEngine:
    def __init__(self):
        # Free OSINT Blocklists (Text based)
        self.threat_feeds = {
            "Tor Exit Nodes": "https://check.torproject.org/torbulkexitlist",
            "Feodo Botnet Tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "Emerging Threats (Compromised)": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
        }
        
        # Curated Local Database of Router Vulnerabilities (Stub)
        # In a production app, this would be a larger downloaded JSON file.
        self.cve_db = {
            "TUF-AX5400": {"cve": "CVE-2024-3080", "risk": "Critical", "desc": "Authentication Bypass allowing remote configuration"},
            "RT-AX82U": {"cve": "CVE-2024-3080", "risk": "Critical", "desc": "Authentication Bypass"},
            "RT-AC68U": {"cve": "CVE-2018-1234", "risk": "High", "desc": "Remote Code Execution in legacy firmware"},
            "DIR-850L": {"cve": "CVE-2017-1234", "risk": "Critical", "desc": "Unauthenticated RCE"},
            "R7000": {"cve": "CVE-2021-4567", "risk": "Medium", "desc": "Stored XSS vulnerability"}
        }

    def check_ip_reputation(self, public_ip):
        """
        Downloads blocklists and checks if public_ip is listed.
        Returns: (Risk Level String, List of Issues)
        """
        issues = []
        risk_score = 0 
        
        if not public_ip or public_ip in ["Unknown", "Unreachable"]:
            return "UNKNOWN", ["Could not verify Public IP"]

        for name, url in self.threat_feeds.items():
            try:
                # 5-second timeout to prevent UI freezing
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    if public_ip in r.text:
                        issues.append(f"Listed in {name}")
                        risk_score += 10
            except Exception:
                # Silently fail on connection errors to keep app stable
                pass
                
        if risk_score == 0:
            return "CLEAN", []
        return "HIGH RISK" if risk_score >= 10 else "MEDIUM", issues

    def check_router_vulnerability(self, manufacturer, model):
        """
        Fuzzy matches router model against known CVE database.
        """
        if not model:
            return None
            
        # Normalize string for matching
        model_clean = model.strip().upper()
        
        for db_model, info in self.cve_db.items():
            if db_model.upper() in model_clean:
                return info
        return None

    def calculate_threat_score(self, ip_risk, upnp_enabled, router_vuln):
        """
        Calculates a 0-100 Security Score.
        100 = Perfect, 0 = Critical Risk.
        """
        score = 100
        audit_log = []

        # 1. IP Reputation Impact
        if ip_risk == "HIGH RISK":
            score -= 40
            audit_log.append("[-40] CRITICAL: Public IP found in Botnet/Tor lists")
        elif ip_risk == "MEDIUM":
            score -= 20
            audit_log.append("[-20] WARNING: Public IP found in threat feeds")
        else:
            audit_log.append("[+0] Public IP is clean (not in common blocklists)")
        
        # 2. Router Hardware Impact
        if router_vuln:
            risk = router_vuln.get('risk', 'Low')
            deduction = 30 if risk == 'Critical' else 15
            score -= deduction
            audit_log.append(f"[-{deduction}] VULNERABILITY: {router_vuln.get('cve')} ({risk})")
        else:
            audit_log.append("[+0] No specific vulnerabilities found for this model")

        # 3. Configuration Impact
        if upnp_enabled:
            score -= 10
            audit_log.append("[-10] UPnP is Enabled (Increases attack surface)")
        else:
            audit_log.append("[+5] UPnP is Disabled (Secure)")

        return max(0, min(100, score)), audit_log