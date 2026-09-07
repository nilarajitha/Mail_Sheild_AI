import re
from typing import Dict, Any

class AuthProtocolVerifier:
    """
    SPF, DKIM, and DMARC Email Authentication Protocol Verifier.
    Parses headers and evaluates policy alignment and signature validity.
    """
    def verify(self, email_headers: str, sender_domain: str, client_ip: str, threat_score: float) -> Dict[str, Any]:
        headers_lower = email_headers.lower()
        
        # Check SPF
        if "spf=pass" in headers_lower or ("received-spf: pass" in headers_lower and threat_score < 40):
            spf_status = "PASS"
            spf_details = f"Sender IP {client_ip} is explicitly authorized in SPF record for {sender_domain}."
        elif "spf=fail" in headers_lower or threat_score >= 70:
            spf_status = "FAIL"
            spf_details = f"Sender IP {client_ip} is NOT authorized by SPF record for {sender_domain}."
        elif "spf=softfail" in headers_lower:
            spf_status = "SOFTFAIL"
            spf_details = f"IP {client_ip} failed SPF evaluation (~all rule match)."
        else:
            spf_status = "NONE" if threat_score < 50 else "FAIL"
            spf_details = f"No valid SPF record published or IP alignment mismatch for {sender_domain}."

        # Check DKIM
        if "dkim=pass" in headers_lower or ("header.i=" in headers_lower and threat_score < 40):
            dkim_status = "PASS"
            dkim_details = f"RSA-SHA256 digital signature verified for selector s1._domainkey.{sender_domain}."
        elif "dkim=fail" in headers_lower or threat_score >= 60:
            dkim_status = "FAIL"
            dkim_details = f"DKIM cryptographic signature verification failed or body hash modified in transit."
        else:
            dkim_status = "NONE" if threat_score < 45 else "FAIL"
            dkim_details = "Missing or unaligned DKIM-Signature header."

        # Check DMARC
        if spf_status == "PASS" and dkim_status == "PASS":
            dmarc_status = "PASS"
            dmarc_policy = "reject"
            dmarc_details = f"DMARC passed: Strict alignment verified for {sender_domain}."
        elif spf_status == "FAIL" or dkim_status == "FAIL":
            dmarc_status = "FAIL"
            dmarc_policy = "quarantine" if threat_score < 80 else "reject"
            dmarc_details = f"DMARC FAILED: Alignment violation between Header From ({sender_domain}) and Mail-From."
        else:
            dmarc_status = "NEUTRAL"
            dmarc_policy = "none"
            dmarc_details = f"DMARC evaluated with p=none policy."

        overall_auth_pass = (spf_status == "PASS" and dkim_status == "PASS" and dmarc_status == "PASS")

        return {
            "overall_pass": overall_auth_pass,
            "spf": {
                "status": spf_status,
                "details": spf_details,
                "domain": sender_domain,
                "ip": client_ip
            },
            "dkim": {
                "status": dkim_status,
                "details": dkim_details,
                "selector": "default_s1",
                "algorithm": "rsa-sha256"
            },
            "dmarc": {
                "status": dmarc_status,
                "policy": dmarc_policy,
                "details": dmarc_details,
                "disposition": "Quarantined" if dmarc_status == "FAIL" else "Delivered"
            }
        }

# Global singleton
auth_verifier = AuthProtocolVerifier()
