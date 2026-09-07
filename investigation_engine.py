from typing import Dict, Any, List

class InvestigationEngine:
    """
    Generates Threat Rationale ("Why Threat Occurred") and
    Actionable Remediation Playbooks ("How to Resolve").
    """
    def generate_investigation(self, threat_score: float, category: str, ml_res: Dict[str, Any], auth_res: Dict[str, Any], domain_res: Dict[str, Any], ip_res: Dict[str, Any]) -> Dict[str, Any]:
        why_threat_occurred = []
        how_to_resolve = []

        # 1. Rationale Generation
        if threat_score >= 40.0:
            why_threat_occurred.append(f"ML Classifier detected suspicious intent pattern categorized as '{category}'.")
        
        for rule in ml_res.get("triggered_rules", []):
            why_threat_occurred.append(rule)

        if not auth_res["spf"]["status"] == "PASS":
            why_threat_occurred.append(f"SPF Policy Mismatch: {auth_res['spf']['details']}")
        if not auth_res["dkim"]["status"] == "PASS":
            why_threat_occurred.append(f"DKIM Cryptographic Failure: {auth_res['dkim']['details']}")
        if not auth_res["dmarc"]["status"] == "PASS":
            why_threat_occurred.append(f"DMARC Protocol Alignment Failure: {auth_res['dmarc']['details']}")

        if domain_res.get("typosquatting_detected"):
            why_threat_occurred.append(f"Brand Impersonation Detected: Sender domain spoofing {domain_res['spoofed_brand']}.")
        if domain_res.get("has_suspicious_tld"):
            why_threat_occurred.append(f"High-Risk TLD detected: Domain extension '{domain_res['domain_name']}' is frequently used in phishing campaigns.")

        if ip_res.get("is_blacklisted"):
            why_threat_occurred.append(f"Sender IP ({ip_res['ip_address']}) is blacklisted on: {', '.join(ip_res['blacklists_hit'])}.")

        if len(why_threat_occurred) == 0:
            why_threat_occurred.append("No security anomalies detected. Sender IP, domain, and authentication protocols are fully verified.")

        # 2. Remediation Generation ("How to Resolve")
        if threat_score >= 70.0:
            how_to_resolve.append("🔴 IMMEDIATELY QUARANTINE EMAIL: Do not click any embedded links or open attachments.")
            how_to_resolve.append(f"🛑 BLOCK SENDER IP & DOMAIN: Add {ip_res['ip_address']} and {domain_res['domain_name']} to firewall and gateway blocklists.")
            how_to_resolve.append("🛡️ REVOKE SESSION TOKENS: If credentials were entered on any link from this email, reset user passwords and revoke active MFA sessions.")
            how_to_resolve.append("📢 REPORT THREAT: Submit headers to SOC security team and report domain abuse to registrar.")
        elif threat_score >= 40.0:
            how_to_resolve.append("🟡 WARN RECIPIENT: Place prominent banner warning recipient of unverified sender identity.")
            how_to_resolve.append("🔍 INSPECT LINKS: Verify destination domain before entering credentials or approving financial requests.")
            how_to_resolve.append("⚙️ ENFORCE DMARC: Update sender domain DNS records to publish p=quarantine or p=reject policies.")
        else:
            how_to_resolve.append("🟢 ALLOW DELIVERY: Message meets all security authentication standards.")
            how_to_resolve.append("💡 STANDARD PRACTICE: Maintain routine employee phishing awareness training.")

        return {
            "why_threat_occurred": why_threat_occurred,
            "how_to_resolve": how_to_resolve,
            "investigation_summary": f"MailShield AI analyzed email against {len(why_threat_occurred)} security threat vectors. Overall threat rating is {threat_score}% ({category})."
        }

# Global singleton
investigation_engine = InvestigationEngine()
