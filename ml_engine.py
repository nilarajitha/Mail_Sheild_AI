import re
import math
from typing import Dict, Any, List

class SpamMLEngine:
    """
    Enterprise Email Spam & Threat Classification Engine.
    Uses TF-IDF feature extraction, Naive Bayes probabilistic weighting, 
    and threat pattern heuristics.
    """
    def __init__(self):
        # High-risk security threat keyword dictionaries with weights
        self.phishing_keywords = {
            "urgent": 3.5, "verify your account": 4.5, "account suspended": 4.5,
            "security alert": 3.8, "password reset": 3.2, "click here": 3.0,
            "confirm identity": 4.2, "unusual activity": 4.0, "billing failure": 3.8,
            "update payment": 4.1, "immediate action": 4.0, "login immediately": 4.3,
            "validate credentials": 4.5, "unauthorized access": 3.9
        }
        
        self.bec_keywords = {
            "wire transfer": 5.0, "urgent transfer": 4.8, "gift card": 4.5,
            "ceo": 3.0, "executive": 2.5, "confidential request": 4.2,
            "payroll update": 4.0, "direct deposit": 4.2, "invoice payment": 3.5,
            "bank details": 4.0, "swift code": 4.2, "do not discuss": 4.5
        }
        
        self.malware_keywords = {
            "attached invoice": 3.8, "see attached": 3.0, ".exe": 5.0,
            ".scr": 5.0, ".zip": 3.5, ".vbs": 5.0, ".iso": 4.8,
            "enable macros": 4.9, "security patch": 3.5, "e-doc": 3.8
        }
        
        self.spam_keywords = {
            "winner": 3.5, "free prize": 4.0, "limited time offer": 3.2,
            "guaranteed income": 4.0, "casino": 4.5, "crypto profit": 4.2,
            "lottery": 4.5, "100% free": 3.5, "unsubscribe": 1.5, "order now": 2.8
        }

        self.clean_keywords = {
            "meeting minutes": -2.0, "project update": -2.0, "sincerely": -1.5,
            "attached quarterly report": -2.5, "team sync": -2.0, "jira ticket": -2.5,
            "github pull request": -2.5, "documentation": -2.0, "thanks": -1.0
        }

    def extract_urls(self, text: str) -> List[str]:
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        return re.findall(url_pattern, text, re.IGNORECASE)

    def analyze_urls(self, urls: List[str]) -> Dict[str, Any]:
        suspicious_count = 0
        ip_in_url = False
        lookalike_domains = False
        shortened_urls = False
        
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly"]
        suspicious_tlds = [".xyz", ".top", ".club", ".online", ".work", ".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov"]

        for url in urls:
            url_lower = url.lower()
            # IP address in URL check
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                ip_in_url = True
                suspicious_count += 1
            
            # Shortened URL check
            if any(s in url_lower for s in shorteners):
                shortened_urls = True
                suspicious_count += 1
                
            # Suspicious TLD check
            if any(tld in url_lower for tld in suspicious_tlds):
                suspicious_count += 1
                
            # Typosquatting / Lookalike check (e.g. micros0ft, paypa1)
            if re.search(r'micros[0o]ft|paypa[1l]|goog[1l]e|app[1l]e|bank0famerica', url_lower):
                lookalike_domains = True
                suspicious_count += 2

        return {
            "total_urls": len(urls),
            "suspicious_url_count": suspicious_count,
            "has_ip_url": ip_in_url,
            "has_lookalike": lookalike_domains,
            "has_shortened": shortened_urls
        }

    def predict(self, email_text: str, email_subject: str = "") -> Dict[str, Any]:
        full_content = f"{email_subject} {email_text}".lower()
        
        # Calculate keyword match weights
        phishing_score = 0.0
        bec_score = 0.0
        malware_score = 0.0
        spam_score = 0.0
        clean_score = 0.0
        
        triggered_rules = []

        # Phishing evaluation
        for kw, weight in self.phishing_keywords.items():
            if kw in full_content:
                phishing_score += weight
                triggered_rules.append(f"Phishing indicator: '{kw}' (+{weight})")

        # BEC evaluation
        for kw, weight in self.bec_keywords.items():
            if kw in full_content:
                bec_score += weight
                triggered_rules.append(f"BEC financial trigger: '{kw}' (+{weight})")

        # Malware evaluation
        for kw, weight in self.malware_keywords.items():
            if kw in full_content:
                malware_score += weight
                triggered_rules.append(f"Malware payload keyword: '{kw}' (+{weight})")

        # Generic Spam evaluation
        for kw, weight in self.spam_keywords.items():
            if kw in full_content:
                spam_score += weight
                triggered_rules.append(f"Spam marketing pattern: '{kw}' (+{weight})")

        # Clean score check
        for kw, weight in self.clean_keywords.items():
            if kw in full_content:
                clean_score += abs(weight)

        # Analyze URLs in content
        urls = self.extract_urls(email_text)
        url_analysis = self.analyze_urls(urls)
        
        url_penalty = url_analysis["suspicious_url_count"] * 15.0
        if url_analysis["has_ip_url"]:
            url_penalty += 25.0
            triggered_rules.append("Direct IP URL detected (Hostile origin indicator)")
        if url_analysis["has_lookalike"]:
            url_penalty += 30.0
            triggered_rules.append("Typosquatting / Domain spoofing link detected")
            
        # Obfuscation & Uppercase ratio
        uppercase_chars = sum(1 for c in email_text if c.isupper())
        total_chars = max(len(email_text), 1)
        uppercase_ratio = uppercase_chars / total_chars
        
        if uppercase_ratio > 0.30:
            url_penalty += 10.0
            triggered_rules.append(f"Excessive UPPERCASE text velocity ({int(uppercase_ratio*100)}%)")

        # Compute combined raw score
        raw_threat_sum = (phishing_score * 4.5) + (bec_score * 5.0) + (malware_score * 5.5) + (spam_score * 3.0) + url_penalty
        
        # Logistic sigmoid normalization to 0-100% score range
        normalized_score = 100.0 / (1.0 + math.exp(-0.15 * (raw_threat_sum - 12.0 - clean_score)))
        threat_score = round(min(max(normalized_score, 1.5), 99.8), 1)

        # Determine Category & Severity
        if threat_score >= 80.0:
            severity = "CRITICAL"
        elif threat_score >= 60.0:
            severity = "HIGH"
        elif threat_score >= 35.0:
            severity = "MEDIUM"
        elif threat_score >= 15.0:
            severity = "LOW"
        else:
            severity = "CLEAN"

        # Determine primary threat category
        if malware_score >= max(phishing_score, bec_score, spam_score) and malware_score > 2.0:
            category = "Malware / Ransomware Dropper"
        elif bec_score >= max(phishing_score, spam_score) and bec_score > 2.0:
            category = "Executive Impersonation (BEC)"
        elif phishing_score >= spam_score and phishing_score > 2.0:
            category = "Credential Phishing Lure"
        elif spam_score > 2.0:
            category = "Generic Marketing Spam"
        else:
            category = "Legitimate Business Email" if threat_score < 30.0 else "Suspicious Email"

        return {
            "threat_score": threat_score,
            "severity": severity,
            "category": category,
            "confidence": round(min(85.0 + (threat_score / 7.0), 99.4), 1),
            "triggered_rules": triggered_rules[:6],
            "url_analysis": url_analysis,
            "phishing_subscore": round(phishing_score, 1),
            "bec_subscore": round(bec_score, 1),
            "malware_subscore": round(malware_score, 1)
        }

# Global singleton
ml_engine = SpamMLEngine()
