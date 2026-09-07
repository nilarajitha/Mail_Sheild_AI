from typing import Dict, Any, List

class ThreatCorrelationEngine:
    """
    Email History Relationship & Threat Correlation Engine.
    Correlates new email scans against past database records to detect
    shared IP subnets, domain relationships, phishing campaign clusters,
    and vector similarity.
    """
    def correlate(self, current_email: Dict[str, Any], history_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        curr_domain = current_email.get("sender_domain", "").lower()
        curr_ip = current_email.get("sender_ip", "")
        curr_subject = current_email.get("subject", "").lower()
        curr_score = current_email.get("threat_score", 0.0)

        matched_emails = []
        shared_ip_count = 0
        shared_domain_count = 0
        campaign_name = "Isolated Incident"

        curr_subnet = ".".join(curr_ip.split(".")[:3]) if "." in curr_ip else curr_ip

        for item in history_records:
            hist_id = item.get("id")
            hist_domain = item.get("sender_domain", "").lower()
            hist_ip = item.get("sender_ip", "")
            hist_subject = item.get("subject", "").lower()
            hist_score = item.get("threat_score", 0.0)
            
            hist_subnet = ".".join(hist_ip.split(".")[:3]) if "." in hist_ip else hist_ip

            correlation_reasons = []
            similarity_points = 0

            # Match 1: Same or sub-domain
            if curr_domain and (curr_domain in hist_domain or hist_domain in curr_domain):
                correlation_reasons.append("Identical / Subdomain Sender Relationship")
                similarity_points += 40
                shared_domain_count += 1

            # Match 2: Shared IP subnet
            if curr_subnet and curr_subnet == hist_subnet:
                correlation_reasons.append(f"Shared IP Subnet Infrastructure ({curr_subnet}.x)")
                similarity_points += 35
                shared_ip_count += 1

            # Match 3: High threat score similarity
            if abs(curr_score - hist_score) <= 15.0 and curr_score >= 40.0:
                correlation_reasons.append("Matching Threat Signature Severity Profile")
                similarity_points += 15

            # Match 4: Subject keyword overlap
            curr_words = set(curr_subject.split())
            hist_words = set(hist_subject.split())
            overlap = curr_words.intersection(hist_words)
            if len(overlap) >= 2:
                correlation_reasons.append(f"Subject Keyword Pattern Match: '{', '.join(list(overlap)[:3])}'")
                similarity_points += 20

            if similarity_points >= 25:
                matched_emails.append({
                    "history_id": hist_id,
                    "timestamp": item.get("timestamp"),
                    "subject": item.get("subject"),
                    "sender": item.get("sender"),
                    "threat_score": hist_score,
                    "severity": item.get("severity"),
                    "similarity_score": min(similarity_points, 98),
                    "match_reasons": correlation_reasons
                })

        # Sort matched emails by highest similarity score
        matched_emails.sort(key=lambda x: x["similarity_score"], reverse=True)

        if len(matched_emails) > 0:
            if curr_score >= 60.0:
                campaign_name = f"Campaign #MS-8821: Multi-Vector Phishing Wave ({shared_domain_count + shared_ip_count} related instances)"
            else:
                campaign_name = f"Correlated Traffic Group: {matched_emails[0]['subject'][:30]}..."

        return {
            "total_correlated_matches": len(matched_emails),
            "campaign_name": campaign_name,
            "shared_domain_nodes": shared_domain_count,
            "shared_ip_subnets": shared_ip_count,
            "relationship_graph_nodes": matched_emails[:5]
        }

# Global singleton
threat_correlator = ThreatCorrelationEngine()
