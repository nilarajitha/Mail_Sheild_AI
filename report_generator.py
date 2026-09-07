import json
from typing import Dict, Any

class ReportGenerator:
    """
    Forensic Audit Report Generator for downloadable JSON and printable formats.
    """
    def generate_json_report(self, report_data: Dict[str, Any]) -> str:
        return json.dumps(report_data, indent=2)

    def generate_html_report(self, report_data: Dict[str, Any]) -> str:
        scan_id = report_data.get("scan_id", "N/A")
        timestamp = report_data.get("timestamp", "N/A")
        subject = report_data.get("subject", "N/A")
        sender = report_data.get("sender", "N/A")
        score = report_data.get("threat_score", 0)
        severity = report_data.get("severity", "CLEAN")
        category = report_data.get("category", "N/A")
        
        blockchain = report_data.get("blockchain_proof", {})

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>MailShield AI Forensic Audit Report - {scan_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; line-height: 1.6; }}
        .header {{ border-bottom: 2px solid #8b5cf6; padding-bottom: 20px; margin-bottom: 30px; }}
        .title {{ font-size: 28px; font-weight: bold; color: #8b5cf6; }}
        .score-box {{ font-size: 42px; font-weight: 800; color: {"#ef4444" if score >= 60 else "#10b981"}; margin: 20px 0; }}
        .section-card {{ background: #1e293b; padding: 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #334155; }}
        .label {{ font-weight: bold; color: #94a3b8; width: 180px; display: inline-block; }}
        .hash {{ font-family: monospace; background: #0f172a; padding: 6px 12px; border-radius: 6px; font-size: 13px; color: #38bdf8; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">🛡️ MailShield AI - Forensic Threat Audit Report</div>
        <div>Report ID: {scan_id} | Generated At: {timestamp}</div>
    </div>

    <div class="section-card">
        <h2>Executive Summary</h2>
        <div><span class="label">Email Subject:</span> {subject}</div>
        <div><span class="label">Sender:</span> {sender}</div>
        <div><span class="label">Threat Category:</span> {category}</div>
        <div class="score-box">Threat Score: {score}% ({severity})</div>
    </div>

    <div class="section-card">
        <h2>Blockchain Evidence Proof</h2>
        <div><span class="label">Network:</span> {blockchain.get("blockchain_network")}</div>
        <div><span class="label">TxHash:</span> <span class="hash">{blockchain.get("transaction_hash")}</span></div>
        <div><span class="label">Block Height:</span> #{blockchain.get("block_height")}</div>
        <div><span class="label">SHA-256 Proof:</span> <span class="hash">{blockchain.get("email_body_sha256")}</span></div>
    </div>

    <div class="section-card">
        <h2>Investigation Rationale</h2>
        <ul>
            {"".join(f"<li>{item}</li>" for item in report_data.get("investigation", {}).get("why_threat_occurred", []))}
        </ul>
    </div>
</body>
</html>"""
        return html

# Global singleton
report_generator = ReportGenerator()
