import uuid
import time
import os
import json
import re
from typing import Dict, Any, Optional

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Import MailShield AI Security Modules
from ml_engine import ml_engine
from intelligence import domain_ip_intel
from geolocation import geo_resolver
from auth_verifier import auth_verifier
from attack_tracer import attack_tracer
from threat_correlation import threat_correlator
from investigation_engine import investigation_engine
from blockchain_verifier import blockchain_verifier
from database import db
from report_generator import report_generator

app = FastAPI(title="MailShield AI Backend", version="1.0.0")

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Helper function to process analysis
def process_email_analysis(email_text: str, email_subject: str = "", sender: str = "", sender_ip: str = "") -> Dict[str, Any]:
    scan_id = f"MS-{uuid.uuid4().hex[:8].upper()}"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # Extract sender address if present in headers/text
    if not sender and "from:" in email_text.lower():
        for line in email_text.splitlines():
            if line.lower().startswith("from:"):
                sender = line.split(":", 1)[1].strip()
                break
    if not sender:
        sender = "security-alert@suspicious-bank-login.xyz"

    # Extract subject if not provided
    if not email_subject and "subject:" in email_text.lower():
        for line in email_text.splitlines():
            if line.lower().startswith("subject:"):
                email_subject = line.split(":", 1)[1].strip()
                break
    if not email_subject:
        email_subject = "Urgent Security Verification Required: Account Access Suspended"

    # Extract IP address accurately from headers & body
    if not sender_ip:
        # Check Received: headers and X-Originating-IP
        ip_candidates = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', email_text)
        public_ips = [ip for ip in ip_candidates if not ip.startswith(("10.", "192.168.", "127.", "0.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.31."))]
        if public_ips:
            sender_ip = public_ips[0]

    if not sender_ip:
        sender_ip = "185.220.101.5"

    sender_domain = domain_ip_intel.extract_domain(sender)

    # 1. ML Threat Classification
    ml_res = ml_engine.predict(email_text, email_subject)
    threat_score = ml_res["threat_score"]
    severity = ml_res["severity"]
    category = ml_res["category"]

    # 2. Domain & IP Intelligence
    domain_res = domain_ip_intel.analyze_domain(sender_domain)
    ip_res = domain_ip_intel.analyze_ip(sender_ip)

    # 3. Geolocation Mapping
    geo_res = geo_resolver.resolve(sender_ip)

    # 4. Authentication Verification (SPF/DKIM/DMARC)
    auth_res = auth_verifier.verify(email_text, sender_domain, sender_ip, threat_score)

    # 5. Attack Hop Path Trace
    attack_trace = attack_tracer.trace(sender_ip, sender_domain, threat_score)

    # 6. Threat Rationale & Remediation
    investigation = investigation_engine.generate_investigation(
        threat_score, category, ml_res, auth_res, domain_res, ip_res
    )

    # 7. Blockchain Evidence Verification
    blockchain_proof = blockchain_verifier.anchor_evidence(email_text[:300], email_text, sender, threat_score)

    # 8. Threat Correlation against Past History Database
    past_scans = db.get_all_scans()
    current_meta = {
        "sender_domain": sender_domain,
        "sender_ip": sender_ip,
        "subject": email_subject,
        "threat_score": threat_score
    }
    correlation = threat_correlator.correlate(current_meta, past_scans)

    report_payload = {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "subject": email_subject,
        "sender": sender,
        "email_text": email_text,
        "sender_domain": sender_domain,
        "sender_ip": sender_ip,
        "threat_score": threat_score,
        "severity": severity,
        "category": category,
        "confidence": ml_res["confidence"],
        "ml_analysis": ml_res,
        "domain_intelligence": domain_res,
        "ip_intelligence": ip_res,
        "geo_location": geo_res,
        "auth_verifier": auth_res,
        "attack_trace": attack_trace,
        "investigation": investigation,
        "blockchain_proof": blockchain_proof,
        "threat_correlation": correlation
    }

    # Save to SQLite Database
    db.save_scan(scan_id, report_payload)

    return report_payload


# API Routes
@app.post("/api/analyze/text")
async def analyze_text(payload: Dict[str, Any]):
    email_text = payload.get("email_text", "").strip()
    if not email_text:
        raise HTTPException(status_code=400, detail="Email content or header text is required.")
    
    email_subject = payload.get("subject", "")
    sender = payload.get("sender", "")
    sender_ip = payload.get("sender_ip", "")

    return process_email_analysis(email_text, email_subject, sender, sender_ip)


@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    content_bytes = await file.read()
    try:
        email_text = content_bytes.decode("utf-8", errors="ignore")
    except Exception:
        email_text = str(content_bytes)

    if not email_text.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    filename = file.filename or "uploaded_email.eml"
    return process_email_analysis(email_text, email_subject=f"File Scan: {filename}")


@app.get("/api/history")
async def get_history():
    return db.get_all_scans()


@app.get("/api/history/{scan_id}")
async def get_history_detail(scan_id: str):
    report = db.get_scan_by_id(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan report not found.")
    return report


@app.delete("/api/history/{scan_id}")
async def delete_history_item(scan_id: str):
    db.delete_scan(scan_id)
    return {"message": f"Scan record {scan_id} deleted successfully."}


@app.delete("/api/history")
async def clear_history():
    db.clear_all()
    return {"message": "All scan history cleared."}


@app.get("/api/report/download/{scan_id}")
async def download_report(scan_id: str):
    report = db.get_scan_by_id(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    
    json_str = report_generator.generate_json_report(report)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=MailShield_Audit_{scan_id}.json"}
    )


@app.get("/api/samples")
async def get_sample_emails():
    return [
        {
            "id": "phishing",
            "title": "🎣 Credential Phishing Lure (Bank Fraud)",
            "subject": "URGENT: Your Account Has Been Suspended - Action Required",
            "sender": "security-alert@micros0ft-login-auth.xyz",
            "sender_ip": "185.220.101.5",
            "text": """Received: from mta-01.micros0ft-login-auth.xyz ([185.220.101.5]) by mx.corporate-gateway.com; Sun, 06 Sep 2026 18:30:00 +0000
From: "Security Operations Center" <security-alert@micros0ft-login-auth.xyz>
To: target-user@company.com
Subject: URGENT: Your Account Has Been Suspended - Action Required

Dear Customer,

We detected unusual login activity on your account from an unrecognized IP address in Moscow, Russia (185.220.101.5).
For your protection, your access has been temporarily suspended.

To restore your access immediately and validate your identity, click the link below:
http://185.220.101.5/verify-credentials?user=target-user

Failure to confirm within 24 hours will result in permanent account deletion.

Sincerely,
Account Security Team"""
        },
        {
            "id": "bec",
            "title": "💼 Executive Impersonation (CEO Wire Fraud)",
            "subject": "CONFIDENTIAL: Urgent Wire Transfer Request",
            "sender": "ceo.johnson@company-executive-corp.top",
            "sender_ip": "194.26.29.112",
            "text": """From: "Robert Johnson (CEO)" <ceo.johnson@company-executive-corp.top>
To: finance-director@company.com
Subject: CONFIDENTIAL: Urgent Wire Transfer Request

Hi Mark,

I am currently in an urgent meeting with our acquisition partners and cannot take phone calls.
We need to process an immediate wire transfer of $84,500 for the confidential acquisition deposit today.

Please send the payment to the following bank details:
Bank: Global Commerce Bank
SWIFT: GCBNUS33
Account Number: 98401840291

Do not discuss this with anyone on the team until the public announcement tomorrow. Send me the wire confirmation receipt immediately.

Thanks,
Robert Johnson
Chief Executive Officer"""
        },
        {
            "id": "malware",
            "title": "☣️ Ransomware / Malware Dropper",
            "subject": "Overdue Invoice #94812 - See Attached ZIP",
            "sender": "billing@global-invoice-pay.club",
            "sender_ip": "91.240.118.42",
            "text": """From: "Accounts Receivable" <billing@global-invoice-pay.club>
To: recipient@company.com
Subject: Overdue Invoice #94812 - See Attached ZIP

Dear Partner,

Your account is currently 45 days past due for Invoice #94812. 
Please download and review the attached invoice details in the compressed file attached to this email.

Attached: Invoice_94812_Details.zip.exe (Contains macros)

Please enable macros upon opening the e-document to confirm payment status.

Regards,
Billing Dept"""
        },
        {
            "id": "clean",
            "title": "🟢 Legitimate Corporate Business Email",
            "subject": "Weekly Team Sync & Sprint Planning Notes",
            "sender": "sarah.connor@company.com",
            "sender_ip": "104.26.12.89",
            "text": """From: "Sarah Connor" <sarah.connor@company.com>
To: engineering-team@company.com
Subject: Weekly Team Sync & Sprint Planning Notes

Hi Everyone,

Thanks for joining the sprint planning meeting this morning.
Attached are the meeting minutes and project updates for this week's sprint.

Key Highlights:
- API endpoint refactoring is completed.
- Documentation for the new security gateway is published.

Let me know if you have any questions before our standup tomorrow.

Best regards,
Sarah Connor
Lead Product Manager"""
        }
    ]


# Serve Static files and root SPA dashboard
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>MailShield AI Backend Server Running</h1>"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
