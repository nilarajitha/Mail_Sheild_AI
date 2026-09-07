import sqlite3
import json
import os
import time
from typing import List, Dict, Any, Optional

# Check if running in Vercel serverless environment
if os.environ.get("VERCEL"):
    DB_FILE = "/tmp/mailshield.db"
else:
    DB_FILE = os.path.join(os.path.dirname(__file__), "mailshield.db")

class ScanHistoryDB:
    def __init__(self):
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        sender TEXT NOT NULL,
                        sender_domain TEXT NOT NULL,
                        sender_ip TEXT NOT NULL,
                        threat_score REAL NOT NULL,
                        severity TEXT NOT NULL,
                        category TEXT NOT NULL,
                        country TEXT NOT NULL,
                        spf_status TEXT NOT NULL,
                        dkim_status TEXT NOT NULL,
                        dmarc_status TEXT NOT NULL,
                        report_json TEXT NOT NULL
                    );
                """)
                conn.commit()
        except Exception as e:
            print("DB init exception:", e)

    def save_scan(self, scan_id: str, report_data: Dict[str, Any]):
        timestamp = report_data.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
        subject = report_data.get("subject", "No Subject")
        sender = report_data.get("sender", "unknown@sender.com")
        sender_domain = report_data.get("sender_domain", "unknown.com")
        sender_ip = report_data.get("sender_ip", "0.0.0.0")
        threat_score = report_data.get("threat_score", 0.0)
        severity = report_data.get("severity", "CLEAN")
        category = report_data.get("category", "Uncategorized")
        country = report_data.get("geo_location", {}).get("country", "Unknown")
        
        auth = report_data.get("auth_verifier", {})
        spf_status = auth.get("spf", {}).get("status", "NONE")
        dkim_status = auth.get("dkim", {}).get("status", "NONE")
        dmarc_status = auth.get("dmarc", {}).get("status", "NONE")

        report_json_str = json.dumps(report_data)

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scan_history (
                    id, timestamp, subject, sender, sender_domain, sender_ip,
                    threat_score, severity, category, country,
                    spf_status, dkim_status, dmarc_status, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                scan_id, timestamp, subject, sender, sender_domain, sender_ip,
                threat_score, severity, category, country,
                spf_status, dkim_status, dmarc_status, report_json_str
            ))
            conn.commit()

    def get_all_scans(self) -> List[Dict[str, Any]]:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT id, timestamp, subject, sender, sender_domain, sender_ip, threat_score, severity, category, country, spf_status, dkim_status, dmarc_status FROM scan_history ORDER BY ROWID DESC LIMIT 50;")
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception:
            return []

    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT report_json FROM scan_history WHERE id = ?;", (scan_id,))
                row = cursor.fetchone()
                if row:
                    return json.loads(row["report_json"])
                return None
        except Exception:
            return None

    def delete_scan(self, scan_id: str):
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM scan_history WHERE id = ?;", (scan_id,))
                conn.commit()
        except Exception:
            pass

    def clear_all(self):
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM scan_history;")
                conn.commit()
        except Exception:
            pass

# Global singleton
db = ScanHistoryDB()
