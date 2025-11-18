#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from typing import Optional
import os

engine = create_engine("postgresql://postgres@localhost/email_gateway")
app = FastAPI(title="Email Gateway API", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Templates and static files
os.makedirs("/opt/email_gateway/templates", exist_ok=True)
os.makedirs("/opt/email_gateway/static", exist_ok=True)
templates = Jinja2Templates(directory="/opt/email_gateway/templates")
app.mount("/static", StaticFiles(directory="/opt/email_gateway/static"), name="static")

class DomainCreate(BaseModel):
    domain_name: str
    backend_server: str
    backend_port: int = 25
    spam_threshold: float = 5.0

class DomainUpdate(BaseModel):
    spam_threshold: Optional[float] = None
    backend_server: Optional[str] = None
    backend_port: Optional[int] = None

class RuleCreate(BaseModel):
    rule_name: str
    rule_type: str  # blacklist or whitelist
    scope_type: str  # common, domain, mail_address
    scope_value: Optional[str] = None
    filter_field: str  # subject, mail_address, sender_domain, body, ip
    match_type: str  # match, include, start, end, regex
    match_value: str
    priority: int = 100

@app.get("/", response_class=HTMLResponse)
async def web_ui(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api")
def root():
    return {"message": "Email Gateway API v2.0", "features": ["Blacklist/Whitelist", "Spam Filtering", "SPF/DKIM/DMARC"]}

# DOMAINS
@app.get("/api/domains")
def list_domains():
    with engine.connect() as conn:
        result = conn.execute(text("SELECT id, domain_name, backend_server, backend_port, is_active, spam_threshold FROM domains ORDER BY id"))
        return {"domains": [{"id": r[0], "domain_name": r[1], "backend_server": r[2], "backend_port": r[3], "is_active": r[4], "spam_threshold": r[5] if r[5] is not None else 5.0} for r in result]}

@app.post("/api/domains")
def add_domain(domain: DomainCreate):
    with engine.connect() as conn:
        try:
            result = conn.execute(text("INSERT INTO domains (domain_name, backend_server, backend_port, spam_threshold) VALUES (:a, :b, :c, :d) RETURNING id, domain_name, backend_server, backend_port, spam_threshold"),
                {"a": domain.domain_name.lower(), "b": domain.backend_server, "c": domain.backend_port, "d": domain.spam_threshold})
            conn.commit()
            r = result.fetchone()
            return {"message": "Added", "domain": {"id": r[0], "domain_name": r[1], "backend_server": r[2], "backend_port": r[3], "spam_threshold": r[4]}}
        except Exception as e:
            conn.rollback()
            if "duplicate" in str(e).lower():
                raise HTTPException(400, f"Domain exists")
            raise HTTPException(500, str(e))

@app.patch("/api/domains/{domain_id}")
def update_domain(domain_id: int, domain: DomainUpdate):
    with engine.connect() as conn:
        result = conn.execute(text("SELECT id FROM domains WHERE id = :i"), {"i": domain_id})
        if not result.fetchone():
            raise HTTPException(404, "Domain not found")

        updates = []
        params = {"id": domain_id}

        if domain.spam_threshold is not None:
            updates.append("spam_threshold = :spam_threshold")
            params["spam_threshold"] = domain.spam_threshold

        if domain.backend_server is not None:
            updates.append("backend_server = :backend_server")
            params["backend_server"] = domain.backend_server

        if domain.backend_port is not None:
            updates.append("backend_port = :backend_port")
            params["backend_port"] = domain.backend_port

        if not updates:
            raise HTTPException(400, "No fields to update")

        query = f"UPDATE domains SET {', '.join(updates)} WHERE id = :id"
        conn.execute(text(query), params)
        conn.commit()

        return {"message": "Domain updated successfully"}

@app.delete("/api/domains/{domain_id}")
def delete_domain(domain_id: int):
    with engine.connect() as conn:
        result = conn.execute(text("SELECT domain_name FROM domains WHERE id = :i"), {"i": domain_id})
        row = result.fetchone()
        if not row:
            raise HTTPException(404, "Not found")
        conn.execute(text("DELETE FROM domains WHERE id = :i"), {"i": domain_id})
        conn.commit()
        return {"message": f"Deleted {row[0]}"}

# EMAILS
@app.get("/api/emails")
def list_emails(limit: int = 50, status: Optional[str] = None):
    with engine.connect() as conn:
        if status:
            query = text("""
                SELECT e.id, e.subject, e.from_address, e.to_address, e.sender_ip, e.status, e.block_reason,
                       e.spam_score, e.spam_result, e.matched_rule_id, e.received_at, d.domain_name
                FROM emails e
                LEFT JOIN domains d ON e.domain_id = d.id
                WHERE e.status = :s
                ORDER BY e.received_at DESC LIMIT :l
            """)
            result = conn.execute(query, {"s": status, "l": limit})
        else:
            query = text("""
                SELECT e.id, e.subject, e.from_address, e.to_address, e.sender_ip, e.status, e.block_reason,
                       e.spam_score, e.spam_result, e.matched_rule_id, e.received_at, d.domain_name
                FROM emails e
                LEFT JOIN domains d ON e.domain_id = d.id
                ORDER BY e.received_at DESC LIMIT :l
            """)
            result = conn.execute(query, {"l": limit})

        emails = []
        for r in result:
            email_id, subject, from_addr, to_addr, sender_ip, status, block_reason, spam_score, spam_result, matched_rule_id, received_at, domain = r

            # Determine filter_log
            filter_log = "None"
            if matched_rule_id:
                # Check if whitelist or blacklist
                rule_result = conn.execute(text("SELECT rule_type FROM filter_rules WHERE id = :i"), {"i": matched_rule_id}).fetchone()
                if rule_result:
                    filter_log = "Whitelist" if rule_result[0] == 'whitelist' else "Blacklist"
            elif spam_result == 'spam':
                filter_log = "Spam"
            elif spam_result == 'safe':
                filter_log = "Safe"

            # Determine delivery status
            delivery_status = "Delivered" if status == 'delivered' else "Undelivered"

            emails.append({
                "id": email_id,
                "subject": subject,
                "from": from_addr,
                "to": to_addr,
                "sender_ip": sender_ip,
                "status": status,
                "delivery_status": delivery_status,
                "filter_log": filter_log,
                "block_reason": block_reason,
                "spam_score": float(spam_score) if spam_score else 0.0,
                "received_at": str(received_at),
                "domain": domain
            })

        return {"emails": emails}

@app.get("/api/emails/{email_id}")
def get_email(email_id: int):
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT e.id, e.subject, e.from_address, e.to_address, e.sender_ip, e.body, e.status, e.block_reason,
                   e.spam_score, e.spam_result, e.spf_result, e.dkim_result, e.dmarc_result, e.matched_rule_id,
                   e.received_at, d.domain_name
            FROM emails e
            LEFT JOIN domains d ON e.domain_id = d.id
            WHERE e.id = :i
        """), {"i": email_id})
        r = result.fetchone()
        if not r:
            raise HTTPException(404, "Email not found")

        email_id, subject, from_addr, to_addr, sender_ip, body, status, block_reason, spam_score, spam_result, spf_result, dkim_result, dmarc_result, matched_rule_id, received_at, domain = r

        # Determine filter_log
        filter_log = "None"
        if matched_rule_id:
            rule_result = conn.execute(text("SELECT rule_type FROM filter_rules WHERE id = :i"), {"i": matched_rule_id}).fetchone()
            if rule_result:
                filter_log = "Whitelist" if rule_result[0] == 'whitelist' else "Blacklist"
        elif spam_result == 'spam':
            filter_log = "Spam"
        elif spam_result == 'safe':
            filter_log = "Safe"

        delivery_status = "Delivered" if status == 'delivered' else "Undelivered"

        return {
            "id": email_id,
            "subject": subject,
            "from": from_addr,
            "to": to_addr,
            "sender_ip": sender_ip,
            "body": body,
            "status": status,
            "delivery_status": delivery_status,
            "filter_log": filter_log,
            "block_reason": block_reason,
            "spam_score": float(spam_score) if spam_score else 0.0,
            "spam_result": spam_result,
            "spf_result": spf_result,
            "dkim_result": dkim_result,
            "dmarc_result": dmarc_result,
            "received_at": str(received_at),
            "domain": domain
        }

# FILTER RULES
@app.get("/api/rules")
def list_rules(scope_type: Optional[str] = None, rule_type: Optional[str] = None):
    with engine.connect() as conn:
        query = "SELECT id, rule_name, rule_type, scope_type, scope_value, filter_field, match_type, match_value, is_active, priority, created_at FROM filter_rules WHERE 1=1"
        params = {}

        if scope_type:
            query += " AND scope_type = :st"
            params["st"] = scope_type
        if rule_type:
            query += " AND rule_type = :rt"
            params["rt"] = rule_type

        query += " ORDER BY priority DESC, id ASC"
        result = conn.execute(text(query), params)

        return {"rules": [{"id": r[0], "rule_name": r[1], "rule_type": r[2], "scope_type": r[3], "scope_value": r[4], "filter_field": r[5], "match_type": r[6], "match_value": r[7], "is_active": r[8], "priority": r[9], "created_at": str(r[10])} for r in result]}

@app.post("/api/rules")
def add_rule(rule: RuleCreate):
    with engine.connect() as conn:
        try:
            if rule.scope_type in ['domain', 'mail_address'] and not rule.scope_value:
                raise HTTPException(400, f"scope_value required for scope_type '{rule.scope_type}'")

            valid_match_types = {
                'subject': ['match', 'include', 'start', 'end', 'regex'],
                'mail_address': ['match', 'include', 'start', 'end', 'regex'],
                'sender_domain': ['match', 'include', 'start', 'end', 'regex'],
                'body': ['include', 'regex'],
                'ip': ['match', 'regex']
            }

            if rule.match_type not in valid_match_types.get(rule.filter_field, []):
                raise HTTPException(400, f"Invalid match_type '{rule.match_type}' for filter_field '{rule.filter_field}'")

            result = conn.execute(text("""
                INSERT INTO filter_rules (rule_name, rule_type, scope_type, scope_value, filter_field, match_type, match_value, priority)
                VALUES (:a, :b, :c, :d, :e, :f, :g, :h)
                RETURNING id, rule_name, rule_type, scope_type, scope_value, filter_field, match_type, match_value, priority
            """), {
                "a": rule.rule_name,
                "b": rule.rule_type,
                "c": rule.scope_type,
                "d": rule.scope_value,
                "e": rule.filter_field,
                "f": rule.match_type,
                "g": rule.match_value,
                "h": rule.priority
            })
            conn.commit()
            r = result.fetchone()
            return {"message": "Rule created", "rule": {"id": r[0], "rule_name": r[1], "rule_type": r[2], "scope_type": r[3], "scope_value": r[4], "filter_field": r[5], "match_type": r[6], "match_value": r[7], "priority": r[8]}}
        except Exception as e:
            conn.rollback()
            raise HTTPException(500, str(e))

@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: int):
    with engine.connect() as conn:
        result = conn.execute(text("SELECT rule_name FROM filter_rules WHERE id = :i"), {"i": rule_id})
        row = result.fetchone()
        if not row:
            raise HTTPException(404, "Rule not found")
        conn.execute(text("DELETE FROM filter_rules WHERE id = :i"), {"i": rule_id})
        conn.commit()
        return {"message": f"Deleted rule: {row[0]}"}

@app.patch("/api/rules/{rule_id}/toggle")
def toggle_rule(rule_id: int):
    with engine.connect() as conn:
        result = conn.execute(text("SELECT is_active FROM filter_rules WHERE id = :i"), {"i": rule_id})
        row = result.fetchone()
        if not row:
            raise HTTPException(404, "Rule not found")
        new_status = not row[0]
        conn.execute(text("UPDATE filter_rules SET is_active = :s WHERE id = :i"), {"s": new_status, "i": rule_id})
        conn.commit()
        return {"message": f"Rule {'enabled' if new_status else 'disabled'}", "is_active": new_status}

# STATS
@app.get("/api/stats")
def get_stats():
    with engine.connect() as conn:
        total_emails = conn.execute(text("SELECT COUNT(*) FROM emails")).fetchone()[0]
        blocked_emails = conn.execute(text("SELECT COUNT(*) FROM emails WHERE status = 'blocked'")).fetchone()[0]
        spam_emails = conn.execute(text("SELECT COUNT(*) FROM emails WHERE status = 'spam'")).fetchone()[0]
        delivered_emails = conn.execute(text("SELECT COUNT(*) FROM emails WHERE status = 'delivered'")).fetchone()[0]
        total_rules = conn.execute(text("SELECT COUNT(*) FROM filter_rules WHERE is_active = true")).fetchone()[0]
        total_domains = conn.execute(text("SELECT COUNT(*) FROM domains WHERE is_active = true")).fetchone()[0]

        return {
            "total_emails": total_emails,
            "blocked_emails": blocked_emails,
            "spam_emails": spam_emails,
            "delivered_emails": delivered_emails,
            "total_rules": total_rules,
            "total_domains": total_domains
        }

# ============================================
# MALWARE SCANNER ENDPOINTS
# ============================================

@app.get("/api/emails/{email_id}/attachments")
def get_email_attachments(email_id: int):
    """Get all attachments for a specific email"""
    with engine.connect() as conn:
        attachments = conn.execute(text("""
            SELECT
                id, filename, file_size, file_hash, mime_type,
                clamav_scanned, clamav_result, clamav_virus_name,
                virustotal_scanned, virustotal_malicious, virustotal_total,
                virustotal_permalink, virustotal_threat_names,
                is_malware, scan_status, created_at
            FROM email_attachments
            WHERE email_id = :email_id
            ORDER BY id ASC
        """), {"email_id": email_id}).fetchall()

        return {
            "email_id": email_id,
            "attachments": [
                {
                    "id": att[0],
                    "filename": att[1],
                    "file_size": att[2],
                    "file_hash": att[3],
                    "mime_type": att[4],
                    "clamav": {
                        "scanned": att[5],
                        "result": att[6],
                        "virus_name": att[7]
                    },
                    "virustotal": {
                        "scanned": att[8],
                        "malicious": att[9],
                        "total": att[10],
                        "permalink": att[11],
                        "threat_names": att[12]
                    },
                    "is_malware": att[13],
                    "scan_status": att[14],
                    "scanned_at": str(att[15])
                }
                for att in attachments
            ]
        }

@app.get("/api/malware/stats")
def get_malware_stats():
    """Get malware detection statistics"""
    with engine.connect() as conn:
        total_attachments = conn.execute(text("SELECT COUNT(*) FROM email_attachments")).fetchone()[0]
        malware_detected = conn.execute(text("SELECT COUNT(*) FROM email_attachments WHERE is_malware = true")).fetchone()[0]
        clamav_scanned = conn.execute(text("SELECT COUNT(*) FROM email_attachments WHERE clamav_scanned = true")).fetchone()[0]
        vt_scanned = conn.execute(text("SELECT COUNT(*) FROM email_attachments WHERE virustotal_scanned = true")).fetchone()[0]

        # Emails with malware
        emails_with_malware = conn.execute(text("SELECT COUNT(*) FROM emails WHERE malware_detected = true")).fetchone()[0]

        # Recent malware (last 7 days)
        recent_malware = conn.execute(text("""
            SELECT filename, clamav_virus_name, virustotal_malicious, created_at
            FROM email_attachments
            WHERE is_malware = true
            AND created_at > NOW() - INTERVAL '7 days'
            ORDER BY created_at DESC
            LIMIT 10
        """)).fetchall()

        return {
            "total_attachments": total_attachments,
            "malware_detected": malware_detected,
            "clean_attachments": total_attachments - malware_detected,
            "clamav_scanned": clamav_scanned,
            "virustotal_scanned": vt_scanned,
            "emails_blocked_by_malware": emails_with_malware,
            "recent_malware": [
                {
                    "filename": m[0],
                    "threat_name": m[1] or "Multiple threats",
                    "vt_detections": m[2],
                    "detected_at": str(m[3])
                }
                for m in recent_malware
            ]
        }

if __name__ == "__main__":
    import uvicorn
    print("Starting API on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
