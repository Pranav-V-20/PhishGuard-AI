"""
backend_app.py
FastAPI backend for PhishGuard POC.
Provides:
- POST /api/analyze  -> analyze a submitted URL/text
- GET  /api/submissions -> list submissions
- POST /api/feedback -> record user feedback (mark safe/malicious)
- GET  /api/userscores -> leaderboard of user phishing awareness
Uses SQLite (file: phishguard.db).
"""

import re
import json
import datetime
import sqlite3
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request, Form
from pydantic import BaseModel
import uvicorn
import tldextract
import requests

# ---------- DB helpers ----------
DB_FILE = "phishguard.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        source TEXT,
        message TEXT,
        urls TEXT,
        verdict TEXT,
        score REAL,
        reasons TEXT,
        feedback TEXT,
        created_at TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        display_name TEXT,
        total_reports INTEGER DEFAULT 0,
        correct_reports INTEGER DEFAULT 0,
        false_positives INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

def db_execute(query, params=()):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(query, params)
    conn.commit()
    lastrowid = c.lastrowid
    conn.close()
    return lastrowid

def db_query(query, params=()):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# initialize DB on startup
init_db()

# ---------- FastAPI ----------
app = FastAPI(title="PhishGuard Backend (POC)")

# ---------- Models ----------
class SubmissionIn(BaseModel):
    user_id: Optional[str] = "anonymous"
    source: Optional[str] = "dashboard"
    message: Optional[str] = ""
    urls: Optional[List[str]] = []

# ---------- Analysis logic (heuristic/rule-based) ----------
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "verify your", "login", "password", "update", "confirm",
    "bank", "account", "click", "suspend", "limited", "secure", "authentication"
]

POPULAR_BRANDS = ["google", "microsoft", "amazon", "paypal", "apple", "facebook", "aws", "netflix"]

def extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    url_pattern = r"https?://[^\s'\"\)\(<>]+"
    return list(set(re.findall(url_pattern, text)))

def is_https(url: str) -> bool:
    return url.lower().startswith("https://")

def has_ip_hostname(url: str) -> bool:
    try:
        host = re.sub(r"^https?://", "", url).split("/")[0]
        return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", host))
    except:
        return False

def domain_length(url: str) -> int:
    ext = tldextract.extract(url)
    return len(ext.domain or "")

def simple_typosquat_check(url: str) -> Optional[str]:
    ext = tldextract.extract(url)
    domain = ext.domain or ""
    for b in POPULAR_BRANDS:
        if b in domain and domain != b:
            # if brand name appears as substring but domain different -> suspicious
            return f"possible typosquat/brand mimicry ({b})"
    return None

def try_whois_age_days(domain:str) -> Optional[int]:
    # intentionally light and safe: we won't call WHOIS to avoid delays for POC.
    # Return None (placeholder). Later: integrate python-whois or WHOIS API.
    return None

def check_ssl_certificate(domain:str) -> Optional[bool]:
    # Lightweight: try HEAD request to https url and check TLS handshake success.
    try:
        r = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        return r.status_code < 500
    except Exception:
        return False

def analyze_payload(message: str, urls: List[str]):
    """
    Returns: (verdict: str, score: float, reasons: list[str])
    Score: 0.0 - 1.0 (higher -> more malicious)
    """
    reasons = []
    score = 0.0

    # keyword heuristics
    text_lower = (message or "").lower()
    kw_count = sum(1 for k in SUSPICIOUS_KEYWORDS if k in text_lower)
    if kw_count:
        reasons.append(f"suspicious keywords ({kw_count})")
        score += min(0.2 * kw_count, 0.4)

    # URL analysis
    if urls:
        for url in urls:
            if not is_https(url):
                reasons.append("no HTTPS (insecure link)")
                score += 0.20
            if has_ip_hostname(url):
                reasons.append("URL uses raw IP address")
                score += 0.20
            dd = domain_length(url)
            if dd and dd > 25:
                reasons.append("long domain name")
                score += 0.05
            ts = simple_typosquat_check(url)
            if ts:
                reasons.append(ts)
                score += 0.15
            # redirect count heuristic
            try:
                r = requests.get(url, timeout=6, allow_redirects=True)
                redirects = len(r.history)
                if redirects >= 3:
                    reasons.append(f"{redirects} redirects (suspicious)")
                    score += 0.10
            except Exception:
                reasons.append("could not fetch URL (network or blocked)")
                score += 0.05
            # quick SSL check
            ext = tldextract.extract(url)
            domain = ext.registered_domain or ext.domain
            ssl_ok = check_ssl_certificate(domain)
            if ssl_ok is False:
                reasons.append("ssl certificate check failed")
                score += 0.15

    # normalize score to 0-1
    if score > 1.0:
        score = 1.0

    # thresholds to verdict
    if score >= 0.6:
        verdict = "malicious"
    elif score >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return verdict, round(score, 2), reasons

# ---------- API Endpoints ----------
@app.post("/api/analyze")
async def analyze(sub: SubmissionIn):
    urls = sub.urls or extract_urls_from_text(sub.message or "")
    verdict, score, reasons = analyze_payload(sub.message or "", urls)

    created_at = datetime.datetime.utcnow().isoformat()

    # store submission
    db_execute("""INSERT INTO submissions
        (user_id, source, message, urls, verdict, score, reasons, feedback, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (sub.user_id, sub.source, sub.message, json.dumps(urls), verdict, score, json.dumps(reasons), None, created_at))

    # ensure user exists
    user = db_query("SELECT * FROM users WHERE user_id = ?", (sub.user_id,))
    if not user:
        db_execute("INSERT OR REPLACE INTO users (user_id, display_name, total_reports, correct_reports, false_positives) VALUES (?, ?, ?, ?, ?)",
                   (sub.user_id, sub.user_id, 1, 0, 0))
    else:
        db_execute("UPDATE users SET total_reports = total_reports + 1 WHERE user_id = ?", (sub.user_id,))

    return {"verdict": verdict, "score": score, "reasons": reasons, "urls": urls, "analyzed_at": created_at}

@app.get("/api/submissions")
async def get_submissions(limit:int = 200):
    rows = db_query("SELECT * FROM submissions ORDER BY id DESC LIMIT ?", (limit,))
    # parse JSON fields
    for r in rows:
        if r.get("urls"):
            r["urls"] = json.loads(r["urls"])
        if r.get("reasons"):
            r["reasons"] = json.loads(r["reasons"])
    return {"count": len(rows), "submissions": rows}

@app.post("/api/feedback")
async def feedback(submission_id: int = Form(...), feedback: str = Form(...)):
    # feedback: safe | malicious
    rows = db_query("SELECT * FROM submissions WHERE id = ?", (submission_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="submission not found")
    sub = rows[0]
    # update submission feedback
    db_execute("UPDATE submissions SET feedback = ? WHERE id = ?", (feedback, submission_id))

    # update user stats
    user_id = sub["user_id"]
    if feedback == "malicious" and sub["verdict"] == "malicious":
        # correct report
        db_execute("UPDATE users SET correct_reports = correct_reports + 1 WHERE user_id = ?", (user_id,))
    elif feedback == "safe" and sub["verdict"] == "safe":
        db_execute("UPDATE users SET correct_reports = correct_reports + 1 WHERE user_id = ?", (user_id,))
    else:
        # false positive or missed
        if feedback == "safe" and sub["verdict"] != "safe":
            db_execute("UPDATE users SET false_positives = false_positives + 1 WHERE user_id = ?", (user_id,))
        # We do not track missed maliciouss in this simple POC.

    return {"status": "ok", "submission_id": submission_id, "feedback": feedback}

@app.get("/api/userscores")
async def userscores():
    rows = db_query("SELECT user_id, display_name, total_reports, correct_reports, false_positives FROM users ORDER BY (correct_reports) DESC, total_reports DESC")
    # compute a simple awareness score 0-100
    for r in rows:
        total = r["total_reports"] or 0
        correct = r["correct_reports"] or 0
        fp = r["false_positives"] or 0
        score = 0
        if total > 0:
            score = max(0, int((correct / total) * 100) - fp * 2)
        r["awareness_score"] = score
    return {"count": len(rows), "users": rows}

# run server
if __name__ == "__main__":
    uvicorn.run("backend_app:app", host="0.0.0.0", port=8000, reload=True)
