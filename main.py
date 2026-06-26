"""
Prompt Firewall — Production Backend v5.0
==========================================
New in v5:
  • PII Masking Pipeline (Pro/Business) — strips credit cards, IDs, emails, phones
  • Usage alert emails — 80% warning + 100% limit notifications
  • Overage tracking — $0.50 per 1,000 extra requests
  • Overage toggle per customer
  • Cron-style background usage checker
  • Crisp support context endpoint
  • Plan cancellation endpoint
  • DB: alert flags, overage settings, organization_id on pro/business
"""

import os, uuid, sqlite3, json, time, secrets, re
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Optional

import bcrypt, httpx
from fastapi import FastAPI, HTTPException, Security, Request, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel

# ── Config ─────────────────────────────────────────────────────────────────
ADMIN_KEY      = os.getenv("FIREWALL_API_KEY",  "dev-secret-change-me")
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN",    "*")
DB_PATH        = os.getenv("DB_PATH",           "firewall.db")
RESEND_API_KEY = os.getenv("RESEND_API_KEY",    "")
FROM_EMAIL     = os.getenv("FROM_EMAIL",        "info@invenova.tech")
BASE_URL       = os.getenv("BASE_URL",          "https://taupe-dusk-70c154.netlify.app")

OVERAGE_RATE   = 0.50   # $ per 1,000 extra requests
PLAN_LIMITS    = {"starter": 10000,  "pro": 100000,  "business": -1}
PLAN_MAX_KEYS  = {"starter": 1,      "pro": 3,        "business": -1}

# ── Rate limiter ───────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["30/minute"])

# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(title="Prompt Firewall 🛡️", version="5.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Friendly error responses ───────────────────────────────────────────────
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={
        "error": "Something went wrong on our end.",
        "message": "Our team has been notified. Please try again in a moment or contact info@invenova.tech if this persists.",
        "status": "error"
    })

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={
        "error": "We could not understand your request.",
        "message": "Please check that your request body is valid JSON and all required fields are included.",
        "status": "error"
    })

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=404, content={
        "error": "This endpoint does not exist.",
        "message": "Check the URL and try again. View all available endpoints at /docs",
        "status": "error"
    })

@app.exception_handler(403)
async def forbidden_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=403, content={
        "error": "Access denied.",
        "message": "Your API key is invalid, missing, or has been revoked. Check your key and try again, or contact info@invenova.tech",
        "status": "error"
    })

@app.exception_handler(429)
async def rate_limit_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=429, content={
        "error": "Too many requests.",
        "message": "You have sent too many requests in a short time. Please wait a moment before trying again.",
        "status": "error"
    })
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_methods=["GET","POST","DELETE","PATCH","PUT"],
    allow_headers=["*"],
)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── DB ─────────────────────────────────────────────────────────────────────
def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id                        TEXT PRIMARY KEY,
                email                     TEXT NOT NULL UNIQUE,
                password                  TEXT,
                organization_id           TEXT,
                plan                      TEXT NOT NULL DEFAULT 'starter',
                status                    TEXT NOT NULL DEFAULT 'active',
                shadow_mode               INTEGER NOT NULL DEFAULT 0,
                overage_enabled           INTEGER NOT NULL DEFAULT 0,
                current_month_requests    INTEGER NOT NULL DEFAULT 0,
                has_80_alert              INTEGER NOT NULL DEFAULT 0,
                has_100_alert             INTEGER NOT NULL DEFAULT 0,
                billing_reset_date        TEXT,
                created_at                TEXT NOT NULL,
                paddle_id                 TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id          TEXT PRIMARY KEY,
                customer_id TEXT NOT NULL,
                api_key     TEXT UNIQUE NOT NULL,
                label       TEXT NOT NULL DEFAULT 'Default',
                status      TEXT NOT NULL DEFAULT 'active',
                created_at  TEXT NOT NULL,
                FOREIGN KEY(customer_id) REFERENCES customers(id)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id        TEXT PRIMARY KEY,
                customer_id     TEXT,
                api_key_id      TEXT,
                timestamp       TEXT NOT NULL,
                status          TEXT NOT NULL,
                reason          TEXT NOT NULL,
                message_preview TEXT NOT NULL,
                latency_ms      INTEGER DEFAULT 0,
                user_id         TEXT DEFAULT NULL,
                target_model    TEXT DEFAULT NULL,
                false_positive  INTEGER DEFAULT 0,
                pii_masked      INTEGER DEFAULT 0
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS reset_tokens (
                token       TEXT PRIMARY KEY,
                customer_id TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                used        INTEGER DEFAULT 0
            )
        """)

@contextmanager
def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()

init_db()

# ── Auth helpers ───────────────────────────────────────────────────────────
def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()

def verify_password(p: str, h: str) -> bool:
    return bcrypt.checkpw(p.encode(), h.encode())

def get_customer_by_key(key: str):
    with get_db() as con:
        return con.execute("""
            SELECT c.*, k.id as key_id, k.label as key_label, k.api_key
            FROM api_keys k JOIN customers c ON k.customer_id=c.id
            WHERE k.api_key=? AND k.status='active' AND c.status='active'
        """, (key,)).fetchone()

def require_admin(key: str = Security(api_key_header)):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key.")
    return key

# ── PII Masking Pipeline (Pro/Business only) ───────────────────────────────
PII_PATTERNS = [
    # Financial
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'),                                  "[REDACTED_FINANCIAL]"),  # credit card
    (re.compile(r'\b\d{6,11}\b(?=.*bank|.*account|.*acc)', re.IGNORECASE),   "[REDACTED_FINANCIAL]"),  # bank account
    (re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b'),                         "[REDACTED_FINANCIAL]"),  # IBAN
    # Identity
    (re.compile(r'\b\d{13}\b'),                                               "[REDACTED_ID]"),         # SA ID number
    (re.compile(r'\b[A-Z]{1,2}\d{7}\b'),                                      "[REDACTED_ID]"),         # passport
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),                                    "[REDACTED_ID]"),         # SSN
    # Contact
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),   "[REDACTED_CONTACT]"),    # email
    (re.compile(r'\b(?:\+27|0)[\s-]?\d{2}[\s-]?\d{3}[\s-]?\d{4}\b'),        "[REDACTED_CONTACT]"),    # SA phone
    (re.compile(r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), "[REDACTED_CONTACT]"),    # US phone
]

def mask_pii(text: str) -> tuple[str, bool]:
    """Run PII masking pipeline. Returns (masked_text, was_modified)."""
    original = text
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text, text != original

# ── Blacklist ──────────────────────────────────────────────────────────────
MAX_LENGTH = 500
BLACKLIST = [
    "ignore previous instructions","ignore your instructions","ignore all instructions",
    "ignore the instruction","ignore all rules","ignore your rules","ignore the rules",
    "disregard all previous","disregard the instructions","forget everything above",
    "forget your instructions","your new instructions are","give me the account",
    "give me account details","give me the password","give me access",
    "you are now in developer mode","developer mode","unrestricted mode",
    "you are now dan","from now on you are","your true self","new persona","jailbreak",
    "do anything now","act as if you have no","act as if you have no rules",
    "you have no rules","no restrictions","without restrictions",
    "pretend you have no restrictions","pretend you are an ai","act as an unrestricted",
    "act like you have no","roleplay as","simulate a","pretend to be evil",
    "pretend you are an unrestricted","disregard your training","forget your guidelines",
    "override your programming","reveal your system prompt","access admin","admin panel",
    "delete database","drop table","rm -rf","sudo","bypass","ignore your boss",
    "tell me a secret code","' or '1'='1","' or 1=1","'; drop table","'; select ",
    "union select","insert into","delete from","exec(","execute(","xp_cmdshell",
    "information_schema","sleep(","1=1--","<script","javascript:","onerror=","onload=",
    "alert(","document.cookie","window.location","eval(","; ls","; cat ","| cat ",
    "&& cat","/etc/passwd","/etc/shadow","wget http","curl http","nc -e","base64 -d",
    "${jndi:","jndi:ldap","jndi:rmi","jndi:dns","<!entity","system(","file:///",
    "*)(&","(|(mail=","../../../","..%2f..%2f","%2e%2e%2f",
]

import base64 as _b64
import re as _re

def _decode(text: str) -> str:
    original = text
    lower = text.lower()
    versions = [lower]
    versions.append(_re.sub(r'\b([A-Za-z])-(?=[A-Za-z]\b)', r'\1', lower))
    try:
        for m in _re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', original):
            try:
                d = _b64.b64decode(m).decode('utf-8', errors='ignore').lower()
                if d.strip(): versions.append(d.strip())
            except: pass
    except: pass
    try:
        versions.append(_re.sub(r'%([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1),16)), lower))
    except: pass
    versions.append(lower.translate(str.maketrans('013456789@$','oieasgbpgas')))
    return '\n'.join(versions)

def analyze_prompt(message: str, max_length: int = MAX_LENGTH):
    if not message.strip():
        return "BLOCKED", "Empty message rejected."
    if len(message) > max_length:
        return "BLOCKED", f"Message too long ({len(message)} chars). Max: {max_length}."
    for version in _decode(message).split('\n'):
        for phrase in BLACKLIST:
            if phrase in version:
                return "BLOCKED", f'Blacklisted phrase detected: "{phrase}"'
    return "PASSED", "No threats detected. Safe to forward to AI."

# ── Email helpers ──────────────────────────────────────────────────────────
async def send_email(to: str, subject: str, html: str):
    if not RESEND_API_KEY:
        print(f"[EMAIL SKIP] To:{to} Subject:{subject}")
        return
    async with httpx.AsyncClient() as client:
        await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={"from": FROM_EMAIL, "to": to, "subject": subject, "html": html}
        )

async def send_api_key_email(email: str, api_key: str, plan: str, label: str = "Default"):
    html = f"""<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px;background:#080c14;color:#f1f5f9;border-radius:10px;">
      <h1 style="color:#f59e0b;font-size:24px;margin-bottom:8px;">🛡️ Welcome to Prompt Firewall</h1>
      <p style="color:#94a3b8;">Your <strong style="color:#f1f5f9;">{plan.title()}</strong> plan is now active.</p>
      <div style="background:#0d1220;border:1px solid #1e293b;border-radius:8px;padding:20px;margin:24px 0;">
        <p style="color:#475569;font-size:12px;margin-bottom:4px;font-family:monospace;">KEY LABEL: {label}</p>
        <p style="color:#475569;font-size:12px;margin-bottom:8px;font-family:monospace;">YOUR API KEY</p>
        <p style="font-family:monospace;font-size:16px;color:#f59e0b;word-break:break-all;">{api_key}</p>
      </div>
      <p style="color:#94a3b8;">Integration (5 lines):</p>
      <pre style="background:#0a0f1a;border:1px solid #1e293b;border-radius:6px;padding:14px;font-size:12px;color:#86efac;">headers={{"X-API-Key": "{api_key}"}}</pre>
      <p style="color:#94a3b8;margin-top:14px;">Endpoint:</p>
      <pre style="background:#0a0f1a;border:1px solid #1e293b;border-radius:6px;padding:14px;font-size:12px;color:#60a5fa;">https://prompt-firewall-production.up.railway.app/analyze</pre>
      <a href="{BASE_URL}/dashboard.html" style="display:inline-block;margin-top:16px;background:#f59e0b;color:#000;font-weight:700;padding:10px 20px;border-radius:6px;text-decoration:none;">Open Dashboard →</a>
      <p style="color:#475569;font-size:13px;margin-top:28px;">Questions? <a href="mailto:info@invenova.tech" style="color:#f59e0b;">info@invenova.tech</a></p>
    </div>"""
    await send_email(to, "🛡️ Your Prompt Firewall API Key", html)

async def send_reset_email(email: str, token: str):
    url = f"{BASE_URL}/dashboard.html?reset={token}"
    html = f"""<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px;background:#080c14;color:#f1f5f9;border-radius:10px;">
      <h1 style="color:#f59e0b;font-size:24px;margin-bottom:8px;">🔐 Reset your password</h1>
      <p style="color:#94a3b8;margin-bottom:24px;">Click below to reset your password. This link expires in 1 hour.</p>
      <a href="{url}" style="display:inline-block;background:#f59e0b;color:#000;font-weight:700;padding:12px 24px;border-radius:6px;text-decoration:none;">Reset Password →</a>
      <p style="color:#475569;font-size:13px;margin-top:28px;">Didn't request this? Ignore this email.<br/>Questions? <a href="mailto:info@invenova.tech" style="color:#f59e0b;">info@invenova.tech</a></p>
    </div>"""
    await send_email(email, "🔐 Reset your Prompt Firewall password", html)

async def send_usage_alert(email: str, plan: str, used: int, limit: int, pct: int, overage_enabled: bool):
    if pct >= 100:
        if overage_enabled:
            subject = "⚠️ You've hit 100% of your Prompt Firewall limit"
            body = f"You've used all {limit:,} requests on your {plan.title()} plan. Your firewall is <strong>staying live</strong> under overage pricing ($0.50 per 1,000 extra requests)."
        else:
            subject = "🚨 Your Prompt Firewall has paused"
            body = f"You've used all {limit:,} requests on your {plan.title()} plan. Your firewall is <strong>now paused</strong> until your billing cycle resets. Enable overages in your dashboard to stay live."
    else:
        subject = "⚠️ You've used 80% of your Prompt Firewall requests"
        body = f"You've used {used:,} of {limit:,} requests ({pct}%) on your {plan.title()} plan. Consider upgrading to avoid hitting your limit."

    html = f"""<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px;background:#080c14;color:#f1f5f9;border-radius:10px;">
      <h1 style="color:#f59e0b;font-size:22px;margin-bottom:12px;">{subject}</h1>
      <p style="color:#94a3b8;line-height:1.7;">{body}</p>
      <div style="background:#0d1220;border:1px solid #1e293b;border-radius:8px;padding:16px;margin:20px 0;">
        <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
          <span style="color:#475569;font-size:12px;">Usage</span>
          <span style="color:#f59e0b;font-family:monospace;font-size:12px;">{used:,} / {limit:,} ({pct}%)</span>
        </div>
      </div>
      <a href="{BASE_URL}/dashboard.html" style="display:inline-block;background:#f59e0b;color:#000;font-weight:700;padding:10px 20px;border-radius:6px;text-decoration:none;">View Dashboard →</a>
      <p style="color:#475569;font-size:13px;margin-top:28px;"><a href="mailto:info@invenova.tech" style="color:#f59e0b;">info@invenova.tech</a></p>
    </div>"""
    await send_email(email, subject, html)

async def send_upgrade_email(email: str, api_key: str, old_plan: str, new_plan: str):
    limits = {"starter":"10,000","pro":"100,000","business":"Unlimited"}
    html = f"""<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px;background:#080c14;color:#f1f5f9;border-radius:10px;">
      <h1 style="color:#f59e0b;font-size:24px;margin-bottom:8px;">🎉 Plan Upgraded to {new_plan.title()}!</h1>
      <p style="color:#94a3b8;">Your plan has been upgraded from <strong>{old_plan.title()}</strong> to <strong style="color:#f59e0b;">{new_plan.title()}</strong>.</p>
      <p style="color:#94a3b8;margin-top:10px;">New monthly limit: <strong style="color:#f1f5f9;">{limits.get(new_plan,'Unknown')} requests</strong></p>
      <p style="color:#94a3b8;margin-top:10px;">Your API key is unchanged — no code changes needed.</p>
      <p style="color:#475569;font-size:13px;margin-top:28px;"><a href="mailto:info@invenova.tech" style="color:#f59e0b;">info@invenova.tech</a></p>
    </div>"""
    await send_email(email, f"🎉 Upgraded to {new_plan.title()}", html)

async def send_cancellation_email(email: str, plan: str, end_date: str):
    html = f"""<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px;background:#080c14;color:#f1f5f9;border-radius:10px;">
      <h1 style="color:#f59e0b;font-size:24px;margin-bottom:8px;">📋 Subscription Cancelled</h1>
      <p style="color:#94a3b8;">Your <strong>{plan.title()}</strong> plan has been cancelled.</p>
      <p style="color:#94a3b8;margin-top:10px;">Your API key remains active until <strong style="color:#f1f5f9;">{end_date}</strong>.</p>
      <p style="color:#94a3b8;margin-top:10px;">We're sorry to see you go. If you change your mind, you can reactivate anytime from your dashboard.</p>
      <p style="color:#475569;font-size:13px;margin-top:28px;">Questions? <a href="mailto:info@invenova.tech" style="color:#f59e0b;">info@invenova.tech</a></p>
    </div>"""
    await send_email(email, "📋 Your Prompt Firewall subscription has been cancelled", html)

# ── Usage alert background checker ────────────────────────────────────────
async def check_usage_alerts():
    """Run after each request to check if alert emails need to be sent."""
    with get_db() as con:
        customers = con.execute("""
            SELECT * FROM customers
            WHERE status='active' AND plan != 'business'
            AND (has_80_alert=0 OR has_100_alert=0)
        """).fetchall()

    for c in customers:
        limit = PLAN_LIMITS.get(c["plan"], 10000)
        if limit <= 0: continue
        used = c["current_month_requests"]
        pct = int((used / limit) * 100)

        if pct >= 100 and not c["has_100_alert"]:
            await send_usage_alert(c["email"], c["plan"], used, limit, pct, bool(c["overage_enabled"]))
            with get_db() as con:
                con.execute("UPDATE customers SET has_100_alert=1 WHERE id=?", (c["id"],))

        elif pct >= 80 and not c["has_80_alert"]:
            await send_usage_alert(c["email"], c["plan"], used, limit, pct, bool(c["overage_enabled"]))
            with get_db() as con:
                con.execute("UPDATE customers SET has_80_alert=1 WHERE id=?", (c["id"],))

# ── Helper: create customer ────────────────────────────────────────────────
def _create_customer(con, email: str, plan: str, paddle_id: str = None):
    cid = str(uuid.uuid4())[:8]
    org_id = f"org_{uuid.uuid4().hex[:12]}" if plan in ("pro","business") else None
    now = datetime.utcnow().isoformat() + "Z"
    reset_date = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
    con.execute("""
        INSERT INTO customers
        (id,email,plan,status,shadow_mode,overage_enabled,current_month_requests,
         has_80_alert,has_100_alert,billing_reset_date,created_at,paddle_id,organization_id)
        VALUES (?,?,?,?,0,0,0,0,0,?,?,?,?)
    """, (cid, email, plan, "active", reset_date, now, paddle_id, org_id))
    api_key = "pf_" + uuid.uuid4().hex[:24]
    kid = str(uuid.uuid4())[:8]
    con.execute("""
        INSERT INTO api_keys (id,customer_id,api_key,label,status,created_at)
        VALUES (?,?,?,?,?,?)
    """, (kid, cid, api_key, "Default", "active", now))
    return cid, api_key, kid

# ── Models ─────────────────────────────────────────────────────────────────
class PromptRequest(BaseModel):
    message: str
    max_length: int = MAX_LENGTH
    user_id: Optional[str] = None
    target_model: Optional[str] = None

class LoginRequest(BaseModel):
    email: str
    password: Optional[str] = None
    api_key: Optional[str] = None

class SetPasswordRequest(BaseModel):
    email: str
    api_key: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    password: str

class GenerateKeyRequest(BaseModel):
    label: str = "New Key"

class OverageRequest(BaseModel):
    enabled: bool

# ── ANALYZE ────────────────────────────────────────────────────────────────
@app.post("/analyze", tags=["Firewall"])
@limiter.limit("30/minute")
async def analyze(request: Request, body: PromptRequest,
                  background_tasks: BackgroundTasks,
                  key: str = Security(api_key_header)):
    start = time.time()

    if key == ADMIN_KEY:
        customer = {"id":"admin","plan":"business","shadow_mode":0,"key_id":None,"key_label":"Admin","overage_enabled":1}
    else:
        customer = get_customer_by_key(key)
        if not customer:
            raise HTTPException(status_code=403, detail="Invalid or missing API key.")
        customer = dict(customer)

    # Check if paused (100% limit reached, overages disabled)
    if customer["plan"] != "business":
        limit = PLAN_LIMITS.get(customer["plan"], 10000)
        if limit > 0:
            with get_db() as con:
                c = con.execute("SELECT * FROM customers WHERE id=?", (customer["id"],)).fetchone()
            if c and c["current_month_requests"] >= limit and not c["overage_enabled"]:
                raise HTTPException(status_code=429, detail="Monthly limit reached. Your firewall is paused. Enable overages or upgrade your plan.")

    # PII masking (Pro/Business)
    message = body.message
    pii_masked = False
    if customer["plan"] in ("pro","business"):
        message, pii_masked = mask_pii(message)

    status, reason = analyze_prompt(message, max_length=body.max_length)
    latency_ms = int((time.time() - start) * 1000)

    real_status = status
    if customer.get("shadow_mode") and status == "BLOCKED":
        status = "PASSED (shadow mode)"

    event = {
        "event_id":       str(uuid.uuid4())[:8],
        "customer_id":    customer.get("id"),
        "api_key_id":     customer.get("key_id"),
        "timestamp":      datetime.utcnow().isoformat() + "Z",
        "status":         real_status,
        "reason":         reason,
        "message_preview": message[:80] + ("…" if len(message) > 80 else ""),
        "latency_ms":     latency_ms,
        "user_id":        body.user_id,
        "target_model":   body.target_model,
        "false_positive": 0,
        "pii_masked":     1 if pii_masked else 0,
    }

    with get_db() as con:
        con.execute("""
            INSERT INTO events VALUES
            (:event_id,:customer_id,:api_key_id,:timestamp,:status,:reason,
             :message_preview,:latency_ms,:user_id,:target_model,:false_positive,:pii_masked)
        """, event)
        if customer["id"] != "admin":
            con.execute("UPDATE customers SET current_month_requests=current_month_requests+1 WHERE id=?",
                        (customer["id"],))

    # Background: check if usage alerts need sending
    if customer["id"] != "admin":
        background_tasks.add_task(check_usage_alerts)

    return {
        "event_id":    event["event_id"],
        "timestamp":   event["timestamp"],
        "status":      status,
        "reason":      reason,
        "message_preview": event["message_preview"],
        "latency_ms":  latency_ms,
        "shadow_mode": bool(customer.get("shadow_mode")),
        "pii_masked":  pii_masked,
    }

# ── AUTH ───────────────────────────────────────────────────────────────────
@app.post("/auth/login", tags=["Auth"])
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest):
    email = body.email.lower().strip()
    with get_db() as con:
        customer = con.execute(
            "SELECT * FROM customers WHERE email=? AND status='active'", (email,)
        ).fetchone()
    if not customer:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    customer = dict(customer)

    if body.api_key and not body.password:
        with get_db() as con:
            key_row = con.execute(
                "SELECT * FROM api_keys WHERE customer_id=? AND api_key=? AND status='active'",
                (customer["id"], body.api_key)
            ).fetchone()
        if not key_row:
            raise HTTPException(status_code=401, detail="Invalid email or API key. Both must be correct.")
        return {"success":True, "customer":_safe(customer), "first_login": not customer["password"]}

    if body.password:
        if not customer["password"]:
            raise HTTPException(status_code=401, detail="No password set. Use your API key to log in first.")
        if not verify_password(body.password, customer["password"]):
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        return {"success":True, "customer":_safe(customer), "first_login":False}

    raise HTTPException(status_code=400, detail="Provide password or api_key.")

def _safe(c):
    return {k:v for k,v in c.items() if k != "password"}

@app.post("/auth/set-password", tags=["Auth"])
@limiter.limit("5/minute")
async def set_password(request: Request, body: SetPasswordRequest):
    email = body.email.lower().strip()
    with get_db() as con:
        customer = con.execute("SELECT * FROM customers WHERE email=? AND status='active'", (email,)).fetchone()
        if not customer:
            raise HTTPException(status_code=404, detail="Account not found.")
        key_row = con.execute(
            "SELECT * FROM api_keys WHERE customer_id=? AND api_key=? AND status='active'",
            (customer["id"], body.api_key)
        ).fetchone()
        if not key_row:
            raise HTTPException(status_code=401, detail="Invalid API key.")
        if len(body.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
        con.execute("UPDATE customers SET password=? WHERE id=?", (hash_password(body.password), customer["id"]))
    return {"success":True}

@app.post("/auth/forgot-password", tags=["Auth"])
@limiter.limit("3/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest):
    email = body.email.lower().strip()
    with get_db() as con:
        customer = con.execute("SELECT * FROM customers WHERE email=? AND status='active'", (email,)).fetchone()
    if customer:
        token = secrets.token_urlsafe(32)
        expires = (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z"
        with get_db() as con:
            con.execute("INSERT INTO reset_tokens VALUES (?,?,?,0)", (token, customer["id"], expires))
        await send_reset_email(email, token)
    return {"message":"If that email has an active account, a reset link has been sent."}

@app.post("/auth/reset-password", tags=["Auth"])
@limiter.limit("5/minute")
async def reset_password(request: Request, body: ResetPasswordRequest):
    with get_db() as con:
        t = con.execute("SELECT * FROM reset_tokens WHERE token=? AND used=0", (body.token,)).fetchone()
        if not t:
            raise HTTPException(status_code=400, detail="Invalid or expired reset link.")
        if datetime.utcnow().isoformat()+"Z" > t["expires_at"]:
            raise HTTPException(status_code=400, detail="Reset link expired. Please request a new one.")
        if len(body.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
        con.execute("UPDATE customers SET password=? WHERE id=?", (hash_password(body.password), t["customer_id"]))
        con.execute("UPDATE reset_tokens SET used=1 WHERE token=?", (body.token,))
    return {"success":True}

# ── CUSTOMER DASHBOARD DATA ────────────────────────────────────────────────
@app.get("/my-log", tags=["Customer"])
@limiter.limit("60/minute")
async def my_log(request: Request, email: str = Query(...),
                 limit: int = 50, key: str = Security(api_key_header)):
    email = email.lower().strip()
    with get_db() as con:
        customer = con.execute("SELECT * FROM customers WHERE email=? AND status='active'", (email,)).fetchone()
        if not customer:
            raise HTTPException(status_code=403, detail="Invalid credentials.")
        key_row = con.execute(
            "SELECT * FROM api_keys WHERE customer_id=? AND api_key=? AND status='active'",
            (customer["id"], key)
        ).fetchone()
        if not key_row:
            raise HTTPException(status_code=403, detail="Invalid credentials.")

        customer = dict(customer)
        keys = con.execute("SELECT * FROM api_keys WHERE customer_id=? ORDER BY created_at DESC", (customer["id"],)).fetchall()
        events = con.execute("""
            SELECT e.*, k.label as key_label FROM events e
            LEFT JOIN api_keys k ON e.api_key_id=k.id
            WHERE e.customer_id=? ORDER BY e.timestamp DESC LIMIT ?
        """, (customer["id"], limit)).fetchall()

        total   = con.execute("SELECT COUNT(*) FROM events WHERE customer_id=?", (customer["id"],)).fetchone()[0]
        blocked = con.execute("SELECT COUNT(*) FROM events WHERE customer_id=? AND status='BLOCKED'", (customer["id"],)).fetchone()[0]
        passed  = con.execute("SELECT COUNT(*) FROM events WHERE customer_id=? AND status='PASSED'", (customer["id"],)).fetchone()[0]
        avg_lat = con.execute("SELECT AVG(latency_ms) FROM events WHERE customer_id=?", (customer["id"],)).fetchone()[0]

        bk_cats = {
            "Prompt Injection":["ignore previous","developer mode","jailbreak","pretend","roleplay","disregard","forget your","override","bypass","dan"],
            "SQL Injection":   ["drop table","union select","insert into","delete from","exec(","sleep("],
            "XSS":             ["<script","javascript:","onerror=","alert(","document.cookie"],
            "Command Injection":["/etc/passwd","wget http","curl http","nc -e","; cat"],
            "Log4Shell / XXE": ["${jndi:","jndi:ldap","<!entity","file:///"],
            "Obfuscation":     ["base64","hex encoded","%2e%2e","../../../"],
        }
        breakdown = {k:0 for k in bk_cats}
        for row in con.execute("SELECT reason FROM events WHERE customer_id=? AND status='BLOCKED'", (customer["id"],)).fetchall():
            r = row["reason"].lower()
            matched = False
            for cat, kws in bk_cats.items():
                if any(kw in r for kw in kws):
                    breakdown[cat] += 1
                    matched = True
                    break
            if not matched:
                breakdown["Prompt Injection"] += 1

    plan_limit    = PLAN_LIMITS.get(customer["plan"], 10000)
    plan_max_keys = PLAN_MAX_KEYS.get(customer["plan"], 1)
    used          = customer["current_month_requests"]
    overage_qty   = max(0, used - plan_limit) if plan_limit > 0 else 0
    overage_cost  = round((overage_qty / 1000) * OVERAGE_RATE, 2) if overage_qty > 0 else 0.0

    return {
        "account": {
            "email":              customer["email"],
            "plan":               customer["plan"],
            "organization_id":    customer["organization_id"],
            "status":             customer["status"],
            "shadow_mode":        bool(customer["shadow_mode"]),
            "overage_enabled":    bool(customer["overage_enabled"]),
            "member_since":       customer["created_at"],
            "monthly_limit":      plan_limit,
            "requests_used":      used,
            "requests_remaining": max(0, plan_limit - used) if plan_limit > 0 else "unlimited",
            "max_keys":           plan_max_keys,
            "password_set":       bool(customer["password"]),
            "billing_reset_date": customer["billing_reset_date"],
            "overage_qty":        overage_qty,
            "overage_cost":       overage_cost,
            "overage_rate":       OVERAGE_RATE,
        },
        "stats": {
            "total_requests": total,
            "passed":         passed,
            "blocked":        blocked,
            "block_rate":     round((blocked/total*100),1) if total>0 else 0,
            "avg_latency_ms": round(avg_lat,1) if avg_lat else 0,
        },
        "attack_breakdown": breakdown,
        "api_keys": [
            {"id":k["id"],"label":k["label"],"api_key":k["api_key"][:6]+"••••••••••••••••","status":k["status"],"created_at":k["created_at"]}
            for k in keys
        ],
        "recent_events": [dict(e) for e in events],
    }

@app.post("/my-log/false-positive/{event_id}", tags=["Customer"])
async def mark_false_positive(event_id: str, key: str = Security(api_key_header)):
    customer = get_customer_by_key(key)
    if not customer:
        raise HTTPException(status_code=403, detail="Invalid API key.")
    with get_db() as con:
        con.execute("UPDATE events SET false_positive=1 WHERE event_id=? AND customer_id=?",
                    (event_id, customer["id"]))
    return {"success":True}

@app.patch("/my-settings/shadow-mode", tags=["Customer"])
async def toggle_shadow(enabled: bool, key: str = Security(api_key_header)):
    customer = get_customer_by_key(key)
    if not customer:
        raise HTTPException(status_code=403, detail="Invalid API key.")
    if customer["plan"] == "starter":
        raise HTTPException(status_code=403, detail="Shadow mode requires Pro or Business plan.")
    with get_db() as con:
        con.execute("UPDATE customers SET shadow_mode=? WHERE id=?", (1 if enabled else 0, customer["id"]))
    return {"success":True, "shadow_mode":enabled}

@app.patch("/my-settings/overage", tags=["Customer"])
async def toggle_overage(body: OverageRequest, key: str = Security(api_key_header)):
    customer = get_customer_by_key(key)
    if not customer:
        raise HTTPException(status_code=403, detail="Invalid API key.")
    if customer["plan"] == "business":
        raise HTTPException(status_code=400, detail="Business plan has unlimited requests.")
    with get_db() as con:
        con.execute("UPDATE customers SET overage_enabled=? WHERE id=?",
                    (1 if body.enabled else 0, customer["id"]))
    return {"success":True, "overage_enabled":body.enabled}

@app.post("/my-keys/generate", tags=["Customer"])
async def generate_key(body: GenerateKeyRequest, key: str = Security(api_key_header)):
    customer = get_customer_by_key(key)
    if not customer:
        raise HTTPException(status_code=403, detail="Invalid API key.")
    max_keys = PLAN_MAX_KEYS.get(customer["plan"], 1)
    with get_db() as con:
        existing = con.execute("SELECT COUNT(*) FROM api_keys WHERE customer_id=? AND status='active'",
                               (customer["id"],)).fetchone()[0]
        if max_keys > 0 and existing >= max_keys:
            raise HTTPException(status_code=403, detail=f"Your {customer['plan']} plan allows {max_keys} key(s).")
        new_key = "pf_" + uuid.uuid4().hex[:24]
        kid = str(uuid.uuid4())[:8]
        now = datetime.utcnow().isoformat()+"Z"
        con.execute("INSERT INTO api_keys (id,customer_id,api_key,label,status,created_at) VALUES (?,?,?,?,?,?)",
                    (kid, customer["id"], new_key, body.label, "active", now))
    return {"success":True, "api_key":new_key, "label":body.label}

@app.delete("/my-keys/{key_id}", tags=["Customer"])
async def revoke_key(key_id: str, key: str = Security(api_key_header)):
    customer = get_customer_by_key(key)
    if not customer:
        raise HTTPException(status_code=403, detail="Invalid API key.")
    with get_db() as con:
        r = con.execute("UPDATE api_keys SET status='revoked' WHERE id=? AND customer_id=?",
                        (key_id, customer["id"]))
        if r.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found.")
    return {"success":True}

@app.post("/my-account/cancel", tags=["Customer"])
async def cancel_plan(key: str = Security(api_key_header)):
    customer = get_customer_by_key(key)
    if not customer:
        raise HTTPException(status_code=403, detail="Invalid API key.")
    end_date = (datetime.utcnow() + timedelta(days=30)).strftime("%B %d, %Y")
    with get_db() as con:
        con.execute("UPDATE customers SET status='cancelling' WHERE id=?", (customer["id"],))
    await send_cancellation_email(customer["email"], customer["plan"], end_date)
    return {"success":True, "message":f"Subscription cancelled. Your access continues until {end_date}."}

@app.get("/my-support-context", tags=["Customer"])
async def support_context(email: str = Query(...), key: str = Security(api_key_header)):
    """Returns context data for Crisp chat widget."""
    email = email.lower().strip()
    with get_db() as con:
        customer = con.execute("SELECT * FROM customers WHERE email=? AND status='active'", (email,)).fetchone()
        if not customer:
            raise HTTPException(status_code=403, detail="Invalid credentials.")
        k = con.execute("SELECT * FROM api_keys WHERE customer_id=? AND api_key=? AND status='active'",
                        (customer["id"], key)).fetchone()
        if not k:
            raise HTTPException(status_code=403, detail="Invalid credentials.")
        total = con.execute("SELECT COUNT(*) FROM events WHERE customer_id=?", (customer["id"],)).fetchone()[0]
    return {
        "email":           customer["email"],
        "plan":            customer["plan"],
        "organization_id": customer["organization_id"],
        "member_since":    customer["created_at"],
        "total_requests":  total,
        "monthly_used":    customer["current_month_requests"],
    }

@app.post("/resend-key", tags=["Customer"])
@limiter.limit("3/minute")
async def resend_key(request: Request, email: str):
    email = email.lower().strip()
    with get_db() as con:
        customer = con.execute("SELECT * FROM customers WHERE email=? AND status='active'", (email,)).fetchone()
        if customer:
            k = con.execute("SELECT * FROM api_keys WHERE customer_id=? AND status='active' ORDER BY created_at LIMIT 1",
                            (customer["id"],)).fetchone()
            if k:
                await send_api_key_email(email, k["api_key"], customer["plan"], k["label"])
    return {"message":"If that email has an active account, the key has been resent."}

# ── ADMIN ──────────────────────────────────────────────────────────────────
@app.get("/log", tags=["Admin"])
@limiter.limit("60/minute")
async def get_log(request: Request, limit: int = 50, _key: str = Security(require_admin)):
    with get_db() as con:
        rows  = con.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        total = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return {"events":[dict(r) for r in rows], "total":total}

@app.get("/customers", tags=["Admin"])
async def list_customers(_key: str = Security(require_admin)):
    with get_db() as con:
        rows = con.execute("SELECT id,email,plan,status,created_at FROM customers ORDER BY created_at DESC").fetchall()
    return {"customers":[dict(r) for r in rows]}

@app.post("/customers/create", tags=["Admin"])
async def create_customer(email: str, plan: str = "starter", _key: str = Security(require_admin)):
    email = email.lower().strip()
    with get_db() as con:
        if con.execute("SELECT id FROM customers WHERE email=?", (email,)).fetchone():
            raise HTTPException(status_code=400, detail="Customer already exists.")
        cid, api_key, kid = _create_customer(con, email, plan)
    await send_api_key_email(email, api_key, plan)
    return {"message":"Created and email sent.", "api_key":api_key, "customer_id":cid}

# ── WEBHOOK ────────────────────────────────────────────────────────────────
@app.post("/webhook/paddle", tags=["Webhooks"])
async def paddle_webhook(request: Request):
    body    = await request.body()
    payload = json.loads(body)
    event_type = payload.get("event_type","")

    if event_type in ["subscription.activated","transaction.completed","subscription.updated"]:
        data  = payload.get("data",{})
        email = (data.get("customer",{}).get("email") or
                 data.get("custom_data",{}).get("email") or "").lower().strip()
        items = data.get("items",[])
        plan  = "starter"
        if items:
            pn = items[0].get("price",{}).get("name","").lower()
            plan = "business" if "business" in pn else "pro" if "pro" in pn else "starter"
        paddle_id = data.get("id","")
        if email:
            with get_db() as con:
                existing = con.execute("SELECT * FROM customers WHERE email=?", (email,)).fetchone()
                if existing:
                    old_plan = existing["plan"]
                    if old_plan != plan:
                        org_id = f"org_{uuid.uuid4().hex[:12]}" if plan in ("pro","business") and not existing["organization_id"] else existing["organization_id"]
                        con.execute("UPDATE customers SET plan=?,paddle_id=?,organization_id=? WHERE email=?",
                                    (plan, paddle_id, org_id, email))
                        k = con.execute("SELECT api_key FROM api_keys WHERE customer_id=? AND status='active' LIMIT 1",
                                        (existing["id"],)).fetchone()
                        if k:
                            await send_upgrade_email(email, k["api_key"], old_plan, plan)
                else:
                    cid, api_key, kid = _create_customer(con, email, plan, paddle_id)
                    await send_api_key_email(email, api_key, plan)

    if event_type == "subscription.canceled":
        email = payload.get("data",{}).get("customer",{}).get("email","").lower().strip()
        if email:
            with get_db() as con:
                con.execute("UPDATE customers SET status='cancelled' WHERE email=?", (email,))

    return {"status":"ok"}

# ── HEALTH ─────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
def health():
    return {"status":"online","version":"5.0.0"}
