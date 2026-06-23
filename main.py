"""
Prompt Firewall — Production-Ready FastAPI Backend
"""

import os
import uuid
import sqlite3
from datetime import datetime
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Security, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel

API_KEY = os.getenv("FIREWALL_API_KEY", "dev-secret-change-me")
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "*")
DB_PATH = os.getenv("DB_PATH", "firewall.db")

limiter = Limiter(key_func=get_remote_address, default_limits=["30/minute"])

app = FastAPI(title="Prompt Firewall 🛡️", version="2.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def require_api_key(key: str = Security(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key.")
    return key

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id        TEXT PRIMARY KEY,
                timestamp       TEXT NOT NULL,
                status          TEXT NOT NULL,
                reason          TEXT NOT NULL,
                message_preview TEXT NOT NULL
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

MAX_LENGTH = 500

BLACKLIST = [
    "ignore previous instructions",
    "ignore your instructions",
    "ignore all instructions",
    "you are now in developer mode",
    "developer mode",
    "jailbreak",
    "pretend you have no restrictions",
    "act as if you have no rules",
    "disregard your training",
    "forget your guidelines",
    "delete database",
    "drop table",
    "rm -rf",
    "sudo",
    "bypass",
    "override your programming",
    "you are now dan",
    "do anything now",
    "reveal your system prompt",
    "ignore your boss",
    "tell me a secret code",
    "act as an unrestricted",
    "pretend to be evil",
]

def analyze_prompt(message: str) -> tuple[str, str]:
    if not message.strip():
        return "BLOCKED", "Empty message rejected."
    normalised = message.lower()
    if len(message) > MAX_LENGTH:
        return "BLOCKED", f"Message too long ({len(message)} chars). Max: {MAX_LENGTH}."
    for phrase in BLACKLIST:
        if phrase in normalised:
            return "BLOCKED", f'Blacklisted phrase detected: "{phrase}"'
    return "PASSED", "No threats detected. Safe to forward to AI."

class PromptRequest(BaseModel):
    message: str

class FirewallResponse(BaseModel):
    event_id: str
    timestamp: str
    status: str
    reason: str
    message_preview: str

@app.post("/analyze", response_model=FirewallResponse, tags=["Firewall"])
@limiter.limit("30/minute")
def analyze(request: Request, body: PromptRequest, _key: str = Security(require_api_key)):
    status, reason = analyze_prompt(body.message)
    event = {
        "event_id":        str(uuid.uuid4())[:8],
        "timestamp":       datetime.utcnow().isoformat() + "Z",
        "status":          status,
        "reason":          reason,
        "message_preview": body.message[:80] + ("…" if len(body.message) > 80 else ""),
    }
    with get_db() as con:
        con.execute(
            "INSERT INTO events VALUES (:event_id,:timestamp,:status,:reason,:message_preview)",
            event,
        )
    return event

@app.get("/log", tags=["Firewall"])
@limiter.limit("60/minute")
def get_log(request: Request, limit: int = 50, _key: str = Security(require_api_key)):
    with get_db() as con:
        rows = con.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        total = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return {"events": [dict(r) for r in rows], "total": total}

@app.delete("/log", tags=["Firewall"])
def clear_log(_key: str = Security(require_api_key)):
    with get_db() as con:
        con.execute("DELETE FROM events")
    return {"message": "Security log cleared."}

@app.get("/health", tags=["Health"])
def health():
    return {"status": "online", "version": "2.0.0"}