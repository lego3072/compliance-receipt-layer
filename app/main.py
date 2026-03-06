import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
LANDING_DIR = BASE_DIR / "landing"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "receipts.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)

APP_NAME = "Compliance Receipt Layer"
APP_SLUG = "receiptlayer"
DEFAULT_BASE_URL = "https://receiptlayer.dataweaveai.com"

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
FOLLOWUP_INBOX_EMAIL = os.getenv("FOLLOWUP_INBOX_EMAIL", "joseph@dataweaveai.com").strip()
FOLLOWUP_FROM_EMAIL = os.getenv("FOLLOWUP_FROM_EMAIL", "ReceiptLayer <noreply@dataweaveai.com>").strip()
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
RECEIPT_SIGNING_KEY = os.getenv("RECEIPT_SIGNING_KEY", "change_this_in_production").strip()

DATAWEAVE_HOME_URL = os.getenv("DATAWEAVE_HOME_URL", "https://dataweaveai.com").strip()
AGENT_ROUTER_URL = os.getenv("AGENT_ROUTER_URL", "https://get-agent-router.com").strip()

CHECKOUT_LINK_STARTER = os.getenv("CHECKOUT_LINK_STARTER", "https://buy.stripe.com/cNidR9bpT0284Or8nf3Je04").strip()
CHECKOUT_LINK_DFY = os.getenv("CHECKOUT_LINK_DFY", "https://buy.stripe.com/cNi14n0Lf8yEep1dHz3Je05").strip()

API_RATE_WINDOW_SECONDS = int(os.getenv("API_RATE_WINDOW_SECONDS", "60"))
LEAD_RATE_LIMIT_PER_MINUTE = int(os.getenv("LEAD_RATE_LIMIT_PER_MINUTE", "15"))
RECEIPT_RATE_LIMIT_PER_MINUTE = int(os.getenv("RECEIPT_RATE_LIMIT_PER_MINUTE", "120"))

CORS_ALLOW_ORIGINS = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",") if o.strip()]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class LeadRequest(BaseModel):
    email: str
    company: str = Field(min_length=2, max_length=120)
    compliance_scope: str = Field(min_length=4, max_length=300)
    plan: str = Field(default="starter", pattern="^(starter|dfy)$")
    source: Optional[str] = Field(default="site", max_length=80)


class ReceiptCreateRequest(BaseModel):
    actor_id: str = Field(min_length=2, max_length=120)
    action_type: str = Field(min_length=2, max_length=120)
    output: str = Field(min_length=1, max_length=40000)
    policy_tags: list[str] = Field(default_factory=list, max_length=20)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReceiptVerifyRequest(BaseModel):
    receipt_id: str = Field(min_length=8, max_length=64)


app = FastAPI(title=APP_NAME, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS if CORS_ALLOW_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

_rate_lock = threading.Lock()
_rate_state: dict[str, list[float]] = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS leads (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                email TEXT NOT NULL,
                company TEXT NOT NULL,
                compliance_scope TEXT NOT NULL,
                plan TEXT NOT NULL,
                source TEXT,
                ip_hash TEXT,
                checkout_url TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                policy_tags_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                prev_receipt_hash TEXT,
                receipt_hash TEXT NOT NULL,
                signature TEXT NOT NULL
            )
            """
        )


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:24]


def check_rate_limit(key: str, limit: int, window_seconds: int) -> None:
    cutoff = time.time() - window_seconds
    with _rate_lock:
        bucket = _rate_state.get(key, [])
        bucket = [ts for ts in bucket if ts >= cutoff]
        if len(bucket) >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        bucket.append(time.time())
        _rate_state[key] = bucket


def checkout_link_for_plan(plan: str) -> str:
    return {
        "starter": CHECKOUT_LINK_STARTER,
        "dfy": CHECKOUT_LINK_DFY,
    }.get(plan, CHECKOUT_LINK_STARTER)


def render_template(name: str) -> str:
    raw = (LANDING_DIR / name).read_text(encoding="utf-8")
    return (
        raw.replace("{{BASE_URL}}", PUBLIC_BASE_URL)
        .replace("{{DATAWEAVE_HOME_URL}}", DATAWEAVE_HOME_URL)
        .replace("{{AGENT_ROUTER_URL}}", AGENT_ROUTER_URL)
        .replace("{{CHECKOUT_LINK_STARTER}}", CHECKOUT_LINK_STARTER)
        .replace("{{CHECKOUT_LINK_DFY}}", CHECKOUT_LINK_DFY)
    )


def sign_value(value: str) -> str:
    return hmac.new(RECEIPT_SIGNING_KEY.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def send_resend_email(subject: str, html: str) -> None:
    if not RESEND_API_KEY:
        return
    payload = {
        "from": FOLLOWUP_FROM_EMAIL,
        "to": [FOLLOWUP_INBOX_EMAIL],
        "subject": subject,
        "html": html,
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8):
            pass
    except urllib.error.URLError:
        return


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "upgrade-insecure-requests"
    return response


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": APP_SLUG, "time": now_iso()}


@app.get("/", response_class=HTMLResponse)
def home() -> HTMLResponse:
    return HTMLResponse(render_template("index.html"))


@app.get("/docs-page", response_class=HTMLResponse)
def docs_page() -> HTMLResponse:
    return HTMLResponse(render_template("docs.html"))


@app.get("/privacy", response_class=HTMLResponse)
def privacy() -> HTMLResponse:
    return HTMLResponse(render_template("privacy.html"))


@app.get("/terms", response_class=HTMLResponse)
def terms() -> HTMLResponse:
    return HTMLResponse(render_template("terms.html"))


@app.get("/llms.txt", response_class=PlainTextResponse)
def llms() -> PlainTextResponse:
    content = (LANDING_DIR / "llms.txt").read_text(encoding="utf-8")
    content = (
        content.replace("{{BASE_URL}}", PUBLIC_BASE_URL)
        .replace("{{CHECKOUT_LINK_STARTER}}", CHECKOUT_LINK_STARTER)
        .replace("{{CHECKOUT_LINK_DFY}}", CHECKOUT_LINK_DFY)
    )
    return PlainTextResponse(content)


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots() -> PlainTextResponse:
    return PlainTextResponse(
        f"""User-agent: *
Allow: /
Disallow: /v1/admin

User-agent: GPTBot
Allow: /
User-agent: OAI-SearchBot
Allow: /
User-agent: ClaudeBot
Allow: /
User-agent: PerplexityBot
Allow: /

Sitemap: {PUBLIC_BASE_URL}/sitemap.xml
"""
    )


@app.get("/sitemap.xml", response_class=PlainTextResponse)
def sitemap() -> PlainTextResponse:
    today = datetime.now(timezone.utc).date().isoformat()
    return PlainTextResponse(
        f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">
  <url><loc>{PUBLIC_BASE_URL}/</loc><lastmod>{today}</lastmod></url>
  <url><loc>{PUBLIC_BASE_URL}/docs-page</loc><lastmod>{today}</lastmod></url>
  <url><loc>{PUBLIC_BASE_URL}/llms.txt</loc><lastmod>{today}</lastmod></url>
</urlset>""",
        media_type="application/xml",
    )


@app.get("/.well-known/agent-offer.json", response_class=JSONResponse)
def agent_offer() -> JSONResponse:
    return JSONResponse(
        {
            "name": APP_NAME,
            "url": PUBLIC_BASE_URL,
            "type": "compliance_receipt_layer",
            "checkout_endpoint": f"{PUBLIC_BASE_URL}/api/public/lead",
            "api_endpoints": [
                f"{PUBLIC_BASE_URL}/v1/receipts/create",
                f"{PUBLIC_BASE_URL}/v1/receipts/verify",
            ],
            "value": "tamper-evident proof of agent actions",
        }
    )


@app.get("/.well-known/ai-plugin.json", response_class=JSONResponse)
def ai_plugin() -> JSONResponse:
    return JSONResponse(
        {
            "schema_version": "v1",
            "name_for_human": APP_NAME,
            "name_for_model": "compliance_receipt_layer",
            "description_for_human": "Create and verify tamper-evident compliance receipts for agent actions.",
            "description_for_model": "Use for signed receipt creation and validation of AI agent actions.",
            "auth": {"type": "none"},
            "api": {"type": "openapi", "url": f"{PUBLIC_BASE_URL}/openapi.json", "is_user_authenticated": False},
            "logo_url": f"{PUBLIC_BASE_URL}/logo-192.png",
            "contact_email": FOLLOWUP_INBOX_EMAIL,
            "legal_info_url": f"{PUBLIC_BASE_URL}/terms",
        }
    )


@app.post("/api/public/lead")
def create_lead(payload: LeadRequest, request: Request) -> dict[str, Any]:
    ip = client_ip(request)
    check_rate_limit(f"lead:{ip}", LEAD_RATE_LIMIT_PER_MINUTE, API_RATE_WINDOW_SECONDS)
    if not EMAIL_RE.match(payload.email.strip()):
        raise HTTPException(status_code=400, detail="Invalid email")

    lead_id = f"lead_{secrets.token_hex(8)}"
    checkout_url = checkout_link_for_plan(payload.plan)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO leads (id, created_at, email, company, compliance_scope, plan, source, ip_hash, checkout_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                lead_id,
                now_iso(),
                payload.email.lower().strip(),
                payload.company.strip(),
                payload.compliance_scope.strip(),
                payload.plan,
                (payload.source or "site").strip(),
                ip_hash(ip),
                checkout_url,
            ),
        )

    send_resend_email(
        subject=f"ReceiptLayer lead: {payload.plan}",
        html=(
            f"<p><strong>New Compliance Receipt lead</strong></p>"
            f"<p>Email: {payload.email}<br>Company: {payload.company}<br>Plan: {payload.plan}<br>"
            f"Checkout: <a href='{checkout_url}'>{checkout_url}</a></p>"
        ),
    )

    return {"ok": True, "lead_id": lead_id, "checkout_url": checkout_url, "plan": payload.plan}


@app.post("/v1/receipts/create")
def create_receipt(payload: ReceiptCreateRequest, request: Request) -> dict[str, Any]:
    ip = client_ip(request)
    check_rate_limit(f"receipt:{ip}", RECEIPT_RATE_LIMIT_PER_MINUTE, API_RATE_WINDOW_SECONDS)

    output_hash = hashlib.sha256(payload.output.encode("utf-8")).hexdigest()
    receipt_id = f"rcpt_{secrets.token_hex(10)}"

    with get_conn() as conn:
        prev = conn.execute("SELECT receipt_hash FROM receipts ORDER BY created_at DESC LIMIT 1").fetchone()
        prev_hash = prev[0] if prev else None
        body = {
            "receipt_id": receipt_id,
            "created_at": now_iso(),
            "actor_id": payload.actor_id,
            "action_type": payload.action_type,
            "output_hash": output_hash,
            "policy_tags": payload.policy_tags,
            "metadata": payload.metadata,
            "prev_receipt_hash": prev_hash,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        receipt_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        signature = sign_value(receipt_hash)

        conn.execute(
            """
            INSERT INTO receipts (id, created_at, actor_id, action_type, output_hash, policy_tags_json, metadata_json, prev_receipt_hash, receipt_hash, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt_id,
                body["created_at"],
                payload.actor_id,
                payload.action_type,
                output_hash,
                json.dumps(payload.policy_tags),
                json.dumps(payload.metadata),
                prev_hash,
                receipt_hash,
                signature,
            ),
        )

    return {
        "ok": True,
        "receipt": {
            "receipt_id": receipt_id,
            "created_at": body["created_at"],
            "actor_id": payload.actor_id,
            "action_type": payload.action_type,
            "output_hash": output_hash,
            "policy_tags": payload.policy_tags,
            "prev_receipt_hash": prev_hash,
            "receipt_hash": receipt_hash,
            "signature": signature,
        },
    }


@app.post("/v1/receipts/verify")
def verify_receipt(payload: ReceiptVerifyRequest) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM receipts WHERE id = ?", (payload.receipt_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Receipt not found")

    stored_hash = row["receipt_hash"]
    stored_sig = row["signature"]
    expected_sig = sign_value(stored_hash)
    signature_ok = hmac.compare_digest(stored_sig, expected_sig)

    return {
        "ok": True,
        "receipt_id": payload.receipt_id,
        "signature_valid": signature_ok,
        "receipt_hash": stored_hash,
        "created_at": row["created_at"],
        "actor_id": row["actor_id"],
        "action_type": row["action_type"],
    }


@app.get("/v1/receipts/{receipt_id}")
def get_receipt(receipt_id: str) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM receipts WHERE id = ?", (receipt_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Receipt not found")
    return {
        "ok": True,
        "receipt": {
            "id": row["id"],
            "created_at": row["created_at"],
            "actor_id": row["actor_id"],
            "action_type": row["action_type"],
            "output_hash": row["output_hash"],
            "policy_tags": json.loads(row["policy_tags_json"]),
            "metadata": json.loads(row["metadata_json"]),
            "prev_receipt_hash": row["prev_receipt_hash"],
            "receipt_hash": row["receipt_hash"],
            "signature": row["signature"],
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
