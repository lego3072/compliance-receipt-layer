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
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

try:
    import stripe
except Exception:  # pragma: no cover - stripe import is required in production
    stripe = None

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

CHECKOUT_LINK_STARTER = os.getenv("CHECKOUT_LINK_STARTER", "https://buy.stripe.com/dRm4gz51vg162Gj5b33Je06").strip()
CHECKOUT_LINK_DFY = os.getenv("CHECKOUT_LINK_DFY", "https://buy.stripe.com/cNidR9bpT0284Or8nf3Je04").strip()

API_RATE_WINDOW_SECONDS = int(os.getenv("API_RATE_WINDOW_SECONDS", "60"))
LEAD_RATE_LIMIT_PER_MINUTE = int(os.getenv("LEAD_RATE_LIMIT_PER_MINUTE", "15"))
RECEIPT_RATE_LIMIT_PER_MINUTE = int(os.getenv("RECEIPT_RATE_LIMIT_PER_MINUTE", "120"))

CORS_ALLOW_ORIGINS = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",") if o.strip()]
INDEXNOW_KEY = os.getenv("INDEXNOW_KEY", "").strip()
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()

if stripe and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ACTIVE_ACCOUNT_STATUSES = {"active", "trialing"}


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


class AccessKeyRequest(BaseModel):
    email: str


app = FastAPI(title=APP_NAME, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS if CORS_ALLOW_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.mount("/assets", StaticFiles(directory=str(LANDING_DIR)), name="assets")

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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_accounts (
                email TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                plan TEXT,
                billing_mode TEXT,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                checkout_session_id TEXT,
                current_period_end TEXT,
                api_key_hash TEXT,
                api_key_last4 TEXT,
                last_event_id TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_events (
                event_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL
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


def send_resend_email(subject: str, html: str, to_addresses: Optional[list[str]] = None) -> None:
    if not RESEND_API_KEY:
        return
    recipients = [a.strip().lower() for a in (to_addresses or [FOLLOWUP_INBOX_EMAIL]) if a and a.strip()]
    if not recipients:
        return
    payload = {
        "from": FOLLOWUP_FROM_EMAIL,
        "to": recipients,
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


def normalize_email(email: str) -> str:
    return email.strip().lower()


def to_iso_from_unix(ts: Any) -> Optional[str]:
    try:
        if ts is None:
            return None
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None


def get_account_by_email(email: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM billing_accounts WHERE email = ?", (normalize_email(email),)).fetchone()


def get_account_by_customer(customer_id: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM billing_accounts WHERE stripe_customer_id = ? ORDER BY updated_at DESC LIMIT 1",
            (customer_id,),
        ).fetchone()


def get_account_by_subscription(subscription_id: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM billing_accounts WHERE stripe_subscription_id = ? ORDER BY updated_at DESC LIMIT 1",
            (subscription_id,),
        ).fetchone()


def upsert_account(
    *,
    email: str,
    status: Optional[str] = None,
    plan: Optional[str] = None,
    billing_mode: Optional[str] = None,
    stripe_customer_id: Optional[str] = None,
    stripe_subscription_id: Optional[str] = None,
    checkout_session_id: Optional[str] = None,
    current_period_end: Optional[str] = None,
    last_event_id: Optional[str] = None,
    rotate_api_key: bool = False,
) -> Optional[str]:
    email = normalize_email(email)
    now = now_iso()
    persisted_status = status or "pending"
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO billing_accounts (
                email, created_at, updated_at, status, plan, billing_mode, stripe_customer_id,
                stripe_subscription_id, checkout_session_id, current_period_end, last_event_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                updated_at = excluded.updated_at,
                status = COALESCE(excluded.status, billing_accounts.status),
                plan = COALESCE(excluded.plan, billing_accounts.plan),
                billing_mode = COALESCE(excluded.billing_mode, billing_accounts.billing_mode),
                stripe_customer_id = COALESCE(excluded.stripe_customer_id, billing_accounts.stripe_customer_id),
                stripe_subscription_id = COALESCE(excluded.stripe_subscription_id, billing_accounts.stripe_subscription_id),
                checkout_session_id = COALESCE(excluded.checkout_session_id, billing_accounts.checkout_session_id),
                current_period_end = COALESCE(excluded.current_period_end, billing_accounts.current_period_end),
                last_event_id = COALESCE(excluded.last_event_id, billing_accounts.last_event_id)
            """,
            (
                email,
                now,
                now,
                persisted_status,
                plan,
                billing_mode,
                stripe_customer_id,
                stripe_subscription_id,
                checkout_session_id,
                current_period_end,
                last_event_id,
            ),
        )
        row = conn.execute("SELECT * FROM billing_accounts WHERE email = ?", (email,)).fetchone()
        should_issue_key = rotate_api_key or (row and not row["api_key_hash"])
        if not should_issue_key:
            return None
        raw_key = f"dwk_{secrets.token_urlsafe(24)}"
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        conn.execute(
            "UPDATE billing_accounts SET api_key_hash = ?, api_key_last4 = ?, updated_at = ? WHERE email = ?",
            (key_hash, raw_key[-4:], now, email),
        )
        return raw_key


def resolve_email_for_event(obj: dict[str, Any]) -> Optional[str]:
    customer_details = obj.get("customer_details") or {}
    if customer_details.get("email"):
        return normalize_email(customer_details["email"])
    if obj.get("customer_email"):
        return normalize_email(obj["customer_email"])
    return None


def ensure_webhook_configured() -> None:
    if not stripe or not STRIPE_SECRET_KEY or not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Billing webhook is not configured")


def require_paid_access(request: Request) -> sqlite3.Row:
    api_key = request.headers.get("x-api-key", "").strip()
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing x-api-key")
    key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT email, status, plan FROM billing_accounts WHERE api_key_hash = ?",
            (key_hash,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if row["status"] not in ACTIVE_ACCOUNT_STATUSES:
        raise HTTPException(status_code=402, detail="Account is not active")
    return row


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "upgrade-insecure-requests"
    response.headers["X-Robots-Tag"] = "index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1"
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


@app.get("/logo.svg", response_class=PlainTextResponse)
def logo() -> PlainTextResponse:
    return PlainTextResponse((LANDING_DIR / "logo.svg").read_text(encoding="utf-8"), media_type="image/svg+xml")


@app.get("/llms.txt", response_class=PlainTextResponse)
def llms() -> PlainTextResponse:
    content = (LANDING_DIR / "llms.txt").read_text(encoding="utf-8")
    content = (
        content.replace("{{BASE_URL}}", PUBLIC_BASE_URL)
        .replace("{{CHECKOUT_LINK_STARTER}}", CHECKOUT_LINK_STARTER)
        .replace("{{CHECKOUT_LINK_DFY}}", CHECKOUT_LINK_DFY)
    )
    return PlainTextResponse(content)


@app.get("/.well-known/llms.txt", response_class=PlainTextResponse)
def llms_well_known() -> PlainTextResponse:
    return llms()


@app.get("/{indexnow_key}.txt", response_class=PlainTextResponse)
def indexnow_key_file(indexnow_key: str) -> PlainTextResponse:
    if not INDEXNOW_KEY or indexnow_key != INDEXNOW_KEY:
        raise HTTPException(status_code=404, detail="Not found")
    return PlainTextResponse(INDEXNOW_KEY)


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
User-agent: Claude-User
Allow: /
User-agent: PerplexityBot
Allow: /
User-agent: Google-Extended
Allow: /
User-agent: CCBot
Allow: /
User-agent: Applebot
Allow: /
User-agent: Bytespider
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
  <url><loc>{PUBLIC_BASE_URL}/privacy</loc><lastmod>{today}</lastmod></url>
  <url><loc>{PUBLIC_BASE_URL}/terms</loc><lastmod>{today}</lastmod></url>
  <url><loc>{PUBLIC_BASE_URL}/llms.txt</loc><lastmod>{today}</lastmod></url>
  <url><loc>{PUBLIC_BASE_URL}/.well-known/llms.txt</loc><lastmod>{today}</lastmod></url>
  <url><loc>{PUBLIC_BASE_URL}/.well-known/agent-offer.json</loc><lastmod>{today}</lastmod></url>
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
            "logo_url": f"{PUBLIC_BASE_URL}/logo.svg",
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


@app.post("/api/public/access-key")
def request_access_key(payload: AccessKeyRequest, request: Request) -> dict[str, Any]:
    ip = client_ip(request)
    check_rate_limit(f"access-key:{ip}", 8, API_RATE_WINDOW_SECONDS)
    email = normalize_email(payload.email)
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid email")
    row = get_account_by_email(email)
    if row and row["status"] in ACTIVE_ACCOUNT_STATUSES:
        new_key = upsert_account(email=email, rotate_api_key=True)
        if new_key:
            send_resend_email(
                subject=f"{APP_NAME} access key issued",
                html=(
                    f"<p>Your {APP_NAME} account is active.</p>"
                    f"<p><strong>API Key:</strong> <code>{new_key}</code></p>"
                    f"<p>Use it in the <code>x-api-key</code> header for protected endpoints.</p>"
                ),
                to_addresses=[email],
            )
            send_resend_email(subject=f"{APP_NAME} key rotated", html=f"<p>API key rotated for {email}</p>")
    return {"ok": True, "message": "If an active account exists, an access key email was sent."}


@app.get("/v1/billing/status")
def billing_status(email: str) -> dict[str, Any]:
    email = normalize_email(email)
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid email")
    row = get_account_by_email(email)
    if not row:
        return {"ok": True, "found": False}
    return {
        "ok": True,
        "found": True,
        "email": row["email"],
        "status": row["status"],
        "plan": row["plan"],
        "billing_mode": row["billing_mode"],
        "current_period_end": row["current_period_end"],
        "updated_at": row["updated_at"],
    }


@app.post("/v1/billing/webhook")
async def billing_webhook(request: Request) -> dict[str, Any]:
    ensure_webhook_configured()
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=signature, secret=STRIPE_WEBHOOK_SECRET)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid webhook signature: {exc}") from exc

    event_id = event.get("id")
    event_type = event.get("type", "")
    obj = event.get("data", {}).get("object", {}) or {}
    now = now_iso()

    with get_conn() as conn:
        exists = conn.execute("SELECT 1 FROM billing_events WHERE event_id = ?", (event_id,)).fetchone()
        if exists:
            return {"ok": True, "duplicate": True}
        conn.execute(
            "INSERT INTO billing_events (event_id, created_at, event_type, payload) VALUES (?, ?, ?, ?)",
            (event_id, now, event_type, json.dumps(event)),
        )

    if event_type == "checkout.session.completed":
        email = resolve_email_for_event(obj)
        if email:
            mode = obj.get("mode") or "payment"
            plan = "starter" if mode == "subscription" else "dfy"
            status = "active" if (obj.get("payment_status") == "paid" or mode == "subscription") else "pending"
            issued_key = upsert_account(
                email=email,
                status=status,
                plan=plan,
                billing_mode=mode,
                stripe_customer_id=obj.get("customer"),
                stripe_subscription_id=obj.get("subscription"),
                checkout_session_id=obj.get("id"),
                last_event_id=event_id,
                rotate_api_key=status in ACTIVE_ACCOUNT_STATUSES,
            )
            if status in ACTIVE_ACCOUNT_STATUSES:
                key_html = (
                    f"<p><strong>API Key:</strong> <code>{issued_key}</code></p>"
                    if issued_key
                    else "<p>Your existing API key remains active.</p>"
                )
                send_resend_email(
                    subject=f"{APP_NAME} access activated ({plan})",
                    html=(
                        f"<p>Payment received. Your {APP_NAME} account is now active.</p>"
                        f"<p>Plan: <strong>{plan}</strong></p>{key_html}"
                        f"<p>Use the <code>x-api-key</code> header on protected endpoints.</p>"
                    ),
                    to_addresses=[email],
                )

    elif event_type in {"customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"}:
        customer_id = obj.get("customer")
        sub_id = obj.get("id")
        sub_status = obj.get("status", "inactive")
        mapped = "active" if sub_status in ACTIVE_ACCOUNT_STATUSES else sub_status
        row = get_account_by_customer(customer_id) if customer_id else None
        email = row["email"] if row else None
        if not email and customer_id and stripe:
            try:
                customer = stripe.Customer.retrieve(customer_id)
                email = normalize_email(customer.get("email", "")) if customer else None
            except Exception:
                email = None
        if email:
            upsert_account(
                email=email,
                status=mapped,
                billing_mode="subscription",
                stripe_customer_id=customer_id,
                stripe_subscription_id=sub_id,
                current_period_end=to_iso_from_unix(obj.get("current_period_end")),
                last_event_id=event_id,
            )

    elif event_type in {"invoice.paid", "invoice.payment_failed"}:
        customer_id = obj.get("customer")
        sub_id = obj.get("subscription")
        row = get_account_by_subscription(sub_id) if sub_id else None
        if not row and customer_id:
            row = get_account_by_customer(customer_id)
        if row:
            upsert_account(
                email=row["email"],
                status="active" if event_type == "invoice.paid" else "past_due",
                stripe_customer_id=customer_id,
                stripe_subscription_id=sub_id,
                last_event_id=event_id,
            )

    return {"ok": True}


@app.post("/v1/receipts/create")
def create_receipt(payload: ReceiptCreateRequest, request: Request) -> dict[str, Any]:
    require_paid_access(request)
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
def verify_receipt(payload: ReceiptVerifyRequest, request: Request) -> dict[str, Any]:
    require_paid_access(request)
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
def get_receipt(receipt_id: str, request: Request) -> dict[str, Any]:
    require_paid_access(request)
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
