# Compliance Receipt Layer

FastAPI service for signed compliance receipts and tamper-evident agent action evidence.

## Core Endpoints
- `POST /v1/receipts/create`
- `POST /v1/receipts/verify`
- `GET /v1/receipts/{receipt_id}`
- `POST /api/public/lead`

## Local run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Security defaults
- hash chaining + HMAC signatures
- strict headers
- IP-based rate limits
- minimal lead metadata retention
