"""
Gmail Extension Backend Server
Proxies chat requests to Kie AI (Gemini 3 Flash, OpenAI-compatible API)
"""
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from typing import List, Dict, Any, Optional, Union
import os
import hashlib
import hmac
import time
import json
from datetime import datetime
from dotenv import load_dotenv
import httpx

# Load environment variables
load_dotenv()

app = FastAPI(title="Gmail Extension Backend", version="1.0.0")

# Configuration — Kie AI Gemini 3 Flash (OpenAI-compatible)
# https://docs.kie.ai/30445303e0 → POST /gemini-3-flash/v1/chat/completions
# OPENAI_API_KEY kept as env alias so existing server .env keeps working
KIE_API_KEY = os.getenv("KIE_API_KEY") or os.getenv("OPENAI_API_KEY")
KIE_CHAT_URL = os.getenv(
    "KIE_CHAT_URL",
    "https://api.kie.ai/gemini-3-flash/v1/chat/completions",
)
KIE_STREAM = os.getenv("KIE_STREAM", "false").lower() in ("1", "true", "yes")
SECRET_KEY = os.getenv("SECRET_KEY")  # Shared secret with extension
ALLOWED_EXTENSION_ID = os.getenv("ALLOWED_EXTENSION_ID")
MAX_REQUEST_AGE = 300  # 5 minutes - requests older than this are rejected
SUBSCRIPTION_EMAILS_FILE = os.getenv(
    "GMAIL_APP_SUBSCRIPTIONS_FILE",
    ".gmail_app_subscriptions.json"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"chrome-extension://{ALLOWED_EXTENSION_ID}"],
    allow_credentials=True,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)


# Request Models
class SubscriptionEmailsRequest(BaseModel):
    """Security envelope for the subscription-emails endpoint (no payload needed)."""
    timestamp: int
    nonce: str
    request_id: str

    @validator('timestamp')
    def validate_timestamp(cls, v):
        current_time = int(time.time())
        if abs(current_time - v) > MAX_REQUEST_AGE:
            raise ValueError('Request timestamp is too old or invalid')
        return v


# Security Functions
def generate_request_signature(
    timestamp: int,
    nonce: str,
    request_id: str,
    body_hash: str,
    secret: str
) -> str:
    """Generate HMAC signature for request validation"""
    message = f"{timestamp}|{nonce}|{request_id}|{body_hash}"
    signature = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    print(f"[SERVER] Signature: msg_len={len(message)} sig={signature[:16]}...")

    return signature


def verify_request_signature(
    signature: str,
    timestamp: int,
    nonce: str,
    request_id: str,
    body_hash: str
) -> bool:
    """Verify the request signature matches expected value"""
    expected_signature = generate_request_signature(
        timestamp, nonce, request_id, body_hash, SECRET_KEY
    )
    return hmac.compare_digest(signature, expected_signature)


def generate_body_hash(body_dict: Dict[str, Any]) -> str:
    """Generate hash of request body for integrity verification"""
    # Format: timestamp|nonce|request_id|message_count
    message_count = len(body_dict["messages"])
    hash_string = f"{body_dict['timestamp']}|{body_dict['nonce']}|{body_dict['request_id']}|{message_count}"

    body_hash = hashlib.sha256(hash_string.encode('utf-8')).hexdigest()

    return body_hash


def generate_simple_body_hash(body_dict: Dict[str, Any]) -> str:
    """Generate hash for requests without a messages payload (e.g. subscription emails)"""
    # Format: timestamp|nonce|request_id
    hash_string = f"{body_dict['timestamp']}|{body_dict['nonce']}|{body_dict['request_id']}"
    return hashlib.sha256(hash_string.encode('utf-8')).hexdigest()


def verify_extension_headers(
    x_extension_version: str = Header(...),
    x_extension_id: str = Header(...),
    x_request_signature: str = Header(...),
    x_client_fingerprint: str = Header(...)
) -> Dict[str, str]:
    """
    Verify custom headers from extension
    Returns dict of verified headers or raises HTTPException
    """
    # Verify extension ID
    if x_extension_id != ALLOWED_EXTENSION_ID:
        raise HTTPException(status_code=403, detail="Invalid extension ID")

    # Verify extension version format
    if not x_extension_version or len(x_extension_version.split('.')) < 2:
        raise HTTPException(status_code=400, detail="Invalid extension version")

    # Verify client fingerprint exists
    if not x_client_fingerprint or len(x_client_fingerprint) < 32:
        raise HTTPException(status_code=400, detail="Invalid client fingerprint")

    return {
        "version": x_extension_version,
        "extension_id": x_extension_id,
        "signature": x_request_signature,
        "fingerprint": x_client_fingerprint
    }


# In-memory nonce tracking (use Redis in production)
used_nonces = set()
MAX_NONCE_CACHE = 10000


def check_and_store_nonce(nonce: str) -> bool:
    """
    Check if nonce has been used before (prevents replay attacks)
    Returns True if nonce is new, False if already used
    """
    if nonce in used_nonces:
        return False

    # Store nonce
    used_nonces.add(nonce)

    # Prevent memory overflow
    if len(used_nonces) > MAX_NONCE_CACHE:
        # Remove oldest 20% of nonces
        to_remove = list(used_nonces)[:2000]
        for old_nonce in to_remove:
            used_nonces.discard(old_nonce)

    return True


# Usage tracking (simple in-memory, use database in production)
usage_stats = {}


def extract_message_content(content: Union[str, List[Any], Dict[str, Any], None]) -> str:
    """Normalize assistant content to a plain string (OpenAI chat.completion shape)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text" and "text" in item:
                    parts.append(str(item["text"]))
                elif "text" in item:
                    parts.append(str(item["text"]))
        return "".join(parts)
    if isinstance(content, dict) and "text" in content:
        return str(content["text"])
    return str(content)


def normalize_chat_completion_response(
    payload: Dict[str, Any],
    requested_model: str,
) -> Dict[str, Any]:
    """
    Ensure the payload matches what the Chrome extension expects from OpenAI:
    choices[].message.content as a string, plus id/object/usage when present.
    """
    if payload.get("code") and payload.get("msg") and "choices" not in payload:
        raise HTTPException(
            status_code=502,
            detail=f"OpenAI API error: {payload.get('msg', payload)}",
        )

    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise HTTPException(
            status_code=502,
            detail="OpenAI API error: invalid response (no choices)",
        )

    for choice in choices:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if isinstance(message, dict) and "content" in message:
            message["content"] = extract_message_content(message.get("content"))

    if not payload.get("model"):
        payload["model"] = requested_model
    if not payload.get("object"):
        payload["object"] = "chat.completion"

    return payload


def track_usage(fingerprint: str, model: str, tokens_used: int):
    """Track API usage per client fingerprint"""
    if fingerprint not in usage_stats:
        usage_stats[fingerprint] = {
            "total_requests": 0,
            "total_tokens": 0,
            "models_used": {},
            "first_request": datetime.now().isoformat(),
            "last_request": datetime.now().isoformat()
        }

    stats = usage_stats[fingerprint]
    stats["total_requests"] += 1
    stats["total_tokens"] += tokens_used
    stats["last_request"] = datetime.now().isoformat()

    if model not in stats["models_used"]:
        stats["models_used"][model] = 0
    stats["models_used"][model] += 1


def load_gmail_app_subscription_emails() -> List[str]:
    """Load gmail_app subscription emails from a local hidden file."""
    if not os.path.exists(SUBSCRIPTION_EMAILS_FILE):
        return []

    try:
        with open(SUBSCRIPTION_EMAILS_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read subscription email file: {str(exc)}"
        ) from exc

    if not isinstance(payload, list):
        raise HTTPException(
            status_code=500,
            detail="Subscription email file must be a JSON array"
        )

    return [
        email.strip().lower()
        for email in payload
        if isinstance(email, str) and email.strip()
    ]


# API Endpoints
@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Gmail Extension Backend",
        "version": "1.0.0",
        "timestamp": int(time.time())
    }


@app.get("/api/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "openai_configured": bool(KIE_API_KEY),
        "secret_configured": bool(SECRET_KEY),
        "timestamp": int(time.time()),
    }


@app.post("/api/openai/chat")
async def chat_completion(
    request: Request,
    headers: Dict[str, str] = Depends(verify_extension_headers)
):
    """
    Chat completions via Kie AI Gemini 3 Flash.
    Validates security parameters before proxying upstream.
    """
    try:
        # Get raw request body
        raw_body = await request.json()

        # Step 1: Verify nonce is unique (prevent replay attacks)
        if not check_and_store_nonce(raw_body['nonce']):
            raise HTTPException(status_code=400, detail="Nonce already used (replay attack detected)")

        # Step 2: Calculate body hash (exact same as client)
        body_dict = {
            "messages": raw_body["messages"],
            "timestamp": raw_body["timestamp"],
            "nonce": raw_body["nonce"],
            "request_id": raw_body["request_id"]
        }

        body_hash = generate_body_hash(body_dict)

        # Step 3: Verify request signature
        signature_valid = verify_request_signature(
            headers["signature"],
            raw_body["timestamp"],
            raw_body["nonce"],
            raw_body["request_id"],
            body_hash
        )

        if not signature_valid:
            raise HTTPException(status_code=401, detail="Invalid request signature")

        requested_model = raw_body.get("model", "gpt-4o-mini")

        # Step 4: All validations passed - proxy to Kie AI (OpenAI-compatible upstream)
        if not KIE_API_KEY:
            raise HTTPException(status_code=503, detail="OpenAI API key not configured")

        upstream_payload: Dict[str, Any] = {
            "messages": raw_body["messages"],
            "temperature": raw_body.get("temperature", 0.7),
            "stream": KIE_STREAM,
        }
        if raw_body.get("max_tokens"):
            upstream_payload["max_tokens"] = raw_body["max_tokens"]

        async with httpx.AsyncClient(timeout=120.0) as client:
            kie_response = await client.post(
                KIE_CHAT_URL,
                json=upstream_payload,
                headers={
                    "Authorization": f"Bearer {KIE_API_KEY}",
                    "Content-Type": "application/json",
                },
            )

            if kie_response.status_code != 200:
                raise HTTPException(
                    status_code=kie_response.status_code,
                    detail=f"OpenAI API error: {kie_response.text}",
                )

            try:
                result = kie_response.json()
            except json.JSONDecodeError as exc:
                raise HTTPException(
                    status_code=502,
                    detail=f"OpenAI API error: invalid JSON response ({exc})",
                ) from exc

            result = normalize_chat_completion_response(result, requested_model)

            tokens_used = result.get("usage", {}).get("total_tokens", 0)
            track_usage(headers["fingerprint"], requested_model, tokens_used)

            return result

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error processing request: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/stats")
async def get_stats(
    x_admin_key: str = Header(None)
):
    """
    Get usage statistics (admin only)
    """
    admin_key = os.getenv("ADMIN_KEY")
    if not admin_key or x_admin_key != admin_key:
        raise HTTPException(status_code=403, detail="Unauthorized")

    return {
        "total_clients": len(usage_stats),
        "total_requests": sum(s["total_requests"] for s in usage_stats.values()),
        "total_tokens": sum(s["total_tokens"] for s in usage_stats.values()),
        "active_nonces": len(used_nonces),
        "clients": usage_stats
    }


@app.post("/api/gmail_app/subscription-emails")
async def get_gmail_app_subscription_emails(
    request: Request,
    headers: Dict[str, str] = Depends(verify_extension_headers)
):
    """
    Return gmail_app subscription emails from local hidden file.
    Protected with the same security stack as the chat endpoint:
    extension-header verification, timestamp freshness, nonce replay
    prevention, and HMAC body-signature verification.
    """
    try:
        raw_body = await request.json()

        if not check_and_store_nonce(raw_body['nonce']):
            raise HTTPException(status_code=400, detail="Nonce already used (replay attack detected)")

        body_hash = generate_simple_body_hash({
            "timestamp": raw_body["timestamp"],
            "nonce": raw_body["nonce"],
            "request_id": raw_body["request_id"],
        })

        if not verify_request_signature(
            headers["signature"],
            raw_body["timestamp"],
            raw_body["nonce"],
            raw_body["request_id"],
            body_hash
        ):
            raise HTTPException(status_code=401, detail="Invalid request signature")

        emails = load_gmail_app_subscription_emails()
        return {
            "count": len(emails),
            "emails": emails
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error processing subscription-emails request: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    print(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info"
    )


