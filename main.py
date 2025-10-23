"""
Gmail Extension Backend Server
Handles OpenAI API requests with sophisticated security validation
"""
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from typing import List, Optional, Dict, Any
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

# Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")  # Shared secret with extension
ALLOWED_EXTENSION_ID = os.getenv("ALLOWED_EXTENSION_ID")
MAX_REQUEST_AGE = 300  # 5 minutes - requests older than this are rejected

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"chrome-extension://{ALLOWED_EXTENSION_ID}"],
    allow_credentials=True,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)


# Request Models
class Message(BaseModel):
    role: str
    content: str

    @validator('role')
    def validate_role(cls, v):
        if v not in ['system', 'user', 'assistant']:
            raise ValueError('Invalid role')
        return v


class OpenAIRequest(BaseModel):
    messages: List[Message]
    model: Optional[str] = "gpt-3.5-turbo"
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None

    # Security parameters
    timestamp: int
    nonce: str
    request_id: str

    @validator('timestamp')
    def validate_timestamp(cls, v):
        current_time = int(time.time())
        if abs(current_time - v) > MAX_REQUEST_AGE:
            raise ValueError('Request timestamp is too old or invalid')
        return v

    @validator('messages')
    def validate_messages(cls, v):
        if not v or len(v) == 0:
            raise ValueError('Messages cannot be empty')
        if len(v) > 50:
            raise ValueError('Too many messages')
        return v

    @validator('model')
    def validate_model(cls, v):
        allowed_models = [
            'gpt-3.5-turbo',
            'gpt-3.5-turbo-16k',
            'gpt-4',
            'gpt-4-turbo-preview',
            'gpt-4-turbo'
        ]
        if v not in allowed_models:
            raise ValueError(f'Model {v} not allowed')
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
    body_str = json.dumps(body_dict, sort_keys=True, separators=(',', ':'))
    body_hash = hashlib.sha256(body_str.encode('utf-8')).hexdigest()

    keys = sorted(body_dict.keys())
    print(f"[SERVER] Body hash: keys=[{','.join(keys)}] len={len(body_str)} hash={body_hash[:16]}...")

    return body_hash


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
        "openai_configured": bool(OPENAI_API_KEY),
        "secret_configured": bool(SECRET_KEY),
        "timestamp": int(time.time())
    }


@app.post("/api/openai/chat")
async def chat_completion(
    request: Request,
    openai_request: OpenAIRequest,
    headers: Dict[str, str] = Depends(verify_extension_headers)
):
    """
    Main endpoint for OpenAI chat completions
    Validates all security parameters before proxying to OpenAI
    """
    try:
        print(f"[SERVER DEBUG] Request received:")
        print(f"  Request ID: {openai_request.request_id}")
        print(f"  Model: {openai_request.model}")
        print(f"  Timestamp: {openai_request.timestamp}")
        print(f"  Nonce: {openai_request.nonce}")
        print(f"  Messages count: {len(openai_request.messages)}")
        print(f"  Temperature: {openai_request.temperature}")
        print(f"  Max tokens: {openai_request.max_tokens}")
        # Step 1: Verify nonce is unique (prevent replay attacks)
        if not check_and_store_nonce(openai_request.nonce):
            raise HTTPException(status_code=400, detail="Nonce already used (replay attack detected)")

        # Step 2: Calculate body hash
        body_dict = {
            "messages": [msg.dict() for msg in openai_request.messages],
            "timestamp": openai_request.timestamp,
            "nonce": openai_request.nonce,
            "request_id": openai_request.request_id
        }
        body_hash = generate_body_hash(body_dict)

        # Step 3: Verify request signature
        print(f"[SERVER] Verification: recv_sig={headers['signature'][:16]}...")

        signature_valid = verify_request_signature(
            headers["signature"],
            openai_request.timestamp,
            openai_request.nonce,
            openai_request.request_id,
            body_hash
        )

        print(f"[SERVER] Result: valid={signature_valid}")

        if not signature_valid:
            raise HTTPException(status_code=401, detail="Invalid request signature")

        # Step 4: All validations passed - make OpenAI API call
        async with httpx.AsyncClient(timeout=60.0) as client:
            openai_response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                json={
                    "model": openai_request.model,
                    "messages": [msg.dict() for msg in openai_request.messages],
                    "temperature": openai_request.temperature,
                    **({"max_tokens": openai_request.max_tokens} if openai_request.max_tokens else {})
                },
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                }
            )

            if openai_response.status_code != 200:
                raise HTTPException(
                    status_code=openai_response.status_code,
                    detail=f"OpenAI API error: {openai_response.text}"
                )

            result = openai_response.json()

            # Track usage
            tokens_used = result.get("usage", {}).get("total_tokens", 0)
            track_usage(headers["fingerprint"], openai_request.model, tokens_used)

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


