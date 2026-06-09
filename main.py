"""
Gmail Extension Backend Server
Proxies chat requests to Kie AI (Gemini 3 Flash, OpenAI-compatible API)
"""
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, validator
from typing import List, Dict, Any, Optional, Union
import os
import hashlib
import hmac
import time
import json
import asyncio
import random
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
DEFAULT_KIE_FALLBACK_URL = "https://api.kie.ai/gemini-3-5-flash-openai/v1/chat/completions"
KIE_STREAM = os.getenv("KIE_STREAM", "false").lower() in ("1", "true", "yes")
KIE_MAX_RETRIES = int(os.getenv("KIE_MAX_RETRIES", "4"))
KIE_RETRY_BASE_DELAY = float(os.getenv("KIE_RETRY_BASE_DELAY", "2.0"))
KIE_REQUEST_TIMEOUT = float(os.getenv("KIE_REQUEST_TIMEOUT", "45"))
# Stay under nginx default 60s proxy_read_timeout to avoid 504 Gateway Timeout
KIE_MAX_RETRY_SECONDS = float(os.getenv("KIE_MAX_RETRY_SECONDS", "50"))
# Kie AI transient errors (455 = maintenance, 429 = rate limit)
KIE_RETRYABLE_HTTP_STATUSES = {429, 455, 500, 502, 503}
KIE_RETRYABLE_API_CODES = {429, 455, 500, 501, 503, 505}
KIE_MAINTENANCE_PHRASE = "being maintained"
SECRET_KEY = os.getenv("SECRET_KEY")  # Shared secret with extension
ALLOWED_EXTENSION_ID = os.getenv("ALLOWED_EXTENSION_ID")
MAX_REQUEST_AGE = 300  # 5 minutes - requests older than this are rejected
MAX_TRANSLATE_TEXT_LENGTH = int(os.getenv("MAX_TRANSLATE_TEXT_LENGTH", "5000"))
# HTML chunks (format=html) — Google Cloud Translation v2 basic allows ~100 KB per request
MAX_TRANSLATE_HTML_LENGTH = int(os.getenv("MAX_TRANSLATE_HTML_LENGTH", "102400"))
# Official Google Cloud Translation API v2 (https://cloud.google.com/translate/docs/reference/rest/v2/translate/translateText)
GOOGLE_TRANSLATE_API_KEY = os.getenv("GOOGLE_TRANSLATE_API_KEY") or os.getenv("GOOGLE_CLOUD_API_KEY")
GOOGLE_CLOUD_TRANSLATE_URL = "https://translation.googleapis.com/language/translate/v2"
GOOGLE_CLOUD_TRANSLATE_CHUNK = int(os.getenv("GOOGLE_CLOUD_TRANSLATE_CHUNK", "4500"))
GOOGLE_CLOUD_TRANSLATE_HTML_CHUNK = int(os.getenv("GOOGLE_CLOUD_TRANSLATE_HTML_CHUNK", "12000"))
MAX_TRANSLATE_CHUNKS_PER_REQUEST = int(os.getenv("MAX_TRANSLATE_CHUNKS_PER_REQUEST", "16"))
SUBSCRIPTION_EMAILS_FILE = os.getenv(
    "GMAIL_APP_SUBSCRIPTIONS_FILE",
    ".gmail_app_subscriptions.json"
)

# Google OAuth — refresh access tokens server-side (client_secret never in extension)
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_OAUTH_CLIENT_ID = os.getenv(
    "GOOGLE_OAUTH_CLIENT_ID",
    "836033547101-qu9bbm4rjpefpivmslc3shdc5i1ohu9c.apps.googleusercontent.com",
)
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
GOOGLE_OAUTH_CLIENT_ID_LEGACY = os.getenv(
    "GOOGLE_OAUTH_CLIENT_ID_LEGACY",
    "796046081733-jraj2so962ub425fi23escegerq2kn80.apps.googleusercontent.com",
)
GOOGLE_OAUTH_CLIENT_SECRET_LEGACY = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET_LEGACY")
GMAIL_APP_ITEM_ID = os.getenv("GMAIL_APP_ITEM_ID", "mailapp-1716052394833")

# CORS: any chrome-extension:// origin (unpacked vs store ID differs).
# Chat auth: X-Extension-Id must match ALLOWED_EXTENSION_ID.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# Request Models
class SignedProxyRequest(BaseModel):
    """Security envelope for signed proxy endpoints without a messages payload."""
    timestamp: int
    nonce: str
    request_id: str

    @validator('timestamp')
    def validate_timestamp(cls, v):
        current_time = int(time.time())
        if abs(current_time - v) > MAX_REQUEST_AGE:
            raise ValueError('Request timestamp is too old or invalid')
        return v


class SubscriptionEmailsRequest(SignedProxyRequest):
    """Security envelope for the subscription-emails endpoint (no payload needed)."""
    pass


class TranslateRequest(SignedProxyRequest):
    text: str
    target_lang: str
    source_lang: str = "auto"

    @validator('text')
    def validate_text(cls, v):
        if not v or not v.strip():
            raise ValueError('text is required')
        if len(v) > MAX_TRANSLATE_TEXT_LENGTH:
            raise ValueError(f'text exceeds {MAX_TRANSLATE_TEXT_LENGTH} characters')
        return v

    @validator('target_lang')
    def validate_target_lang(cls, v):
        if not v or not v.strip():
            raise ValueError('target_lang is required')
        return v.strip()


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


def get_kie_chat_urls() -> List[str]:
    """Primary Kie chat URL plus optional fallback endpoints."""
    urls: List[str] = []
    primary = (KIE_CHAT_URL or "").strip()
    if primary:
        urls.append(primary)
    fallback_env = os.getenv("KIE_CHAT_FALLBACK_URL", "")
    if fallback_env:
        for item in fallback_env.split(","):
            item = item.strip()
            if item and item not in urls:
                urls.append(item)
    elif DEFAULT_KIE_FALLBACK_URL not in urls:
        urls.append(DEFAULT_KIE_FALLBACK_URL)
    return urls


def is_kie_fallback_worthy_error(detail: str) -> bool:
    lowered = detail.lower()
    return KIE_MAINTENANCE_PHRASE in lowered or "rate limit" in lowered


def is_kie_retryable_response(
    http_status: int,
    payload: Optional[Dict[str, Any]],
    response_text: str = "",
) -> bool:
    """Return True when Kie AI returned a transient error worth retrying."""
    if http_status in KIE_RETRYABLE_HTTP_STATUSES:
        return True
    if KIE_MAINTENANCE_PHRASE in (response_text or "").lower():
        return True
    if not isinstance(payload, dict):
        return False
    api_code = payload.get("code")
    if isinstance(api_code, int) and api_code in KIE_RETRYABLE_API_CODES:
        return "choices" not in payload
    api_msg = str(payload.get("msg", ""))
    if KIE_MAINTENANCE_PHRASE in api_msg.lower():
        return "choices" not in payload
    return False


async def kie_chat_completion_to_url(
    chat_url: str,
    upstream_payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Call one Kie chat endpoint with retries for transient upstream failures."""
    last_http_status = 502
    last_payload: Dict[str, Any] = {}
    last_text = ""
    started_at = time.monotonic()
    kie_timeout = httpx.Timeout(KIE_REQUEST_TIMEOUT)

    async with httpx.AsyncClient(timeout=kie_timeout) as client:
        for attempt in range(KIE_MAX_RETRIES + 1):
            kie_response = await client.post(
                chat_url,
                json=upstream_payload,
                headers={
                    "Authorization": f"Bearer {KIE_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            last_http_status = kie_response.status_code
            last_text = kie_response.text

            try:
                last_payload = kie_response.json()
            except json.JSONDecodeError:
                last_payload = {}

            if kie_response.status_code == 200 and not is_kie_retryable_response(
                kie_response.status_code, last_payload, last_text
            ):
                return last_payload

            if attempt < KIE_MAX_RETRIES and is_kie_retryable_response(
                kie_response.status_code, last_payload, last_text
            ):
                api_code = last_payload.get("code", kie_response.status_code)
                api_msg = last_payload.get("msg", last_text[:200])
                delay = KIE_RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1.5)
                elapsed = time.monotonic() - started_at
                if elapsed + delay > KIE_MAX_RETRY_SECONDS:
                    print(
                        f"[KIE] retry budget exhausted after {elapsed:.1f}s "
                        f"(code={api_code} msg={api_msg})"
                    )
                    break
                print(
                    f"[KIE] transient error code={api_code} url={chat_url} "
                    f"attempt={attempt + 1}/{KIE_MAX_RETRIES + 1} "
                    f"retry_in={delay:.1f}s msg={api_msg}"
                )
                await asyncio.sleep(delay)
                continue

            break

    if last_http_status != 200:
        raise HTTPException(
            status_code=last_http_status if last_http_status >= 400 else 502,
            detail=f"OpenAI API error: {last_text}",
        )

    if last_payload.get("code") and last_payload.get("msg") and "choices" not in last_payload:
        raise HTTPException(
            status_code=502,
            detail=f"OpenAI API error: {last_payload.get('msg', last_payload)}",
        )

    return last_payload


async def kie_chat_completion(upstream_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Call Kie AI chat completions, falling back to alternate endpoints when needed."""
    urls = get_kie_chat_urls()
    if not urls:
        raise HTTPException(status_code=503, detail="OpenAI API error: no Kie endpoints configured")

    last_exc: Optional[HTTPException] = None
    for url_index, chat_url in enumerate(urls):
        try:
            result = await kie_chat_completion_to_url(chat_url, upstream_payload)
            if url_index > 0:
                print(f"[KIE] succeeded via fallback url: {chat_url}")
            return result
        except HTTPException as exc:
            last_exc = exc
            detail = str(exc.detail)
            if url_index < len(urls) - 1 and is_kie_fallback_worthy_error(detail):
                print(f"[KIE] url failed ({detail[:120]}), trying fallback: {urls[url_index + 1]}")
                continue
            raise

    if last_exc:
        raise last_exc
    raise HTTPException(status_code=502, detail="OpenAI API error: Kie request failed")


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


def normalize_google_translate_lang(lang: str) -> str:
    """Map extension locale codes to Google Translate language codes."""
    if not lang:
        return "en"
    mapping = {
        "iw": "he",
        "en-GB": "en",
        "pt-BR": "pt",
        "pt-PT": "pt",
        "fr-CA": "fr",
    }
    return mapping.get(lang, lang)


def split_text_for_translation(text: str, max_len: int) -> List[str]:
    """Split long text into chunks suitable for translation APIs."""
    if len(text) <= max_len:
        return [text]
    chunks: List[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= max_len:
            chunks.append(remaining)
            break
        split_at = remaining.rfind("\n", 0, max_len)
        if split_at < max_len // 3:
            split_at = remaining.rfind(" ", 0, max_len)
        if split_at < max_len // 3:
            split_at = max_len
        chunks.append(remaining[:split_at])
        remaining = remaining[split_at:]
    return chunks


async def google_cloud_translate(
    q: Union[str, List[str]],
    target_lang: str,
    source_lang: str = "auto",
    fmt: str = "text",
) -> Union[str, List[str]]:
    """Official Google Cloud Translation API v2 (text or html format)."""
    if not GOOGLE_TRANSLATE_API_KEY:
        raise HTTPException(
            status_code=503,
            detail=(
                "Google Cloud Translation API key is not configured. "
                "Set GOOGLE_TRANSLATE_API_KEY in the proxy server environment."
            ),
        )

    single = isinstance(q, str)
    q_list: List[str] = [q] if single else list(q)
    if not q_list:
        raise HTTPException(status_code=400, detail="Nothing to translate")

    tl = normalize_google_translate_lang(target_lang)
    body: Dict[str, Any] = {
        "q": q_list if not single else q_list[0],
        "target": tl,
        "format": fmt if fmt in ("text", "html") else "text",
    }
    if source_lang and source_lang != "auto":
        body["source"] = normalize_google_translate_lang(source_lang)

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            GOOGLE_CLOUD_TRANSLATE_URL,
            params={"key": GOOGLE_TRANSLATE_API_KEY},
            json=body,
        )

    if response.status_code != 200:
        detail = response.text[:300]
        raise HTTPException(
            status_code=502,
            detail=f"Google Cloud Translation API error ({response.status_code}): {detail}",
        )

    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Google Cloud Translation API invalid JSON: {exc}",
        ) from exc

    translations = payload.get("data", {}).get("translations")
    if not translations:
        raise HTTPException(status_code=502, detail="Google Cloud Translation API empty response")

    results: List[str] = []
    for item in translations:
        translated = item.get("translatedText")
        if not translated:
            raise HTTPException(status_code=502, detail="Google Cloud Translation API empty segment")
        results.append(str(translated))

    if single:
        return results[0]
    return results


async def translate_html_chunks_upstream(
    chunks: List[str],
    target_lang: str,
    source_lang: str = "auto",
) -> List[str]:
    """Translate HTML chunks, batching multiple segments per API request."""
    translated: List[str] = []
    for index in range(0, len(chunks), MAX_TRANSLATE_CHUNKS_PER_REQUEST):
        batch = chunks[index:index + MAX_TRANSLATE_CHUNKS_PER_REQUEST]
        batch_result = await google_cloud_translate(
            batch, target_lang, source_lang, fmt="html"
        )
        if isinstance(batch_result, str):
            translated.append(batch_result)
        else:
            translated.extend(batch_result)
    return translated


async def translate_text_upstream(text: str, target_lang: str, source_lang: str = "auto") -> str:
    """Translate plain text via Google Cloud Translation API (chunked for long text)."""
    parts = split_text_for_translation(text, GOOGLE_CLOUD_TRANSLATE_CHUNK)
    translated_chunks: List[str] = []
    for chunk in parts:
        result = await google_cloud_translate(chunk, target_lang, source_lang, fmt="text")
        translated_chunks.append(result if isinstance(result, str) else result[0])
    return "".join(translated_chunks)


async def verify_signed_proxy_request(
    raw_body: Dict[str, Any],
    signature: str,
) -> None:
    if not check_and_store_nonce(raw_body["nonce"]):
        raise HTTPException(
            status_code=400,
            detail="Nonce already used (replay attack detected)",
        )
    body_hash = generate_simple_body_hash({
        "timestamp": raw_body["timestamp"],
        "nonce": raw_body["nonce"],
        "request_id": raw_body["request_id"],
    })
    if not verify_request_signature(
        signature,
        raw_body["timestamp"],
        raw_body["nonce"],
        raw_body["request_id"],
        body_hash,
    ):
        raise HTTPException(status_code=401, detail="Invalid request signature")


def estr(raw: str, offset: int = 1) -> str:
    """Match extension eStr(): shift each char code by offset."""
    return "".join(chr(ord(char) + offset) for char in raw)


def dstr(raw: str, offset: int = -1) -> str:
    """Match extension dStr(): reverse eStr encoding."""
    return estr(raw, offset)


def encode_oauth_response(payload: Dict[str, Any]) -> str:
    """Extension expects plain text body: dStr(JSON.stringify(payload))."""
    return estr(json.dumps(payload, separators=(",", ":")))


def resolve_oauth_client_credentials(use_legacy_client: bool) -> tuple[str, str]:
    if use_legacy_client:
        client_id = GOOGLE_OAUTH_CLIENT_ID_LEGACY
        client_secret = GOOGLE_OAUTH_CLIENT_SECRET_LEGACY or GOOGLE_OAUTH_CLIENT_SECRET
    else:
        client_id = GOOGLE_OAUTH_CLIENT_ID
        client_secret = GOOGLE_OAUTH_CLIENT_SECRET

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=503,
            detail="Google OAuth client credentials are not configured on the proxy server",
        )

    return client_id, client_secret


def decode_refresh_token_from_body(body: Dict[str, Any]) -> str:
    refresh_token = body.get("refresh_token")
    if isinstance(refresh_token, str) and refresh_token.strip():
        return refresh_token.strip()

    encoded_token = body.get("ert")
    if isinstance(encoded_token, str) and encoded_token:
        try:
            decoded = dstr(encoded_token)
        except (ValueError, OverflowError) as exc:
            raise HTTPException(status_code=400, detail="Invalid ert encoding") from exc
        if decoded.strip():
            return decoded.strip()

    raise HTTPException(status_code=400, detail="refresh_token or ert is required")


async def google_refresh_access_token(refresh_token: str, use_legacy_client: bool) -> Dict[str, Any]:
    client_id, client_secret = resolve_oauth_client_credentials(use_legacy_client)

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            GOOGLE_OAUTH_TOKEN_URL,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    try:
        payload = response.json()
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=502,
            detail=f"Google OAuth token endpoint returned invalid JSON ({response.status_code})",
        ) from None

    if response.status_code != 200:
        # Return OAuth error in-body (HTTP 200) so the extension can prompt re-grant.
        return {
            "error": payload.get("error", "token_refresh_failed"),
            "error_description": payload.get(
                "error_description",
                f"Google OAuth token endpoint returned {response.status_code}",
            ),
        }

    if not payload.get("access_token"):
        return {
            "error": "invalid_response",
            "error_description": "Google OAuth token endpoint did not return access_token",
        }

    return payload


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
    """
    Health check for the extension (openaiClient.testConnection).
    Expects: data.status === 'healthy'
    """
    return JSONResponse(
        content={
            "status": "healthy",
            "openai_configured": bool(KIE_API_KEY),
            "translate_configured": bool(GOOGLE_TRANSLATE_API_KEY),
            "oauth_configured": bool(GOOGLE_OAUTH_CLIENT_SECRET),
            "secret_configured": bool(SECRET_KEY),
            "timestamp": int(time.time()),
        },
        headers={"Cache-Control": "no-store"},
    )


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
        upstream_payload: Dict[str, Any] = {
            "messages": raw_body["messages"],
            "temperature": raw_body.get("temperature", 0.7),
            "stream": KIE_STREAM,
        }
        if raw_body.get("max_tokens"):
            upstream_payload["max_tokens"] = raw_body["max_tokens"]

        try:
            result = await kie_chat_completion(upstream_payload)
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
        await verify_signed_proxy_request(raw_body, headers["signature"])

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


@app.post("/api/oauth/token")
@app.post("/oauthToken")
async def oauth_token(request: Request):
    """
    Refresh Google OAuth access tokens for the Chrome extension.

    Contract matches legacy extensions-auth.uc.r.appspot.com/oauthToken:
    - Request JSON: { version, ert, extension, old_client_id? }
    - Response: plain text body = eStr(JSON.stringify(google_token_response))
    """
    try:
        raw_body = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    if not isinstance(raw_body, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")

    version = raw_body.get("version")
    if version is None:
        raise HTTPException(status_code=400, detail="version is required")

    extension_item_id = raw_body.get("extension")
    if GMAIL_APP_ITEM_ID and extension_item_id and extension_item_id != GMAIL_APP_ITEM_ID:
        raise HTTPException(status_code=403, detail="Invalid extension identifier")

    refresh_token = decode_refresh_token_from_body(raw_body)
    use_legacy_client = bool(raw_body.get("old_client_id"))

    payload = await google_refresh_access_token(refresh_token, use_legacy_client)
    return PlainTextResponse(
        content=encode_oauth_response(payload),
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/translate")
async def translate_text(
    request: Request,
    headers: Dict[str, str] = Depends(verify_extension_headers),
):
    """
    Translate text via Google Translate (server-side upstream).
    Same signed-request security as subscription-emails.
    """
    try:
        raw_body = await request.json()
        await verify_signed_proxy_request(raw_body, headers["signature"])

        target_lang = raw_body["target_lang"]
        source_lang = raw_body.get("source_lang", "auto")
        chunks = raw_body.get("chunks")

        if chunks is not None:
            if not isinstance(chunks, list) or not chunks:
                raise HTTPException(status_code=400, detail="chunks must be a non-empty array")
            for chunk in chunks:
                if not isinstance(chunk, str):
                    raise HTTPException(status_code=400, detail="each chunk must be a string")
                if len(chunk) > MAX_TRANSLATE_HTML_LENGTH:
                    raise HTTPException(
                        status_code=400,
                        detail=f"chunk exceeds {MAX_TRANSLATE_HTML_LENGTH} characters",
                    )
            translated_chunks = await translate_html_chunks_upstream(
                chunks, target_lang, source_lang
            )
            return {
                "translated_chunks": translated_chunks,
                "translated": "".join(translated_chunks),
            }

        text = raw_body.get("text")
        if not text or not str(text).strip():
            raise HTTPException(status_code=400, detail="text or chunks is required")

        fmt = raw_body.get("format", "text")
        if fmt == "html":
            translated = await google_cloud_translate(
                str(text), target_lang, source_lang, fmt="html"
            )
        else:
            translated = await translate_text_upstream(str(text), target_lang, source_lang)
        return {"translated": translated}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error processing translate request: {str(e)}")
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


