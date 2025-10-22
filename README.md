# Gmail Extension Backend Server

Python FastAPI backend for handling OpenAI API requests with sophisticated security validation.

## Features

- **Multi-layer Security Validation**
  - Custom header verification (extension ID, version, fingerprint)
  - HMAC-SHA256 request signature validation
  - Timestamp validation (prevents old request replay)
  - Nonce tracking (prevents replay attacks)
  - Body hash integrity verification
  
- **Rate Limiting & Usage Tracking**
  - Per-client usage statistics
  - Token usage tracking
  - Request counting

- **OpenAI Proxy**
  - Secure API key storage
  - Request validation before proxying
  - Support for multiple GPT models

## Setup

### 1. Install Python Dependencies

```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:
```
OPENAI_API_KEY=sk-proj-your-actual-key
SECRET_KEY=generate-a-random-32-character-string
ADMIN_KEY=another-random-string-for-admin-access
ALLOWED_EXTENSION_ID=your-chrome-extension-id
PORT=8000
```

**Important**: The `SECRET_KEY` must match the one in your extension's client-side code!

### 3. Get Your Extension ID

1. Go to `chrome://extensions/` in Chrome
2. Enable "Developer mode"
3. Find your extension and copy its ID (long string like `abcdefghijklmnopqrstuvwxyz123456`)
4. Put this ID in `.env` as `ALLOWED_EXTENSION_ID`

### 4. Run the Server

```bash
# Development mode (with auto-reload)
python main.py

# Or using uvicorn directly
uvicorn main:app --reload --port 8000
```

Server will start at `http://localhost:8000`

## API Endpoints

### Health Check
```
GET /
GET /api/health
```

### Chat Completion
```
POST /api/openai/chat
```

**Required Headers:**
- `X-Extension-Version`: Extension version (e.g., "1.0.0")
- `X-Extension-Id`: Your extension ID
- `X-Request-Signature`: HMAC signature of request
- `X-Client-Fingerprint`: Unique client identifier

**Request Body:**
```json
{
  "messages": [
    {"role": "user", "content": "Hello"}
  ],
  "model": "gpt-3.5-turbo",
  "temperature": 0.7,
  "timestamp": 1698765432,
  "nonce": "random-unique-string",
  "request_id": "unique-request-id"
}
```

### Usage Statistics (Admin Only)
```
GET /api/stats
Header: X-Admin-Key: your-admin-key
```

## Security Features Explained

### 1. Extension ID Verification
Only requests from your specific Chrome extension are accepted.

### 2. Request Signature
Each request must include an HMAC signature calculated as:
```
HMAC-SHA256(timestamp|nonce|request_id|body_hash, SECRET_KEY)
```

### 3. Timestamp Validation
Requests older than 5 minutes are rejected to prevent replay attacks.

### 4. Nonce Tracking
Each nonce can only be used once. Duplicate nonces are rejected.

### 5. Body Hash
Request body is hashed to ensure it hasn't been tampered with.

### 6. Client Fingerprint
Unique identifier for each client installation, used for usage tracking.

## Deployment

### Option 1: Heroku
```bash
# Install Heroku CLI, then:
heroku create your-app-name
heroku config:set OPENAI_API_KEY=your-key
heroku config:set SECRET_KEY=your-secret
heroku config:set ALLOWED_EXTENSION_ID=your-extension-id
git push heroku master
```

### Option 2: DigitalOcean App Platform
1. Connect your GitHub repo
2. Set environment variables in dashboard
3. Deploy automatically

### Option 3: AWS Lambda (Serverless)
Use Mangum adapter for FastAPI on Lambda

### Option 4: Docker
```bash
docker build -t gmail-extension-backend .
docker run -p 8000:8000 --env-file .env gmail-extension-backend
```

## Production Considerations

1. **Use Redis for Nonce Storage**
   - Current implementation uses in-memory storage
   - Switch to Redis for distributed systems

2. **Database for Usage Tracking**
   - Store usage stats in PostgreSQL/MySQL
   - Enable better analytics and billing

3. **Rate Limiting**
   - Add proper rate limiting middleware
   - Consider using slowapi or similar

4. **HTTPS**
   - Always use HTTPS in production
   - Get SSL certificate (Let's Encrypt is free)

5. **Monitoring**
   - Add logging (e.g., with Sentry)
   - Monitor API costs
   - Set up alerts for unusual activity

6. **Secrets Management**
   - Use AWS Secrets Manager, Azure Key Vault, etc.
   - Rotate keys regularly

## Testing

Test the health endpoint:
```bash
curl http://localhost:8000/api/health
```

Test with the extension running, or use the test script (create one if needed).

## Troubleshooting

### CORS Errors
- Verify `ALLOWED_EXTENSION_ID` matches your actual extension ID
- Check browser console for the actual origin being sent

### Invalid Signature Errors
- Ensure `SECRET_KEY` matches between backend and extension
- Check that timestamp is being generated correctly
- Verify body hash calculation matches on both sides

### OpenAI API Errors
- Check your `OPENAI_API_KEY` is valid
- Verify you have credits in your OpenAI account
- Check the model name is correct

## Support

For issues, check the logs:
```bash
# Server logs will show detailed error messages
```

