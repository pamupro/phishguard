# PhishGuard Backend API

FastAPI backend powering the PhishGuard phishing detection dashboard.  
Integrates **VirusTotal**, **Google Safe Browsing**, **URLhaus**, and **AbuseIPDB**.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/scan/url` | Scan a URL for phishing |
| POST | `/scan/domain` | Check a domain for spoofing |
| POST | `/scan/email` | Analyze email content |
| POST | `/scan/file` | Scan an uploaded file |
| GET | `/health` | Check API status + configured keys |
| GET | `/docs` | Interactive Swagger UI (auto-generated) |

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard/backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure API Keys

```bash
cp .env.example .env
# Edit .env and add your API keys
```

Get your free API keys:
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey (free tier: 500 req/day)
- **Google Safe Browsing**: https://console.cloud.google.com → Enable "Safe Browsing API" → Create API key
- **AbuseIPDB**: https://www.abuseipdb.com/account/api (free tier: 1000 req/day)
- **URLhaus**: No key needed — completely free!

### 3. Run the Server

```bash
uvicorn main:app --reload --port 8000
```

Visit http://localhost:8000/docs to see the interactive API documentation.

### 4. Connect the Frontend

In `index.html`, update the `API_BASE` variable:
```javascript
const API_BASE = 'http://localhost:8000'; // development
// or:
const API_BASE = 'https://your-deployed-api.railway.app'; // production
```

## Deploy to Railway (Free)

Railway is the easiest way to host this backend for free:

1. Push your code to GitHub
2. Go to https://railway.app → **New Project** → **Deploy from GitHub repo**
3. Select your `phishguard` repo → choose the `backend/` folder
4. Add your environment variables in Railway's **Variables** tab
5. Railway auto-detects the Dockerfile and deploys it
6. Copy your Railway URL and update `API_BASE` in the frontend

## Deploy with Docker

```bash
docker build -t phishguard-api .
docker run -p 8000:8000 --env-file .env phishguard-api
```

## Example Requests

```bash
# Scan a URL
curl -X POST http://localhost:8000/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypa1-verify.xyz/login"}'

# Check a domain
curl -X POST http://localhost:8000/scan/domain \
  -H "Content-Type: application/json" \
  -d '{"domain": "amaz0n-account-verify.xyz"}'

# Analyze email
curl -X POST http://localhost:8000/scan/email \
  -H "Content-Type: application/json" \
  -d '{"content": "From: support@paypa1.com\nSubject: URGENT: Account suspended"}'

# Scan a file
curl -X POST http://localhost:8000/scan/file \
  -F "file=@suspicious.doc"
```

## Security Notes

- Never commit your `.env` file (it's in `.gitignore`)
- Lock down `CORS` in `main.py` to your specific frontend domain in production
- The free VirusTotal tier allows 500 requests/day — consider caching results
