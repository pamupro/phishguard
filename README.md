<div align="center">

```
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
```

### 🛡️ Real-time Phishing Detection Dashboard

[![Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)

<br/>

> Detect phishing URLs, malicious emails, suspicious domains, and dangerous file attachments — powered by **VirusTotal**, **Google Safe Browsing**, **URLhaus**, and **AbuseIPDB**.

</div>

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔗 **URL Scanner** | Detects phishing URLs via VirusTotal, Google Safe Browsing, URLhaus, and pattern analysis |
| ✉️ **Email Analyzer** | Inspects SPF/DKIM/DMARC headers, urgency language, spoofed senders, and embedded links |
| 🌐 **Domain Checker** | Catches typosquatting, homoglyph attacks, lookalike brand domains, and suspicious TLDs |
| 📎 **File Upload Scanner** | Scans attachments via VirusTotal for malware, macros, and embedded threats |
| 📊 **Live Threat Feed** | Real-time stream of detections with severity ratings (HIGH / MED / LOW) |
| 📈 **Dashboard Overview** | Stats, threat breakdowns, and severity distribution charts |
| ⚡ **Async FastAPI Backend** | Parallel API calls for fast, non-blocking scans |
| 🐳 **Docker Ready** | One-command deployment anywhere |

---

## 🏗️ Tech Stack

```
Frontend          Backend           Threat Intelligence
─────────         ───────           ───────────────────
HTML / CSS / JS   FastAPI           VirusTotal API
Vanilla JS        Python 3.12       Google Safe Browsing
                  httpx (async)     URLhaus (free)
                  Pydantic          AbuseIPDB
                  Uvicorn
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- pip

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
```

### 2. Install dependencies

```bash
cd backend
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure API keys

```bash
cp .env.example .env
```

Open `.env` and add your keys:

```env
VIRUSTOTAL_API_KEY=your_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
# URLhaus needs no key — it's completely free!
```

### 4. Start the backend

```bash
uvicorn main:app --reload --port 8000
```

### 5. Open the frontend

Open `index.html` in your browser — or serve it:

```bash
npx serve .
# Visit http://localhost:3000
```

> **No backend?** The frontend runs in **demo mode** automatically — all scanners still work with simulated results.

---

## 🔑 Get Your Free API Keys

| Service | Free Tier | Sign Up |
|---|---|---|
| **VirusTotal** | 500 requests/day | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| **Google Safe Browsing** | 10,000 requests/day | [console.cloud.google.com](https://console.cloud.google.com) → Enable Safe Browsing API |
| **AbuseIPDB** | 1,000 requests/day | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| **URLhaus** | ∞ Unlimited | No key needed — free forever |

---

## 📡 API Reference

Base URL: `http://localhost:8000`  
Interactive docs: [`/docs`](http://localhost:8000/docs) ← Swagger UI, auto-generated by FastAPI

### Endpoints

```
POST  /scan/url      Scan a URL for phishing
POST  /scan/domain   Check a domain for spoofing / lookalike
POST  /scan/email    Analyze email headers and body
POST  /scan/file     Upload a file for malware scanning
GET   /health        Check server status and configured API keys
GET   /docs          Interactive Swagger UI
```

### Example — Scan a URL

```bash
curl -X POST http://localhost:8000/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypa1-verify.xyz/login"}'
```

**Response:**

```json
{
  "verdict": "DANGEROUS",
  "risk_score": 91,
  "indicators": [
    { "label": "VT: 12/94 engines flagged", "type": "bad" },
    { "label": "Google Safe Browsing: SOCIAL_ENGINEERING", "type": "bad" },
    { "label": "URLhaus: listed as phishing", "type": "bad" },
    { "label": "Suspicious keyword: 'verify'", "type": "warn" },
    { "label": "Suspicious TLD: .xyz", "type": "warn" }
  ],
  "details": "High-confidence phishing URL — do not visit.",
  "sources": [
    { "name": "VirusTotal", "result": "12 malicious, 3 suspicious", "link": "https://virustotal.com/..." },
    { "name": "Google Safe Browsing", "result": "Threat found", "link": "" },
    { "name": "URLhaus", "result": "Listed", "link": "https://urlhaus.abuse.ch" }
  ]
}
```

---

## 🐳 Deploy with Docker

```bash
# Build the image
docker build -t phishguard-api ./backend

# Run with your .env file
docker run -p 8000:8000 --env-file backend/.env phishguard-api
```

---

## ☁️ Deploy to Railway (Free Hosting)

Railway auto-detects the Dockerfile and deploys in minutes:

1. Push your code to GitHub
2. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub**
3. Select your `phishguard` repo
4. Add environment variables in the **Variables** tab
5. Copy your Railway URL and update `API_BASE` in `index.html`:

```javascript
const API_BASE = 'https://your-app.railway.app';
```

---

## 📁 Project Structure

```
phishguard/
├── index.html              # Frontend dashboard (zero dependencies)
├── README.md
└── backend/
    ├── main.py             # FastAPI app — all routes and integrations
    ├── requirements.txt    # Python dependencies
    ├── Dockerfile          # Container definition
    ├── .env.example        # API key template (copy to .env)
    └── README.md           # Backend-specific docs
```

---

## 🛡️ How Detection Works

```
Input (URL / Email / Domain / File)
         │
         ▼
  ┌──────────────┐     ┌───────────────────────┐
  │  FastAPI     │────▶│  VirusTotal            │
  │  Backend     │────▶│  Google Safe Browsing  │  (parallel async calls)
  │              │────▶│  URLhaus               │
  │              │────▶│  AbuseIPDB             │
  └──────────────┘     └───────────────────────┘
         │
         ▼
  Scoring Engine
  (aggregates signals + applies heuristics)
         │
         ▼
  Verdict: SAFE / SUSPICIOUS / DANGEROUS
  + Risk Score (0–100)
  + Indicator tags with source attribution
```

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

**Ideas for contributions:**
- 🔒 Add rate limiting / API key authentication
- 💾 Store scan history in SQLite or PostgreSQL
- 📧 Email alert notifications for new threats
- 🧩 Browser extension integration
- 📊 More chart types on the dashboard

---

## ⚠️ Disclaimer

PhishGuard is intended for **defensive security research and educational purposes only**. Always ensure you have permission before scanning URLs or domains that do not belong to you.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made with ❤️ for a safer internet

**⭐ Star this repo if you find it useful!**

</div>
