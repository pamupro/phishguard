"""
PhishGuard Backend API
FastAPI server integrating VirusTotal, Google Safe Browsing, URLhaus, and AbuseIPDB
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import hashlib
import base64
import asyncio
import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="PhishGuard API",
    description="Phishing detection API powered by VirusTotal, Google Safe Browsing, URLhaus & AbuseIPDB",
    version="1.0.0"
)

# Allow your frontend (GitHub Pages or localhost) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock this down in production to your actual domain
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Keys (set in .env file) ──────────────────────────────────────────────
VT_API_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
GSB_API_KEY      = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
ABUSEIPDB_KEY    = os.getenv("ABUSEIPDB_API_KEY", "")
# URLhaus is free — no key needed

# ── Request / Response Models ────────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str

class DomainRequest(BaseModel):
    domain: str

class EmailRequest(BaseModel):
    content: str  # raw email headers + body

class ScanResult(BaseModel):
    verdict: str           # SAFE | SUSPICIOUS | DANGEROUS
    risk_score: int        # 0–100
    indicators: list[dict] # [{label, type}]  type: good|warn|bad
    details: str
    sources: list[dict]    # [{name, result, link}]


# ── Helpers ──────────────────────────────────────────────────────────────────

def score_to_verdict(score: int) -> str:
    if score >= 70: return "DANGEROUS"
    if score >= 35: return "SUSPICIOUS"
    return "SAFE"

def vt_url_id(url: str) -> str:
    """VirusTotal expects base64url-encoded URL (no padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


# ── VirusTotal ───────────────────────────────────────────────────────────────

async def virustotal_scan_url(url: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}
    url_id = vt_url_id(url)

    async with httpx.AsyncClient(timeout=15) as client:
        # First try a GET (cached result)
        r = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )
        if r.status_code == 404:
            # Submit for analysis
            submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )
            if submit.status_code != 200:
                return {"error": f"VT submit failed: {submit.status_code}"}
            analysis_id = submit.json()["data"]["id"]
            # Poll once (in production, use a queue)
            await asyncio.sleep(3)
            r = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )

        if r.status_code != 200:
            return {"error": f"VT error: {r.status_code}"}

        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "total_engines": total,
            "link": f"https://www.virustotal.com/gui/url/{url_id}"
        }


async def virustotal_scan_file(file_bytes: bytes, filename: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    file_hash = hashlib.sha256(file_bytes).hexdigest()
    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}

    async with httpx.AsyncClient(timeout=30) as client:
        # Check by hash first (free, instant)
        r = await client.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers
        )
        if r.status_code == 404:
            # Upload the file
            files = {"file": (filename, file_bytes)}
            upload = await client.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files=files
            )
            if upload.status_code != 200:
                return {"error": f"VT upload failed: {upload.status_code}"}
            analysis_id = upload.json()["data"]["id"]
            await asyncio.sleep(5)
            r = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )

        if r.status_code != 200:
            return {"error": f"VT error: {r.status_code}"}

        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()) or 1,
            "sha256": file_hash,
            "link": f"https://www.virustotal.com/gui/file/{file_hash}"
        }


# ── Google Safe Browsing ─────────────────────────────────────────────────────

async def google_safe_browsing(url: str) -> dict:
    if not GSB_API_KEY:
        return {"error": "Google Safe Browsing API key not configured"}

    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=payload
        )
        if r.status_code != 200:
            return {"error": f"GSB error: {r.status_code}"}

        data = r.json()
        matches = data.get("matches", [])
        return {
            "is_threat": len(matches) > 0,
            "threats": [m.get("threatType") for m in matches],
            "match_count": len(matches)
        }


# ── URLhaus ──────────────────────────────────────────────────────────────────

async def urlhaus_lookup(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url}
        )
        if r.status_code != 200:
            return {"error": f"URLhaus error: {r.status_code}"}

        data = r.json()
        query_status = data.get("query_status", "")
        return {
            "found": query_status == "is_listed",
            "status": query_status,
            "threat": data.get("threat", ""),
            "tags": data.get("tags", []),
            "blacklists": data.get("blacklists", {})
        }


# ── AbuseIPDB ────────────────────────────────────────────────────────────────

async def abuseipdb_check(ip_or_domain: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"error": "AbuseIPDB API key not configured"}

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip_or_domain, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        )
        if r.status_code != 200:
            return {"error": f"AbuseIPDB error: {r.status_code}"}

        data = r.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "is_whitelisted": data.get("isWhitelisted", False)
        }


# ── Scoring Engine ───────────────────────────────────────────────────────────

def build_url_result(url: str, vt: dict, gsb: dict, urlhaus: dict) -> ScanResult:
    score = 0
    indicators = []
    sources = []

    # VirusTotal
    if "error" not in vt:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        total = vt.get("total_engines", 1)
        if mal > 5:
            score += 50
            indicators.append({"label": f"VT: {mal}/{total} engines flagged", "type": "bad"})
        elif mal > 0:
            score += 25
            indicators.append({"label": f"VT: {mal}/{total} engines flagged", "type": "warn"})
        else:
            indicators.append({"label": f"VT: clean ({total} engines)", "type": "good"})
        if sus > 0:
            score += 10
            indicators.append({"label": f"VT: {sus} suspicious detections", "type": "warn"})
        sources.append({"name": "VirusTotal", "result": f"{mal} malicious, {sus} suspicious", "link": vt.get("link", "")})
    else:
        indicators.append({"label": "VirusTotal: not configured", "type": "warn"})

    # Google Safe Browsing
    if "error" not in gsb:
        if gsb.get("is_threat"):
            score += 40
            for t in gsb.get("threats", []):
                indicators.append({"label": f"GSB: {t.replace('_', ' ').title()}", "type": "bad"})
        else:
            indicators.append({"label": "Google Safe Browsing: clean", "type": "good"})
        sources.append({"name": "Google Safe Browsing", "result": "Threat found" if gsb.get("is_threat") else "Clean", "link": ""})
    else:
        indicators.append({"label": "Google Safe Browsing: not configured", "type": "warn"})

    # URLhaus
    if "error" not in urlhaus:
        if urlhaus.get("found"):
            score += 35
            indicators.append({"label": f"URLhaus: listed as {urlhaus.get('threat', 'malware')}", "type": "bad"})
            for tag in urlhaus.get("tags") or []:
                indicators.append({"label": f"Tag: {tag}", "type": "bad"})
        else:
            indicators.append({"label": "URLhaus: not listed", "type": "good"})
        sources.append({"name": "URLhaus", "result": "Listed" if urlhaus.get("found") else "Not listed", "link": "https://urlhaus.abuse.ch"})

    # Heuristic checks
    suspicious_patterns = ["login", "verify", "secure", "account", "update", "confirm", "paypa", "amaz", "micros", "apple-id"]
    suspicious_tlds = [".xyz", ".top", ".info", ".tk", ".ml", ".ga", ".cf"]
    for p in suspicious_patterns:
        if p in url.lower():
            score += 5
            indicators.append({"label": f"Suspicious keyword: '{p}'", "type": "warn"})
            break
    for tld in suspicious_tlds:
        if tld in url.lower():
            score += 10
            indicators.append({"label": f"Suspicious TLD: {tld}", "type": "warn"})
            break
    if not url.startswith("https://"):
        score += 10
        indicators.append({"label": "No HTTPS", "type": "bad"})
    else:
        indicators.append({"label": "HTTPS present", "type": "good"})

    score = min(score, 100)
    verdict = score_to_verdict(score)

    detail_map = {
        "SAFE": "No significant threats detected across all sources.",
        "SUSPICIOUS": "Some indicators found — manual review recommended.",
        "DANGEROUS": "High-confidence phishing URL — do not visit."
    }

    return ScanResult(
        verdict=verdict,
        risk_score=score,
        indicators=indicators,
        details=detail_map[verdict],
        sources=sources
    )


# ── API Routes ───────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "PhishGuard API is running", "docs": "/docs"}


@app.post("/scan/url", response_model=ScanResult)
async def scan_url(req: URLRequest):
    """Scan a URL using VirusTotal, Google Safe Browsing, and URLhaus."""
    if not req.url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    vt, gsb, urlhaus = await asyncio.gather(
        virustotal_scan_url(req.url),
        google_safe_browsing(req.url),
        urlhaus_lookup(req.url),
        return_exceptions=True
    )

    vt = vt if isinstance(vt, dict) else {"error": str(vt)}
    gsb = gsb if isinstance(gsb, dict) else {"error": str(gsb)}
    urlhaus = urlhaus if isinstance(urlhaus, dict) else {"error": str(urlhaus)}

    return build_url_result(req.url, vt, gsb, urlhaus)


@app.post("/scan/domain", response_model=ScanResult)
async def scan_domain(req: DomainRequest):
    """Check a domain via VirusTotal + URLhaus + heuristics."""
    url = f"http://{req.domain}" if not req.domain.startswith("http") else req.domain
    vt, urlhaus = await asyncio.gather(
        virustotal_scan_url(url),
        urlhaus_lookup(url),
        return_exceptions=True
    )
    vt = vt if isinstance(vt, dict) else {"error": str(vt)}
    urlhaus = urlhaus if isinstance(urlhaus, dict) else {"error": str(urlhaus)}

    # Domain-specific heuristics
    score = 0
    indicators = []
    sources = []

    if "error" not in vt:
        mal = vt.get("malicious", 0)
        if mal > 0:
            score += 40
            indicators.append({"label": f"VT: {mal} engines flagged domain", "type": "bad"})
        else:
            indicators.append({"label": "VT: domain not flagged", "type": "good"})
        sources.append({"name": "VirusTotal", "result": f"{mal} flagged", "link": vt.get("link", "")})

    if "error" not in urlhaus and urlhaus.get("found"):
        score += 35
        indicators.append({"label": "URLhaus: domain listed", "type": "bad"})

    # Lookalike detection (basic)
    brands = ["paypal", "amazon", "apple", "microsoft", "google", "netflix", "facebook", "instagram", "bank"]
    d = req.domain.lower()
    for brand in brands:
        if brand in d and brand + ".com" not in d:
            score += 25
            indicators.append({"label": f"Lookalike of '{brand}' detected", "type": "bad"})
            break

    suspicious_tlds = [".xyz", ".top", ".info", ".tk", ".ml", ".ga", ".cf", ".cc"]
    for tld in suspicious_tlds:
        if d.endswith(tld):
            score += 15
            indicators.append({"label": f"High-risk TLD: {tld}", "type": "warn"})
            break

    has_numbers = any(c.isdigit() for c in d.split(".")[0])
    if has_numbers:
        score += 10
        indicators.append({"label": "Digits in domain name (homoglyph risk)", "type": "warn"})

    score = min(score, 100)
    verdict = score_to_verdict(score)

    return ScanResult(
        verdict=verdict,
        risk_score=score,
        indicators=indicators,
        details=f"Domain analysis complete. {'High risk detected.' if score >= 70 else 'Some indicators found.' if score >= 35 else 'Domain appears legitimate.'}",
        sources=sources
    )


@app.post("/scan/email", response_model=ScanResult)
async def scan_email(req: EmailRequest):
    """Analyze email content for phishing indicators."""
    content = req.content.lower()
    score = 0
    indicators = []
    sources = [{"name": "Heuristic Engine", "result": "Pattern analysis", "link": ""}]
    urls_found = []

    # Extract URLs for scanning
    import re
    found_urls = re.findall(r'https?://[^\s<>"]+', req.content)
    urls_found = found_urls[:3]  # Limit to first 3

    # Urgency language
    urgency_words = ["urgent", "immediately", "suspended", "verify now", "act now", "limited time", "expires", "locked", "unauthorized"]
    found_urgency = [w for w in urgency_words if w in content]
    if found_urgency:
        score += 20
        indicators.append({"label": f"Urgency language: {', '.join(found_urgency[:2])}", "type": "bad"})

    # Spoofed sender patterns
    spoof_patterns = ["paypa1", "amaz0n", "micros0ft", "app1e", "gooogle", "netfllx"]
    for p in spoof_patterns:
        if p in content:
            score += 30
            indicators.append({"label": f"Spoofed sender pattern: '{p}'", "type": "bad"})

    # Authentication failures
    if "spf=fail" in content or "spf=softfail" in content:
        score += 20
        indicators.append({"label": "SPF check failed", "type": "bad"})
    elif "spf=pass" in content:
        indicators.append({"label": "SPF passed", "type": "good"})

    if "dkim=fail" in content or "dkim=none" in content:
        score += 15
        indicators.append({"label": "DKIM check failed/missing", "type": "warn"})
    elif "dkim=pass" in content:
        indicators.append({"label": "DKIM passed", "type": "good"})

    if "dmarc=fail" in content:
        score += 15
        indicators.append({"label": "DMARC failed", "type": "bad"})

    # Reply-to mismatch indicator
    if "reply-to:" in content and "from:" in content:
        from_match = re.search(r'from:.*?@([\w.-]+)', content)
        reply_match = re.search(r'reply-to:.*?@([\w.-]+)', content)
        if from_match and reply_match and from_match.group(1) != reply_match.group(1):
            score += 20
            indicators.append({"label": "Reply-To domain differs from From domain", "type": "bad"})

    # Credential harvesting keywords
    cred_words = ["password", "username", "credit card", "ssn", "social security", "bank account", "login credentials"]
    for w in cred_words:
        if w in content:
            score += 10
            indicators.append({"label": f"Credential request: '{w}'", "type": "bad"})
            break

    # Suspicious URLs in email
    if urls_found:
        # Scan the first URL found
        vt = await virustotal_scan_url(urls_found[0])
        urlhaus = await urlhaus_lookup(urls_found[0])
        if "error" not in vt and vt.get("malicious", 0) > 0:
            score += 30
            indicators.append({"label": f"Malicious URL found in email (VT: {vt['malicious']} engines)", "type": "bad"})
        elif urls_found:
            indicators.append({"label": f"{len(urls_found)} URL(s) found in email", "type": "warn"})
        if "error" not in urlhaus and urlhaus.get("found"):
            score += 25
            indicators.append({"label": "Email URL listed in URLhaus", "type": "bad"})

    if not found_urgency and score < 20:
        indicators.append({"label": "No urgency manipulation detected", "type": "good"})
    if not urls_found:
        indicators.append({"label": "No embedded URLs found", "type": "good"})

    score = min(score, 100)
    verdict = score_to_verdict(score)

    return ScanResult(
        verdict=verdict,
        risk_score=score,
        indicators=indicators,
        details=f"Email analysis complete. {'High-confidence phishing email.' if score >= 70 else 'Suspicious patterns detected.' if score >= 35 else 'Email appears legitimate.'}",
        sources=sources
    )


@app.post("/scan/file", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    """Scan an uploaded file using VirusTotal."""
    max_size = 32 * 1024 * 1024  # 32MB
    contents = await file.read()

    if len(contents) > max_size:
        raise HTTPException(status_code=413, detail="File too large (max 32MB)")

    vt = await virustotal_scan_file(contents, file.filename or "upload")

    score = 0
    indicators = []
    sources = []

    if "error" not in vt:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        total = vt.get("total_engines", 1)
        if mal > 5:
            score += 70
            indicators.append({"label": f"VT: {mal}/{total} engines detected malware", "type": "bad"})
        elif mal > 0:
            score += 40
            indicators.append({"label": f"VT: {mal}/{total} engines detected threats", "type": "warn"})
        else:
            indicators.append({"label": f"VT: clean ({total} engines scanned)", "type": "good"})
        if sus > 0:
            score += 15
            indicators.append({"label": f"VT: {sus} suspicious detections", "type": "warn"})
        sources.append({"name": "VirusTotal", "result": f"{mal} malicious", "link": vt.get("link", "")})
        indicators.append({"label": f"SHA256: {vt.get('sha256', '')[:16]}...", "type": "good"})
    else:
        indicators.append({"label": "VirusTotal: not configured", "type": "warn"})

    # File type heuristics
    fname = (file.filename or "").lower()
    risky_exts = [".exe", ".bat", ".ps1", ".vbs", ".js", ".jar", ".scr", ".com"]
    office_exts = [".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"]
    for ext in risky_exts:
        if fname.endswith(ext):
            score += 20
            indicators.append({"label": f"High-risk file type: {ext}", "type": "bad"})
            break
    for ext in office_exts:
        if fname.endswith(ext):
            score += 10
            indicators.append({"label": f"Office file — check for macros", "type": "warn"})
            break

    score = min(score, 100)
    verdict = score_to_verdict(score)

    return ScanResult(
        verdict=verdict,
        risk_score=score,
        indicators=indicators,
        details=f"File '{file.filename}' scanned. {'Malware detected.' if score >= 70 else 'Suspicious content found.' if score >= 35 else 'No threats detected.'}",
        sources=sources
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "apis_configured": {
            "virustotal": bool(VT_API_KEY),
            "google_safe_browsing": bool(GSB_API_KEY),
            "abuseipdb": bool(ABUSEIPDB_KEY),
            "urlhaus": True  # free, no key needed
        }
    }
