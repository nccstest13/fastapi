import os
import sys
import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import httpx
from fastapi.middleware.cors import CORSMiddleware

# --- LOGGING SETUP ---
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Clear existing handlers
for h in logger.handlers:
    logger.removeHandler(h)

# Add a single StreamHandler
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# --- FASTAPI SETUP ---
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Use specific domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("APILAYER_KEY")
if not API_KEY:
    raise RuntimeError("APILAYER_KEY env var is not set")

class DomainsRequest(BaseModel):
    domains: List[str]

@app.post("/whois")
async def whois_lookup(request: DomainsRequest):
    domains = request.domains
    if not domains:
        raise HTTPException(status_code=400, detail="Invalid domains list")

    results = []
    min_remaining_day: Optional[int] = None

    headers = { "apikey": API_KEY }

    async with httpx.AsyncClient() as client:
        for domain in domains:
            url = f"https://api.apilayer.com/whois/query?domain={domain}"
            logger.debug(f"Requesting WHOIS for: {domain}")

            try:
                resp = await client.get(url, headers=headers, timeout=10.0)
                logger.debug(f"[{domain}] Status code: {resp.status_code}")
                logger.debug(f"[{domain}] Raw response: {resp.text}")
            except httpx.ReadTimeout:
                logger.error(f"[{domain}] Timeout occurred.")
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": "Timeout on the end of upstream provider. Try again later"
                })
                continue
            except httpx.RequestError as e:
                logger.error(f"[{domain}] Request error: {str(e)}")
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": f"Request error: {str(e)}"
                })
                continue

            if resp.status_code == 429:
                logger.warning(f"[{domain}] Rate limit exceeded.")
                raise HTTPException(status_code=429, detail="Too many requests. Rate limit exceeded.")

            if resp.status_code >= 500:
                logger.error(f"[{domain}] Upstream server error.")
                raise HTTPException(status_code=502, detail="Upstream WHOIS API provider error.")

            # Rate limit header
            day_remaining_str = resp.headers.get("X-RateLimit-Remaining-Day")
            if day_remaining_str:
                try:
                    day_remaining = int(day_remaining_str)
                    if min_remaining_day is None or day_remaining < min_remaining_day:
                        min_remaining_day = day_remaining
                    logger.debug(f"[{domain}] X-RateLimit-Remaining-Day: {day_remaining}")
                except ValueError:
                    logger.warning(f"[{domain}] Invalid rate limit header: {day_remaining_str}")

            # Parse JSON
            try:
                data = resp.json()
                logger.debug(f"[{domain}] Parsed JSON: {data}")
            except Exception as e:
                logger.error(f"[{domain}] JSON parse error: {str(e)}")
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": "Invalid JSON response from API"
                })
                continue

            if data.get("result") == "error":
                logger.warning(f"[{domain}] API returned error: {data.get('message')}")
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": data.get("message", "Unknown error")
                })
                continue

            res = data.get("result", {})
            logger.debug(f"[{domain}] Extracted 'result' field: {res}")

            results.append({
                "domain": domain,
                "creation_date": res.get("creation_date", "No information"),
                "registrar": res.get("registrar", "No information"),
                "status": ", ".join(res.get("status")) if isinstance(res.get("status"), list) else res.get("status", "No information"),
                "name_servers": "\n".join([ns.lower() for ns in res.get("name_servers", [])]) if isinstance(res.get("name_servers"), list) else res.get("name_servers", "No information"),
                "expiration_date": res.get("expiration_date"),
                "result": "success"
            })

    return { "results": results, "minRemainingDay": min_remaining_day }
