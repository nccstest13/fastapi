import os
import sys
import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import httpx

from fastapi.middleware.cors import CORSMiddleware


# Configure logging explicitly to stdout with formatter
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

if not logger.hasHandlers():
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
else:
    # Replace all handlers with a single stdout handler for consistency
    for h in logger.handlers:
        logger.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or your domain
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

    headers = {
        "apikey": API_KEY,
    }

    async with httpx.AsyncClient() as client:
        for domain in domains:
            url = f"https://api.apilayer.com/whois/query?domain={domain}"
            logger.debug(f"Fetching WHOIS data for domain: {domain}")
            try:
                resp = await client.get(url, headers=headers)
                logger.debug(f"Response status code for {domain}: {resp.status_code}")
                logger.debug(f"Full API response text for {domain}: {resp.text}")

            except httpx.RequestError as e:
                logger.error(f"Request error for domain {domain}: {str(e)}")
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": f"Request error: {str(e)}"
                })
                continue

            if resp.status_code == 429:
                logger.error(f"Rate limit exceeded while querying {domain}")
                raise HTTPException(status_code=429, detail="Too many requests. Rate limit exceeded.")
            if resp.status_code >= 500:
                logger.error(f"Upstream WHOIS API provider error while querying {domain}")
                raise HTTPException(status_code=502, detail="Upstream WHOIS API provider error.")

            day_remaining_str = resp.headers.get("X-RateLimit-Remaining-Day")
            if day_remaining_str is not None:
                try:
                    day_remaining = int(day_remaining_str)
                    if min_remaining_day is None or day_remaining < min_remaining_day:
                        min_remaining_day = day_remaining
                    logger.debug(f"Rate limit remaining today: {day_remaining}")
                except ValueError:
                    logger.warning(f"Invalid rate limit header value: {day_remaining_str}")

            try:
                data = resp.json()
                logger.debug(f"Parsed JSON data for {domain}: {data}")
            except Exception as e:
                logger.error(f"Invalid JSON response for {domain}: {str(e)}")
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": "Invalid JSON response from API"
                })
                continue

            if data.get("result") == "error":
                logger.error(f"API returned error for {domain}: {data.get('message')}")
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": data.get("message", "Unknown error")
                })
            else:
                # Defensive data extraction with logging
                res = data.get("result", {})
                logger.debug(f"Extracted 'result' field for {domain}: {res}")

                results.append({
                    "domain": domain,                    
                    "creation_date": res.get("creation_date", "No information"),
                    "registrar": res.get("registrar", "No information"),
                    "status": ", ".join(res.get("status")) if isinstance(res.get("status"), list) else res.get("status", "No information"),
                    "name_servers": "\n".join([ns.lower() for ns in res.get("name_servers", [])]) if isinstance(res.get("name_servers"), list) else res.get("name_servers", "No information"),
                    "expiration_date": res.get("expiration_date"),                   
                })

    return {"results": results, "minRemainingDay": min_remaining_day}
