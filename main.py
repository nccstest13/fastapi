from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Body
import os, sys, logging
import httpx
from httpx import ReadTimeout, RequestError
import whoisdomain
from datetime import datetime, timedelta
from typing import Dict

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
if logger.hasHandlers():
    logger.handlers.clear()
logger.addHandler(handler)

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with frontend origin for better security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ENV
API_KEY = os.getenv("APILAYER_KEY")
if not API_KEY:
    raise RuntimeError("APILAYER_KEY env var is not set")

# Cache: domain -> (result, expiry_time)
cache: Dict[str, tuple] = {}
CACHE_TTL = timedelta(hours=1)

async def fetch_whois_api(client: httpx.AsyncClient, domain: str, headers: dict):
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    resp = await client.get(url, headers=headers, timeout=10.0)
    resp.raise_for_status()
    return resp.json()

@app.post("/whois")
async def whois_lookup(domain: str = Body(...)):
    domain = domain.lower().strip()
    now = datetime.utcnow()

    # Check cache
    if domain in cache and cache[domain][1] > now:
        logger.debug(f"Cache hit for domain: {domain}")
        return cache[domain][0]
    elif domain in cache:
        logger.debug(f"Cache expired for domain: {domain}")

    headers = {"apikey": API_KEY}
    lookup_type = "whois_api"
    data = None

    async with httpx.AsyncClient() as client:
        try:
            try:
                data = await fetch_whois_api(client, domain, headers)
            except ReadTimeout:
                logger.warning(f"Timeout on API lookup for {domain}, retrying once...")
                data = await fetch_whois_api(client, domain, headers)
        except (ReadTimeout, RequestError) as e:
            logger.warning(f"API lookup failed for {domain}: {e}. Falling back to local.")
            lookup_type = "local"

    if lookup_type == "local":
        try:
            w = whoisdomain.Whois(domain)
            logger.debug(f"Local WHOIS raw data for {domain}: {vars(w)}")
            result = {
                "domain": domain,
                "creation_date": w.creation_date or "No information",
                "registrar": w.registrar or "No information",
                "status": ", ".join(w.status) if w.status else "No information",
                "name_servers": "\n".join(w.name_servers) if w.name_servers else "No information",
                "expiration_date": w.expiration_date,
                "result": "success",
                "lookup_type": lookup_type
            }
        except Exception as e:
            logger.error(f"Local WHOIS failed for {domain}: {str(e)}")
            return {
                "domain": domain,
                "result": "error",
                "message": f"Local WHOIS failed: {str(e)}",
                "lookup_type": lookup_type
            }
    else:
        if data.get("result") == "error":
            logger.error(f"API returned error for {domain}: {data.get('message')}")
            return {
                "domain": domain,
                "result": "error",
                "message": data.get("message", "Unknown error"),
                "lookup_type": lookup_type
            }

        res = data.get("result", {})
        result = {
            "domain": domain,
            "creation_date": res.get("creation_date", "No information"),
            "registrar": res.get("registrar", "No information"),
            "status": ", ".join(res.get("status")) if isinstance(res.get("status"), list) else res.get("status", "No information"),
            "name_servers": "\n".join(ns.lower() for ns in res.get("name_servers", [])) if isinstance(res.get("name_servers"), list) else res.get("name_servers", "No information"),
            "expiration_date": res.get("expiration_date"),
            "result": "success",
            "lookup_type": lookup_type
        }

    cache[domain] = (result, now + CACHE_TTL)
    return result
