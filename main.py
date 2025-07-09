import os
import sys
import logging
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict
from datetime import datetime, timedelta
import httpx
from httpx import ReadTimeout, RequestError
import whoisdomain

# Setup logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.handlers = [handler]

# FastAPI app
app = FastAPI()

# CORS (allow all origins for testing/development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Env variable
API_KEY = os.getenv("APILAYER_KEY")
if not API_KEY:
    raise RuntimeError("APILAYER_KEY environment variable is not set")

# In-memory cache: domain → (result, expiry)
cache: Dict[str, tuple] = {}
CACHE_TTL = timedelta(hours=1)

# WHOIS API fetcher
async def fetch_whois_api(client: httpx.AsyncClient, domain: str, headers: dict):
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    resp = await client.get(url, headers=headers, timeout=10.0)
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="Domain not registered")
    resp.raise_for_status()
    return resp.json()

@app.post("/whois")
async def whois_lookup(domain: str = Body(..., embed=True)):
    domain = domain.lower().strip()
    now = datetime.utcnow()

    # Check cache
    cached = cache.get(domain)
    if cached and cached[1] > now:
        logger.debug(f"Cache hit for domain: {domain}")
        return cached[0]
    elif cached:
        logger.debug(f"Cache expired for domain: {domain}")

    headers = {"apikey": API_KEY}
    lookup_type = "whois_api"
    data = None

    # API call with retry
    async with httpx.AsyncClient() as client:
        try:
            try:
                data = await fetch_whois_api(client, domain, headers)
                logger.debug(f"API raw response for {domain}: {data}")
            except ReadTimeout:
                logger.warning(f"Timeout on API lookup for {domain}, retrying once...")
                data = await fetch_whois_api(client, domain, headers)
                logger.debug(f"API raw response after retry for {domain}: {data}")
        except (ReadTimeout, RequestError, HTTPException) as e:
            logger.warning(f"API lookup failed for {domain}: {e}")
            lookup_type = "local"

    # Handle local fallback
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
            cache[domain] = (result, now + CACHE_TTL)
            return result
        except Exception as e:
            logger.error(f"Local WHOIS lookup failed for {domain}: {str(e)}")
            return {
                "domain": domain,
                "result": "error",
                "message": f"Local WHOIS lookup failed: {str(e)}",
                "lookup_type": lookup_type
            }

    # Handle API result
    res = data.get("result", {})
    if not res:
        logger.warning(f"No result field in API response for {domain}")
        return {
            "domain": domain,
            "result": "error",
            "message": "No WHOIS data available",
            "lookup_type": lookup_type
        }

    if res.get("registered") is False:
        logger.info(f"{domain} is not registered")
        return {
            "domain": domain,
            "result": "error",
            "message": "Domain is not registered",
            "lookup_type": lookup_type
        }

    try:
        result = {
            "domain": domain,
            "creation_date": res.get("creation_date", "No information"),
            "registrar": res.get("registrar", "No information"),
            "status": ", ".join(res["status"]) if isinstance(res.get("status"), list) else res.get("status", "No information"),
            "name_servers": "\n".join(ns.lower() for ns in res.get("name_servers", [])) if isinstance(res.get("name_servers"), list) else res.get("name_servers", "No information"),
            "expiration_date": res.get("expiration_date", "No information"),
            "result": "success",
            "lookup_type": lookup_type
        }
        cache[domain] = (result, now + CACHE_TTL)
        return result
    except Exception as e:
        logger.error(f"Failed to parse API data for {domain}: {e}")
        return {
            "domain": domain,
            "result": "error",
            "message": f"API parsing failed: {str(e)}",
            "lookup_type": lookup_type
        }
