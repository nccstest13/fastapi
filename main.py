import os
import sys
import logging
from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
import httpx
from httpx import ReadTimeout, RequestError
import whoisdomain
from datetime import datetime, timedelta

# Setup logger
logger = logging.getLogger("whois_logger")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
if not logger.hasHandlers():
    logger.addHandler(handler)
else:
    logger.handlers.clear()
    logger.addHandler(handler)

app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

API_KEY = os.getenv("APILAYER_KEY")
if not API_KEY:
    raise RuntimeError("APILAYER_KEY environment variable is not set")

cache = {}  # domain -> (result_dict, expiry)
CACHE_TTL = timedelta(hours=1)
PER_DOMAIN_DELAY_SECONDS = 2  # for estimated time calculation

async def fetch_whois_api(client: httpx.AsyncClient, domain: str, headers: dict):
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    resp = await client.get(url, headers=headers, timeout=10.0)
    logger.debug(f"API call status for {domain}: {resp.status_code}")
    logger.debug(f"API raw response for {domain}: {resp.text}")
    resp.raise_for_status()
    return resp

@app.post("/whois")
async def whois_lookup(domain: str = Body(...)):
    domain = domain.lower().strip()
    now = datetime.utcnow()
    logger.info(f"Processing lookup for domain: {domain}")

    # Estimate processing time (just 1 domain here)
    est_seconds = PER_DOMAIN_DELAY_SECONDS
    est_msg = f"Estimated processing time: ~{est_seconds} seconds."

    # Cache check
    cached = cache.get(domain)
    if cached and cached[1] > now:
        logger.debug(f"Cache hit for domain: {domain}")
        cached_result = cached[0]
        cached_result["estimated_time"] = est_msg
        return cached_result
    elif cached:
        logger.debug(f"Cache expired for domain: {domain}")

    headers = {"apikey": API_KEY}
    async with httpx.AsyncClient() as client:
        try:
            try:
                resp = await fetch_whois_api(client, domain, headers)
                lookup_type = "whois_api"
                remaining = resp.headers.get("X-RateLimit-Remaining")
                data = resp.json()
            except ReadTimeout:
                logger.warning(f"API timeout on {domain}, retrying once")
                resp = await fetch_whois_api(client, domain, headers)
                lookup_type = "whois_api"
                remaining = resp.headers.get("X-RateLimit-Remaining")
                data = resp.json()
        except (ReadTimeout, RequestError, httpx.HTTPStatusError) as e:
            logger.warning(f"API lookup failed for {domain}: {str(e)}. Falling back to local lookup.")
            lookup_type = "local"
            data = None
            remaining = None

    if lookup_type == "local":
        try:
            w = whoisdomain.query(domain)
            logger.debug(f"Local WHOIS raw data for {domain}: {w}")
            result = {
                "domain": domain,
                "creation_date": w.creation_date or "No information",
                "registrar": w.registrar or "No information",
                "status": ", ".join(w.status) if w.status else "No information",
                "name_servers": "\n".join(w.name_servers) if w.name_servers else "No information",
                "expiration_date": w.expiration_date,
                "result": "success",
                "lookup_type": lookup_type,
                "estimated_time": est_msg,
                "rate_limit_remaining": remaining,
            }
        except Exception as e:
            logger.error(f"Local WHOIS lookup failed for {domain}: {str(e)}")
            result = {
                "domain": domain,
                "result": "error",
                "message": f"Local WHOIS lookup failed: {str(e)}",
                "lookup_type": lookup_type,
                "estimated_time": est_msg,
                "rate_limit_remaining": remaining,
            }
    else:
        # API response handling
        if resp.status_code == 404:
            logger.info(f"Domain not registered: {domain}")
            result = {
                "domain": domain,
                "result": "error",
                "message": "Domain not registered",
                "lookup_type": lookup_type,
                "estimated_time": est_msg,
                "rate_limit_remaining": remaining,
            }
        elif data.get("result") == "error":
            logger.error(f"API error for {domain}: {data.get('message')}")
            result = {
                "domain": domain,
                "result": "error",
                "message": data.get("message", "Unknown error"),
                "lookup_type": lookup_type,
                "estimated_time": est_msg,
                "rate_limit_remaining": remaining,
            }
        else:
            res = data.get("result", {})
            result = {
                "domain": domain,
                "creation_date": res.get("creation_date", "No information"),
                "registrar": res.get("registrar", "No information"),
                "status": ", ".join(res.get("status")) if isinstance(res.get("status"), list) else res.get("status", "No information"),
                "name_servers": "\n".join(ns.lower() for ns in res.get("name_servers", [])) if isinstance(res.get("name_servers"), list) else res.get("name_servers", "No information"),
                "expiration_date": res.get("expiration_date"),
                "result": "success",
                "lookup_type": lookup_type,
                "estimated_time": est_msg,
                "rate_limit_remaining": remaining,
            }

    # Cache only successful lookups
    if result.get("result") == "success":
        cache[domain] = (result, now + CACHE_TTL)

    return result
