import os
import sys
import logging
from datetime import datetime, timedelta
from typing import Dict

import httpx
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from httpx import ReadTimeout, RequestError
import whoisdomain

# Logging config
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
else:
    for h in list(logger.handlers):
        logger.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

app = FastAPI()

# CORS config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("APILAYER_KEY")
if not API_KEY:
    raise RuntimeError("APILAYER_KEY environment variable is not set")

# In-memory cache: domain -> (result_dict, expiry_datetime)
cache: Dict[str, tuple] = {}
CACHE_TTL = timedelta(hours=1)

async def fetch_whois_api(client: httpx.AsyncClient, domain: str, headers: dict):
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    try:
        resp = await client.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 404:
            logger.info(f"API says domain {domain} is not registered (404).")
            return {"result": {"registered": False}}
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        raise RequestError(f"API status {e.response.status_code}: {e.response.text}")

@app.post("/whois")
async def whois_lookup(domain: str = Body(..., embed=False)):
    domain = domain.lower().strip()
    now = datetime.utcnow()

    # Check cache
    cached = cache.get(domain)
    if cached and cached[1] > now:
        logger.debug(f"Cache hit for {domain}")
        return cached[0]
    else:
        if cached:
            logger.debug(f"Cache expired for {domain}")

    headers = {"apikey": API_KEY}
    async with httpx.AsyncClient() as client:
        try:
            try:
                data = await fetch_whois_api(client, domain, headers)
                lookup_type = "whois_api"
            except ReadTimeout:
                logger.warning(f"Timeout during API lookup for {domain}, retrying...")
                data = await fetch_whois_api(client, domain, headers)
                lookup_type = "whois_api"
        except (ReadTimeout, RequestError) as e:
            logger.warning(f"API lookup failed for {domain}: {str(e)}. Falling back to local.")
            lookup_type = "local"
            data = None

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
            logger.error(f"Local lookup failed for {domain}: {str(e)}")
            return {
                "domain": domain,
                "result": "error",
                "message": f"Local WHOIS lookup failed: {str(e)}",
                "lookup_type": lookup_type
            }
    else:
        logger.debug(f"API raw response for {domain}: {data}")
        res = data.get("result", {})

        if not res or res.get("registered") is False:
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
                "status": ", ".join(res.get("status")) if isinstance(res.get("status"), list) else res.get("status", "No information"),
                "name_servers": "\n".join(ns.lower() for ns in res.get("name_servers", [])) if isinstance(res.get("name_servers"), list) else res.get("name_servers", "No information"),
                "expiration_date": res.get("expiration_date"),
                "result": "success",
                "lookup_type": lookup_type
            }
        except Exception as e:
            logger.error(f"API data parsing failed for {domain}: {str(e)}")
            return {
                "domain": domain,
                "result": "error",
                "message": f"Failed to parse API data: {str(e)}",
                "lookup_type": lookup_type
            }

    # Cache only successful results
    if result["result"] == "success":
        cache[domain] = (result, now + CACHE_TTL)
    return result
