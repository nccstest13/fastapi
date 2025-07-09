import os
import sys
import logging
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict
import httpx
from httpx import ReadTimeout, RequestError
import whoisdomain
import asyncio
from datetime import datetime, timedelta
from fastapi import Body
# Setup logging to stdout with formatter
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

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or specific domains for security
    allow_credentials=True,
    allow_methods=["*"],  # this must allow OPTIONS and POST
    allow_headers=["*"],
)


API_KEY = os.getenv("APILAYER_KEY")
if not API_KEY:
    raise RuntimeError("APILAYER_KEY env var is not set")

# Simple in-memory cache: domain -> (result_dict, expiry_datetime)
cache: Dict[str, tuple] = {}
CACHE_TTL = timedelta(hours=1)

async def fetch_whois_api(client: httpx.AsyncClient, domain: str, headers: dict):
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    resp = await client.get(url, headers=headers, timeout=10.0)
    resp.raise_for_status()
    return resp.json()

@app.post("/whois")
async def whois_lookup(domain: str = Body(...)):
    domain = request.domain.lower().strip()
    now = datetime.utcnow()

    # Check cache first
    cached = cache.get(domain)
    if cached and cached[1] > now:
        logger.debug(f"Cache hit for domain: {domain}")
        return cached[0]
    else:
        if cached:
            logger.debug(f"Cache expired for domain: {domain}")

    headers = {"apikey": API_KEY}
    async with httpx.AsyncClient() as client:
        try:
            # Try API lookup with retry on timeout
            try:
                data = await fetch_whois_api(client, domain, headers)
                lookup_type = "whois_api"
            except ReadTimeout:
                logger.warning(f"Timeout on API lookup for {domain}, retrying once...")
                data = await fetch_whois_api(client, domain, headers)
                lookup_type = "whois_api"
        except (ReadTimeout, RequestError) as e:
            # Fallback to local whoisdomain on any API timeout or request error
            logger.warning(f"API lookup failed for {domain} with error: {str(e)}. Falling back to local lookup.")
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
            logger.error(f"Local WHOIS lookup failed for {domain}: {str(e)}")
            result = {
                "domain": domain,
                "result": "error",
                "message": f"Local WHOIS lookup failed: {str(e)}",
                "lookup_type": lookup_type
            }
    else:
        # Parse API response
        if data.get("result") == "error":
            logger.error(f"API returned error for {domain}: {data.get('message')}")
            result = {
                "domain": domain,
                "result": "error",
                "message": data.get("message", "Unknown error"),
                "lookup_type": lookup_type
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
                "lookup_type": lookup_type
            }

    # Cache the result with expiry
    cache[domain] = (result, now + CACHE_TTL)
    return result
