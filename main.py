import os
import sys
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
import httpx
import grabio

# Logger setup
logger = logging.getLogger("whois_api")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.handlers = [handler]

app = FastAPI()

# CORS (for dev; restrict in prod)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("APILAYER_KEY")
if not API_KEY:
    raise RuntimeError("APILAYER_KEY env var not set")

CACHE_TTL = timedelta(hours=1)
cache: Dict[str, Tuple[dict, datetime]] = {}  # domain -> (result, expiry)


async def fetch_whois_api(client: httpx.AsyncClient, domain: str, headers: dict) -> Tuple[dict, dict]:
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    resp = await client.get(url, headers=headers, timeout=10.0)
    logger.debug(f"API response status for {domain}: {resp.status_code}")
    if resp.status_code == 404:
        logger.debug(f"API 404 for {domain}: {resp.text}")
        return {"result": "not found", "message": "No match", "raw": resp.text}, dict(resp.headers)
    resp.raise_for_status()
    json_data = resp.json()
    logger.debug(f"API raw response for {domain}: {json_data}")
    return json_data, dict(resp.headers)


@app.get("/status", response_class=PlainTextResponse)
def status():
    return "Active"


@app.post("/whois")
async def whois_lookup(domain: str = Body(..., embed=False)):
    domain = domain.strip().lower()
    now = datetime.utcnow()

    # Cache check
    if domain in cache:
        cached_result, expiry = cache[domain]
        if expiry > now:
            logger.debug(f"Cache hit for domain {domain}")
            cached_result["lookup_type"] += ", cached" if "cached" not in cached_result["lookup_type"] else ""
            return cached_result
        else:
            logger.debug(f"Cache expired for {domain}")
            cache.pop(domain)

    headers = {"apikey": API_KEY}
    async with httpx.AsyncClient() as client:
        attempt = 0
        max_attempts = 3
        api_result = None
        api_headers = {}

        while attempt < max_attempts:
            try:
                api_result, api_headers = await fetch_whois_api(client, domain, headers)
                break
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    logger.error(f"Rate limited for {domain}: {e}")
                    return {
                        "domain": domain,
                        "result": "error",
                        "message": "Rate limit exceeded",
                        "lookup_type": "whois_api",
                        "remaining_api_calls": 0,
                        "registered": None,
                    }
                logger.warning(f"HTTP error on attempt {attempt+1} for {domain}: {e}")
            except (httpx.RequestError, httpx.ReadTimeout) as e:
                logger.warning(f"Request error on attempt {attempt+1} for {domain}: {e}")
            attempt += 1

        # Handle unregistered or failed API response
        if not api_result or not isinstance(api_result.get("result"), dict):
            logger.info(f"API returned non-dict or empty for {domain}, treating as unregistered")
            result = {
                "domain": domain,
                "result": "not_registered",
                "message": api_result.get("message", "Domain not found"),
                "lookup_type": "whois_api",
                "registered": False,
                "remaining_api_calls": None,
            }
            cache[domain] = (result, now + CACHE_TTL)
            return result

    res = api_result["result"]
    creation_date = res.get("creation_date", "No information")
    registrar = res.get("registrar", "No information")

    status = res.get("status")
    if isinstance(status, list):
        status = ", ".join(status)
    elif isinstance(status, str):
        status = status
    else:
        status = "No information"

    name_servers = res.get("name_servers")
    if isinstance(name_servers, list):
        name_servers = "\n".join(ns.lower() for ns in name_servers)
    else:
        name_servers = name_servers or "No information"

    raw_remaining = api_headers.get("X-RateLimit-Remaining")
    try:
        remaining_api_calls = int(raw_remaining) if raw_remaining is not None else None
    except ValueError:
        remaining_api_calls = None

    result = {
        "domain": domain,
        "creation_date": creation_date,
        "registrar": registrar,
        "status": status,
        "name_servers": name_servers,
        "expiration_date": res.get("expiration_date", "No information"),
        "result": "success",
        "lookup_type": "whois_api",
        "registered": True,
        "remaining_api_calls": remaining_api_calls
    }

    cache[domain] = (result, now + CACHE_TTL)
    return result
