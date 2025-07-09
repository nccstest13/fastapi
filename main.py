import os
import sys
import logging
from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
import httpx
import grabio
from datetime import datetime, timedelta
from typing import Dict, Optional

# Logger setup
logger = logging.getLogger("whois_api")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.handlers = [handler]

app = FastAPI()

# CORS config (allow all origins for testing, tighten in prod)
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
cache: Dict[str, tuple] = {}  # domain -> (result_dict, expiry_datetime)

async def fetch_whois_api(client: httpx.AsyncClient, domain: str, headers: dict):
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    resp = await client.get(url, headers=headers, timeout=10.0)
    logger.debug(f"API response status for {domain}: {resp.status_code}")
    if resp.status_code == 404:
        text = await resp.text()
        logger.debug(f"API 404 for {domain}: {text}")
        return {"result": "error", "message": "Domain not registered", "raw": text}, resp.headers
    resp.raise_for_status()
    json_data = resp.json()
    logger.debug(f"API raw response for {domain}: {json_data}")
    return json_data, resp.headers

from fastapi.responses import PlainTextResponse

@app.get("/status", response_class=PlainTextResponse)
def status():
    return "Active"


@app.post("/whois")
async def whois_lookup(domain: str = Body(..., embed=False)):
    domain = domain.strip().lower()
    now = datetime.utcnow()

    # Check cache
    if domain in cache:
        cached_result, expiry = cache[domain]
        if expiry > now:
            logger.debug(f"Cache hit for domain {domain}")
            lookup_type = cached_result.get("lookup_type", "")
            if "cached" not in lookup_type:
                cached_result["lookup_type"] = f"{lookup_type}, cached" if lookup_type else "cached"
            return cached_result
        else:
            logger.debug(f"Cache expired for domain {domain}")
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
                    logger.error(f"Rate limited by API for domain {domain}: {e}")
                    return {
                        "domain": domain,
                        "result": "error",
                        "message": "Rate limit exceeded",
                        "lookup_type": "whois_api",
                        "remaining_api_calls": 0
                    }
                else:
                    logger.warning(f"HTTP error on attempt {attempt+1} for {domain}: {e}")
            except (httpx.RequestError, httpx.ReadTimeout) as e:
                logger.warning(f"Request error on attempt {attempt+1} for {domain}: {e}")
            attempt += 1

        if not api_result:
            logger.warning(f"API lookup failed for {domain}, falling back to grabio")
            # Fallback to grabio
            try:
                g = grabio.Grabio(f"https://{domain}")
                whois_data = g.whois_info()
                logger.debug(f"Local grabio raw data for {domain}: {whois_data}")

                creation_date = whois_data.get("creation_date", "No information")
                registrar = whois_data.get("registrar", "No information")
                status = whois_data.get("status")
                if isinstance(status, list):
                    status = ", ".join(status)
                else:
                    status = status or "No information"
                name_servers = whois_data.get("name_servers")
                if isinstance(name_servers, list):
                    name_servers = "\n".join(ns.lower() for ns in name_servers)
                else:
                    name_servers = name_servers or "No information"
                expiration_date = whois_data.get("expiration_date")

                result = {
                    "domain": domain,
                    "creation_date": creation_date,
                    "registrar": registrar,
                    "status": status,
                    "name_servers": name_servers,
                    "expiration_date": expiration_date,
                    "result": "success",
                    "lookup_type": "local",
                    "remaining_api_calls": None
                }
                cache[domain] = (result, now + CACHE_TTL)
                return result

            except Exception as e:
                logger.error(f"Local WHOIS lookup failed for {domain} (grabio): {e}")
                return {
                    "domain": domain,
                    "result": "error",
                    "message": f"Local WHOIS lookup failed: {str(e)}",
                    "lookup_type": "local",
                    "remaining_api_calls": None
                }

    # Parse API result
    res = api_result.get("result", {})
    creation_date = res.get("creation_date") or "No information"
    registrar = res.get("registrar") or "No information"
    status = res.get("status")
    if isinstance(status, list):
        status = ", ".join(status)
    else:
        status = status or "No information"
    name_servers = res.get("name_servers")
    if isinstance(name_servers, list):
        name_servers = "\n".join(ns.lower() for ns in name_servers)
    else:
        name_servers = name_servers or "No information"

    # Extract remaining calls safely
    raw_remaining = api_headers.get("X-RateLimit-Remaining")
    try:
        remaining_api_calls: Optional[int] = int(raw_remaining) if raw_remaining is not None else None
    except ValueError:
        remaining_api_calls = None

    result = {
        "domain": domain,
        "creation_date": creation_date,
        "registrar": registrar,
        "status": status,
        "name_servers": name_servers,
        "expiration_date": res.get("expiration_date"),
        "result": "success",
        "lookup_type": "whois_api",
        "remaining_api_calls": remaining_api_calls
    }

    cache[domain] = (result, now + CACHE_TTL)
    return result
