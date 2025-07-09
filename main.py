import logging
from fastapi import FastAPI, Body, HTTPException
from datetime import datetime, timedelta
import httpx
import whoisdomain

app = FastAPI()
logger = logging.getLogger("uvicorn.error")  # Or your logger

API_KEY = "your_api_key_here"
CACHE_TTL = timedelta(hours=1)
cache = {}

async def fetch_whois_api(client: httpx.AsyncClient, domain: str, headers: dict):
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    logger.debug(f"Calling apilayer WHOIS API for domain: {domain}")
    response = await client.get(url, headers=headers, timeout=10.0)
    logger.debug(f"API Response status code: {response.status_code}")
    try:
        json_data = response.json()
        logger.debug(f"API raw response for {domain}: {json_data}")
    except Exception as e:
        logger.error(f"Failed to parse JSON response from API for {domain}: {e}")
        json_data = None
    return response.status_code, json_data

@app.post("/whois")
async def whois_lookup(domain: str = Body(..., embed=False)):
    domain = domain.lower().strip()
    now = datetime.utcnow()
    logger.info(f"Received WHOIS lookup request for domain: {domain}")

    # Cache check
    cached = cache.get(domain)
    if cached and cached[1] > now:
        logger.info(f"Cache hit for domain: {domain}")
        return cached[0]
    if cached:
        logger.info(f"Cache expired for domain: {domain}")

    headers = {"apikey": API_KEY}
    async with httpx.AsyncClient() as client:
        try:
            status_code, data = await fetch_whois_api(client, domain, headers)
            if status_code == 404:
                logger.warning(f"Domain {domain} not registered (404 from API).")
                result = {
                    "domain": domain,
                    "result": "error",
                    "message": "Domain not registered",
                    "lookup_type": "whois_api"
                }
                cache[domain] = (result, now + CACHE_TTL)
                return result
            elif status_code != 200:
                logger.error(f"API returned status code {status_code} for domain {domain}")
                raise HTTPException(status_code=502, detail="Bad response from WHOIS API")
            lookup_type = "whois_api"
        except Exception as e:
            logger.warning(f"API lookup failed for {domain} with error: {e}. Falling back to local lookup.")
            lookup_type = "local"
            data = None

    if lookup_type == "local":
        try:
            w = whoisdomain.Whois(domain)
            raw_local_data = vars(w)
            logger.debug(f"Local WHOIS raw data for {domain}: {raw_local_data}")
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
            logger.error(f"Local WHOIS lookup failed for {domain}: {e}")
            result = {
                "domain": domain,
                "result": "error",
                "message": f"Local WHOIS lookup failed: {e}",
                "lookup_type": lookup_type
            }
            return result
    else:
        # Parse API response assuming the structure you gave before
        try:
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
        except Exception as e:
            logger.error(f"Error parsing API data for {domain}: {e}")
            result = {
                "domain": domain,
                "result": "error",
                "message": f"Error parsing API response: {e}",
                "lookup_type": lookup_type
            }
            return result

    # Cache successful results only
    if result.get("result") == "success":
        cache[domain] = (result, now + CACHE_TTL)
        logger.info(f"Cached result for domain: {domain}")

    return result
