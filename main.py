import os
import sys
import logging
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
import httpx
from httpx import ReadTimeout, RequestError
from pydantic import BaseModel
from datetime import datetime, timedelta
import whoisdomain

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.handlers = [handler]

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("APILAYER_KEY")
if not API_KEY:
    raise RuntimeError("APILAYER_KEY env var is not set")

cache = {}
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

    cached = cache.get(domain)
    if cached and cached[1] > now:
        logger.debug(f"Cache hit for {domain}")
        return cached[0]

    headers = {"apikey": API_KEY}
    result = {}
    lookup_type = "whois_api"

    async with httpx.AsyncClient() as client:
        try:
            data = await fetch_whois_api(client, domain, headers)
            logger.debug(f"API raw response for {domain}: {data}")
            res = data.get("result", {})

            if not res.get("creation_date") and not res.get("registrar"):
                raise ValueError("Domain likely not registered")

            result = {
                "domain": domain,
                "creation_date": res.get("creation_date", "No information"),
                "registrar": res.get("registrar", "No information"),
                "status": ", ".join(res.get("status", [])) if isinstance(res.get("status"), list) else res.get("status", "No information"),
                "name_servers": "\n".join(res.get("name_servers", [])) if isinstance(res.get("name_servers"), list) else res.get("name_servers", "No information"),
                "expiration_date": res.get("expiration_date", None),
                "result": "success",
                "lookup_type": lookup_type
            }

        except Exception as e:
            logger.warning(f"API failed for {domain} — {e}")
            lookup_type = "local"
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
                logger.error(f"Local WHOIS failed for {domain}: {e}")
                return {
                    "domain": domain,
                    "result": "error",
                    "message": str(e),
                    "lookup_type": lookup_type
                }

    cache[domain] = (result, now + CACHE_TTL)
    return result
