import os
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import httpx

app = FastAPI()

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
            try:
                resp = await client.get(url, headers=headers)
            except httpx.RequestError as e:
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": f"Request error: {str(e)}"
                })
                continue

            if resp.status_code == 429:
                raise HTTPException(status_code=429, detail="Too many requests. Rate limit exceeded.")
            if resp.status_code >= 500:
                raise HTTPException(status_code=502, detail="Upstream WHOIS API provider error.")

            day_remaining_str = resp.headers.get("X-RateLimit-Remaining-Day")
            if day_remaining_str is not None:
                try:
                    day_remaining = int(day_remaining_str)
                    if min_remaining_day is None or day_remaining < min_remaining_day:
                        min_remaining_day = day_remaining
                except ValueError:
                    pass

            try:
                data = resp.json()
            except Exception:
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": "Invalid JSON response from API"
                })
                continue

            if data.get("result") == "error":
                results.append({
                    "domain": domain,
                    "result": "error",
                    "message": data.get("message", "Unknown error")
                })
            else:
                # Defensive data extraction
                res = data.get("result", {})

                results.append({
                    "domain": domain,
                    "creation_date": res.get("creation_date", "No information"),
                    "registrar": res.get("registrar", "No information"),
                    "status": ", ".join(res.get("status")) if isinstance(res.get("status"), list) else res.get("status", "No information"),
                    "name_servers": ", ".join([ns.lower() for ns in res.get("name_servers", [])]) if isinstance(res.get("name_servers"), list) else res.get("name_servers", "No information"),
                    "expiration_date": res.get("expiration_date"),
                    "result": "success"
                })


    return {"results": results, "minRemainingDay": min_remaining_day}
