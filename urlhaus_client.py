"""Opt-in URLhaus indicator lookup."""

from __future__ import annotations

import os

import requests


def check_urlhaus(url: str) -> dict:
    if os.getenv("THREAT_INTELLIGENCE_ENABLED", "true").lower() != "true":
        return {"source": "URLhaus", "status": "disabled", "url": url}
    key = os.getenv("URLHAUS_AUTH_KEY")
    if not key:
        return {"source": "URLhaus", "status": "not_configured", "url": url}
    try:
        response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": key}, timeout=12)
        if response.status_code == 429:
            return {"source": "URLhaus", "status": "rate_limited", "url": url}
        response.raise_for_status()
        data = response.json()
        return {"source": "URLhaus", "status": "success", "url": url, "query_status": data.get("query_status"), "urlhaus_reference": data.get("urlhaus_reference"), "threat": data.get("threat"), "tags": data.get("tags", []), "url_status": data.get("url_status")}
    except requests.Timeout:
        return {"source": "URLhaus", "status": "timeout", "url": url}
    except (requests.RequestException, ValueError) as error:
        return {"source": "URLhaus", "status": "request_error", "url": url, "error": str(error)}
