"""Opt-in URLScan historical search; no scans are created."""

from __future__ import annotations

import os

import requests


def search_urlscan(domain: str) -> dict:
    if os.getenv("THREAT_INTELLIGENCE_ENABLED", "true").lower() != "true":
        return {"source": "urlscan", "status": "disabled", "domain": domain}
    key = os.getenv("URLSCAN_API_KEY")
    if not key:
        return {"source": "urlscan", "status": "not_configured", "domain": domain}
    try:
        response = requests.get("https://urlscan.io/api/v1/search/", headers={"API-Key": key}, params={"q": f"page.domain:{domain}", "size": 10}, timeout=12)
        if response.status_code in {401, 403}:
            return {"source": "urlscan", "status": "unauthorized", "domain": domain}
        if response.status_code == 429:
            return {"source": "urlscan", "status": "rate_limited", "domain": domain}
        response.raise_for_status()
        data = response.json()
        return {"source": "urlscan", "status": "success", "domain": domain, "total": data.get("total", 0), "results": data.get("results", [])}
    except requests.Timeout:
        return {"source": "urlscan", "status": "timeout", "domain": domain}
    except (requests.RequestException, ValueError) as error:
        return {"source": "urlscan", "status": "request_error", "domain": domain, "error": str(error)}
