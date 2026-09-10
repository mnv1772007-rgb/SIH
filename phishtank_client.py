"""Opt-in PhishTank URL lookup; disabled to avoid sharing indicators by default."""

from __future__ import annotations

import os

import requests


def check_url(url: str) -> dict:
    """Ask PhishTank only when the operator explicitly enables sharing URLs."""
    if os.getenv("THREAT_INTELLIGENCE_ENABLED", "true").lower() != "true":
        return {"source": "PhishTank", "status": "disabled", "url": url}
    if os.getenv("PHISHTANK_ENABLED", "false").lower() != "true":
        return {"source": "PhishTank", "status": "disabled", "url": url, "reason": "Set PHISHTANK_ENABLED=true to permit URL lookup sharing."}
    payload = {"url": url, "format": "json"}
    key = os.getenv("PHISHTANK_API_KEY")
    if key:
        payload["app_key"] = key
    try:
        response = requests.post("https://checkurl.phishtank.com/checkurl/", data=payload, timeout=12)
        if response.status_code == 429:
            return {"source": "PhishTank", "status": "rate_limited", "url": url}
        if response.status_code in {401, 403}:
            return {"source": "PhishTank", "status": "unauthorized", "url": url}
        response.raise_for_status()
        data = response.json()
        results = data.get("results", {}) if isinstance(data, dict) else {}
        return {
            "source": "PhishTank", "status": "success", "url": url,
            "in_database": bool(results.get("in_database")),
            "verified": bool(results.get("verified")),
            "valid": bool(results.get("valid")),
            "phish_detail_page": results.get("phish_detail_page"),
        }
    except requests.Timeout:
        return {"source": "PhishTank", "status": "timeout", "url": url}
    except (requests.RequestException, ValueError) as error:
        return {"source": "PhishTank", "status": "request_error", "url": url, "error": str(error)}
