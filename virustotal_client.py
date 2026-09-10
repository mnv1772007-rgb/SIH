"""Opt-in lookup of existing VirusTotal URL reports; URLs are never submitted."""

from __future__ import annotations

import base64
import os

import requests


def lookup_url(url: str) -> dict:
    if os.getenv("THREAT_INTELLIGENCE_ENABLED", "true").lower() != "true":
        return {"source": "VirusTotal", "status": "disabled", "url": url}
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return {"source": "VirusTotal", "status": "not_configured", "url": url}
    identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{identifier}", headers={"x-apikey": key, "Accept": "application/json"}, timeout=12)
        if response.status_code == 404:
            return {"source": "VirusTotal", "status": "not_found", "url": url}
        if response.status_code == 401:
            return {"source": "VirusTotal", "status": "unauthorized", "url": url}
        if response.status_code == 429:
            return {"source": "VirusTotal", "status": "rate_limited", "url": url}
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        return {"source": "VirusTotal", "status": "success", "url": url, "reputation": attributes.get("reputation"), "last_analysis_stats": attributes.get("last_analysis_stats", {}), "categories": attributes.get("categories", {}), "times_submitted": attributes.get("times_submitted")}
    except requests.Timeout:
        return {"source": "VirusTotal", "status": "timeout", "url": url}
    except (requests.RequestException, ValueError) as error:
        return {"source": "VirusTotal", "status": "request_error", "url": url, "error": str(error)}
