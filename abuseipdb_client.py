"""Opt-in AbuseIPDB indicator lookup."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import requests


def check_ip(ip: str) -> dict:
    if os.getenv("THREAT_INTELLIGENCE_ENABLED", "true").lower() != "true":
        return {"source": "AbuseIPDB", "status": "disabled", "ip": ip}
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        return {"source": "AbuseIPDB", "status": "not_configured", "ip": ip}
    try:
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": key, "Accept": "application/json"}, params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
        if response.status_code == 401:
            return {"source": "AbuseIPDB", "status": "unauthorized", "ip": ip}
        if response.status_code == 429:
            return {"source": "AbuseIPDB", "status": "rate_limited", "ip": ip}
        response.raise_for_status()
        data = response.json().get("data", {})
        return {"source": "AbuseIPDB", "status": "success", "checked_at": datetime.now(timezone.utc).isoformat(), "ip": ip, "abuse_confidence_score": data.get("abuseConfidenceScore", 0), "total_reports": data.get("totalReports", 0), "country_code": data.get("countryCode"), "usage_type": data.get("usageType"), "isp": data.get("isp"), "domain": data.get("domain"), "is_whitelisted": data.get("isWhitelisted")}
    except requests.Timeout:
        return {"source": "AbuseIPDB", "status": "timeout", "ip": ip}
    except (requests.RequestException, ValueError) as error:
        return {"source": "AbuseIPDB", "status": "request_error", "ip": ip, "error": str(error)}
