"""Bounded RDAP domain lookup, enabled only by the central service configuration."""

from __future__ import annotations

import requests


def lookup_rdap(domain: str) -> dict:
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"}, timeout=12)
        if response.status_code == 404:
            return {"source": "RDAP", "status": "not_found", "domain": domain}
        response.raise_for_status()
        data = response.json()
        events = {item.get("eventAction"): item.get("eventDate") for item in data.get("events", []) if item.get("eventAction") and item.get("eventDate")}
        nameservers = [item.get("ldhName") for item in data.get("nameservers", []) if item.get("ldhName")]
        return {"source": "RDAP", "status": "success", "domain": domain, "handle": data.get("handle"), "status_codes": data.get("status", []), "events": events, "nameservers": nameservers}
    except requests.Timeout:
        return {"source": "RDAP", "status": "timeout", "domain": domain}
    except (requests.RequestException, ValueError) as error:
        return {"source": "RDAP", "status": "request_error", "domain": domain, "error": str(error)}
