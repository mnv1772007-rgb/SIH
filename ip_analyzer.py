"""IP-address classification without contacting an address."""

from __future__ import annotations

import ipaddress


def analyze_ip(value: str) -> dict[str, object]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return {"ip": value, "error": "Invalid IP address", "is_global": False}
    return {
        "ip": str(address), "version": address.version, "is_private": address.is_private,
        "is_global": address.is_global, "is_loopback": address.is_loopback,
        "is_reserved": address.is_reserved, "is_link_local": address.is_link_local,
    }
