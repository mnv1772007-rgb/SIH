"""Received-header relay-chain reconstruction."""

from __future__ import annotations

import ipaddress
import re
from typing import Any


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def analyze_received_headers(received_headers: list[str]) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for order, header in enumerate(received_headers, start=1):
        from_match = re.search(r"\bfrom\s+([^\s(]+)", header, re.IGNORECASE)
        by_match = re.search(r"\bby\s+([^\s;]+)", header, re.IGNORECASE)
        ips = []
        for value in IP_PATTERN.findall(header):
            try:
                normalized = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if normalized not in ips:
                ips.append(normalized)
        hops.append({"header_order": order, "from_server": from_match.group(1) if from_match else None, "to_server": by_match.group(1) if by_match else None, "ip_addresses": ips, "raw_header": header})
    return hops


def find_origin_candidates(hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for hop in reversed(hops):
        for value in hop.get("ip_addresses", []):
            address = ipaddress.ip_address(value)
            score = 50 if address.is_global else -50
            if address.is_loopback:
                score -= 50
            if address.is_reserved:
                score -= 20
            candidates.append({"ip": value, "header_order": hop["header_order"], "from_server": hop.get("from_server"), "to_server": hop.get("to_server"), "is_private": address.is_private, "is_global": address.is_global, "is_loopback": address.is_loopback, "is_reserved": address.is_reserved, "is_link_local": address.is_link_local, "candidate_score": score})
    return sorted(candidates, key=lambda candidate: candidate["candidate_score"], reverse=True)


def build_relay_path(hops: list[dict[str, Any]]) -> list[str]:
    path: list[str] = []
    for hop in reversed(hops):
        for server in (hop.get("from_server"), hop.get("to_server")):
            if server and server not in path:
                path.append(server)
    return path
