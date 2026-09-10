"""Explainable header consistency checks."""

from __future__ import annotations

from email.utils import parseaddr


def extract_domain(address: str | None) -> str | None:
    _, parsed = parseaddr(address or "")
    return parsed.rsplit("@", 1)[1].lower() if "@" in parsed else None


def same_or_related_domain(first: str | None, second: str | None) -> bool:
    if not first or not second:
        return False
    first, second = first.lower(), second.lower()
    return first == second or first.endswith("." + second) or second.endswith("." + first)


def analyze_headers(message: object) -> dict[str, object]:
    from_address = message.get("From")
    reply_to = message.get("Reply-To")
    return_path = message.get("Return-Path")
    message_id = message.get("Message-ID")
    from_domain = extract_domain(from_address)
    reply_domain = extract_domain(reply_to)
    return_domain = extract_domain(return_path)
    message_id_domain = message_id.rsplit("@", 1)[1].replace(">", "").strip().lower() if message_id and "@" in message_id else None
    findings: list[dict[str, str]] = []

    def mismatch(kind: str, other: str | None, label: str) -> None:
        if other and from_domain and not same_or_related_domain(other, from_domain):
            findings.append({"type": kind, "severity": "medium", "message": f"{label} domain differs from the From domain."})

    if not from_address:
        findings.append({"type": "missing_from", "severity": "high", "message": "From header is missing."})
    mismatch("reply_to_mismatch", reply_domain, "Reply-To")
    mismatch("return_path_mismatch", return_domain, "Return-Path")
    mismatch("message_id_domain_mismatch", message_id_domain, "Message-ID")
    display_name, email_address = parseaddr(from_address or "")
    if display_name and email_address and display_name.strip().lower() in {"admin", "administrator", "ceo", "cfo", "finance", "security", "hr", "legal", "payroll"}:
        findings.append({"type": "privileged_display_name", "severity": "medium", "message": "Email uses a potentially high-value organizational display name."})
    return {
        "from_domain": from_domain, "reply_to_domain": reply_domain,
        "return_path_domain": return_domain, "message_id_domain": message_id_domain,
        "findings": findings,
    }
