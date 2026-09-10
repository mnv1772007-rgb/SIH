"""Create portable forensic reports from evidence already produced by the pipeline."""

from __future__ import annotations

from html import escape
from typing import Any, Iterable


def _value(value: Any) -> str:
    if value is None or value == "":
        return "Not available"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _bullets(values: Iterable[str], empty: str = "No evidence recorded.") -> list[str]:
    items = [f"- {value}" for value in values if value]
    return items or [f"- {empty}"]


def build_markdown_report(report: dict[str, Any]) -> str:
    """Render an analyst-readable Markdown report without creating a file."""
    verdict = report["verdict"]
    email = report["email"]
    authentication = report["authentication"]
    headers = report.get("header_analysis", {})
    lines = [
        "# Email Threat Forensics Report",
        "",
        "## Executive Summary",
        f"- Case: `{report['case']['case_id']}`",
        f"- Classification: **{verdict['classification']}**",
        f"- Risk: **{verdict['risk_level']} ({verdict['risk_score']}/100)**",
        f"- Confidence: {verdict['confidence']}%",
        "",
        "## Email Identity",
    ]
    lines.extend(_bullets(f"{label}: {_value(email.get(key))}" for key, label in (
        ("from", "From"), ("to", "To"), ("cc", "Cc"), ("date", "Date"),
        ("subject", "Subject"), ("reply_to", "Reply-To"),
        ("return_path", "Return-Path"), ("message_id", "Message-ID"),
    )))
    lines.extend(["", "## Authentication"])
    lines.extend(_bullets(
        f"{method.upper()}: {_value(authentication.get(method, {}).get('display_status'))} "
        f"(source: {_value(authentication.get(method, {}).get('source'))})"
        for method in ("spf", "dkim", "dmarc")
    ))
    lines.append(f"- DKIM signature present: {_value(authentication.get('dkim_signature_present'))}; a signature is not verification.")
    lines.extend(["", "## Headers and Relay Path"])
    lines.extend(_bullets(
        f"[{str(item.get('severity', 'info')).upper()}] {_value(item.get('message'))}"
        for item in headers.get("findings", [])
    ))
    lines.extend(_bullets((f"Relay: {hop}" for hop in headers.get("relay_path", [])), "No relay path reconstructed."))
    lines.extend(["", "## URLs"])
    lines.extend(_bullets((
        f"{_value(item.get('classification')).upper()} ({item.get('risk_contribution', 0)}): "
        f"{_value(item.get('url'))} | normalized: {_value(item.get('normalized_url'))} | reputation: {_value(item.get('reputation'))}"
        for item in report.get("urls", [])
    ), "No URLs extracted."))
    lines.extend(["", "## HTML"])
    lines.extend(_bullets((
        f"Destination mismatch: {_value(item.get('destination_mismatch'))}; unsafe scheme: {_value(item.get('is_dangerous_scheme'))}; actual domain: {_value(item.get('actual_domain'))}"
        for item in report.get("html_analysis", [])
    ), "No HTML links extracted."))
    lines.extend(["", "## Attachments"])
    lines.extend(_bullets((
        f"{_value(item.get('filename'))} | {_value(item.get('content_type'))} | SHA-256: {_value(item.get('sha256'))} | executable extension: {_value(item.get('is_executable_extension'))}"
        for item in report.get("attachments", [])
    ), "No attachments found."))
    lines.extend(["", "## Infrastructure and Geolocation"])
    lines.extend(_bullets((
        f"IP {_value(item.get('ip'))}: global={_value(item.get('is_global'))}, private={_value(item.get('is_private'))}"
        for item in report.get("ip_analysis", [])
    ), "No IP addresses extracted."))
    lines.extend(_bullets((
        f"Geolocation {_value(item.get('ip'))}: {_value(item.get('status'))}, {_value(item.get('city'))}, {_value(item.get('country'))}"
        for item in report.get("geolocation", [])
    ), "No geolocation records."))
    lines.extend(["", "## Domains, DNS, and RDAP"])
    lines.extend(_bullets((
        f"{_value(item.get('domain'))}: DNS={_value(item.get('dns', {}).get('status'))}, RDAP={_value(item.get('rdap', {}).get('status'))}"
        for item in report.get("domain_intelligence", [])
    ), "No domains extracted."))
    lines.extend(["", "## Threat Intelligence"])
    lines.extend(_bullets((
        f"{_value(item.get('source'))}: {_value(item.get('status'))} for {_value(item.get('indicator'))}; malicious={_value(item.get('malicious'))}"
        for item in report.get("threat_intelligence", {}).get("results", [])
    ), "No intelligence checks ran."))
    lines.extend(["", "## NLP and Risk Evidence"])
    lines.append(f"- NLP classification: {_value(report.get('nlp_analysis', {}).get('classification'))}; {_value(report.get('nlp_analysis', {}).get('explanation'))}")
    model = report.get("nlp_analysis", {}).get("model_analysis", {})
    lines.append(
        f"- Optional ML baseline: {_value(model.get('status'))}; label={_value(model.get('label'))}; "
        f"confidence={_value(model.get('confidence'))}. This is supporting evidence only."
    )
    lines.extend(_bullets(
        f"[{_value(item.get('evidence_tier'))}] {_value(item.get('factor'))}: {item.get('weight', 0)} — {_value(item.get('reason'))}"
        for item in report.get("risk_factors", [])
    ))
    lines.extend(["", "## Correlation and Graph"])
    correlation = report.get("campaign_correlation", {})
    lines.append(
        f"- Correlation status: {_value(correlation.get('status'))}; strength: {_value(correlation.get('strength'))}; "
        f"cluster: {_value(correlation.get('campaign_id'))}"
    )
    lines.extend(_bullets((reason for match in correlation.get("matches", []) for reason in match.get("reasons", [])), "No shared case evidence."))
    graph = report.get("graph", {})
    lines.append(f"- Graph: {_value(graph.get('storage'))}; {len(graph.get('nodes', []))} nodes, {len(graph.get('edges', []))} edges.")
    lines.extend(["", "## Recommendations"])
    lines.extend(_bullets(report.get("recommendations", [])))
    lines.extend([
        "", "## Limitations",
        "- Infrastructure geolocation is approximate network location, not a person's location.",
        "- A clean, unavailable, or not-found threat-intelligence response does not prove safety.",
        "- URLs are never fetched or followed; redirect destinations are not resolved.",
        "- Findings show evidence for analyst review and do not establish attribution.",
    ])
    return "\n".join(lines)


def build_html_report(report: dict[str, Any]) -> str:
    """Render a self-contained, escaped HTML report suitable for printing."""
    markdown = build_markdown_report(report)
    sections = []
    current_title = ""
    current_items: list[str] = []
    for line in markdown.splitlines():
        if line.startswith("## "):
            if current_title:
                sections.append((current_title, current_items))
            current_title, current_items = line[3:], []
        elif line.startswith("- "):
            current_items.append(line[2:])
    if current_title:
        sections.append((current_title, current_items))
    body = "".join(
        f"<section><h2>{escape(title)}</h2><ul>{''.join(f'<li>{escape(item)}</li>' for item in items)}</ul></section>"
        for title, items in sections
    )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Email Threat Forensics Report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#172033}"
        "section{border-top:1px solid #d7dee9;padding:.75rem 0}li{margin:.35rem 0;overflow-wrap:anywhere}</style></head>"
        f"<body><h1>Email Threat Forensics Report</h1>{body}</body></html>"
    )
