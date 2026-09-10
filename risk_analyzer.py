"""Provisional header-risk tally used as explainable supporting evidence."""

from __future__ import annotations


def calculate_header_risk(header_result: dict, authentication: dict) -> dict:
    tally, reasons, indicators = 0, [], []
    weights = {"critical": 45, "high": 35, "medium": 20, "low": 8, "info": 3}
    for finding in header_result.get("findings", []):
        severity = str(finding.get("severity", "low")).lower()
        tally += weights.get(severity, 0)
        reasons.append(finding.get("message", "Header anomaly detected."))
        indicators.append({"type": finding.get("type"), "severity": severity, "description": reasons[-1], "confidence": "high"})
    for method, severity, weight in (("spf", "high", 25), ("dkim", "high", 20), ("dmarc", "high", 25)):
        result = str(authentication.get(method, "")).lower()
        if result in {"fail", "permerror", "reject"}:
            tally += weight
            text = f"{method.upper()} authentication result is {result}."
            reasons.append(text)
            indicators.append({"type": f"{method}_{result}", "severity": severity, "description": text, "confidence": "high"})
        elif result in {"softfail", "temperror", "quarantine"}:
            tally += 12
            text = f"{method.upper()} authentication result is {result}."
            reasons.append(text)
            indicators.append({"type": f"{method}_{result}", "severity": "medium", "description": text, "confidence": "medium"})
    tally = min(100, tally)
    return {"tally": tally, "score": tally, "risk_score": tally, "risk_level": "HIGH" if tally >= 50 else "MEDIUM" if tally >= 25 else "LOW", "risk_category": "anomalous" if tally >= 50 else "elevated" if tally >= 25 else "some_anomalies" if tally >= 10 else "minimal", "reasons": reasons, "finding_types": [item["type"] for item in indicators], "indicators": indicators, "sources_checked": ["SPF", "DKIM", "DMARC", "Header_Analysis"], "note": "Provisional evidence tally only; it is not a calibrated phishing probability."}
