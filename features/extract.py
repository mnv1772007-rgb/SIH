"""
ml/features/extract.py - Feature extraction from email data
Author: BTech Cyber Security Student

Extracts structured features from a normalized email dict/Series for ML model input.

Design:
  - Works with dict, pandas.Series, or any mapping
  - Returns a flat dict of float/int features
  - Handles missing fields gracefully (fills with safe defaults)
  - Does NOT require parser.py or any external service

Feature categories:
  1. Text / NLP features
  2. URL features
  3. Domain / header features
  4. Security signal features (SPF/DKIM/DMARC)
  5. BEC / impersonation indicators
  6. Structural features (attachments, HTML)
"""

import re
import math
import logging
from collections import Counter
from email.utils import parseaddr
from typing import Any, Dict, List, Optional, Union

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Keyword lists (used as features, not hard rules)
# ---------------------------------------------------------------------------

_URGENCY_KEYWORDS = [
    "urgent", "immediately", "asap", "action required", "verify now",
    "time sensitive", "time-sensitive", "important", "attention required",
    "expires", "expiring", "final notice", "last chance", "limited time",
    "act now", "respond immediately", "suspended", "your account",
]

_FINANCIAL_KEYWORDS = [
    "invoice", "payment", "transfer", "wire", "bank account", "salary",
    "refund", "reimburs", "direct deposit", "gift card", "bitcoin",
    "cryptocurrency", "western union", "moneygram", "fund", "remittance",
]

_CREDENTIAL_KEYWORDS = [
    "password", "login", "credential", "verify", "confirm", "authenticate",
    "sign in", "sign-in", "username", "account", "reset", "update your info",
    "secure your", "validate",
]

_EXECUTIVE_TITLES = {
    "ceo", "cfo", "cto", "coo", "president", "vice president", "vp",
    "director", "manager", "executive", "chief", "head of", "finance",
    "hr", "legal", "admin", "administrator",
}

_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".click", ".download", ".zip", ".mov",
}


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------

def extract_all_features(row: Union[Dict, Any]) -> Dict[str, float]:
    """
    Extract all ML features from a single email row.

    Args:
        row: dict, pandas.Series, or any mapping with email fields

    Returns:
        Flat dict of feature_name → numeric value (float or int)

    Email fields consumed (all optional with safe defaults):
        body / body_text       - email body text
        subject                - subject line
        sender / from          - sender address (may include display name)
        reply_to               - Reply-To header
        return_path            - Return-Path header
        spf                    - SPF result string ('pass', 'fail', 'softfail', etc.)
        dkim                   - DKIM result string
        dmarc                  - DMARC result string
        urls                   - pipe-separated URL string OR list
        header_risk_tally      - numeric risk tally from header analysis
        header_findings        - list of finding dicts
        attachment_count       - number of attachments
        executable_attachments - number of executable attachments
        html_destination_mismatch - 0/1 flag
    """
    if isinstance(row, pd.Series):
        row = row.to_dict()

    features: Dict[str, float] = {}

    # --- Resolve field name aliases ---
    body = _safe_str(row.get("body") or row.get("body_text", ""))
    subject = _safe_str(row.get("subject", ""))
    sender = _safe_str(row.get("sender") or row.get("from", ""))
    reply_to = _safe_str(row.get("reply_to", ""))
    return_path = _safe_str(row.get("return_path", ""))

    # --- Text features ---
    features.update(_text_features(body, subject))

    # --- URL features ---
    url_list = _parse_urls(row)
    features.update(_url_features(url_list))

    # --- Security signal features ---
    features.update(_auth_features(row))

    # --- Header features ---
    features.update(_header_features(row, sender, reply_to, return_path))

    # --- BEC / impersonation features ---
    features.update(_bec_features(row, sender, reply_to, return_path, body, subject))

    # --- Structural features ---
    features.update(_structural_features(row))

    # Sanity: replace any NaN/inf with 0
    features = {k: _safe_float(v) for k, v in features.items()}

    return features


def extract_batch_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract features from an entire DataFrame.

    Args:
        df: DataFrame where each row is one email

    Returns:
        DataFrame with feature columns (aligned with input index)
    """
    feature_rows = []
    for _, row in df.iterrows():
        feature_rows.append(extract_all_features(row))

    return pd.DataFrame(feature_rows, index=df.index).fillna(0.0)


# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------

def _text_features(body: str, subject: str) -> Dict[str, float]:
    """NLP / text statistics features."""
    feats: Dict[str, float] = {}
    combined = f"{subject} {body}"

    # Lengths
    feats["text_length"] = float(len(body))
    feats["body_length"] = float(len(body))
    feats["body_char_count"] = float(len(body))
    feats["subject_length"] = float(len(subject))
    feats["combined_length"] = float(len(combined))
    feats["word_count"] = float(len(body.split()))
    feats["subject_word_count"] = float(len(subject.split()))

    # Ratios (handle empty text)
    n = max(len(body), 1)
    feats["uppercase_ratio"] = sum(1 for c in body if c.isupper()) / n
    feats["digit_ratio"] = sum(1 for c in body if c.isdigit()) / n
    feats["space_ratio"] = body.count(" ") / n

    # Punctuation markers
    feats["exclamation_count"] = body.count("!")
    feats["question_count"] = body.count("?")
    feats["dollar_sign_count"] = body.count("$")
    feats["at_sign_count"] = body.count("@")

    # Readability — use textstat if available; otherwise skip gracefully
    try:
        import textstat
        feats["readability_flesch"] = float(textstat.flesch_reading_ease(body)) if body else 0.0
        feats["readability_grade"] = float(textstat.flesch_kincaid_grade(body)) if body else 0.0
    except Exception:
        feats["readability_flesch"] = 0.0
        feats["readability_grade"] = 0.0

    # Keyword hit counts (features, not hard rules)
    body_lower = body.lower()
    subj_lower = subject.lower()
    combined_lower = f"{subj_lower} {body_lower}"

    feats["urgency_keyword_hits"] = sum(
        1 for kw in _URGENCY_KEYWORDS if kw in combined_lower
    )
    feats["financial_keyword_hits"] = sum(
        1 for kw in _FINANCIAL_KEYWORDS if kw in combined_lower
    )
    feats["credential_keyword_hits"] = sum(
        1 for kw in _CREDENTIAL_KEYWORDS if kw in combined_lower
    )

    # Subject-level indicators
    feats["subject_has_re"] = 1.0 if subj_lower.startswith("re:") else 0.0
    feats["subject_has_fwd"] = 1.0 if subj_lower.startswith("fwd:") or subj_lower.startswith("fw:") else 0.0
    feats["subject_all_caps"] = 1.0 if subject.isupper() and len(subject) > 3 else 0.0

    # Number of unique words (lexical diversity)
    words = body.lower().split()
    if words:
        feats["lexical_diversity"] = len(set(words)) / len(words)
    else:
        feats["lexical_diversity"] = 0.0

    return feats


def _parse_urls(row: Dict) -> List[str]:
    """Parse URLs from a row into a list."""
    urls = row.get("urls", "")
    if isinstance(urls, list):
        return [str(u).strip() for u in urls if u and str(u).strip()]
    if isinstance(urls, str) and urls:
        return [u.strip() for u in urls.split("|") if u.strip()]
    return []


def _url_features(url_list: List[str]) -> Dict[str, float]:
    """URL-based features."""
    feats: Dict[str, float] = {}
    n_urls = len(url_list)

    feats["url_count"] = float(n_urls)

    if n_urls == 0:
        feats["has_http_only_url"] = 0.0
        feats["https_ratio"] = 0.0
        feats["ip_based_urls"] = 0.0
        feats["punycode_urls"] = 0.0
        feats["has_credentials_in_url"] = 0.0
        feats["url_entropy"] = 0.0
        feats["url_avg_length"] = 0.0
        feats["url_subdomain_count"] = 0.0
        feats["suspicious_tld_count"] = 0.0
        feats["url_has_query_params"] = 0.0
        return feats

    http_only = sum(1 for u in url_list if u.startswith("http://"))
    https = sum(1 for u in url_list if u.startswith("https://"))

    feats["has_http_only_url"] = 1.0 if http_only > 0 else 0.0
    feats["https_ratio"] = https / n_urls

    feats["ip_based_urls"] = float(sum(1 for u in url_list if _is_ip_url(u)))
    feats["punycode_urls"] = float(sum(1 for u in url_list if "xn--" in u.lower()))
    feats["has_credentials_in_url"] = float(_has_creds_url(url_list))
    feats["url_entropy"] = _calc_url_entropy(url_list)
    feats["url_avg_length"] = float(np.mean([len(u) for u in url_list]))

    # Subdomains
    subdomain_counts = [_count_subdomains(u) for u in url_list]
    feats["url_subdomain_count"] = float(np.mean(subdomain_counts)) if subdomain_counts else 0.0

    # Suspicious TLD
    feats["suspicious_tld_count"] = float(
        sum(1 for u in url_list if any(u.lower().split("?")[0].endswith(t) for t in _SUSPICIOUS_TLDS))
    )

    # Query parameters
    feats["url_has_query_params"] = 1.0 if any("?" in u for u in url_list) else 0.0

    return feats


def _auth_features(row: Dict) -> Dict[str, float]:
    """SPF / DKIM / DMARC / ARC features."""
    spf = str(row.get("spf", "") or "").lower().strip()
    dkim = str(row.get("dkim", "") or "").lower().strip()
    dmarc = str(row.get("dmarc", "") or "").lower().strip()
    arc = str(row.get("arc", "") or "").lower().strip()

    feats = {
        "spf_pass": 1.0 if spf == "pass" else 0.0,
        "spf_fail": 1.0 if spf == "fail" else 0.0,
        "spf_softfail": 1.0 if spf == "softfail" else 0.0,
        "spf_neutral": 1.0 if spf == "neutral" else 0.0,
        "dkim_pass": 1.0 if dkim == "pass" else 0.0,
        "dkim_fail": 1.0 if dkim == "fail" else 0.0,
        "dmarc_pass": 1.0 if dmarc == "pass" else 0.0,
        "dmarc_fail": 1.0 if dmarc == "fail" else 0.0,
        "arc_pass": 1.0 if arc == "pass" else 0.0,
        "auth_all_pass": 1.0 if (spf == "pass" and dkim == "pass" and dmarc == "pass") else 0.0,
        "auth_all_fail": 1.0 if (spf == "fail" and dkim == "fail" and dmarc == "fail") else 0.0,
        "auth_inconsistency": 1.0 if (spf == "pass" and dmarc == "fail") else 0.0,
    }
    return feats


def _header_features(
    row: Dict, sender: str, reply_to: str, return_path: str
) -> Dict[str, float]:
    """Header-derived features."""
    feats: Dict[str, float] = {}

    from_domain = _extract_domain(sender)
    reply_domain = _extract_domain(reply_to)
    return_domain = _extract_domain(return_path)

    feats["reply_to_mismatch"] = float(
        bool(from_domain and reply_domain and from_domain != reply_domain)
    )
    feats["from_equals_reply_to"] = float(
        bool(from_domain and reply_domain and from_domain == reply_domain) or (bool(from_domain) and not reply_domain)
    )
    feats["return_path_mismatch"] = float(
        bool(from_domain and return_domain and from_domain != return_domain)
    )
    feats["from_domain_present"] = 1.0 if from_domain else 0.0

    # Header risk signals (from forensic analysis)
    feats["header_risk_tally"] = float(row.get("header_risk_tally", 0) or 0)
    feats["header_findings_count"] = float(len(row.get("header_findings", []) or []))

    # Received chain
    received = row.get("received_chain", []) or []
    feats["received_hop_count"] = float(len(received))

    return feats


def _bec_features(
    row: Dict,
    sender: str,
    reply_to: str,
    return_path: str,
    body: str,
    subject: str,
) -> Dict[str, float]:
    """BEC and impersonation indicator features."""
    feats: Dict[str, float] = {}

    display_name = _extract_display_name(sender)
    feats["display_name_length"] = float(len(display_name))
    feats["display_name_privileged"] = 1.0 if _is_privileged(display_name) else 0.0

    # Display name vs domain mismatch (impersonation indicator)
    from_domain = _extract_domain(sender)
    reply_domain = _extract_domain(reply_to)
    feats["display_name_domain_mismatch"] = float(
        bool(display_name and from_domain and
             any(brand in display_name.lower() for brand in ["microsoft", "google", "amazon", "paypal", "apple"])
             and not any(brand in (from_domain or "") for brand in ["microsoft", "google", "amazon", "paypal", "apple"]))
    )

    # Urgency in subject
    subj_lower = subject.lower()
    feats["subject_urgency"] = float(
        any(kw in subj_lower for kw in ["urgent", "action required", "immediately", "asap", "expires"])
    )

    # Financial request in body
    body_lower = body.lower()
    feats["body_wire_transfer_mention"] = float("wire transfer" in body_lower or "wire the" in body_lower)
    feats["body_gift_card_mention"] = float("gift card" in body_lower)
    feats["body_payroll_mention"] = float("payroll" in body_lower or "direct deposit" in body_lower)

    # Reply-to divergence from sender domain (strong BEC signal)
    feats["reply_to_different_domain"] = float(
        bool(reply_domain and from_domain and reply_domain != from_domain)
    )

    return feats


def _structural_features(row: Dict) -> Dict[str, float]:
    """Attachment and structural email features."""
    feats = {
        "attachment_count": float(row.get("attachment_count", 0) or 0),
        "executable_attachments": float(row.get("executable_attachments", 0) or 0),
        "html_destination_mismatch": float(row.get("html_destination_mismatch", 0) or 0),
        "ip_count": float(row.get("ip_count", 0) or 0),
        "private_ips": float(row.get("private_ips", 0) or 0),
        "html_link_count": float(row.get("html_link_count", 0) or 0),
        "evidence_tally": float(row.get("evidence_tally", 0) or 0),
    }
    return feats


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _safe_str(v: Any) -> str:
    """Convert any value to a clean string."""
    if v is None:
        return ""
    return str(v).strip()


def _safe_float(v: Any) -> float:
    """Convert to float; replace NaN/inf with 0."""
    try:
        f = float(v)
        if math.isnan(f) or math.isinf(f):
            return 0.0
        return f
    except (TypeError, ValueError):
        return 0.0


def _extract_domain(addr: str) -> Optional[str]:
    """Extract domain from an email address string."""
    if not addr:
        return None
    _, email_part = parseaddr(addr)
    if not email_part:
        # Try raw domain extraction
        m = re.search(r"@([a-zA-Z0-9.\-]+)", addr)
        return m.group(1).lower() if m else None
    if "@" in email_part:
        return email_part.split("@")[-1].lower()
    return None


def _extract_display_name(addr: str) -> str:
    """Extract display name from an email address string."""
    if not addr:
        return ""
    name, _ = parseaddr(addr)
    return name.strip()


def _is_privileged(name: str) -> bool:
    """Check if display name uses executive/privileged titles."""
    if not name:
        return False
    name_lower = name.lower().strip()
    return any(title in name_lower for title in _EXECUTIVE_TITLES)


def _is_ip_url(url: str) -> bool:
    """Check if URL uses raw IP address instead of a domain name."""
    if not url:
        return False
    return bool(re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url))


def _has_creds_url(urls: List[str]) -> int:
    """Check if any URL embeds credentials (user:pass@host)."""
    if not urls:
        return 0
    for u in urls:
        # Pattern: http://user:pass@host
        if re.search(r"https?://[^@]+:[^@]+@", u):
            return 1
    return 0


def _calc_url_entropy(urls: List[str]) -> float:
    """
    Calculate mean Shannon entropy of URL strings.
    High entropy indicates random/generated URLs (suspicious).
    """
    if not urls:
        return 0.0
    entropies = []
    for u in urls:
        if not u:
            continue
        counts = Counter(u)
        total = len(u)
        if total == 0:
            continue
        h = -sum((c / total) * math.log2(c / total) for c in counts.values())
        entropies.append(h)
    return round(float(np.mean(entropies)), 4) if entropies else 0.0


def _count_subdomains(url: str) -> int:
    """Count number of subdomains in a URL."""
    try:
        # Strip scheme
        host = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]
        parts = host.split(".")
        # Subtract 2 for domain.tld
        return max(0, len(parts) - 2)
    except Exception:
        return 0