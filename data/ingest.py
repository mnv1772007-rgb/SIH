"""
ml/data/ingest.py - Email data ingestion for ML pipeline
Author: BTech Cyber Security Student

Provides two ingestion paths:

1. dict_to_ml_row(email_dict) — consume a pre-parsed email dict (e.g., from Role 1 parser)
2. eml_to_ml_row(eml_path)   — parse a raw .eml file directly (optional, needs parser.py)

The ML module does NOT require parser.py. If it's unavailable, use dict_to_ml_row().

Fixed:
  - Removed hard dependency on parser.py (import is now optional/graceful)
  - Fixed sys.path calculation (was 4 levels up instead of 3)
  - Handles 'parser' name collision with Python stdlib
  - Supports loading CSV datasets for training (no .eml files needed)
"""

import logging
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional parser import (Role 1 integration)
# ---------------------------------------------------------------------------

_parser_available = False
_parse_email_fn = None

try:
    import sys
    import importlib

    # parser.py is at the project root (3 levels up from ml/data/)
    _project_root = str(Path(__file__).parent.parent.parent)
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)

    # Use importlib to avoid clashing with Python stdlib 'parser' module
    _spec = importlib.util.spec_from_file_location(
        "email_parser",
        str(Path(_project_root) / "parser.py"),
    )
    if _spec and _spec.loader:
        _email_parser_module = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_email_parser_module)
        _parse_email_fn = getattr(_email_parser_module, "parse_email", None)
        if _parse_email_fn:
            _parser_available = True
            logger.info("Role 1 parser.py loaded successfully")
        else:
            logger.warning("parser.py found but does not expose 'parse_email' function")
except Exception as exc:
    logger.debug(f"Role 1 parser.py not loaded (optional): {exc}")


# ---------------------------------------------------------------------------
# Normalized field accessors
# ---------------------------------------------------------------------------

def _safe_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def _extract_domain(addr: str) -> Optional[str]:
    """Extract domain from email address string."""
    if not addr:
        return None
    from email.utils import parseaddr
    import re
    _, email_part = parseaddr(addr)
    if email_part and "@" in email_part:
        return email_part.split("@")[-1].lower()
    # Fallback: regex
    m = re.search(r"@([\w.\-]+)", addr)
    return m.group(1).lower() if m else None


def _parse_urls(urls_value: Any) -> str:
    """Normalize URLs to a pipe-separated string."""
    if urls_value is None:
        return ""
    if isinstance(urls_value, list):
        return "|".join(str(u) for u in urls_value if u)
    return str(urls_value)


# ---------------------------------------------------------------------------
# dict_to_ml_row — primary ingestion path (no parser dependency)
# ---------------------------------------------------------------------------

def dict_to_ml_row(email_dict: Dict) -> pd.Series:
    """
    Convert a normalized email dict to a feature-ready pandas Series.

    This is the PRIMARY ingestion path for the ML module.
    It works with any dict that contains email fields — whether produced by
    Role 1's parser, a CSV row, or a direct API call.

    Args:
        email_dict: Dict with any subset of the following keys:
            subject, body / body_text, sender / from, reply_to, return_path,
            spf, dkim, dmarc, arc, urls, label, ...

    Returns:
        pandas.Series ready for feature extraction
    """
    d = email_dict

    # Normalize field name aliases
    body = _safe_str(d.get("body") or d.get("body_text", ""))
    sender = _safe_str(d.get("sender") or d.get("from", ""))
    reply_to = _safe_str(d.get("reply_to", ""))
    return_path = _safe_str(d.get("return_path", ""))
    subject = _safe_str(d.get("subject", ""))

    row = pd.Series({
        # Identity
        "email_id": _safe_str(d.get("email_id", "")),
        "sender": sender,
        "from_domain": _extract_domain(sender),
        "reply_to": reply_to,
        "reply_to_domain": _extract_domain(reply_to),
        "return_path": return_path,
        "return_path_domain": _extract_domain(return_path),
        "subject": subject,

        # Body (both aliases preserved)
        "body": body,
        "body_text": body,
        "body_length": len(body),

        # Authentication
        "spf": _safe_str(d.get("spf", "")),
        "dkim": _safe_str(d.get("dkim", "")),
        "dmarc": _safe_str(d.get("dmarc", "")),
        "arc": _safe_str(d.get("arc", "")),

        # Header analysis (from Role 1 if available)
        "header_findings": d.get("header_findings", []),
        "header_risk_tally": float(d.get("header_risk_tally", 0) or 0),
        "received_chain": d.get("received_chain", []),

        # URLs
        "urls": _parse_urls(d.get("urls", "")),
        "url_count": int(d.get("url_count", 0) or 0),
        "html_link_count": int(d.get("html_link_count", 0) or 0),
        "html_destination_mismatch": int(bool(d.get("html_destination_mismatch", 0))),

        # IPs
        "ip_count": int(d.get("ip_count", 0) or 0),
        "private_ips": int(d.get("private_ips", 0) or 0),

        # Attachments
        "attachment_count": int(d.get("attachment_count", 0) or 0),
        "executable_attachments": int(d.get("executable_attachments", 0) or 0),

        # Evidence (from Role 1's evidence_analyzer if available)
        "evidence_tally": float(d.get("evidence_tally", 0) or 0),
        "evidence_risk_category": _safe_str(d.get("evidence_risk_category", "")),

        # Label (None for inference; set for training)
        "label": d.get("label"),
    })

    return row


# ---------------------------------------------------------------------------
# eml_to_ml_row — optional path using Role 1 parser
# ---------------------------------------------------------------------------

def eml_to_ml_row(eml_path: str) -> pd.Series:
    """
    Parse a .eml file and convert to a feature-ready pandas Series.

    Requires Role 1's parser.py to be available at the project root.
    Falls back gracefully if parser is not available.

    Args:
        eml_path: Absolute or relative path to a .eml file

    Returns:
        pandas.Series ready for feature extraction

    Raises:
        RuntimeError: If parser.py is not available
        FileNotFoundError: If .eml file does not exist
    """
    eml_path = Path(eml_path)
    if not eml_path.exists():
        raise FileNotFoundError(f".eml file not found: {eml_path}")

    email_dict = None
    if _parser_available and _parse_email_fn is not None:
        try:
            result = _parse_email_fn(str(eml_path))
            # Map parser output fields to ML dict format
            email_info = result.get("email", {})
            auth = result.get("authentication", {})
            header = result.get("header_analysis", {})
            urls_list = result.get("url_analysis", [])
            html_links = result.get("html_links", [])
            ips = result.get("ip_analysis", [])
            attachments = result.get("attachments", [])
            evidence = result.get("evidence_analysis", {})
            received = result.get("received_chain", [])
            body = _extract_body_from_result(result)

            email_dict = {
                "email_id": email_info.get("email_id", ""),
                "sender": email_info.get("from", ""),
                "reply_to": email_info.get("reply_to", ""),
                "return_path": email_info.get("return_path", ""),
                "subject": email_info.get("subject", ""),
                "body": body,
                "body_text": body,
                "spf": auth.get("spf", ""),
                "dkim": auth.get("dkim", ""),
                "dmarc": auth.get("dmarc", ""),
                "header_findings": header.get("findings", []),
                "header_risk_tally": result.get("header_risk", {}).get("tally", 0),
                "received_chain": received,
                "urls": "|".join(u.get("url", "") for u in urls_list if u.get("url")),
                "url_count": len(urls_list),
                "html_link_count": len(html_links),
                "html_destination_mismatch": int(any(l.get("destination_mismatch") for l in html_links)),
                "ip_count": len(ips),
                "private_ips": sum(1 for ip in ips if ip.get("is_private")),
                "attachment_count": len(attachments),
                "executable_attachments": sum(1 for a in attachments if a.get("is_executable_extension")),
                "evidence_tally": evidence.get("tally", 0),
                "evidence_risk_category": evidence.get("risk_category", ""),
                "label": None,
            }
        except Exception as exc:
            logger.warning(f"Role 1 parser failed on {eml_path} ({exc}); using stdlib fallback parser.")
            email_dict = _parse_eml_stdlib(eml_path)
    else:
        email_dict = _parse_eml_stdlib(eml_path)

    return dict_to_ml_row(email_dict)


def _parse_eml_stdlib(eml_path: Path) -> Dict[str, Any]:
    """Parse .eml file using Python standard library email module."""
    import email
    from email import policy
    import re

    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    subject = str(msg.get("Subject", "") or "")
    sender = str(msg.get("From", "") or "")
    reply_to = str(msg.get("Reply-To", "") or "")
    return_path = str(msg.get("Return-Path", "") or "")
    auth_results = str(msg.get("Authentication-Results", "") or "")

    body = ""
    attachments = 0
    exec_attachments = 0
    exec_exts = {".exe", ".bat", ".cmd", ".vbs", ".scr", ".js", ".ps1", ".hta"}

    if msg.is_multipart():
        for part in msg.walk():
            fn = part.get_filename()
            if fn:
                attachments += 1
                if Path(fn).suffix.lower() in exec_exts:
                    exec_attachments += 1
            ct = part.get_content_type()
            if ct == "text/plain" and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            elif ct == "text/html" and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
        else:
            body = str(msg.get_payload() or "")

    spf, dkim, dmarc = "", "", ""
    auth_lower = auth_results.lower()
    for auth_type in ["spf", "dkim", "dmarc"]:
        m = re.search(rf"{auth_type}=(\w+)", auth_lower)
        if m:
            val = m.group(1)
            if auth_type == "spf": spf = val
            elif auth_type == "dkim": dkim = val
            elif auth_type == "dmarc": dmarc = val

    url_pattern = re.compile(r'https?://[^\s<>"\'\)]+')
    urls = url_pattern.findall(body)

    return {
        "email_id": str(msg.get("Message-ID", eml_path.stem) or ""),
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "body": body,
        "body_text": body,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "header_findings": [],
        "header_risk_tally": 0,
        "received_chain": [],
        "urls": "|".join(urls),
        "url_count": len(urls),
        "html_link_count": 0,
        "html_destination_mismatch": 0,
        "ip_count": 0,
        "private_ips": 0,
        "attachment_count": attachments,
        "executable_attachments": exec_attachments,
        "evidence_tally": 0.0,
        "evidence_risk_category": "",
        "label": None,
    }


def _extract_body_from_result(result: Dict) -> str:
    """Extract plain text body from parser result."""
    body = ""
    # Some parsers expose the raw message object
    message = result.get("_raw_message")
    if message and hasattr(message, "is_multipart"):
        if message.is_multipart():
            for part in message.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    try:
                        body += part.get_content()
                    except Exception:
                        pass
        else:
            try:
                if message.get_content_type() == "text/plain":
                    body = message.get_content()
            except Exception:
                pass

    # Fallback to result fields
    if not body:
        body = str(result.get("body", "") or result.get("body_text", "") or "")

    return body


# ---------------------------------------------------------------------------
# CSV / DataFrame ingestion for training
# ---------------------------------------------------------------------------

def load_csv_dataset(
    path: str,
    label_col: str = "label",
    required_cols: Optional[List[str]] = None,
    drop_empty_label: bool = True,
) -> pd.DataFrame:
    """
    Load a CSV training dataset and normalize it for ML use.

    Expected columns (any subset is acceptable):
        subject, body / body_text, sender / from, reply_to, return_path,
        spf, dkim, dmarc, urls, label

    Args:
        path: Path to CSV file
        label_col: Column name containing class labels
        required_cols: If set, raise if these columns are missing
        drop_empty_label: Drop rows where label is NaN/empty

    Returns:
        Normalized pd.DataFrame
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"CSV dataset not found: {path}")

    df = pd.read_csv(path, encoding="utf-8", on_bad_lines="warn")
    initial_len = len(df)
    logger.info(f"Loaded {initial_len} rows from {path}")

    # Remove duplicates
    df = df.drop_duplicates()
    dupes_removed = initial_len - len(df)
    if dupes_removed:
        logger.info(f"Removed {dupes_removed} duplicate rows")

    # Normalize label column
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found. Available: {list(df.columns)}")

    if drop_empty_label:
        before = len(df)
        df = df[df[label_col].notna() & (df[label_col].astype(str).str.strip() != "")]
        dropped = before - len(df)
        if dropped:
            logger.warning(f"Dropped {dropped} rows with empty/null labels")

    # Normalize 'ham' → 'benign'
    df[label_col] = df[label_col].astype(str).str.lower().str.strip()
    df[label_col] = df[label_col].replace({"ham": "benign"})

    # Check label distribution
    dist = df[label_col].value_counts()
    logger.info(f"Class distribution:\n{dist.to_string()}")

    # Check for unexpected labels
    valid_labels = {"benign", "spam", "phishing", "bec", "impersonation"}
    unknown = set(df[label_col].unique()) - valid_labels
    if unknown:
        logger.warning(f"Unknown label values found (will be kept but may cause issues): {unknown}")

    # Check required columns
    if required_cols:
        missing = [c for c in required_cols if c not in df.columns]
        if missing:
            raise ValueError(f"Required columns missing from dataset: {missing}")

    # Normalize body column alias
    if "body" not in df.columns and "body_text" in df.columns:
        df["body"] = df["body_text"]
    elif "body_text" not in df.columns and "body" in df.columns:
        df["body_text"] = df["body"]

    return df.reset_index(drop=True)


def load_eml_directory_ml(directory: str, label: Optional[str] = None) -> pd.DataFrame:
    """
    Load all .eml files from a directory and convert to DataFrame.

    Requires Role 1 parser.py.

    Args:
        directory: Path to directory containing .eml files
        label: Optional label to assign to all emails

    Returns:
        DataFrame with one row per email (empty if directory is empty or parser unavailable)
    """
    if not _parser_available:
        logger.warning(
            "Role 1 parser.py not available. Cannot load .eml files. "
            "Use load_csv_dataset() instead."
        )
        return pd.DataFrame()

    path = Path(directory)
    if not path.exists():
        logger.warning(f"Directory not found: {path}")
        return pd.DataFrame()

    eml_files = list(path.glob("*.eml")) + list(path.glob("*.EML"))
    if not eml_files:
        logger.warning(f"No .eml files found in {path}")
        return pd.DataFrame()

    rows = []
    failed = 0
    for f in eml_files:
        try:
            row = eml_to_ml_row(str(f))
            if label:
                row["label"] = label
            rows.append(row)
        except Exception as exc:
            logger.warning(f"Failed to parse {f.name}: {exc}")
            failed += 1

    if failed:
        logger.warning(f"Failed to parse {failed}/{len(eml_files)} .eml files")

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    return df