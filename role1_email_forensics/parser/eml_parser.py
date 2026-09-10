"""
EML Parser — ingests .eml files and returns a parsed email.message.Message object.
SIH 26106 — IronPulse | Role 1
"""

from __future__ import annotations

import email
import email.policy
import hashlib
from pathlib import Path


def parse_eml_file(path: str | Path) -> tuple[email.message.Message, str, int]:
    """
    Parse a .eml file from disk.

    Returns:
        (message, raw_sha256_hex, raw_size_bytes)
    """
    path = Path(path)
    raw_bytes = path.read_bytes()
    return _parse_raw(raw_bytes)


def parse_eml_bytes(raw_bytes: bytes) -> tuple[email.message.Message, str, int]:
    """
    Parse an .eml from raw bytes (e.g., uploaded via API).

    Returns:
        (message, raw_sha256_hex, raw_size_bytes)
    """
    return _parse_raw(raw_bytes)


def _parse_raw(raw: bytes) -> tuple[email.message.Message, str, int]:
    sha256 = hashlib.sha256(raw).hexdigest()
    size   = len(raw)

    # Use the modern email policy for better header handling
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception:
        # Fallback: strip null bytes and retry
        raw = raw.replace(b"\x00", b"")
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)

    return msg, sha256, size
