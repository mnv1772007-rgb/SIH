"""
Body Extractor — handles MIME multipart decoding, text/HTML body extraction,
and attachment enumeration with hashing.
SIH 26106 — IronPulse | Role 1
"""

from __future__ import annotations

import base64
import email.message
import hashlib
import quopri
from dataclasses import dataclass, field
from typing import Optional

import chardet


@dataclass
class BodyContent:
    text_plain: Optional[str]        = None
    text_html: Optional[str]         = None
    attachments: list["Attachment"]  = field(default_factory=list)


@dataclass
class Attachment:
    filename: Optional[str]
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    payload_bytes: bytes  # raw attachment bytes (kept in memory for hashing)

    @property
    def is_executable(self) -> bool:
        exts = {".exe", ".bat", ".cmd", ".ps1", ".sh", ".vbs", ".js", ".jar",
                ".com", ".scr", ".pif", ".msi", ".dll"}
        if self.filename:
            import pathlib
            return pathlib.Path(self.filename).suffix.lower() in exts
        return False

    @property
    def is_archive(self) -> bool:
        exts = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
                ".iso", ".cab", ".ace"}
        if self.filename:
            import pathlib
            return pathlib.Path(self.filename).suffix.lower() in exts
        return False

    @property
    def is_office_doc(self) -> bool:
        exts = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                ".odt", ".ods", ".odp", ".rtf", ".pdf"}
        if self.filename:
            import pathlib
            return pathlib.Path(self.filename).suffix.lower() in exts
        return False


def extract_body(msg: email.message.Message) -> BodyContent:
    """
    Walk the MIME tree and extract:
    - text/plain body
    - text/html body
    - All attachments with MD5/SHA1/SHA256 hashes
    """
    content = BodyContent()

    for part in msg.walk():
        ct = part.get_content_type()
        disp = part.get_content_disposition() or ""

        # Skip multipart containers
        if ct.startswith("multipart/"):
            continue

        raw_payload = _decode_payload(part)
        if raw_payload is None:
            continue

        # Text parts (body)
        if ct == "text/plain" and "attachment" not in disp and content.text_plain is None:
            content.text_plain = _bytes_to_str(raw_payload)
            continue

        if ct == "text/html" and "attachment" not in disp and content.text_html is None:
            content.text_html = _bytes_to_str(raw_payload)
            continue

        # Everything else is an attachment
        filename = _get_filename(part)
        att = _make_attachment(raw_payload, filename, ct)
        content.attachments.append(att)

    return content


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_payload(part: email.message.Message) -> bytes | None:
    """Decode a MIME part payload to raw bytes, handling CTE."""
    try:
        raw = part.get_payload(decode=True)
        if raw is not None:
            return raw
        # Fallback: get raw string and encode
        raw_str = part.get_payload()
        if isinstance(raw_str, str):
            return raw_str.encode("utf-8", errors="replace")
        return None
    except Exception:
        return None


def _bytes_to_str(data: bytes) -> str:
    """Convert bytes to str using chardet for encoding detection."""
    detected = chardet.detect(data[:4096])
    enc = detected.get("encoding") or "utf-8"
    try:
        return data.decode(enc, errors="replace")
    except Exception:
        return data.decode("utf-8", errors="replace")


def _get_filename(part: email.message.Message) -> str | None:
    """Extract filename from Content-Disposition or Content-Type params."""
    filename = part.get_filename()
    if filename:
        from ..utils.helpers import decode_mime_words
        return decode_mime_words(filename)
    return None


def _make_attachment(raw: bytes, filename: str | None, ct: str) -> Attachment:
    return Attachment(
        filename=filename,
        content_type=ct,
        size_bytes=len(raw),
        md5=hashlib.md5(raw).hexdigest(),
        sha1=hashlib.sha1(raw).hexdigest(),
        sha256=hashlib.sha256(raw).hexdigest(),
        payload_bytes=raw,
    )
