"""Static attachment metadata analysis; attachment payloads are never executed."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any


EXECUTABLE_EXTENSIONS = {
    ".ade", ".adp", ".app", ".bat", ".cmd", ".com", ".dll", ".exe",
    ".hta", ".iso", ".jar", ".js", ".jse", ".lnk", ".msi", ".msp",
    ".ps1", ".scr", ".vbe", ".vbs", ".wsf",
}
EXPECTED_MIME_TYPES = {
    ".pdf": {"application/pdf"},
    ".jpg": {"image/jpeg"}, ".jpeg": {"image/jpeg"}, ".png": {"image/png"},
    ".gif": {"image/gif"}, ".txt": {"text/plain"},
    ".html": {"text/html"}, ".htm": {"text/html"},
    ".zip": {"application/zip", "application/x-zip-compressed"},
}


def analyze_attachment(part: Any) -> dict[str, Any]:
    """Return static metadata and hashes for one MIME attachment."""
    filename = part.get_filename()
    content_type = part.get_content_type()
    payload = part.get_payload(decode=True) or b""
    extension = Path(filename).suffix.lower() if filename else None
    allowed_types = EXPECTED_MIME_TYPES.get(extension)
    return {
        "filename": filename,
        "extension": extension,
        "content_type": content_type,
        "content_disposition": part.get_content_disposition(),
        "content_id": part.get("Content-ID"),
        "content_transfer_encoding": part.get("Content-Transfer-Encoding"),
        "size_bytes": len(payload),
        "sha256": sha256(payload).hexdigest() if payload else None,
        "is_executable_extension": bool(extension and extension in EXECUTABLE_EXTENSIONS),
        "mime_extension_mismatch": bool(allowed_types and content_type not in allowed_types),
    }
