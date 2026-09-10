"""Defensive MIME decoding helpers for untrusted, real-world email corpora.

Email charset declarations are sender-controlled metadata.  They are therefore
treated as a hint, never as something that is safe to pass directly to
``bytes.decode``.  The helpers in this module intentionally preserve text with
replacement characters rather than letting one bad message stop a batch.
"""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass
from email.header import decode_header
from typing import Any


FALLBACK_CHARSETS = ("utf-8", "latin-1", "cp1252")


@dataclass(frozen=True)
class DecodedText:
    """Decoded content and non-fatal issues observed while decoding it."""

    text: str
    charset_used: str
    warnings: tuple[str, ...] = ()


def normalize_charset(value: Any) -> str | None:
    """Return a known Python codec name for a declared charset, or ``None``.

    Real messages often use quoted, padded, or otherwise malformed values.
    This validates values through Python's codec registry instead of maintaining
    a fragile list of one-off bad declarations.
    """

    if not isinstance(value, str):
        return None
    candidate = value.strip().strip("\"'").lower()
    candidate = re.sub(r"\s+", "", candidate).replace("_", "-")
    if not candidate or len(candidate) > 80 or any(ord(char) < 32 for char in candidate):
        return None
    try:
        return codecs.lookup(candidate).name
    except LookupError:
        return None


def safe_decode_bytes(payload: bytes | bytearray | memoryview | str | None, declared_charset: Any = None) -> DecodedText:
    """Decode untrusted MIME bytes without propagating charset/Unicode failures.

    The declared charset is attempted first when it resolves to a supported
    codec.  A fixed, general fallback sequence then retains as much evidence as
    possible.  ``errors='replace'`` is deliberately used only after strict
    decoding fails, allowing the caller to retain useful warning metadata.
    """

    if payload is None:
        return DecodedText("", "none", ("empty_payload",))
    if isinstance(payload, str):
        return DecodedText(payload.replace("\x00", "�"), "already_text", ())
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return DecodedText("", "none", ("unsupported_payload_type",))

    data = bytes(payload)
    warnings: list[str] = []
    if b"\x00" in data:
        warnings.append("null_bytes_replaced")

    normalized_declared = normalize_charset(declared_charset)
    if declared_charset and not normalized_declared:
        warnings.append("invalid_declared_charset")

    candidates: list[str] = []
    if normalized_declared:
        candidates.append(normalized_declared)
    candidates.extend(charset for charset in FALLBACK_CHARSETS if charset not in candidates)

    for charset in candidates:
        try:
            return DecodedText(data.decode(charset, errors="strict").replace("\x00", "�"), charset, tuple(warnings))
        except (LookupError, UnicodeDecodeError) as exc:
            warnings.append(f"decode_failed:{charset}:{type(exc).__name__}")

    # latin-1 is defined for every byte, but retain a final defensive path for
    # unusual bytes-like objects or platform codec failures.
    try:
        return DecodedText(data.decode("utf-8", errors="replace").replace("\x00", "�"), "utf-8-replace", tuple(warnings + ["replacement_decode_used"]))
    except (LookupError, UnicodeDecodeError, ValueError, TypeError) as exc:
        return DecodedText("", "unavailable", tuple(warnings + [f"unrecoverable_payload:{type(exc).__name__}"]))


def safe_decode_header(value: Any) -> DecodedText:
    """Decode RFC 2047 header text while tolerating bad charset declarations."""

    if value is None:
        return DecodedText("", "none", ())
    try:
        chunks = decode_header(str(value))
    except (ValueError, TypeError, UnicodeError) as exc:
        return DecodedText(str(value).replace("\x00", "�"), "raw_header", (f"malformed_header:{type(exc).__name__}",))

    decoded: list[str] = []
    warnings: list[str] = []
    charsets: list[str] = []
    for chunk, declared_charset in chunks:
        result = safe_decode_bytes(chunk, declared_charset)
        decoded.append(result.text)
        charsets.append(result.charset_used)
        warnings.extend(result.warnings)
    return DecodedText("".join(decoded), ",".join(charsets) or "none", tuple(dict.fromkeys(warnings)))


def safe_get_part_text(part: Any) -> DecodedText:
    """Decode a MIME part without trusting its transfer encoding or charset."""

    warnings: list[str] = []
    try:
        payload = part.get_payload(decode=True)
    except (LookupError, UnicodeDecodeError, ValueError, TypeError, AttributeError) as exc:
        payload = None
        warnings.append(f"malformed_mime_payload:{type(exc).__name__}")

    if payload is None:
        try:
            payload = part.get_payload(decode=False)
        except (LookupError, UnicodeDecodeError, ValueError, TypeError, AttributeError) as exc:
            return DecodedText("", "unavailable", tuple(warnings + [f"payload_unavailable:{type(exc).__name__}"]))

    try:
        declared_charset = part.get_content_charset()
    except (LookupError, UnicodeDecodeError, ValueError, TypeError, AttributeError) as exc:
        declared_charset = None
        warnings.append(f"charset_unavailable:{type(exc).__name__}")

    result = safe_decode_bytes(payload, declared_charset)
    return DecodedText(result.text, result.charset_used, tuple(dict.fromkeys(warnings + list(result.warnings))))
