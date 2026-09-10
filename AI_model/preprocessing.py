"""Safe corpus loading and text normalization for the offline ML baseline."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Iterable

try:
    from AI_model.email_decoding import safe_decode_header, safe_get_part_text
except ModuleNotFoundError:  # pragma: no cover - direct script compatibility
    from email_decoding import safe_decode_header, safe_get_part_text


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_ROOT = PROJECT_ROOT / "datasets" / "downloads"
LABELLED_DIRECTORIES = {
    "easy_ham": "benign",
    "hard_ham": "benign",
    "spam": "spam",
    "spam_2": "spam",
}


@dataclass(frozen=True)
class CorpusDocument:
    path: Path
    label: str
    text: str
    group: str


def extract_email_text(raw: bytes) -> str:
    """Extract headers and visible text without executing or rendering content."""
    message = BytesParser(policy=policy.default).parsebytes(raw)
    headers = " ".join(
        safe_decode_header(message.get(name, "")).text
        for name in ("Subject", "From", "To", "Reply-To")
    )
    fragments: list[str] = []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_disposition() == "attachment" or part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        fragments.append(safe_get_part_text(part).text)
    return normalise_text(" ".join([headers, *fragments]))


def normalise_text(value: str) -> str:
    """Normalize whitespace and redact volatile tokens to reduce train/test leakage."""
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"https?://\S+", " URL ", value, flags=re.IGNORECASE)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", " EMAIL ", value)
    value = re.sub(r"\b[0-9a-f]{24,}\b", " TOKEN ", value, flags=re.IGNORECASE)
    return " ".join(value.lower().split())


def corpus_documents(corpus_root: Path = DEFAULT_CORPUS_ROOT, limit_per_label: int | None = None) -> Iterable[CorpusDocument]:
    """Yield labelled SpamAssassin corpus documents, deduplicated by text hash."""
    seen: set[str] = set()
    per_label: dict[str, int] = {}
    for directory, label in LABELLED_DIRECTORIES.items():
        source = corpus_root / directory
        if not source.is_dir():
            continue
        for path in sorted(source.rglob("*")):
            if not path.is_file() or path.name == "cmds":
                continue
            if limit_per_label is not None and per_label.get(label, 0) >= limit_per_label:
                continue
            try:
                text = extract_email_text(path.read_bytes())
            except (OSError, UnicodeError, ValueError):
                continue
            if len(text) < 20:
                continue
            group = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
            if group in seen:
                continue
            seen.add(group)
            per_label[label] = per_label.get(label, 0) + 1
            yield CorpusDocument(path=path, label=label, text=text, group=group)
