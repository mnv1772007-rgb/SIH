#!/usr/bin/env python3
"""Normalize untrusted RFC822 corpora into a validated, offline JSONL dataset.

The processor deliberately treats every input file as hostile or malformed. A
bad message becomes a structured issue record; it never terminates a batch or
causes the original corpus to be moved or overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Iterable

try:  # Supports both ``python -m AI_model...`` and direct script execution.
    from AI_model.dataset_utils import near_duplicate_components, normalise_for_fingerprint
    from AI_model.email_decoding import safe_decode_header, safe_get_part_text
except ModuleNotFoundError:  # pragma: no cover - direct CLI compatibility
    from dataset_utils import near_duplicate_components, normalise_for_fingerprint
    from email_decoding import safe_decode_header, safe_get_part_text


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS_DIR = PROJECT_ROOT / "datasets" / "downloads"
PROCESSED_DIR = PROJECT_ROOT / "datasets" / "processed"
QUARANTINE_DIR = PROJECT_ROOT / "datasets" / "quarantine"
METADATA_DIR = PROJECT_ROOT / "datasets" / "metadata"
MAX_FILE_BYTES = 10 * 1024 * 1024
URL_PATTERN = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
ARCHIVE_SUFFIXES = {".tar", ".gz", ".bz2", ".zip", ".tgz", ".tbz", ".tbz2", ".7z"}


@dataclass
class EmailRecord:
    id: str
    label: str
    source_dataset: str
    subject: str
    body: str
    text: str
    text_hash: str
    metadata: dict[str, Any]
    # Compatibility fields used by the existing training and forensic modules.
    body_text: str = ""
    body_html: str = ""
    sender_domain: str = ""
    has_url: bool = False
    url_count: int = 0
    attachment_count: int = 0
    source_file: str = ""
    sha256: str = ""
    near_duplicate_group: str = ""


@dataclass
class ProcessingOutcome:
    record: EmailRecord | None = None
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def extract_sender_domain(from_header: str) -> str:
    _, address = parseaddr(from_header)
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def extract_urls(text: str) -> list[str]:
    return [match.rstrip(".,;:!?)]") for match in URL_PATTERN.findall(text or "")]


def _visible_html(value: str) -> str:
    """Extract text without rendering, executing, or fetching HTML resources."""
    value = re.sub(r"(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>", " ", value)
    return re.sub(r"(?s)<[^>]+>", " ", value)


def _clean(value: str, limit: int = 20_000) -> str:
    value = (value or "").replace("\x00", "�")
    value = "\n".join(line.rstrip() for line in value.splitlines())
    return value[:limit]


def _message_defects(message: Any) -> list[str]:
    return [f"parser_defect:{type(defect).__name__}" for defect in (getattr(message, "defects", ()) or ())]


def _safe_header(message: Any, name: str) -> tuple[str, list[str]]:
    try:
        decoded = safe_decode_header(message.get(name, ""))
        return decoded.text, list(decoded.warnings)
    except (LookupError, UnicodeDecodeError, ValueError, TypeError, AttributeError) as exc:
        return "", [f"header_unavailable:{name}:{type(exc).__name__}"]


def _part_disposition(part: Any) -> str:
    try:
        return (part.get_content_disposition() or "").lower()
    except (LookupError, UnicodeDecodeError, ValueError, TypeError, AttributeError):
        return ""


def _part_content_type(part: Any) -> str:
    try:
        return (part.get_content_type() or "").lower()
    except (LookupError, UnicodeDecodeError, ValueError, TypeError, AttributeError):
        return "application/octet-stream"


def process_email_file(path: Path, label: str, source_dataset: str, max_file_bytes: int = MAX_FILE_BYTES) -> ProcessingOutcome:
    """Return an extracted record or a non-fatal, machine-readable reason."""
    try:
        if path.stat().st_size > max_file_bytes:
            return ProcessingOutcome(reason="file_too_large")
        raw = path.read_bytes()
    except (OSError, ValueError) as exc:
        return ProcessingOutcome(reason=f"read_error:{type(exc).__name__}")
    if not raw or not raw.strip(b"\x00\r\n\t "):
        return ProcessingOutcome(reason="empty_file")
    if b":" not in raw[:8192]:
        return ProcessingOutcome(reason="not_rfc822_like")

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # Parser defects vary by Python version and source data.
        return ProcessingOutcome(reason=f"parse_error:{type(exc).__name__}")

    warnings = _message_defects(message)
    if b"\x00" in raw:
        warnings.append("raw_null_bytes_present")
    subject_value, subject_warnings = _safe_header(message, "Subject")
    sender_value, sender_warnings = _safe_header(message, "From")
    warnings.extend(subject_warnings)
    warnings.extend(sender_warnings)
    subject = _clean(subject_value, limit=500)
    sender_domain = extract_sender_domain(sender_value)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachment_count = 0
    content_types: set[str] = set()
    try:
        parts: Iterable[Any] = message.walk() if message.is_multipart() else (message,)
        for part in parts:
            disposition = _part_disposition(part)
            content_type = _part_content_type(part)
            content_types.add(content_type)
            if disposition == "attachment":
                attachment_count += 1
                continue
            if content_type not in {"text/plain", "text/html"}:
                continue
            decoded = safe_get_part_text(part)
            warnings.extend(decoded.warnings)
            content = _clean(decoded.text)
            if content_type == "text/html":
                html_parts.append(content)
            elif content:
                text_parts.append(content)
    except (LookupError, UnicodeDecodeError, ValueError, TypeError, AttributeError) as exc:
        return ProcessingOutcome(reason=f"mime_walk_error:{type(exc).__name__}", warnings=list(dict.fromkeys(warnings)))

    body_text = _clean("\n".join(text_parts))
    body_html = _clean("\n".join(html_parts))
    body = body_text or _clean(_visible_html(body_html))
    normalized = normalise_for_fingerprint(f"{subject}\n{body_text}\n{_visible_html(body_html)}")
    if len(normalized) < 20:
        return ProcessingOutcome(reason="insufficient_visible_text", warnings=list(dict.fromkeys(warnings)))

    urls = extract_urls(f"{body_text}\n{body_html}")
    raw_hash = hashlib.sha256(raw).hexdigest()
    text_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    record = EmailRecord(
        id=raw_hash[:16], label=label, source_dataset=source_dataset, subject=subject,
        body=body, text=normalized, text_hash=text_hash,
        metadata={
            "parse_warnings": list(dict.fromkeys(warnings)),
            "content_types": sorted(content_types), "has_html": bool(body_html),
            "charset_handling": "declared charset validated with utf-8, latin-1, cp1252 fallbacks",
        },
        body_text=body_text, body_html=body_html, sender_domain=sender_domain,
        has_url=bool(urls), url_count=len(urls), attachment_count=attachment_count,
        source_file=_safe_relative(path, PROJECT_ROOT), sha256=raw_hash, near_duplicate_group=text_hash,
    )
    return ProcessingOutcome(record=record, warnings=list(dict.fromkeys(warnings)))


def iter_candidate_files(root: Path) -> Iterable[Path]:
    """Yield mail candidates irrespective of filename extension.

    ``os.walk`` also sees legacy Windows names ending in a period, which
    ``Path.rglob(...).is_file()`` can miss. URL data and archives are excluded.
    """
    for directory, _, names in os.walk(root):
        directory_path = Path(directory)
        for name in names:
            path = directory_path / name
            relative_parts = _safe_relative(path, root).replace("\\", "/").split("/")
            if name == "cmds" or "urls" in relative_parts or path.suffix.lower() in ARCHIVE_SUFFIXES:
                continue
            yield path


def load_label_mapping() -> dict[str, str]:
    return {
        "easy_ham": "benign", "hard_ham": "benign", "spam": "spam", "spam_2": "spam",
        "benign": "benign", "phishing": "phishing", "bec": "bec", "malware": "malware",
        "maildir": "unlabelled",
    }


def _copy_to_quarantine(path: Path, quarantine_dir: Path, reason: str) -> str | None:
    try:
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.name) or "sample.eml"
        destination = quarantine_dir / f"{reason.split(':', 1)[0]}_{hashlib.sha256(str(path).encode()).hexdigest()[:12]}_{name}"
        shutil.copy2(path, destination)
        return str(destination)
    except (OSError, ValueError):
        return None


def _validate_jsonl(path: Path) -> tuple[int, int]:
    valid, invalid = 0, 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                parsed = json.loads(line)
                if all(parsed.get(field) is not None for field in ("id", "label", "source_dataset", "text", "text_hash", "metadata")):
                    valid += 1
                else:
                    invalid += 1
            except json.JSONDecodeError:
                invalid += 1
    return valid, invalid


def main() -> int:
    parser = argparse.ArgumentParser(description="Process raw email datasets into resilient normalized JSONL")
    parser.add_argument("--input", type=Path, default=DOWNLOADS_DIR, help="Input directory with raw emails")
    parser.add_argument("--output", type=Path, default=PROCESSED_DIR / "emails.jsonl", help="Output JSONL path")
    parser.add_argument("--quarantine", type=Path, default=QUARANTINE_DIR, help="Optional copy destination for unusable samples")
    parser.add_argument("--copy-quarantine", action="store_true", help="Copy unusable samples; default is log-only and preserves the corpus")
    parser.add_argument("--limit-per-label", type=int, help="Limit accepted samples per label for a quick smoke run")
    parser.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES, help="Skip larger files safely")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    if args.copy_quarantine:
        args.quarantine.mkdir(parents=True, exist_ok=True)

    label_map = load_label_mapping()
    candidates = sorted(iter_candidate_files(args.input), key=lambda path: str(path).lower())
    print(f"Scanning {args.input} for email-like corpus files...")
    print(f"Found {len(candidates)} candidate files")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    issues_path = METADATA_DIR / f"email_processing_issues_{timestamp}.jsonl"
    stats: dict[str, Any] = {
        "candidate_files": len(candidates), "processed": 0, "duplicates": 0,
        "skipped_unlabelled": 0, "skipped_limit": 0, "malformed": 0,
        "by_label": {}, "by_source": {}, "issues_by_reason": {}, "warning_samples": 0,
    }
    accepted: list[EmailRecord] = []
    seen_text_hashes: dict[str, EmailRecord] = {}
    with issues_path.open("w", encoding="utf-8") as issue_handle:
        for position, path in enumerate(candidates, start=1):
            relative_parts = _safe_relative(path, args.input).replace("\\", "/").split("/")
            source_dataset = relative_parts[0] if relative_parts else "unknown"
            label = label_map.get(source_dataset, "unknown")
            issue_base = {"source_file": _safe_relative(path, PROJECT_ROOT), "source_dataset": source_dataset, "label": label}
            if position % 500 == 0:
                print(f"  Progress: {position}/{len(candidates)} candidates, {stats['processed']} accepted", flush=True)
            if label in {"unlabelled", "unknown"}:
                stats["skipped_unlabelled"] += 1
                issue_handle.write(json.dumps({**issue_base, "reason": "unlabelled_source"}) + "\n")
                continue
            if args.limit_per_label and stats["by_label"].get(label, 0) >= args.limit_per_label:
                stats["skipped_limit"] += 1
                continue
            outcome = process_email_file(path, label, source_dataset, args.max_file_bytes)
            if outcome.record is None:
                reason = outcome.reason or "unknown_processing_error"
                stats["malformed"] += 1
                stats["issues_by_reason"][reason] = stats["issues_by_reason"].get(reason, 0) + 1
                issue = {**issue_base, "reason": reason, "warnings": outcome.warnings}
                if args.copy_quarantine:
                    issue["quarantine_copy"] = _copy_to_quarantine(path, args.quarantine, reason)
                issue_handle.write(json.dumps(issue) + "\n")
                continue
            record = outcome.record
            if record.text_hash in seen_text_hashes:
                stats["duplicates"] += 1
                existing = seen_text_hashes[record.text_hash]
                issue_handle.write(json.dumps({**issue_base, "reason": "exact_text_duplicate", "duplicate_of": existing.id, "cross_label": existing.label != label}) + "\n")
                continue
            seen_text_hashes[record.text_hash] = record
            accepted.append(record)
            stats["processed"] += 1
            stats["by_label"][label] = stats["by_label"].get(label, 0) + 1
            stats["by_source"][source_dataset] = stats["by_source"].get(source_dataset, 0) + 1
            if outcome.warnings:
                stats["warning_samples"] += 1

    fingerprints, components, compared_pairs = near_duplicate_components([record.text for record in accepted])
    for index, record in enumerate(accepted):
        record.metadata["simhash64"] = f"{fingerprints[index]:016x}"
    for component in components:
        group_id = min(accepted[index].text_hash for index in component)
        for index in component:
            accepted[index].near_duplicate_group = group_id
            accepted[index].metadata["near_duplicate_group"] = group_id
    stats.update({"near_duplicate_groups": len(components), "near_duplicate_samples": sum(len(component) for component in components), "near_duplicate_candidate_pairs_compared": compared_pairs})

    temporary_output = args.output.with_suffix(args.output.suffix + ".tmp")
    with temporary_output.open("w", encoding="utf-8", newline="\n") as output_handle:
        for record in accepted:
            output_handle.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")
    temporary_output.replace(args.output)
    jsonl_valid, jsonl_invalid = _validate_jsonl(args.output)
    stats["jsonl_valid_lines"], stats["jsonl_invalid_lines"] = jsonl_valid, jsonl_invalid
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "input_dir": str(args.input),
        "output_file": str(args.output), "issues_file": str(issues_path), "stats": stats,
        "quarantine_mode": "copy" if args.copy_quarantine else "log_only",
        "notes": ["Original corpora are preserved by default.", "Near-duplicate groups are intended for leakage-safe splits, not automatic relabelling."],
    }
    report_path = METADATA_DIR / f"email_processing_report_{timestamp}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\nProcessing complete:")
    print(f"  Candidate files:      {stats['candidate_files']}")
    print(f"  Processed:            {stats['processed']}")
    print(f"  Exact duplicates:     {stats['duplicates']}")
    print(f"  Malformed/skipped:    {stats['malformed']}")
    print(f"  Unlabelled skipped:   {stats['skipped_unlabelled']}")
    print(f"  Near-duplicate groups:{stats['near_duplicate_groups']}")
    for label, count in sorted(stats["by_label"].items()):
        print(f"  {label}: {count}")
    print(f"  JSONL validation:     {jsonl_valid} valid, {jsonl_invalid} invalid")
    print(f"  Issue log: {issues_path}")
    print(f"  Report: {report_path}")
    return 0 if jsonl_invalid == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
